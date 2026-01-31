import subprocess
import json
import os
import tempfile
from datetime import datetime

class NucleiEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        
    def run(self, target_urls):
        """
        Runs Nuclei scan on the provided target URLs.
        Returns a list of vulnerability objects (dicts) ready for DB insertion.
        """
        if not target_urls:
            print("No target URLs provided for Nuclei scan.")
            return []

        results = []
        
        # Create a temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as targets_file:
            for target in target_urls:
                targets_file.write(f"{target.url}\n")
            targets_path = targets_file.name
            
        # Create a temporary file for JSON output
        output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json')
        output_path = output_file.name
        output_file.close() # Close usage, nuclei will write to it
        
        try:
            # Build Nuclei Command
            # -silent: Less terminal noise
            # -json-export: Export results to JSON file
            # -l: Targets file
            # Default templates are used. Assuming 'nuclei' is in PATH.
            cmd = [
                'nuclei',
                '-l', targets_path,
                '-json-export', output_path,
                '-silent'
            ]
            
            print(f"Running Nuclei: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                print(f"Nuclei Execution Warning: {process.stderr}")
                
            # Parse JSON output
            results = self._parse_results(output_path)
            
        except Exception as e:
            print(f"Nuclei Engine Error: {e}")
        finally:
            # Cleanup
            if os.path.exists(targets_path):
                os.remove(targets_path)
            if os.path.exists(output_path):
                os.remove(output_path)
                
        return results

    def _parse_results(self, output_path):
        vulnerabilities = []
        
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return vulnerabilities
            
        try:
            with open(output_path, 'r') as f:
                # Nuclei writes JSON array? Actually modern nuclei writes array if -json-export used?
                # Let's check format. Often it is line-delimited JSON or a full array.
                # Newer versions with -json-export write a JSON Array usually.
                # But let's handle if it is line-based just in case, or array.
                
                content = f.read()
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        items = data
                    else:
                        items = [data]
                except json.JSONDecodeError:
                    # Maybe line delimited?
                     items = [json.loads(line) for line in content.splitlines() if line.strip()]

                for item in items:
                    vuln = self._map_to_vulnerability(item)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            print(f"Error parsing Nuclei JSON: {e}")
            
        return vulnerabilities

    def _map_to_vulnerability(self, item):
        """
        Maps Nuclei JSON format to our Vulnerability model dict.
        """
        try:
            info = item.get('info', {})
            
            # Map Severity
            severity_map = {
                'critical': 'CRITICAL',
                'high': 'HIGH',
                'medium': 'MEDIUM',
                'low': 'LOW',
                'info': 'INFO'
            }
            nuclei_severity = info.get('severity', 'info').lower()
            severity = severity_map.get(nuclei_severity, 'INFO')

            # Handle CWEs safely
            cwe_list = info.get('classification', {}).get('cwe-id', [])
            if isinstance(cwe_list, list):
                owasp_cat = ', '.join(cwe_list)
            elif isinstance(cwe_list, str):
                owasp_cat = cwe_list
            else:
                owasp_cat = ''

            # Create Vulnerability Object
            from app.models import Vulnerability
            
            vuln = Vulnerability(
                scan_id=self.scan_id,
                tool='nuclei',
                vuln_id=item.get('template-id', 'unknown'),
                title=info.get('name', 'Unknown Vulnerability'),
                description=info.get('description', 'No description provided.'),
                severity=severity,
                file_path=item.get('matched-at', ''),
                line_number=0,
                fix_recommendation=info.get('remediation', ''),
                owasp_category=owasp_cat
            )
            return vuln
            
        except Exception as e:
            print(f"Error mapping nuclei item: {e}")
            return None
