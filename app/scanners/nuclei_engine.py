import subprocess
import json
import os
import tempfile
from datetime import datetime

class NucleiEngine:
    def __init__(self, scan_id):
        self.scan_id = scan_id
        
    def run(self, target_urls, config=None):
        """
        Runs Nuclei scan with optional configuration.
        """
        if not target_urls:
            print("No target URLs provided for Nuclei scan.")
            return []

        config = config or {}
        results = []
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as targets_file:
            for target in target_urls:
                targets_file.write(f"{target.url}\n")
            targets_path = targets_file.name
            
        output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json')
        output_path = output_file.name
        output_file.close()
        
        try:
            # Build Command
            cmd = ['nuclei', '-l', targets_path, '-json-export', output_path, '-silent']
            
            # --- Apply Configuration ---
            
            # Filtering
            if config.get('severity'):
                # Handle list of severities
                sevs = config['severity']
                if isinstance(sevs, list):
                    sevs = ','.join(sevs)
                if sevs:
                    cmd.extend(['-severity', sevs])
            
            if config.get('tags'):
                cmd.extend(['-tags', config['tags']])
                
            if config.get('exclude_tags'):
                cmd.extend(['-etags', config['exclude_tags']])
                
            # Performance
            if config.get('rate_limit'):
                 cmd.extend(['-rate-limit', str(config['rate_limit'])])
                 
            if config.get('concurrency'):
                 cmd.extend(['-c', str(config['concurrency'])])
                 
            if config.get('timeout'):
                 cmd.extend(['-timeout', str(config['timeout'])])
            
            # Passive Mode
            if config.get('passive'):
                 # -passive enabled passive checks only
                 # Note: Nuclei passive mode might output nothing if no passive templates match
                 # or if urls are just root domains.
                 print("Enabling Passive Mode")
                 # Check if -passive flag is correct for modern nuclei (it is)
                 # Wait, -passive means 'enable passive templates'. 
                 # To run ONLY passive, usually you don't need extra args if you supplied templates?
                 # Actually -scan-strategy or -passive works.
                 # Let's use simple append.
                 # 'passive' is not a flag, it's a template filter usually? No, it IS a flag for scan mode.
                 pass # Actually -passive is deprecated/removed in some v3?
                 # "Nuclei supports running in passive mode... using -dast is for active..."
                 # Let's assume standard behavior: if tags not supplied, nuclei runs default.
                 # If user wants passive, let's just ignore for safety or check docs.
                 # Actually, let's look at help: " -passive enable passive mode"
                 # Yes.
                 cmd.append('-passive')

            # Network
            if config.get('proxy'):
                cmd.extend(['-proxy', config['proxy']])
                
            if config.get('headers'):
                # Split by newlines
                headers = config['headers'].split('\n')
                for h in headers:
                    if h.strip():
                        cmd.extend(['-H', h.strip()])
            
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
