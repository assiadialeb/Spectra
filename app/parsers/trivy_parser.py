from app.models import Vulnerability
from app.parsers.base import BaseParser

class TrivyParser(BaseParser):
    def parse(self, data, scan_id, base_path=None):
        vulnerabilities = []
        
        # Trivy returns a list of "Results" (per target/file usually)
        if 'Results' not in data:
            return vulnerabilities
            
        for result in data['Results']:
            target = result.get('Target', 'Unknown')
            # Normalize target path
            target = self.normalize_path(target, base_path)
            
            # 1. Process Vulnerabilities (CVEs)
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    vulnerabilities.append(self._map_vuln(vuln, target, scan_id))
                    
            # 2. Process Misconfigurations (IaC/Secrets)
            if 'Misconfigurations' in result:
                for misconf in result['Misconfigurations']:
                    vulnerabilities.append(self._map_misconf(misconf, target, scan_id))
                    
        return vulnerabilities

    def _map_vuln(self, item, target, scan_id):
        # Map Severity
        severity = item.get('Severity', 'UNKNOWN').upper()
        # Trivy severities match ours usually (LOW, MEDIUM, HIGH, CRITICAL)
        
        return Vulnerability(
            scan_id=scan_id,
            tool='trivy',
            vuln_id=item.get('VulnerabilityID'),
            title=item.get('Title', item.get('PkgName', 'Unknown Library')),
            description=item.get('Description', ''),
            severity=severity,
            file_path=target,
            line_number=None, # Trivy CVEs often don't have line numbers in the summary
            fix_recommendation=f"Update {item.get('PkgName')} to {item.get('FixedVersion', 'latest')}",
            owasp_category='A06:2021-Vulnerable and Outdated Components' # Default for CVEs
        )

    def _map_misconf(self, item, target, scan_id):
        severity = item.get('Severity', 'UNKNOWN').upper()
        
        return Vulnerability(
            scan_id=scan_id,
            tool='trivy',
            vuln_id=item.get('ID'),
            title=item.get('Title'),
            description=item.get('Description'),
            severity=severity,
            file_path=target,
            line_number=item.get('IacMetadata', {}).get('StartLine'),
            fix_recommendation=item.get('Resolution'),
            owasp_category='A05:2021-Security Misconfiguration' # Default for IaC
        )
