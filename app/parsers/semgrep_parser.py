from app.models import Vulnerability
from app.parsers.base import BaseParser

class SemgrepParser(BaseParser):
    def parse(self, data, scan_id, base_path=None):
        vulnerabilities = []
        
        if 'results' not in data:
            return vulnerabilities
            
        for result in data['results']:
            vulnerabilities.append(self._map_result(result, scan_id, base_path))
            
        return vulnerabilities

    def _map_result(self, item, scan_id, base_path):
        extra = item.get('extra', {})
        metadata = extra.get('metadata', {})
        
        # Severity Mapping
        semgrep_sev = extra.get('severity', 'INFO').upper()
        severity = self._normalize_severity(semgrep_sev)
        
        # OWASP mapping from metadata if available
        owasp = metadata.get('owasp', 'Unknown')
        if isinstance(owasp, list):
            owasp = owasp[0] # Take first if list
            
        path = item.get('path')
        path = self.normalize_path(path, base_path)

        return Vulnerability(
            scan_id=scan_id,
            tool='semgrep',
            vuln_id=item.get('check_id'),
            title=item.get('check_id').split('.')[-1].replace('-', ' ').title(),
            description=extra.get('message'),
            severity=severity,
            file_path=path,
            line_number=item.get('start', {}).get('line'),
            fix_recommendation=extra.get('fix'), # Semgrep sometimes provides autofix
            owasp_category=owasp
        )

    def _normalize_severity(self, severity):
        # Semgrep: ERROR, WARNING, INFO
        if severity == 'ERROR':
            return 'HIGH' # Often matches High/Critical
        elif severity == 'WARNING':
            return 'MEDIUM'
        elif severity == 'INFO':
            return 'LOW'
        return 'INFO'
