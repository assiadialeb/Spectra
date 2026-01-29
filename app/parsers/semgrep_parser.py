from app.models import Vulnerability, QualityIssue
from app.parsers.base import BaseParser

class SemgrepParser(BaseParser):
    def parse(self, data, scan_id, base_path=None):
        vulnerabilities = []
        quality_issues = []
        
        if 'results' not in data:
            return vulnerabilities, quality_issues
            
        for result in data['results']:
            item = self._map_result(result, scan_id, base_path)
            if isinstance(item, Vulnerability):
                vulnerabilities.append(item)
            elif isinstance(item, QualityIssue):
                quality_issues.append(item)
            
        return vulnerabilities, quality_issues

    def _map_result(self, item, scan_id, base_path):
        extra = item.get('extra', {})
        metadata = extra.get('metadata', {})
        
        # Severity Mapping
        semgrep_sev = extra.get('severity', 'INFO').upper()
        severity = self._normalize_severity(semgrep_sev)

        path = item.get('path')
        path = self.normalize_path(path, base_path)
        
        # Categorization
        category = metadata.get('category', 'unknown').lower()
        
        # 1. SECURITY FINDING
        if category in ['security', 'cwe', 'owasp', 'infrastructure']:
            # OWASP mapping from metadata if available
            owasp = metadata.get('owasp', 'Unknown')
            if isinstance(owasp, list):
                owasp = owasp[0]

            return Vulnerability(
                scan_id=scan_id,
                tool='semgrep',
                vuln_id=item.get('check_id'),
                title=item.get('check_id').split('.')[-1].replace('-', ' ').title(),
                description=extra.get('message'),
                severity=severity,
                file_path=path,
                line_number=item.get('start', {}).get('line'),
                fix_recommendation=extra.get('fix'), 
                owasp_category=owasp
            )
        
        # 2. QUALITY FINDING
        else:
            # Map Semgrep impact/confidence to estimated effort? For now default 5min.
            # Categories: maintainability, correctness, best-practice, performance...
            return QualityIssue(
                scan_id=scan_id,
                tool='semgrep',
                check_id=item.get('check_id'),
                title=item.get('check_id').split('.')[-1].replace('-', ' ').title(),
                description=extra.get('message'),
                category=category.title(), 
                severity=severity, # INFO/WARNING/ERROR
                file_path=path,
                line_number=item.get('start', {}).get('line'),
                effort_minutes=10 if severity == 'HIGH' else 5
            )

    def _normalize_severity(self, severity):
        # Semgrep: ERROR, WARNING, INFO
        if severity == 'ERROR':
            return 'HIGH' 
        elif severity == 'WARNING':
            return 'MEDIUM'
        elif severity == 'INFO':
            return 'LOW'
        return 'INFO'
