"""HTML report generator for DevOps Buddy."""

from typing import Dict, Any
from datetime import datetime
from pathlib import Path

from .base import BaseReportGenerator
from ..core.models import ScanResult, SeverityLevel


class HTMLReportGenerator(BaseReportGenerator):
    """Generates reports in HTML format."""
    
    @property
    def file_extension(self) -> str:
        return ".html"
    
    def generate_scan_report(self, scan_result: ScanResult, output_path: str, **kwargs) -> str:
        """Generate an HTML scan report."""
        
        output_file = self.ensure_output_directory(output_path)
        
        # Generate HTML content
        html_content = self._generate_html_template(scan_result)
        
        # Write HTML report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_file)
    
    def _generate_html_template(self, scan_result: ScanResult) -> str:
        """Generate HTML template with scan results."""
        
        stats_html = self._generate_stats_html(scan_result)
        findings_html = self._generate_findings_html(scan_result.findings)
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DevOps Buddy Security Report</title>
    <style>{self._get_css()}</style>
</head>
<body>
    <div class="container">
        <h1>🔍 DevOps Buddy Security Report</h1>
        <div class="header-info">
            <p><strong>Target:</strong> {scan_result.target.path or 'Unknown'}</p>
            <p><strong>Duration:</strong> {scan_result.duration_seconds:.2f}s</p>
            <p><strong>Findings:</strong> {scan_result.total_findings}</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            {stats_html}
        </div>
        
        <div class="findings">
            <h2>Findings</h2>
            {findings_html}
        </div>
    </div>
</body>
</html>
        """
        
        return html_template.strip()
    
    def _generate_stats_html(self, scan_result: ScanResult) -> str:
        """Generate statistics HTML."""
        
        stats = f"<p>Total: {scan_result.total_findings}</p>"
        
        if scan_result.findings_by_severity:
            for severity, count in scan_result.findings_by_severity.items():
                stats += f"<p>{severity.value}: {count}</p>"
        
        return stats
    
    def _generate_findings_html(self, findings) -> str:
        """Generate findings HTML."""
        
        if not findings:
            return "<p>No findings detected.</p>"
        
        findings_html = ""
        for finding in findings:
            findings_html += f"""
            <div class="finding severity-{finding.severity.value.lower()}">
                <h3>{finding.title}</h3>
                <p><strong>Severity:</strong> {finding.severity.value}</p>
                <p><strong>Category:</strong> {finding.category}</p>
                <p>{finding.description}</p>
            </div>
            """
        
        return findings_html
    
    def _get_css(self) -> str:
        """Get basic CSS styles."""
        
        return """
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1000px; margin: 0 auto; }
        .header-info { background: #f0f0f0; padding: 10px; margin: 20px 0; }
        .summary, .findings { margin: 20px 0; }
        .finding { margin: 15px 0; padding: 15px; border-left: 4px solid; }
        .severity-critical { border-color: #dc3545; background: #f8d7da; }
        .severity-high { border-color: #fd7e14; background: #ffeaa7; }
        .severity-medium { border-color: #ffc107; background: #fff3cd; }
        .severity-low { border-color: #28a745; background: #d1ecf1; }
        h1, h2, h3 { color: #333; }
        """ 