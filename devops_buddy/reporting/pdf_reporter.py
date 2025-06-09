"""PDF report generator for DevOps Buddy."""

from .base import BaseReportGenerator
from ..core.models import ScanResult


class PDFReportGenerator(BaseReportGenerator):
    """Generates reports in PDF format."""
    
    @property
    def file_extension(self) -> str:
        return ".pdf"
    
    def generate_scan_report(self, scan_result: ScanResult, output_path: str, **kwargs) -> str:
        """Generate a PDF scan report."""
        
        # For now, fall back to HTML and suggest conversion
        self.logger.warning("PDF generation requires additional dependencies. Generating HTML instead.")
        
        from .html_reporter import HTMLReportGenerator
        
        html_generator = HTMLReportGenerator()
        html_path = output_path.replace('.pdf', '.html')
        
        return html_generator.generate_scan_report(scan_result, html_path, **kwargs) 