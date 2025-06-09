"""Base CI/CD integration class."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..core.models import ScanResult, SeverityLevel
from ..utils.logger import get_logger


class BaseCICDIntegration(ABC):
    """Base class for CI/CD platform integrations."""
    
    def __init__(self):
        """Initialize the CI/CD integration."""
        self.logger = get_logger(f"devops_buddy.{self.__class__.__name__}")
        self.platform_name = self.__class__.__name__.replace("Integration", "").lower()
    
    @property
    @abstractmethod
    def supported_output_formats(self) -> List[str]:
        """Return list of supported output formats for this platform."""
        pass
    
    @abstractmethod
    def generate_config(
        self, 
        project_path: str, 
        scan_config: Dict[str, Any]
    ) -> str:
        """Generate CI/CD configuration file content.
        
        Args:
            project_path: Path to the project
            scan_config: Scanner configuration
            
        Returns:
            Configuration file content as string
        """
        pass
    
    @abstractmethod
    def format_output(
        self, 
        scan_result: ScanResult, 
        output_format: str
    ) -> str:
        """Format scan results for the CI/CD platform.
        
        Args:
            scan_result: The scan result to format
            output_format: Desired output format
            
        Returns:
            Formatted output as string
        """
        pass
    
    def should_fail_build(
        self, 
        scan_result: ScanResult, 
        fail_on_critical: bool = True, 
        fail_on_high: bool = False
    ) -> bool:
        """Determine if the build should fail based on scan results.
        
        Args:
            scan_result: The scan result to evaluate
            fail_on_critical: Whether to fail on critical findings
            fail_on_high: Whether to fail on high severity findings
            
        Returns:
            True if build should fail, False otherwise
        """
        return scan_result.has_blocking_findings(fail_on_critical, fail_on_high)
    
    def get_exit_code(
        self, 
        scan_result: ScanResult, 
        fail_on_critical: bool = True, 
        fail_on_high: bool = False
    ) -> int:
        """Get appropriate exit code for CI/CD pipeline.
        
        Args:
            scan_result: The scan result to evaluate
            fail_on_critical: Whether to fail on critical findings
            fail_on_high: Whether to fail on high severity findings
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        if self.should_fail_build(scan_result, fail_on_critical, fail_on_high):
            # Use different exit codes for different severity levels
            critical_count = scan_result.findings_by_severity.get(SeverityLevel.CRITICAL, 0)
            high_count = scan_result.findings_by_severity.get(SeverityLevel.HIGH, 0)
            
            if fail_on_critical and critical_count > 0:
                return 2  # Critical findings
            elif fail_on_high and high_count > 0:
                return 1  # High severity findings
        
        return 0  # Success
    
    def generate_summary(self, scan_result: ScanResult) -> str:
        """Generate a summary of scan results.
        
        Args:
            scan_result: The scan result to summarize
            
        Returns:
            Summary text
        """
        summary_lines = [
            f"🔍 DevOps Buddy Security Scan Complete",
            f"📊 Total Findings: {scan_result.total_findings}",
            f"⏱️  Duration: {scan_result.duration_seconds:.2f}s"
        ]
        
        if scan_result.findings_by_severity:
            summary_lines.append("📈 Findings by Severity:")
            for severity, count in scan_result.findings_by_severity.items():
                emoji = self._get_severity_emoji(severity)
                summary_lines.append(f"   {emoji} {severity.value}: {count}")
        
        if scan_result.errors:
            summary_lines.append(f"❌ Errors: {len(scan_result.errors)}")
        
        if scan_result.warnings:
            summary_lines.append(f"⚠️  Warnings: {len(scan_result.warnings)}")
        
        return "\n".join(summary_lines)
    
    def _get_severity_emoji(self, severity: SeverityLevel) -> str:
        """Get emoji for severity level."""
        emoji_map = {
            SeverityLevel.CRITICAL: "🚨",
            SeverityLevel.HIGH: "🔴",
            SeverityLevel.MEDIUM: "🟡",
            SeverityLevel.LOW: "🟢"
        }
        return emoji_map.get(severity, "📍")
    
    def create_artifact_paths(self, output_dir: str) -> Dict[str, str]:
        """Create standard artifact file paths.
        
        Args:
            output_dir: Output directory path
            
        Returns:
            Dictionary mapping artifact types to file paths
        """
        output_path = Path(output_dir)
        
        return {
            "json": str(output_path / "devops-buddy-results.json"),
            "junit": str(output_path / "devops-buddy-junit.xml"),
            "sarif": str(output_path / "devops-buddy-results.sarif"),
            "html": str(output_path / "devops-buddy-report.html"),
            "summary": str(output_path / "devops-buddy-summary.txt")
        } 