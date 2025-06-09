"""Base report generator for DevOps Buddy."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pathlib import Path
import json

from ..core.models import ScanResult, ComplianceReport, SBOM
from ..utils.logger import get_logger


class BaseReportGenerator(ABC):
    """Base class for report generators."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.logger = get_logger(f"devops_buddy.{self.__class__.__name__}")
        self.format_name = self.__class__.__name__.replace("ReportGenerator", "").lower()
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Return the file extension for this report format."""
        pass
    
    @abstractmethod
    def generate_scan_report(
        self, 
        scan_result: ScanResult, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate a scan report.
        
        Args:
            scan_result: The scan result to report on
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        pass
    
    def generate_compliance_report(
        self, 
        compliance_report: ComplianceReport, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate a compliance report.
        
        Args:
            compliance_report: The compliance report to format
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        # Default implementation for formats that don't override
        raise NotImplementedError(f"Compliance reporting not implemented for {self.format_name}")
    
    def generate_sbom_report(
        self, 
        sbom: SBOM, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate an SBOM report.
        
        Args:
            sbom: The SBOM to report on
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        # Default implementation for formats that don't override
        raise NotImplementedError(f"SBOM reporting not implemented for {self.format_name}")
    
    def ensure_output_directory(self, output_path: str) -> Path:
        """Ensure the output directory exists.
        
        Args:
            output_path: Path to the output file
            
        Returns:
            Path object for the output file
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    
    def get_report_metadata(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Get common report metadata.
        
        Args:
            scan_result: The scan result
            
        Returns:
            Dictionary containing metadata
        """
        return {
            "scan_id": scan_result.scan_id,
            "scan_type": scan_result.scan_type.value,
            "target": {
                "type": scan_result.target.type,
                "path": scan_result.target.path,
                "url": scan_result.target.url
            },
            "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
            "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
            "duration_seconds": scan_result.duration_seconds,
            "scanner_version": scan_result.scanner_version,
            "total_findings": scan_result.total_findings,
            "findings_by_severity": {
                severity.value: count 
                for severity, count in scan_result.findings_by_severity.items()
            },
            "status": scan_result.status.value
        }


class MultiFormatReportGenerator:
    """Manager for multiple report format generators."""
    
    def __init__(self):
        """Initialize the multi-format report generator."""
        self.logger = get_logger("devops_buddy.ReportManager")
        self._generators: Dict[str, BaseReportGenerator] = {}
        self._load_generators()
    
    def _load_generators(self):
        """Load available report generators."""
        try:
            from .json_reporter import JSONReportGenerator
            from .html_reporter import HTMLReportGenerator
            from .pdf_reporter import PDFReportGenerator
            
            self._generators["json"] = JSONReportGenerator()
            self._generators["html"] = HTMLReportGenerator()
            self._generators["pdf"] = PDFReportGenerator()
            
            self.logger.info(f"Loaded {len(self._generators)} report generators")
            
        except ImportError as e:
            self.logger.warning(f"Some report generators could not be loaded: {e}")
    
    def get_available_formats(self) -> List[str]:
        """Get list of available report formats.
        
        Returns:
            List of format names
        """
        return list(self._generators.keys())
    
    def generate_report(
        self, 
        format_name: str, 
        scan_result: ScanResult, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate a report in the specified format.
        
        Args:
            format_name: Name of the report format
            scan_result: The scan result to report on
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        if format_name not in self._generators:
            raise ValueError(f"Unsupported report format: {format_name}")
        
        generator = self._generators[format_name]
        
        # Ensure output path has correct extension
        output_path = self._ensure_extension(output_path, generator.file_extension)
        
        try:
            result_path = generator.generate_scan_report(scan_result, output_path, **kwargs)
            self.logger.info(f"Generated {format_name} report: {result_path}")
            return result_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate {format_name} report", exc_info=e)
            raise
    
    def generate_compliance_report(
        self, 
        format_name: str, 
        compliance_report: ComplianceReport, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate a compliance report in the specified format.
        
        Args:
            format_name: Name of the report format
            compliance_report: The compliance report to format
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        if format_name not in self._generators:
            raise ValueError(f"Unsupported report format: {format_name}")
        
        generator = self._generators[format_name]
        output_path = self._ensure_extension(output_path, generator.file_extension)
        
        try:
            result_path = generator.generate_compliance_report(compliance_report, output_path, **kwargs)
            self.logger.info(f"Generated {format_name} compliance report: {result_path}")
            return result_path
            
        except NotImplementedError:
            raise ValueError(f"Compliance reporting not supported for format: {format_name}")
        except Exception as e:
            self.logger.error(f"Failed to generate {format_name} compliance report", exc_info=e)
            raise
    
    def generate_sbom_report(
        self, 
        format_name: str, 
        sbom: SBOM, 
        output_path: str,
        **kwargs
    ) -> str:
        """Generate an SBOM report in the specified format.
        
        Args:
            format_name: Name of the report format
            sbom: The SBOM to report on
            output_path: Path to save the report
            **kwargs: Additional generation options
            
        Returns:
            Path to the generated report file
        """
        if format_name not in self._generators:
            raise ValueError(f"Unsupported report format: {format_name}")
        
        generator = self._generators[format_name]
        output_path = self._ensure_extension(output_path, generator.file_extension)
        
        try:
            result_path = generator.generate_sbom_report(sbom, output_path, **kwargs)
            self.logger.info(f"Generated {format_name} SBOM report: {result_path}")
            return result_path
            
        except NotImplementedError:
            raise ValueError(f"SBOM reporting not supported for format: {format_name}")
        except Exception as e:
            self.logger.error(f"Failed to generate {format_name} SBOM report", exc_info=e)
            raise
    
    def _ensure_extension(self, output_path: str, extension: str) -> str:
        """Ensure output path has the correct file extension.
        
        Args:
            output_path: Original output path
            extension: Required file extension
            
        Returns:
            Output path with correct extension
        """
        path = Path(output_path)
        
        if not path.suffix or path.suffix != extension:
            return str(path.with_suffix(extension))
        
        return output_path 