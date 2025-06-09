"""Base scanner plugin class for DevOps Buddy security scanner."""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any, Optional

from ..core.config import Config
from ..core.models import (
    ScanResult, ScanTarget, ScanType, ScanStatus, 
    Finding, SBOM, ComplianceReport
)
from ..utils.logger import get_logger


class BaseScannerPlugin(ABC):
    """Base class for all scanner plugins."""
    
    def __init__(self, config: Config):
        """Initialize the scanner plugin.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = get_logger(f"devops_buddy.{self.__class__.__name__}")
        self.scanner_name = self.__class__.__name__
        self.version = "1.0.0"
    
    @property
    @abstractmethod
    def scan_type(self) -> ScanType:
        """Return the scan type this plugin handles."""
        pass
    
    @property
    @abstractmethod
    def supported_targets(self) -> List[str]:
        """Return list of supported target types (e.g., 'file', 'directory', 'container')."""
        pass
    
    def can_scan_target(self, target: ScanTarget) -> bool:
        """Check if this scanner can handle the given target.
        
        Args:
            target: The target to scan
            
        Returns:
            True if this scanner can handle the target, False otherwise
        """
        return target.type in self.supported_targets
    
    @abstractmethod
    async def scan(self, target: ScanTarget) -> ScanResult:
        """Perform the security scan.
        
        Args:
            target: The target to scan
            
        Returns:
            ScanResult containing findings and metadata
        """
        pass
    
    def create_scan_result(self, target: ScanTarget, scan_id: Optional[str] = None) -> ScanResult:
        """Create a new scan result object.
        
        Args:
            target: The target being scanned
            scan_id: Optional scan ID. If None, generates a UUID.
            
        Returns:
            ScanResult object initialized with basic information
        """
        return ScanResult(
            scan_id=scan_id or str(uuid.uuid4()),
            scan_type=self.scan_type,
            target=target,
            scanner_version=self.version,
            started_at=datetime.now(),
            status=ScanStatus.RUNNING
        )
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        category: str,
        **kwargs
    ) -> Finding:
        """Create a finding object with common fields populated.
        
        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            category: Finding category
            **kwargs: Additional finding attributes
            
        Returns:
            Finding object
        """
        from ..core.models import SeverityLevel
        
        finding_id = kwargs.pop('id', str(uuid.uuid4()))
        
        return Finding(
            id=finding_id,
            title=title,
            description=description,
            severity=SeverityLevel(severity.upper()),
            scan_type=self.scan_type,
            category=category,
            **kwargs
        )
    
    def filter_by_severity_threshold(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings based on configured severity threshold.
        
        Args:
            findings: List of findings to filter
            
        Returns:
            Filtered list of findings
        """
        threshold = self.config.scanner.severity_threshold
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        try:
            min_index = severity_order.index(threshold)
            return [
                f for f in findings 
                if severity_order.index(f.severity.value) >= min_index
            ]
        except ValueError:
            self.logger.warning(f"Invalid severity threshold: {threshold}")
            return findings
    
    async def validate_target(self, target: ScanTarget) -> bool:
        """Validate that the target is accessible and scannable.
        
        Args:
            target: The target to validate
            
        Returns:
            True if target is valid and accessible, False otherwise
        """
        if not self.can_scan_target(target):
            return False
        
        # Basic validation - can be overridden by specific scanners
        if target.path:
            from pathlib import Path
            return Path(target.path).exists()
        
        if target.url:
            # Basic URL validation
            import re
            url_pattern = re.compile(
                r'^https?://'  # http:// or https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                r'localhost|'  # localhost...
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
                r'(?::\d+)?'  # optional port
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            return url_pattern.match(target.url) is not None
        
        return True
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get information about this scanner.
        
        Returns:
            Dictionary containing scanner metadata
        """
        return {
            "name": self.scanner_name,
            "version": self.version,
            "scan_type": self.scan_type.value,
            "supported_targets": self.supported_targets,
            "description": self.__class__.__doc__ or "No description available"
        }


class CloudScannerMixin:
    """Mixin for cloud-based scanners."""
    
    def get_cloud_credentials(self, provider: str) -> Dict[str, Any]:
        """Get cloud credentials for a specific provider.
        
        Args:
            provider: Cloud provider name (aws, azure, gcp)
            
        Returns:
            Dictionary of credentials
        """
        if hasattr(self, 'config') and hasattr(self.config, 'cloud'):
            return getattr(self.config.cloud, provider, {})
        return {}
    
    def validate_cloud_credentials(self, provider: str) -> bool:
        """Validate cloud credentials for a provider.
        
        Args:
            provider: Cloud provider name
            
        Returns:
            True if credentials are valid, False otherwise
        """
        # This is a basic check - specific implementations should override
        credentials = self.get_cloud_credentials(provider)
        return bool(credentials)


class ContainerScannerMixin:
    """Mixin for container-based scanners."""
    
    def is_container_target(self, target: ScanTarget) -> bool:
        """Check if target is a container.
        
        Args:
            target: Target to check
            
        Returns:
            True if target is a container, False otherwise
        """
        return target.type in ["container", "docker_image"]
    
    def get_container_info(self, target: ScanTarget) -> Dict[str, Any]:
        """Get container information from target.
        
        Args:
            target: Container target
            
        Returns:
            Dictionary containing container metadata
        """
        return target.metadata.get("container_info", {}) 