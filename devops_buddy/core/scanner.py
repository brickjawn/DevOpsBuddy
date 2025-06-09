"""Main security scanner orchestrator for DevOps Buddy."""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Type, Any
from pathlib import Path

from .config import Config
from .models import (
    ScanResult, ScanTarget, ScanType, ScanStatus, 
    Finding, SeverityLevel, SBOM, ComplianceReport
)
from ..scanners.base import BaseScannerPlugin
from ..utils.logger import setup_logger
from ..utils.exceptions import ScannerError, ConfigurationError


class SecurityScanner:
    """Main security scanner that orchestrates all scanning operations."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the security scanner.
        
        Args:
            config: Configuration object. If None, will load from default locations.
        """
        self.config = config or Config.load_from_file()
        self.config.setup_directories()
        
        # Set up logging
        self.logger = setup_logger(
            name="devops_buddy",
            level=self.config.log_level,
            log_file=self.config.log_file
        )
        
        # Plugin registry for different scanner types
        self._scanner_plugins: Dict[ScanType, Type[BaseScannerPlugin]] = {}
        self._active_scans: Dict[str, ScanResult] = {}
        
        # Initialize scanner plugins
        self._load_scanner_plugins()
        
        self.logger.info("DevOps Buddy Security Scanner initialized")
    
    def _load_scanner_plugins(self) -> None:
        """Load and register scanner plugins."""
        try:
            # Import and register scanner plugins
            from ..scanners.cloud_misconfig import CloudMisconfigScanner
            from ..scanners.container_security import ContainerSecurityScanner
            from ..scanners.iac_scanner import IaCScanner
            from ..scanners.dependency_scanner import DependencyScanner
            from ..scanners.sbom_generator import SBOMGenerator
            from ..scanners.kubernetes_security import KubernetesSecurityScanner
            from ..scanners.compliance_checker import ComplianceChecker
            
            # Register plugins
            self._scanner_plugins[ScanType.CLOUD_MISCONFIG] = CloudMisconfigScanner
            self._scanner_plugins[ScanType.CONTAINER_SECURITY] = ContainerSecurityScanner
            self._scanner_plugins[ScanType.IAC_SCANNER] = IaCScanner
            self._scanner_plugins[ScanType.DEPENDENCY_SCANNER] = DependencyScanner
            self._scanner_plugins[ScanType.SBOM_GENERATOR] = SBOMGenerator
            self._scanner_plugins[ScanType.KUBERNETES_SECURITY] = KubernetesSecurityScanner
            self._scanner_plugins[ScanType.COMPLIANCE_CHECK] = ComplianceChecker
            
            self.logger.info(f"Loaded {len(self._scanner_plugins)} scanner plugins")
            
        except ImportError as e:
            self.logger.warning(f"Some scanner plugins could not be loaded: {e}")
    
    async def scan(
        self,
        target: ScanTarget,
        scan_types: Optional[List[ScanType]] = None,
        scan_id: Optional[str] = None
    ) -> ScanResult:
        """Perform a comprehensive security scan.
        
        Args:
            target: The target to scan (file, directory, container, cloud account, etc.)
            scan_types: List of scan types to perform. If None, uses enabled scanners from config.
            scan_id: Optional scan ID. If None, generates a UUID.
            
        Returns:
            ScanResult containing all findings from the scan.
        """
        scan_id = scan_id or str(uuid.uuid4())
        
        # Determine which scans to run
        if scan_types is None:
            scan_types = [ScanType(scanner) for scanner in self.config.scanner.enabled_scanners 
                         if ScanType(scanner) in self._scanner_plugins]
        
        # Create main scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.CLOUD_MISCONFIG,  # Primary type - will be updated
            target=target,
            started_at=datetime.now(),
            status=ScanStatus.RUNNING,
            scanner_version="1.0.0"
        )
        
        self._active_scans[scan_id] = scan_result
        self.logger.info(f"Starting scan {scan_id} for target: {target.path or target.url}")
        
        try:
            # Run scans in parallel up to max_parallel_scans limit
            semaphore = asyncio.Semaphore(self.config.scanner.max_parallel_scans)
            tasks = []
            
            for scan_type in scan_types:
                if scan_type in self._scanner_plugins:
                    task = self._run_scanner_with_semaphore(
                        semaphore, scan_type, target, scan_id
                    )
                    tasks.append(task)
                else:
                    self.logger.warning(f"Scanner plugin not found for type: {scan_type}")
            
            # Execute all scans
            individual_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(individual_results):
                if isinstance(result, Exception):
                    scan_result.errors.append(f"Scanner {scan_types[i]} failed: {str(result)}")
                    self.logger.error(f"Scanner {scan_types[i]} failed", exc_info=result)
                elif isinstance(result, ScanResult):
                    # Merge findings from individual scan
                    for finding in result.findings:
                        scan_result.add_finding(finding)
                    
                    # Merge errors and warnings
                    scan_result.errors.extend(result.errors)
                    scan_result.warnings.extend(result.warnings)
                    
                    # Update statistics
                    if result.scanned_files_count:
                        scan_result.scanned_files_count = (
                            scan_result.scanned_files_count or 0
                        ) + result.scanned_files_count
                    
                    if result.scanned_resources_count:
                        scan_result.scanned_resources_count = (
                            scan_result.scanned_resources_count or 0
                        ) + result.scanned_resources_count
            
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.now()
            
            if scan_result.started_at and scan_result.completed_at:
                scan_result.duration_seconds = (
                    scan_result.completed_at - scan_result.started_at
                ).total_seconds()
            
            self.logger.info(
                f"Scan {scan_id} completed with {scan_result.total_findings} findings "
                f"in {scan_result.duration_seconds:.2f} seconds"
            )
            
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(f"Scan failed: {str(e)}")
            scan_result.completed_at = datetime.now()
            self.logger.error(f"Scan {scan_id} failed", exc_info=e)
            raise ScannerError(f"Scan failed: {str(e)}") from e
        
        finally:
            # Clean up active scan tracking
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]
        
        return scan_result
    
    async def _run_scanner_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        scan_type: ScanType,
        target: ScanTarget,
        scan_id: str
    ) -> ScanResult:
        """Run an individual scanner with semaphore control."""
        async with semaphore:
            return await self._run_individual_scanner(scan_type, target, scan_id)
    
    async def _run_individual_scanner(
        self,
        scan_type: ScanType,
        target: ScanTarget,
        scan_id: str
    ) -> ScanResult:
        """Run an individual scanner plugin."""
        scanner_class = self._scanner_plugins[scan_type]
        scanner = scanner_class(self.config)
        
        try:
            self.logger.debug(f"Running {scan_type} scanner for scan {scan_id}")
            
            # Create timeout for individual scanner
            result = await asyncio.wait_for(
                scanner.scan(target),
                timeout=self.config.scanner.scan_timeout
            )
            
            self.logger.debug(
                f"{scan_type} scanner completed with {result.total_findings} findings"
            )
            
            return result
            
        except asyncio.TimeoutError:
            self.logger.warning(f"{scan_type} scanner timed out after {self.config.scanner.scan_timeout}s")
            # Return partial result with timeout error
            result = ScanResult(
                scan_id=f"{scan_id}_{scan_type}",
                scan_type=scan_type,
                target=target,
                status=ScanStatus.TIMEOUT
            )
            result.errors.append(f"Scanner timed out after {self.config.scanner.scan_timeout} seconds")
            return result
        
        except Exception as e:
            self.logger.error(f"{scan_type} scanner failed", exc_info=e)
            # Return failed result
            result = ScanResult(
                scan_id=f"{scan_id}_{scan_type}",
                scan_type=scan_type,
                target=target,
                status=ScanStatus.FAILED
            )
            result.errors.append(f"Scanner failed: {str(e)}")
            return result
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Get the status of an active scan."""
        if scan_id in self._active_scans:
            return self._active_scans[scan_id].status
        return None
    
    def get_active_scans(self) -> List[str]:
        """Get list of active scan IDs."""
        return list(self._active_scans.keys())
    
    async def generate_sbom(
        self,
        target: ScanTarget,
        include_vulnerabilities: bool = True
    ) -> SBOM:
        """Generate Software Bill of Materials for a target.
        
        Args:
            target: Target to analyze (typically a project directory or container)
            include_vulnerabilities: Whether to include vulnerability information
            
        Returns:
            SBOM object containing all discovered components and vulnerabilities
        """
        if ScanType.SBOM_GENERATOR not in self._scanner_plugins:
            raise ScannerError("SBOM generator plugin not available")
        
        scanner_class = self._scanner_plugins[ScanType.SBOM_GENERATOR]
        scanner = scanner_class(self.config)
        
        self.logger.info(f"Generating SBOM for target: {target.path or target.url}")
        
        try:
            sbom = await scanner.generate_sbom(target, include_vulnerabilities)
            self.logger.info(
                f"SBOM generated with {sbom.total_components} components "
                f"and {sbom.total_vulnerabilities} vulnerabilities"
            )
            return sbom
            
        except Exception as e:
            self.logger.error("SBOM generation failed", exc_info=e)
            raise ScannerError(f"SBOM generation failed: {str(e)}") from e
    
    async def check_compliance(
        self,
        target: ScanTarget,
        frameworks: Optional[List[str]] = None
    ) -> List[ComplianceReport]:
        """Check compliance against regulatory frameworks.
        
        Args:
            target: Target to assess
            frameworks: List of compliance frameworks to check. If None, uses config.
            
        Returns:
            List of compliance reports for each framework
        """
        if ScanType.COMPLIANCE_CHECK not in self._scanner_plugins:
            raise ScannerError("Compliance checker plugin not available")
        
        frameworks = frameworks or self.config.compliance.enabled_frameworks
        
        scanner_class = self._scanner_plugins[ScanType.COMPLIANCE_CHECK]
        scanner = scanner_class(self.config)
        
        self.logger.info(f"Checking compliance for frameworks: {frameworks}")
        
        try:
            reports = []
            for framework in frameworks:
                report = await scanner.check_framework_compliance(target, framework)
                reports.append(report)
                self.logger.info(
                    f"{framework} compliance: {report.compliance_percentage:.1f}% "
                    f"({report.passed_controls}/{report.total_controls} controls passed)"
                )
            
            return reports
            
        except Exception as e:
            self.logger.error("Compliance check failed", exc_info=e)
            raise ScannerError(f"Compliance check failed: {str(e)}") from e
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get information about available scanners and configuration."""
        return {
            "version": "1.0.0",
            "available_scanners": list(self._scanner_plugins.keys()),
            "enabled_scanners": self.config.scanner.enabled_scanners,
            "max_parallel_scans": self.config.scanner.max_parallel_scans,
            "scan_timeout": self.config.scanner.scan_timeout,
            "severity_threshold": self.config.scanner.severity_threshold,
            "active_scans": len(self._active_scans)
        } 