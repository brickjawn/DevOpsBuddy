"""Core data models for the DevOps Buddy security scanner."""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanType(str, Enum):
    """Types of security scans."""
    CLOUD_MISCONFIG = "cloud_misconfig"
    CONTAINER_SECURITY = "container_security"
    IAC_SCANNER = "iac_scanner"
    DEPENDENCY_SCANNER = "dependency_scanner"
    SBOM_GENERATOR = "sbom_generator"
    KUBERNETES_SECURITY = "kubernetes_security"
    COMPLIANCE_CHECK = "compliance_check"


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    CIS = "CIS"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS"
    NIST = "NIST"


class Location(BaseModel):
    """Location information for a finding."""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    resource_id: Optional[str] = None
    cloud_region: Optional[str] = None


class Remediation(BaseModel):
    """Remediation information for a finding."""
    description: str
    steps: List[str] = Field(default_factory=list)
    code_snippet: Optional[str] = None
    documentation_url: Optional[str] = None
    automated: bool = Field(default=False)
    estimated_effort: Optional[str] = None  # e.g., "5 minutes", "1 hour"


class CVEInfo(BaseModel):
    """CVE (Common Vulnerabilities and Exposures) information."""
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cwe_ids: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Individual security finding."""
    
    # Core identification
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    
    # Classification
    severity: SeverityLevel
    scan_type: ScanType
    category: str = Field(..., description="Finding category (e.g., 'IAM', 'Storage', 'Network')")
    
    # Location and context
    location: Location = Field(default_factory=Location)
    affected_resource: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    
    # Technical details
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    cve_info: Optional[CVEInfo] = None
    
    # Impact and risk
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    exploitability_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    public_exposure: bool = Field(default=False)
    
    # Remediation
    remediation: Optional[Remediation] = None
    
    # Compliance mapping
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    false_positive: bool = Field(default=False)
    suppressed: bool = Field(default=False)
    suppression_reason: Optional[str] = None
    
    # Additional context
    context: Dict[str, Any] = Field(default_factory=dict)


class ScanTarget(BaseModel):
    """Target to be scanned."""
    
    type: str  # e.g., "file", "directory", "container", "cloud_account"
    path: Optional[str] = None
    url: Optional[str] = None
    cloud_account_id: Optional[str] = None
    cloud_region: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of a security scan."""
    
    # Scan identification
    scan_id: str = Field(..., description="Unique scan identifier")
    scan_type: ScanType
    
    # Scan execution details
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Scan target and configuration
    target: ScanTarget
    scanner_version: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)
    
    # Results
    findings: List[Finding] = Field(default_factory=list)
    total_findings: int = Field(default=0)
    findings_by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict)
    
    # Statistics
    scanned_files_count: Optional[int] = None
    scanned_resources_count: Optional[int] = None
    
    # Error handling
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the scan result."""
        self.findings.append(finding)
        self.total_findings = len(self.findings)
        
        # Update severity counts
        if finding.severity not in self.findings_by_severity:
            self.findings_by_severity[finding.severity] = 0
        self.findings_by_severity[finding.severity] += 1
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]
    
    def get_high_findings(self) -> List[Finding]:
        """Get all high severity findings."""
        return [f for f in self.findings if f.severity == SeverityLevel.HIGH]
    
    def has_blocking_findings(self, fail_on_critical: bool = True, fail_on_high: bool = False) -> bool:
        """Check if scan has findings that should block CI/CD pipeline."""
        if fail_on_critical and self.findings_by_severity.get(SeverityLevel.CRITICAL, 0) > 0:
            return True
        if fail_on_high and self.findings_by_severity.get(SeverityLevel.HIGH, 0) > 0:
            return True
        return False


class SBOMComponent(BaseModel):
    """Software Bill of Materials component."""
    
    name: str
    version: str
    type: str  # e.g., "library", "framework", "application"
    purl: Optional[str] = None  # Package URL
    supplier: Optional[str] = None
    license: Optional[str] = None
    hash_value: Optional[str] = None
    vulnerabilities: List[CVEInfo] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)  # Component names this depends on


class SBOM(BaseModel):
    """Software Bill of Materials."""
    
    # Metadata
    creation_date: datetime = Field(default_factory=datetime.now)
    created_by: str = Field(default="DevOps Buddy")
    format_version: str = Field(default="1.0")
    
    # Target information
    target_name: str
    target_version: Optional[str] = None
    target_type: str  # e.g., "application", "container", "library"
    
    # Components
    components: List[SBOMComponent] = Field(default_factory=list)
    total_components: int = Field(default=0)
    
    # Vulnerability summary
    total_vulnerabilities: int = Field(default=0)
    vulnerabilities_by_severity: Dict[SeverityLevel, int] = Field(default_factory=dict)
    
    def add_component(self, component: SBOMComponent) -> None:
        """Add a component to the SBOM."""
        self.components.append(component)
        self.total_components = len(self.components)
        
        # Update vulnerability counts
        for vuln in component.vulnerabilities:
            self.total_vulnerabilities += 1
            # Note: This assumes CVE severity mapping - might need enhancement
    
    def get_vulnerable_components(self) -> List[SBOMComponent]:
        """Get components with known vulnerabilities."""
        return [c for c in self.components if c.vulnerabilities]


class ComplianceReport(BaseModel):
    """Compliance assessment report."""
    
    # Report metadata
    report_id: str
    framework: ComplianceFramework
    generated_at: datetime = Field(default_factory=datetime.now)
    
    # Scope
    target: ScanTarget
    assessment_period: Optional[str] = None
    
    # Results
    total_controls: int = Field(default=0)
    passed_controls: int = Field(default=0)
    failed_controls: int = Field(default=0)
    compliance_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    
    # Detailed findings
    control_results: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    
    # Evidence and audit trail
    evidence_files: List[str] = Field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list) 