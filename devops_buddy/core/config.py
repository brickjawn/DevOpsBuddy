"""Configuration management for DevOps Buddy security scanner."""

import os
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml
from pydantic import BaseModel, Field, field_validator


class CloudConfig(BaseModel):
    """Cloud provider configuration."""
    
    aws: Dict[str, Any] = Field(default_factory=dict)
    azure: Dict[str, Any] = Field(default_factory=dict)
    gcp: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        extra = "allow"


class ScannerConfig(BaseModel):
    """Scanner-specific configuration."""
    
    enabled_scanners: List[str] = Field(default=[
        "cloud_misconfig",
        "container_security", 
        "iac_scanner",
        "dependency_scanner",
        "sbom_generator"
    ])
    
    severity_threshold: str = Field(default="MEDIUM")
    max_parallel_scans: int = Field(default=5)
    scan_timeout: int = Field(default=300)  # seconds
    
    @field_validator('severity_threshold')
    def validate_severity(cls, v):
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if v.upper() not in valid_severities:
            raise ValueError(f"Invalid severity. Must be one of: {valid_severities}")
        return v.upper()


class CICDConfig(BaseModel):
    """CI/CD integration configuration."""
    
    enabled_platforms: List[str] = Field(default=["jenkins", "gitlab", "github"])
    output_formats: List[str] = Field(default=["json", "junit", "sarif"])
    fail_on_critical: bool = Field(default=True)
    fail_on_high: bool = Field(default=False)


class ComplianceConfig(BaseModel):
    """Compliance and reporting configuration."""
    
    enabled_frameworks: List[str] = Field(default=["CIS", "GDPR", "HIPAA", "SOC2"])
    report_formats: List[str] = Field(default=["pdf", "json", "html"])
    audit_trail: bool = Field(default=True)


class AIConfig(BaseModel):
    """AI/ML configuration for vulnerability prioritization."""
    
    enabled: bool = Field(default=True)
    model_path: Optional[str] = Field(default=None)
    threat_intelligence_feeds: List[str] = Field(default=[
        "nvd.nist.gov",
        "cve.mitre.org"
    ])
    prioritization_factors: List[str] = Field(default=[
        "cvss_score",
        "exploitability",
        "public_exposure",
        "business_impact"
    ])


class DatabaseConfig(BaseModel):
    """Database configuration."""
    
    type: str = Field(default="sqlite")
    host: str = Field(default="localhost")
    port: int = Field(default=5432)
    database: str = Field(default="devops_buddy")
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    
    @property
    def connection_string(self) -> str:
        """Generate database connection string."""
        if self.type == "sqlite":
            return f"sqlite:///{self.database}.db"
        elif self.type == "postgresql":
            auth = ""
            if self.username and self.password:
                auth = f"{self.username}:{self.password}@"
            return f"postgresql://{auth}{self.host}:{self.port}/{self.database}"
        else:
            raise ValueError(f"Unsupported database type: {self.type}")


class Config(BaseModel):
    """Main configuration class."""
    
    # Core settings
    log_level: str = Field(default="INFO")
    log_file: Optional[str] = Field(default="devops_buddy.log")
    
    # Component configurations
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    cicd: CICDConfig = Field(default_factory=CICDConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Paths
    config_dir: Path = Field(default=Path.home() / ".devops_buddy")
    cache_dir: Path = Field(default=Path.home() / ".devops_buddy" / "cache")
    reports_dir: Path = Field(default=Path.cwd() / "reports")
    
    @classmethod
    def load_from_file(cls, config_path: Optional[str] = None) -> "Config":
        """Load configuration from YAML file."""
        if config_path is None:
            # Look for config in common locations
            possible_paths = [
                Path.cwd() / "devops_buddy.yaml",
                Path.cwd() / "devops_buddy.yml",
                Path.home() / ".devops_buddy" / "config.yaml",
                Path.home() / ".devops_buddy" / "config.yml"
            ]
            
            config_path = None
            for path in possible_paths:
                if path.exists():
                    config_path = str(path)
                    break
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            return cls(**config_data)
        
        return cls()
    
    def save_to_file(self, config_path: Optional[str] = None) -> None:
        """Save configuration to YAML file."""
        if config_path is None:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            config_path = str(self.config_dir / "config.yaml")
        
        config_dict = self.dict()
        # Convert Path objects to strings for YAML serialization
        for key, value in config_dict.items():
            if isinstance(value, Path):
                config_dict[key] = str(value)
        
        with open(config_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
    
    def setup_directories(self) -> None:
        """Create necessary directories."""
        directories = [self.config_dir, self.cache_dir, self.reports_dir]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True) 