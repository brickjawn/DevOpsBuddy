"""DevOps Buddy - Automated DevSecOps Security Scanner.

A comprehensive security scanning tool for cloud infrastructure,
containers, dependencies, and compliance checking.
"""

__version__ = "1.0.0"
__author__ = "DevOps Buddy Team"
__email__ = "security@devopsbuddy.com"
__license__ = "MIT"
__description__ = "Automated DevSecOps Security Scanner for Cloud-Native Applications"

# Core imports for easy access
from .core.config import Config
from .core.scanner import SecurityScanner
from .core.models import (
    ScanResult, ScanTarget, ScanType, ScanStatus, 
    Finding, SeverityLevel, ComplianceFramework
)

# Integration imports
from .integrations.github_actions import GitHubActionsIntegration
from .reporting.base import MultiFormatReportGenerator

__all__ = [
    "Config",
    "SecurityScanner", 
    "ScanResult",
    "ScanTarget",
    "ScanType",
    "ScanStatus",
    "Finding",
    "SeverityLevel",
    "ComplianceFramework",
    "GitHubActionsIntegration",
    "MultiFormatReportGenerator",
] 