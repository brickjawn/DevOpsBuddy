"""Custom exceptions for DevOps Buddy security scanner."""


class DevOpsBuddyException(Exception):
    """Base exception for DevOps Buddy."""
    pass


class ConfigurationError(DevOpsBuddyException):
    """Raised when there's a configuration error."""
    pass


class ScannerError(DevOpsBuddyException):
    """Raised when a scanner encounters an error."""
    pass


class PluginError(DevOpsBuddyException):
    """Raised when a plugin encounters an error."""
    pass


class CloudProviderError(DevOpsBuddyException):
    """Raised when there's an error with cloud provider operations."""
    pass


class AuthenticationError(DevOpsBuddyException):
    """Raised when authentication fails."""
    pass


class ValidationError(DevOpsBuddyException):
    """Raised when data validation fails."""
    pass


class ReportGenerationError(DevOpsBuddyException):
    """Raised when report generation fails."""
    pass


class CICDIntegrationError(DevOpsBuddyException):
    """Raised when CI/CD integration encounters an error."""
    pass 