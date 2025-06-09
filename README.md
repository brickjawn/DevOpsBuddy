# DevOps Buddy 🛡️

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**DevOps Buddy** is a comprehensive, production-ready DevSecOps security scanner that automates cloud misconfiguration detection, vulnerability assessment, SBOM generation, and compliance reporting. Built for modern cloud-native applications with seamless CI/CD integration.

## 🌟 Features

### Core Security Scanning
- **🌐 Cloud Misconfiguration Detection**: Automated scanning for AWS, Azure, and Google Cloud misconfigurations
- **📦 Dependency Vulnerability Scanning**: Identifies vulnerable packages and libraries
- **🐳 Container Security**: Docker and container image vulnerability assessment
- **☸️ Kubernetes Security**: K8s cluster and workload security analysis
- **🏗️ Infrastructure as Code (IaC)**: Terraform, CloudFormation, and ARM template scanning

### Advanced Capabilities
- **📋 SBOM Generation**: CycloneDX and SPDX format support
- **🔧 Automated Remediation**: Suggests and applies security fixes
- **📊 Compliance Reporting**: GDPR, HIPAA, PCI-DSS, SOC2 frameworks
- **🤖 AI-Powered Prioritization**: Machine learning-based vulnerability ranking
- **⚡ CI/CD Integration**: Native support for Jenkins, GitLab CI, and GitHub Actions

### Reporting & Integration
- **📈 Multi-Format Reports**: JSON, HTML, PDF, and SARIF output
- **🔄 Real-time Monitoring**: Continuous security posture assessment
- **📱 Multiple Interfaces**: CLI, REST API, and web dashboard
- **🔌 Extensible Plugin System**: Custom scanner development

## 🚀 Quick Start

### Installation

```bash
# Using pip (recommended)
pip install devops-buddy

# From source
git clone https://github.com/your-username/DevOpsBuddy.git
cd DevOpsBuddy
pip install -e .

# With development dependencies
pip install -e ".[dev]"

# With all optional dependencies
pip install -e ".[all]"
```

### Basic Usage

```bash
# Scan current directory
devops-buddy scan

# Scan specific target with output format
devops-buddy scan --target /path/to/project --format html

# Generate SBOM
devops-buddy sbom --format cyclonedx --output sbom.json

# Check compliance
devops-buddy compliance --framework gdpr --output compliance-report.html

# Generate CI/CD configuration
devops-buddy generate-cicd --platform github-actions --output .github/workflows/
```

## 📋 Installation Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: Minimum 512MB RAM
- **Disk Space**: 100MB for installation

### System Dependencies (Optional)
```bash
# For PDF report generation
sudo apt-get install wkhtmltopdf  # Ubuntu/Debian
brew install wkhtmltopdf          # macOS

# For advanced container scanning
docker --version  # Docker required for container analysis
```

## 🔧 Configuration

DevOps Buddy uses a flexible configuration system supporting multiple formats:

### Configuration File (`devops-buddy.yaml`)

```yaml
# Cloud Provider Credentials
aws:
  access_key_id: "${AWS_ACCESS_KEY_ID}"
  secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
  region: "us-east-1"

azure:
  subscription_id: "${AZURE_SUBSCRIPTION_ID}"
  tenant_id: "${AZURE_TENANT_ID}"

gcp:
  project_id: "${GCP_PROJECT_ID}"
  credentials_path: "${GOOGLE_APPLICATION_CREDENTIALS}"

# Scanning Configuration
scanning:
  target_types:
    - cloud_resources
    - containers
    - dependencies
    - iac_templates
  
  severity_threshold: "medium"
  max_findings: 1000
  parallel_scans: 4

# Compliance Frameworks
compliance:
  frameworks:
    - gdpr
    - hipaa
    - pci_dss
  
  generate_reports: true
  auto_remediate: false

# Reporting
reporting:
  formats:
    - json
    - html
    - sarif
  
  output_directory: "./reports"
  include_raw_data: false

# CI/CD Integration
cicd:
  fail_on_high_severity: true
  fail_on_critical_severity: true
  upload_artifacts: true
  notifications:
    slack_webhook: "${SLACK_WEBHOOK_URL}"
```

### Environment Variables

```bash
# Cloud Credentials
export AWS_ACCESS_KEY_ID="your-aws-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret"
export AZURE_SUBSCRIPTION_ID="your-azure-subscription"
export GCP_PROJECT_ID="your-gcp-project"

# DevOps Buddy Configuration
export DEVOPS_BUDDY_CONFIG_PATH="/path/to/config.yaml"
export DEVOPS_BUDDY_LOG_LEVEL="INFO"
export DEVOPS_BUDDY_OUTPUT_DIR="/path/to/reports"
```

## 📖 Detailed Usage

### Scanning Commands

#### Basic Project Scan
```bash
# Scan current directory
devops-buddy scan

# Scan specific directory
devops-buddy scan --target /path/to/project

# Scan with specific types
devops-buddy scan --types cloud,containers,dependencies
```

#### Advanced Scanning Options
```bash
# High-severity findings only
devops-buddy scan --severity high --format json

# Parallel scanning for faster results
devops-buddy scan --parallel 8 --timeout 300

# Include remediation suggestions
devops-buddy scan --include-remediation --auto-fix safe
```

### SBOM Generation

```bash
# Generate CycloneDX SBOM
devops-buddy sbom --format cyclonedx --output sbom.json

# Generate SPDX SBOM with detailed dependencies
devops-buddy sbom --format spdx --include-dev-deps --output sbom.spdx

# SBOM for specific package managers
devops-buddy sbom --package-managers npm,pip,maven
```

### Compliance Reporting

```bash
# GDPR compliance check
devops-buddy compliance --framework gdpr

# Multiple frameworks
devops-buddy compliance --frameworks gdpr,hipaa,pci_dss --output compliance.html

# Detailed compliance with remediation
devops-buddy compliance --framework soc2 --include-remediation
```

### CI/CD Integration

#### GitHub Actions
```bash
# Generate GitHub Actions workflow
devops-buddy generate-cicd --platform github-actions --output .github/workflows/

# Custom workflow with specific triggers
devops-buddy generate-cicd --platform github-actions --triggers "push,pull_request" --fail-on critical
```

#### GitLab CI
```bash
# Generate GitLab CI configuration
devops-buddy generate-cicd --platform gitlab --output .gitlab-ci.yml

# With custom stages and artifacts
devops-buddy generate-cicd --platform gitlab --stages "test,security,deploy" --upload-artifacts
```

## 🏗️ Architecture

DevOps Buddy follows a modular, plugin-based architecture:

```
devops_buddy/
├── core/                   # Core scanning engine
│   ├── config.py          # Configuration management
│   ├── models.py          # Data models and schemas
│   └── scanner.py         # Main scanner orchestrator
├── scanners/              # Individual scanner plugins
│   ├── cloud_misconfig.py # Cloud misconfiguration scanner
│   ├── dependency_scanner.py # Dependency vulnerability scanner
│   ├── container_security.py # Container security scanner
│   ├── kubernetes_security.py # Kubernetes scanner
│   ├── iac_scanner.py     # Infrastructure as Code scanner
│   └── compliance_checker.py # Compliance framework checker
├── integrations/          # CI/CD and tool integrations
│   ├── github_actions.py  # GitHub Actions integration
│   ├── gitlab_ci.py       # GitLab CI integration
│   └── jenkins.py         # Jenkins integration
├── reporting/             # Report generation
│   ├── json_reporter.py   # JSON report generator
│   ├── html_reporter.py   # HTML report generator
│   ├── pdf_reporter.py    # PDF report generator
│   └── sarif_reporter.py  # SARIF report generator
├── utils/                 # Utility modules
│   ├── logging.py         # Logging configuration
│   ├── exceptions.py      # Custom exceptions
│   └── helpers.py         # Helper functions
└── cli/                   # Command-line interface
    └── main.py            # CLI entry point
```

## 🔌 Plugin Development

DevOps Buddy supports custom scanner plugins:

```python
from devops_buddy.scanners.base import BaseScanner
from devops_buddy.core.models import Finding, SeverityLevel

class CustomScanner(BaseScanner):
    def __init__(self):
        super().__init__("custom-scanner", "1.0.0")
    
    async def scan(self, target: str) -> List[Finding]:
        """Implement your custom scanning logic."""
        findings = []
        # Your scanning logic here
        finding = Finding(
            id="CUSTOM-001",
            title="Custom Security Issue",
            description="Description of the issue",
            severity=SeverityLevel.HIGH,
            file_path=target,
            line_number=1,
            remediation="How to fix this issue"
        )
        findings.append(finding)
        return findings
```

## 📊 Report Examples

### JSON Report Structure
```json
{
  "scan_id": "scan-123456",
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "total_findings": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  },
  "findings": [
    {
      "id": "AWS-S3-001",
      "title": "S3 Bucket Public Access",
      "severity": "critical",
      "description": "S3 bucket allows public read access",
      "file_path": "terraform/s3.tf",
      "line_number": 15,
      "remediation": "Set block_public_acls = true"
    }
  ],
  "compliance": {
    "gdpr": {"score": 85, "compliant": false},
    "hipaa": {"score": 92, "compliant": true}
  }
}
```

### SARIF Report Support
DevOps Buddy generates SARIF 2.1.0 compatible reports for integration with GitHub Security tab and other security tools.

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/your-username/DevOpsBuddy.git
cd DevOpsBuddy

# Create virtual environment
python -m venv devops_buddy_env
source devops_buddy_env/bin/activate  # Linux/macOS
# or
devops_buddy_env\Scripts\activate     # Windows

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=devops_buddy --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run integration tests
pytest tests/integration/
```

### Code Quality

```bash
# Format code
black devops_buddy/ tests/

# Sort imports
isort devops_buddy/ tests/

# Lint code
flake8 devops_buddy/

# Type checking
mypy devops_buddy/
```

## 🚀 CI/CD Integration Examples

### GitHub Actions Workflow

```yaml
name: DevOps Buddy Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install DevOps Buddy
      run: pip install devops-buddy
    
    - name: Run Security Scan
      run: devops-buddy scan --format sarif --output security-results.sarif
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-results.sarif
    
    - name: Generate Reports
      run: |
        devops-buddy scan --format html --output security-report.html
        devops-buddy compliance --framework gdpr --output compliance-report.html
    
    - name: Upload Reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          security-report.html
          compliance-report.html
```

### GitLab CI Configuration

```yaml
stages:
  - security
  - compliance
  - deploy

security-scan:
  stage: security
  image: python:3.11
  before_script:
    - pip install devops-buddy
  script:
    - devops-buddy scan --format json --output security-results.json
    - devops-buddy scan --format sarif --output security-results.sarif
  artifacts:
    reports:
      sast: security-results.sarif
    paths:
      - security-results.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"

compliance-check:
  stage: compliance
  image: python:3.11
  before_script:
    - pip install devops-buddy
  script:
    - devops-buddy compliance --framework gdpr,hipaa --output compliance-report.html
  artifacts:
    paths:
      - compliance-report.html
    expire_in: 1 month
  only:
    - main
    - develop
```

## 🐳 Docker Support

### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install DevOps Buddy
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 scanner
USER scanner

ENTRYPOINT ["devops-buddy"]
CMD ["--help"]
```

### Docker Usage
```bash
# Build the image
docker build -t devops-buddy .

# Run a scan
docker run -v $(pwd):/workspace devops-buddy scan --target /workspace

# Run with environment variables
docker run -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  -v $(pwd):/workspace devops-buddy scan --target /workspace
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Format your code (`black devops_buddy/`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Reporting Issues

Please use GitHub Issues to report bugs or request features. Include:
- DevOps Buddy version
- Python version
- Operating system
- Detailed description of the issue
- Steps to reproduce
- Expected vs. actual behavior

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Security research community for vulnerability databases
- Cloud providers for security best practices documentation
- Open source security tools that inspired this project
- Contributors and maintainers

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/your-username/DevOpsBuddy/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-username/DevOpsBuddy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/DevOpsBuddy/discussions)
- **Email**: security@devopsbuddy.com

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes and version history.

---

**Built with ❤️ for the DevSecOps community**

*DevOps Buddy helps organizations shift security left and build more secure cloud-native applications.* 