# Changelog

All notable changes to DevOps Buddy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added
- Initial release of DevOps Buddy security scanner
- Core security scanning engine with async support
- Cloud misconfiguration detection for AWS, Azure, and GCP
- Dependency vulnerability scanning
- Container security analysis
- Kubernetes security scanning
- Infrastructure as Code (IaC) scanning
- SBOM generation (CycloneDX and SPDX formats)
- Compliance checking for GDPR, HIPAA, PCI-DSS, SOC2
- Automated remediation suggestions
- Multi-format reporting (JSON, HTML, PDF, SARIF)
- CI/CD integration with GitHub Actions
- Command-line interface with Click
- Plugin-based architecture for extensibility
- Comprehensive configuration system
- Production-ready error handling and logging

### Security
- Updated all dependencies to latest secure versions
- Resolved pydantic ReDoS vulnerability (upgraded to >=2.4.0)
- Fixed jinja2 XSS vulnerability CVE-2024-22195 (upgraded to >=3.1.3)
- **URGENT**: Fixed jinja2 sandbox bypass vulnerabilities CVE-2024-56201 and CVE-2024-56326 (upgraded to >=3.1.5)
- Updated Azure and GCP SDKs to latest versions

### Documentation
- Comprehensive README with installation and usage instructions
- Architecture documentation
- Plugin development guide
- CI/CD integration examples
- Docker support documentation
- Contributing guidelines

## [Unreleased]

### Planned
- GitLab CI integration
- Jenkins integration
- REST API for programmatic access
- Web dashboard interface
- Real-time monitoring capabilities
- Machine learning-based vulnerability prioritization
- Enhanced container registry scanning
- Kubernetes cluster runtime security
- Additional compliance frameworks (ISO 27001, NIST)
- Performance optimizations for large codebases

---

### Legend
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes 