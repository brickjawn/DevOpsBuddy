# Contributing to DevOps Buddy

Thank you for your interest in contributing to DevOps Buddy! This document provides guidelines and information for contributors.

## 🌟 How to Contribute

### Reporting Issues

1. **Search existing issues** first to avoid duplicates
2. **Use the issue templates** provided
3. **Include detailed information**:
   - DevOps Buddy version
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs. actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. **Check the roadmap** in README.md first
2. **Open a feature request** with:
   - Clear description of the feature
   - Use cases and benefits
   - Potential implementation approach
   - Any relevant examples or mockups

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch** from `main`
3. **Make your changes** following our coding standards
4. **Add tests** for new functionality
5. **Update documentation** if needed
6. **Submit a pull request**

## 🛠️ Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/DevOpsBuddy.git
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

# Run tests with coverage
pytest --cov=devops_buddy --cov-report=html

# Run specific test category
pytest tests/unit/
pytest tests/integration/

# Run tests for specific module
pytest tests/test_scanner.py -v
```

### Code Quality Checks

```bash
# Format code (automatically fixes issues)
black devops_buddy/ tests/

# Sort imports
isort devops_buddy/ tests/

# Lint code (reports issues)
flake8 devops_buddy/

# Type checking
mypy devops_buddy/

# Run all quality checks
pre-commit run --all-files
```

## 📋 Coding Standards

### Python Style Guide

- Follow **PEP 8** style guidelines
- Use **Black** for code formatting
- Use **isort** for import sorting
- Use **type hints** for all functions and methods
- Write **docstrings** for all public functions/classes

### Code Structure

```python
"""Module docstring explaining the purpose."""

import standard_library
import third_party_packages
import local_imports

from typing import List, Dict, Optional


class ExampleClass:
    """Class docstring with purpose and usage examples.
    
    Args:
        param1: Description of parameter
        param2: Description of parameter
        
    Attributes:
        attr1: Description of attribute
        attr2: Description of attribute
    """
    
    def __init__(self, param1: str, param2: Optional[int] = None) -> None:
        """Initialize the class."""
        self.attr1 = param1
        self.attr2 = param2
    
    def public_method(self, arg: str) -> Dict[str, str]:
        """Public method with clear docstring.
        
        Args:
            arg: Description of argument
            
        Returns:
            Dictionary with results
            
        Raises:
            ValueError: When arg is invalid
        """
        if not arg:
            raise ValueError("Argument cannot be empty")
        
        return {"result": arg}
    
    def _private_method(self) -> None:
        """Private method for internal use only."""
        pass
```

### Testing Guidelines

- Write tests for **all new functionality**
- Use **pytest** framework
- Follow **AAA pattern** (Arrange, Act, Assert)
- Use **descriptive test names**
- Include **edge cases** and **error conditions**

```python
def test_scanner_detects_vulnerability_in_package_json():
    """Test that dependency scanner detects known vulnerabilities."""
    # Arrange
    scanner = DependencyScanner()
    test_file = "tests/fixtures/vulnerable_package.json"
    
    # Act
    findings = scanner.scan(test_file)
    
    # Assert
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.HIGH
    assert "lodash" in findings[0].description
```

### Documentation

- Update **README.md** for user-facing changes
- Update **docstrings** for API changes
- Add **examples** for new features
- Update **CHANGELOG.md** with your changes

## 🔌 Plugin Development

### Creating a Scanner Plugin

1. **Inherit from BaseScanner**
2. **Implement required methods**
3. **Add comprehensive tests**
4. **Document usage and configuration**

```python
from devops_buddy.scanners.base import BaseScanner
from devops_buddy.core.models import Finding, SeverityLevel

class YourScanner(BaseScanner):
    """Scanner for detecting specific security issues."""
    
    def __init__(self):
        super().__init__("your-scanner", "1.0.0")
    
    async def scan(self, target: str) -> List[Finding]:
        """Implement your scanning logic."""
        # Your implementation here
        pass
    
    def _validate_target(self, target: str) -> bool:
        """Validate if target is supported by this scanner."""
        # Your validation logic
        pass
```

### Creating a Reporter Plugin

```python
from devops_buddy.reporting.base import BaseReportGenerator

class YourReporter(BaseReportGenerator):
    """Custom report generator."""
    
    def generate(self, scan_result: ScanResult, output_path: str) -> None:
        """Generate custom format report."""
        # Your implementation here
        pass
```

## 🚀 Pull Request Process

### Before Submitting

1. **Rebase** your branch on the latest `main`
2. **Run all tests** and ensure they pass
3. **Run code quality checks** and fix any issues
4. **Update documentation** if needed
5. **Add/update tests** for your changes

### Pull Request Description

Use this template for your PR description:

```markdown
## Description
Brief description of what this PR does.

## Changes Made
- List of specific changes
- Another change
- etc.

## Testing
- [ ] Added unit tests
- [ ] Added integration tests
- [ ] Manual testing performed
- [ ] All existing tests pass

## Documentation
- [ ] Updated README if needed
- [ ] Updated docstrings
- [ ] Updated CHANGELOG.md

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests added for new functionality
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
```

### Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **Code review** by maintainers
3. **Testing** in different environments
4. **Approval** from at least one maintainer
5. **Merge** by maintainers

## 🐛 Bug Reports

### Security Issues

**Do NOT create public issues for security vulnerabilities!**

Instead, email us at: **security@devopsbuddy.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Regular Bug Reports

Use the bug report template and include:

1. **Environment details**
2. **Steps to reproduce**
3. **Expected behavior**
4. **Actual behavior**
5. **Error messages/logs**
6. **Minimal reproduction case**

## 📝 Documentation

### Types of Documentation

- **README.md**: User-facing documentation
- **Docstrings**: API documentation
- **CHANGELOG.md**: Version history
- **This file**: Contributor guidelines

### Documentation Standards

- Use **clear, concise language**
- Include **examples** where helpful
- Keep **up-to-date** with code changes
- Use **proper Markdown formatting**

## 🤝 Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please:

- **Be respectful** and inclusive
- **Use welcoming language**
- **Accept constructive criticism**
- **Focus on what's best** for the community
- **Show empathy** toward other members

### Communication

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas, general discussion
- **Pull Requests**: Code contributions
- **Email**: Security issues, private matters

## 🏆 Recognition

Contributors will be recognized in:

- **CHANGELOG.md** for significant contributions
- **README.md** acknowledgments section
- **GitHub contributors** page

## 📧 Questions?

If you have questions about contributing, feel free to:

1. **Check existing documentation** first
2. **Search closed issues** for similar questions
3. **Open a GitHub Discussion**
4. **Contact us** at security@devopsbuddy.com

Thank you for contributing to DevOps Buddy! 🛡️ 