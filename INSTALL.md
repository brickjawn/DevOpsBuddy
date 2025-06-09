# Installation Guide

## Prerequisites

- **Python**: 3.8 or higher
- **Git**: For cloning the repository
- **Operating System**: Linux, macOS, Windows

## Installation from Source

Since DevOps Buddy is not yet published to PyPI, you must install it from source:

### 1. Clone the Repository

```bash
git clone https://github.com/brickjawn/DevOpsBuddy.git
cd DevOpsBuddy
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv devops_buddy_env

# Activate virtual environment
# Linux/macOS:
source devops_buddy_env/bin/activate

# Windows:
devops_buddy_env\Scripts\activate
```

### 3. Install DevOps Buddy

```bash
# Install in development mode (recommended)
pip install -e .

# Or install with all optional dependencies
pip install -e ".[all]"

# For development with testing tools
pip install -e ".[dev]"
```

### 4. Verify Installation

```bash
# Check if installation was successful
devops-buddy --version
devops-buddy --help
```

## Installation Options

### Basic Installation
```bash
pip install -e .
```
Includes core scanning capabilities.

### Development Installation
```bash
pip install -e ".[dev]"
```
Includes testing tools (pytest, black, flake8, mypy, etc.).

### Full Installation
```bash
pip install -e ".[all]"
```
Includes all optional dependencies for reporting (PDF generation, etc.).

## System Dependencies

### PDF Report Generation (Optional)
```bash
# Ubuntu/Debian
sudo apt-get install wkhtmltopdf

# macOS
brew install wkhtmltopdf

# Windows
# Download and install from: https://wkhtmltopdf.org/downloads.html
```

### Container Scanning (Optional)
Docker is required for container security scanning:
```bash
# Verify Docker installation
docker --version
```

## Troubleshooting

### Common Issues

#### 1. Permission Errors
```bash
# If you get permission errors, ensure you're in a virtual environment
python -m venv devops_buddy_env
source devops_buddy_env/bin/activate  # Linux/macOS
pip install -e .
```

#### 2. Missing Dependencies
```bash
# Update pip and setuptools first
pip install --upgrade pip setuptools wheel
pip install -e .
```

#### 3. Python Version Issues
```bash
# Verify Python version (must be 3.8+)
python --version

# If using multiple Python versions
python3.8 -m venv devops_buddy_env
# or
python3.11 -m venv devops_buddy_env
```

## Uninstallation

```bash
# If installed with -e flag
pip uninstall devops-buddy

# Remove virtual environment
deactivate
rm -rf devops_buddy_env
```

## Future PyPI Release

Once DevOps Buddy is published to PyPI, installation will be simplified to:

```bash
# Future installation (not available yet)
pip install devops-buddy
```

Stay tuned for the official PyPI release! 