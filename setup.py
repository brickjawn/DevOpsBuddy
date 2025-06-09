#!/usr/bin/env python3
"""Setup script for DevOps Buddy."""

from setuptools import setup, find_packages
import pathlib

# Get the directory where this script is located
HERE = pathlib.Path(__file__).parent

# Read the README file for long description
README = (HERE / "README.md").read_text(encoding="utf-8")

# Read version from __init__.py
def get_version():
    with open(HERE / "devops_buddy" / "__init__.py", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"').strip("'")
    raise RuntimeError("Cannot find version string")

setup(
    name="devops-buddy",
    version=get_version(),
    author="DevOps Buddy Team",
    author_email="security@devopsbuddy.com",
    description="Automated DevSecOps Security Scanner for Cloud-Native Applications",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/brickjawn/DevOpsBuddy",
    project_urls={
        "Bug Reports": "https://github.com/brickjawn/DevOpsBuddy/issues",
        "Source": "https://github.com/brickjawn/DevOpsBuddy",
        "Documentation": "https://github.com/brickjawn/DevOpsBuddy/blob/main/README.md",
    },
    packages=find_packages(exclude=["tests*", "sample_project*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.0",
        "pydantic>=2.4.0",
        "PyYAML>=6.0.1",
        "jinja2>=3.1.5",
        "asyncio>=3.4.3",
        "packaging>=23.0",
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "azure-storage-blob>=12.18.0",
        "azure-identity>=1.15.0",
        "google-cloud-storage>=2.10.0",
        "google-auth>=2.23.0",
        "boto3>=1.29.0",
        "botocore>=1.32.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
            "pre-commit>=3.0.0",
        ],
        "reporting": [
            "reportlab>=4.0.0",
            "weasyprint>=59.0",
            "matplotlib>=3.7.0",
        ],
        "all": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
            "pre-commit>=3.0.0",
            "reportlab>=4.0.0",
            "weasyprint>=59.0",
            "matplotlib>=3.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "devops-buddy=devops_buddy.cli.main:cli",
            "devbuddy=devops_buddy.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "devops_buddy": [
            "templates/*.yaml",
            "templates/*.yml",
            "templates/*.json",
            "configs/*.yaml",
            "configs/*.yml",
        ],
    },
    zip_safe=False,
    keywords=[
        "security", "devops", "devsecops", "cloud", "scanning", 
        "vulnerability", "compliance", "ci-cd", "sbom", "containers", 
        "kubernetes", "aws", "azure", "gcp", "terraform", "infrastructure"
    ],
    license="MIT",
) 