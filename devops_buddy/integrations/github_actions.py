"""GitHub Actions integration for DevOps Buddy."""

import json
import yaml
from typing import Dict, Any, List
from datetime import datetime

from .base import BaseCICDIntegration
from ..core.models import ScanResult, Finding


class GitHubActionsIntegration(BaseCICDIntegration):
    """Integration for GitHub Actions CI/CD platform."""
    
    @property
    def supported_output_formats(self) -> List[str]:
        """Return list of supported output formats."""
        return ["json", "sarif", "junit", "github-summary"]
    
    def generate_config(self, project_path: str, scan_config: Dict[str, Any]) -> str:
        """Generate GitHub Actions workflow configuration."""
        
        config = {
            "name": "DevOps Buddy Security Scan",
            "on": {
                "push": {"branches": ["main", "master"]},
                "pull_request": {"branches": ["main", "master"]}
            },
            "jobs": {
                "security-scan": {
                    "runs-on": "ubuntu-latest",
                    "permissions": {
                        "contents": "read",
                        "security-events": "write"
                    },
                    "steps": [
                        {"name": "Checkout", "uses": "actions/checkout@v4"},
                        {"name": "Setup Python", "uses": "actions/setup-python@v4", 
                         "with": {"python-version": "3.11"}},
                        {"name": "Install DevOps Buddy", "run": "git clone https://github.com/brickjawn/DevOpsBuddy.git && cd DevOpsBuddy && pip install -e ."},
                        {"name": "Run scan", "run": "devops-buddy scan . --output results.json"},
                        {"name": "Upload results", "uses": "actions/upload-artifact@v4",
                         "with": {"name": "scan-results", "path": "results.json"}}
                    ]
                }
            }
        }
        
        return yaml.dump(config, default_flow_style=False, indent=2)
    
    def format_output(self, scan_result: ScanResult, output_format: str) -> str:
        """Format scan results for GitHub Actions."""
        
        if output_format == "sarif":
            return self._generate_sarif(scan_result)
        elif output_format == "github-summary":
            return self._generate_summary_markdown(scan_result)
        elif output_format == "json":
            return json.dumps(scan_result.dict(), indent=2, default=str)
        else:
            return json.dumps(scan_result.dict(), indent=2, default=str)
    
    def _generate_sarif(self, scan_result: ScanResult) -> str:
        """Generate SARIF format output."""
        
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "DevOps Buddy",
                        "version": "1.0.0"
                    }
                },
                "results": []
            }]
        }
        
        for finding in scan_result.findings:
            result = {
                "ruleId": finding.rule_id or f"devops-buddy-{finding.category}",
                "message": {"text": finding.description},
                "level": self._severity_to_sarif_level(finding.severity.value)
            }
            
            if finding.location.file_path:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.file_path}
                    }
                }]
                
                if finding.location.line_number:
                    result["locations"][0]["physicalLocation"]["region"] = {
                        "startLine": finding.location.line_number
                    }
            
            sarif["runs"][0]["results"].append(result)
        
        return json.dumps(sarif, indent=2)
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning", 
            "LOW": "note"
        }
        return mapping.get(severity, "warning")
    
    def _generate_summary_markdown(self, scan_result: ScanResult) -> str:
        """Generate GitHub markdown summary."""
        
        lines = [
            "# 🔍 DevOps Buddy Security Scan Results",
            "",
            f"**Total Findings:** {scan_result.total_findings}",
            f"**Duration:** {scan_result.duration_seconds:.2f}s",
            ""
        ]
        
        if scan_result.findings_by_severity:
            lines.append("## Findings by Severity")
            lines.append("")
            for severity, count in scan_result.findings_by_severity.items():
                emoji = self._get_severity_emoji(severity)
                lines.append(f"- {emoji} **{severity.value}:** {count}")
            lines.append("")
        
        return "\n".join(lines) 