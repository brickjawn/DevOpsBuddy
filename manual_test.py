#!/usr/bin/env python3
"""Manual test script that simulates DevOps Buddy CLI functionality."""

import json
import os
from pathlib import Path

def analyze_sample_project():
    """Manually analyze the sample project and generate a mock scan result."""
    
    print("🔍 Analyzing sample project...")
    
    # Check what files we have
    sample_dir = Path("sample_project")
    if not sample_dir.exists():
        print("❌ Sample project directory not found!")
        return False
    
    findings = []
    
    # Check package.json for vulnerable dependencies
    package_json = sample_dir / "package.json"
    if package_json.exists():
        print("✅ Found package.json")
        with open(package_json) as f:
            package_data = json.load(f)
            
        # Check for vulnerable lodash version
        if "lodash" in package_data.get("dependencies", {}):
            version = package_data["dependencies"]["lodash"]
            if version == "4.17.15":
                findings.append({
                    "id": "DEP-001",
                    "title": "Vulnerable lodash dependency detected",
                    "description": f"Package 'lodash' version {version} has known security vulnerabilities including prototype pollution (CVE-2020-8203).",
                    "severity": "CRITICAL",
                    "category": "Dependency Vulnerability",
                    "file_path": "sample_project/package.json",
                    "line_number": 15,
                    "cve_id": "CVE-2020-8203"
                })
                print("🚨 Found vulnerable lodash dependency!")
    
    # Check Terraform files
    tf_file = sample_dir / "terraform" / "main.tf"
    if tf_file.exists():
        print("✅ Found Terraform configuration")
        with open(tf_file) as f:
            tf_content = f.read()
        
        # Check for security issues
        if "block_public_acls       = false" in tf_content:
            findings.append({
                "id": "IAC-001", 
                "title": "S3 bucket allows public ACLs",
                "description": "S3 bucket is configured to allow public ACLs, which could lead to data exposure.",
                "severity": "HIGH",
                "category": "Infrastructure Security",
                "file_path": "sample_project/terraform/main.tf",
                "line_number": 42,
                "resource": "aws_s3_bucket_public_access_block.app_logs_pab"
            })
            print("⚠️  Found S3 public access misconfiguration!")
        
        if 'cidr_blocks = ["0.0.0.0/0"]' in tf_content:
            findings.append({
                "id": "IAC-002",
                "title": "Security group allows access from anywhere", 
                "description": "Security group rule allows inbound traffic from any IP address (0.0.0.0/0).",
                "severity": "HIGH",
                "category": "Network Security",
                "file_path": "sample_project/terraform/main.tf", 
                "line_number": 58,
                "resource": "aws_security_group.web_sg"
            })
            print("⚠️  Found overly permissive security group!")
    
    # Check Dockerfile
    dockerfile = sample_dir / "Dockerfile"
    if dockerfile.exists():
        print("✅ Found Dockerfile")
        with open(dockerfile) as f:
            dockerfile_content = f.read()
        
        if "FROM node:14" in dockerfile_content:
            findings.append({
                "id": "CONTAINER-001",
                "title": "Outdated base image",
                "description": "Using outdated Node.js 14 base image which may contain security vulnerabilities.",
                "severity": "MEDIUM",
                "category": "Container Security",
                "file_path": "sample_project/Dockerfile",
                "line_number": 4
            })
            print("📦 Found outdated base image!")
        
        if "USER" not in dockerfile_content:
            findings.append({
                "id": "CONTAINER-002",
                "title": "Container running as root",
                "description": "Container is running as root user, violating security best practices.",
                "severity": "MEDIUM", 
                "category": "Container Security",
                "file_path": "sample_project/Dockerfile",
                "line_number": 6
            })
            print("👤 Found root user issue!")
    
    return findings


def generate_mock_reports(findings):
    """Generate mock reports in different formats."""
    
    print(f"\n📊 Generating reports for {len(findings)} findings...")
    
    # Create reports directory
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Generate JSON report
    json_report = {
        "scan_id": "manual-test-001",
        "timestamp": "2024-06-09T13:00:00Z",
        "target": "sample_project/",
        "total_findings": len(findings),
        "findings_by_severity": {
            "CRITICAL": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "HIGH": len([f for f in findings if f["severity"] == "HIGH"]), 
            "MEDIUM": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "LOW": len([f for f in findings if f["severity"] == "LOW"])
        },
        "findings": findings
    }
    
    json_path = reports_dir / "scan_results.json"
    with open(json_path, 'w') as f:
        json.dump(json_report, f, indent=2)
    print(f"✅ JSON report saved: {json_path}")
    
    # Generate simple HTML report
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DevOps Buddy Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; margin-bottom: 20px; }}
        .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid; }}
        .critical {{ border-color: #dc3545; background: #f8d7da; }}
        .high {{ border-color: #fd7e14; background: #ffeaa7; }}
        .medium {{ border-color: #ffc107; background: #fff3cd; }}
        .low {{ border-color: #28a745; background: #d1ecf1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 DevOps Buddy Security Report</h1>
        <p><strong>Target:</strong> sample_project/</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        <p><strong>Generated:</strong> Manual Test</p>
    </div>
    
    <div class="findings">
        <h2>Security Findings</h2>
"""
    
    for finding in findings:
        severity_class = finding["severity"].lower()
        html_content += f'''
        <div class="finding {severity_class}">
            <h3>{finding["title"]}</h3>
            <p><strong>Severity:</strong> {finding["severity"]}</p>
            <p><strong>Category:</strong> {finding["category"]}</p>
            <p><strong>File:</strong> {finding["file_path"]} (line {finding.get("line_number", "N/A")})</p>
            <p>{finding["description"]}</p>
        </div>
        '''
    
    html_content += """
    </div>
</body>
</html>
    """
    
    html_path = reports_dir / "scan_report.html"
    with open(html_path, 'w') as f:
        f.write(html_content)
    print(f"✅ HTML report saved: {html_path}")
    
    return json_path, html_path


def main():
    """Run the manual test."""
    
    print("🚀 DevOps Buddy Manual Test")
    print("=" * 40)
    
    # Analyze the sample project
    findings = analyze_sample_project()
    
    if not findings:
        print("❌ No findings detected or sample project not found!")
        return False
    
    print(f"\n🎯 Analysis complete! Found {len(findings)} security issues:")
    
    # Show summary
    severity_counts = {}
    for finding in findings:
        severity = finding["severity"]
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        emoji = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "📍")
        print(f"  {emoji} {severity}: {count}")
    
    # Generate reports
    json_path, html_path = generate_mock_reports(findings)
    
    print(f"\n📋 Next steps:")
    print(f"1. View JSON report: cat {json_path}")
    print(f"2. Open HTML report: open {html_path}")
    print(f"3. Review the GitHub Actions workflow: .github/workflows/devops-buddy.yml")
    print(f"4. Fix the security issues in sample_project/")
    
    print(f"\n🎉 Manual test completed successfully!")
    return True


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 