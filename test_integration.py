#!/usr/bin/env python3
"""Test script to demonstrate DevOps Buddy CI/CD integration and reporting features."""

import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path

# DevOps Buddy imports
from devops_buddy.core.models import (
    ScanResult, ScanTarget, ScanType, ScanStatus, Finding, 
    FindingLocation, SeverityLevel, CVEInfo
)
from devops_buddy.integrations.github_actions import GitHubActionsIntegration
from devops_buddy.reporting.base import MultiFormatReportGenerator


def create_sample_scan_result() -> ScanResult:
    """Create a sample scan result for testing."""
    
    # Create sample findings
    findings = [
        Finding(
            id="finding-001",
            title="Unencrypted S3 bucket",
            description="S3 bucket 'my-app-logs' is not encrypted at rest, potentially exposing sensitive data.",
            severity=SeverityLevel.HIGH,
            scan_type=ScanType.CLOUD_MISCONFIGURATION,
            category="Storage Security",
            location=FindingLocation(
                resource_id="my-app-logs",
                cloud_region="us-east-1"
            ),
            affected_resource="s3://my-app-logs",
            rule_id="AWS.S3.1",
            rule_name="S3 bucket should be encrypted",
            created_at=datetime.now()
        ),
        Finding(
            id="finding-002", 
            title="Vulnerable dependency detected",
            description="Package 'lodash' version 4.17.15 has a known prototype pollution vulnerability.",
            severity=SeverityLevel.CRITICAL,
            scan_type=ScanType.DEPENDENCY_SCAN,
            category="Dependency Vulnerability",
            location=FindingLocation(
                file_path="package.json",
                line_number=15
            ),
            cve_info=CVEInfo(
                cve_id="CVE-2020-8203",
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                description="Prototype pollution in lodash",
                published_date=datetime(2020, 7, 21)
            ),
            created_at=datetime.now()
        ),
        Finding(
            id="finding-003",
            title="Kubernetes pod running as root",
            description="Pod 'api-service' is running with root privileges, violating security best practices.",
            severity=SeverityLevel.MEDIUM,
            scan_type=ScanType.CONTAINER_SECURITY,
            category="Container Security",
            location=FindingLocation(
                file_path="k8s/deployment.yaml",
                line_number=32
            ),
            affected_resource="pod/api-service",
            rule_id="K8S.POD.1",
            created_at=datetime.now()
        )
    ]
    
    target = ScanTarget(
        type="directory",
        path="/tmp/sample-project"
    )
    
    return ScanResult(
        scan_id="test-scan-001",
        scan_type=ScanType.COMPREHENSIVE,
        target=target,
        status=ScanStatus.COMPLETED,
        findings=findings,
        started_at=datetime.now(),
        completed_at=datetime.now(),
        duration_seconds=45.6,
        scanner_version="1.0.0",
        scanned_files_count=156,
        scanned_resources_count=23
    )


def test_github_actions_integration():
    """Test GitHub Actions integration."""
    
    print("🔧 Testing GitHub Actions Integration...")
    
    integration = GitHubActionsIntegration()
    scan_result = create_sample_scan_result()
    
    # Test workflow generation
    scan_config = {
        'scanners': ['cloud_misconfig', 'dependency_scanner', 'container_security'],
        'fail_on_critical': True,
        'fail_on_high': False,
        'cloud_providers': ['aws', 'azure'],
        'generate_sbom': True,
        'compliance_check': True
    }
    
    workflow_yaml = integration.generate_config("/tmp/sample-project", scan_config)
    
    print("✅ Generated GitHub Actions workflow:")
    print(workflow_yaml[:500] + "..." if len(workflow_yaml) > 500 else workflow_yaml)
    
    # Test SARIF output
    sarif_output = integration.format_output(scan_result, "sarif")
    sarif_data = json.loads(sarif_output)
    
    print(f"\n✅ Generated SARIF report with {len(sarif_data['runs'][0]['results'])} findings")
    
    # Test GitHub summary
    github_summary = integration.format_output(scan_result, "github-summary")
    
    print("✅ Generated GitHub summary:")
    print(github_summary[:300] + "..." if len(github_summary) > 300 else github_summary)
    
    # Test exit code logic
    exit_code = integration.get_exit_code(scan_result, fail_on_critical=True, fail_on_high=False)
    print(f"✅ Exit code for CI/CD: {exit_code}")
    
    return True


def test_report_generation():
    """Test multi-format report generation."""
    
    print("\n📊 Testing Report Generation...")
    
    report_generator = MultiFormatReportGenerator()
    scan_result = create_sample_scan_result()
    
    available_formats = report_generator.get_available_formats()
    print(f"✅ Available report formats: {available_formats}")
    
    # Test report generation for each format
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        for format_name in available_formats:
            try:
                output_path = temp_path / f"test_report.{format_name}"
                
                report_path = report_generator.generate_report(
                    format_name, 
                    scan_result, 
                    str(output_path)
                )
                
                if Path(report_path).exists():
                    file_size = Path(report_path).stat().st_size
                    print(f"✅ Generated {format_name} report: {report_path} ({file_size} bytes)")
                    
                    # Show sample content for text-based formats
                    if format_name in ['json', 'html']:
                        with open(report_path, 'r') as f:
                            content = f.read()
                            preview = content[:200] + "..." if len(content) > 200 else content
                            print(f"   Preview: {preview}")
                else:
                    print(f"❌ Failed to generate {format_name} report")
                    
            except Exception as e:
                print(f"❌ Error generating {format_name} report: {e}")
    
    return True


def test_ci_cd_workflow_scenarios():
    """Test various CI/CD workflow scenarios."""
    
    print("\n🔄 Testing CI/CD Workflow Scenarios...")
    
    integration = GitHubActionsIntegration()
    
    # Scenario 1: Critical findings should fail build
    critical_result = create_sample_scan_result()
    should_fail = integration.should_fail_build(critical_result, fail_on_critical=True)
    print(f"✅ Scenario 1 - Critical findings with fail-on-critical=True: {'FAIL' if should_fail else 'PASS'}")
    
    # Scenario 2: High findings only, fail-on-high disabled
    high_only_findings = [f for f in critical_result.findings if f.severity == SeverityLevel.HIGH]
    high_result = ScanResult(
        scan_id="test-high",
        scan_type=ScanType.COMPREHENSIVE,
        target=critical_result.target,
        status=ScanStatus.COMPLETED,
        findings=high_only_findings,
        started_at=datetime.now(),
        completed_at=datetime.now(),
        duration_seconds=30.0,
        scanner_version="1.0.0"
    )
    
    should_fail_high = integration.should_fail_build(high_result, fail_on_critical=True, fail_on_high=False)
    print(f"✅ Scenario 2 - High findings only with fail-on-high=False: {'FAIL' if should_fail_high else 'PASS'}")
    
    # Scenario 3: No blocking findings
    low_findings = [Finding(
        id="low-001",
        title="Minor style issue",
        description="Code style recommendation",
        severity=SeverityLevel.LOW,
        scan_type=ScanType.STATIC_ANALYSIS,
        category="Code Quality",
        created_at=datetime.now()
    )]
    
    low_result = ScanResult(
        scan_id="test-low",
        scan_type=ScanType.COMPREHENSIVE,
        target=critical_result.target,
        status=ScanStatus.COMPLETED,
        findings=low_findings,
        started_at=datetime.now(),
        completed_at=datetime.now(),
        duration_seconds=15.0,
        scanner_version="1.0.0"
    )
    
    should_pass = integration.should_fail_build(low_result, fail_on_critical=True, fail_on_high=True)
    print(f"✅ Scenario 3 - Low findings only: {'FAIL' if should_pass else 'PASS'}")
    
    return True


def main():
    """Run all integration tests."""
    
    print("🚀 DevOps Buddy CI/CD Integration & Reporting Test Suite")
    print("=" * 60)
    
    tests = [
        test_github_actions_integration,
        test_report_generation,
        test_ci_cd_workflow_scenarios
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! CI/CD integration is ready for deployment.")
    else:
        print("⚠️  Some tests failed. Please review the output above.")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 