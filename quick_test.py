#!/usr/bin/env python3
"""Quick test script for DevOps Buddy core functionality."""

import sys
import os
import tempfile
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path so we can import devops_buddy
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from devops_buddy.core.models import (
        ScanResult, ScanTarget, ScanType, ScanStatus, Finding, 
        FindingLocation, SeverityLevel
    )
    from devops_buddy.integrations.github_actions import GitHubActionsIntegration
    print("✅ Core modules imported successfully!")
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're in the DevOps Buddy directory and have the required dependencies installed.")
    sys.exit(1)


def create_test_scan_result():
    """Create a test scan result."""
    
    findings = [
        Finding(
            id="test-001",
            title="Test High Severity Finding",
            description="This is a test high severity security finding for demonstration.",
            severity=SeverityLevel.HIGH,
            scan_type=ScanType.CLOUD_MISCONFIGURATION,
            category="Test Category",
            location=FindingLocation(
                file_path="test-file.yaml",
                line_number=10
            ),
            created_at=datetime.now()
        ),
        Finding(
            id="test-002", 
            title="Test Critical Finding",
            description="This is a test critical security finding.",
            severity=SeverityLevel.CRITICAL,
            scan_type=ScanType.DEPENDENCY_SCAN,
            category="Vulnerability",
            location=FindingLocation(
                file_path="package.json",
                line_number=25
            ),
            created_at=datetime.now()
        )
    ]
    
    target = ScanTarget(
        type="directory",
        path="/tmp/test-project"
    )
    
    return ScanResult(
        scan_id="quick-test-001",
        scan_type=ScanType.COMPREHENSIVE,
        target=target,
        status=ScanStatus.COMPLETED,
        findings=findings,
        started_at=datetime.now(),
        completed_at=datetime.now(),
        duration_seconds=15.0,
        scanner_version="1.0.0-test"
    )


def test_github_actions():
    """Test GitHub Actions integration."""
    
    print("\n🔧 Testing GitHub Actions Integration...")
    
    try:
        integration = GitHubActionsIntegration()
        scan_result = create_test_scan_result()
        
        # Test workflow generation
        scan_config = {
            'scanners': ['cloud_misconfig', 'dependency_scanner'],
            'fail_on_critical': True,
            'fail_on_high': False
        }
        
        workflow_yaml = integration.generate_config("/tmp/test-project", scan_config)
        print("✅ GitHub Actions workflow generated successfully!")
        print(f"   Workflow length: {len(workflow_yaml)} characters")
        
        # Test SARIF generation
        sarif_output = integration.format_output(scan_result, "sarif")
        print("✅ SARIF output generated successfully!")
        print(f"   SARIF length: {len(sarif_output)} characters")
        
        # Test exit codes
        exit_code = integration.get_exit_code(scan_result, fail_on_critical=True, fail_on_high=False)
        print(f"✅ Exit code logic working: {exit_code}")
        
        return True
        
    except Exception as e:
        print(f"❌ GitHub Actions test failed: {e}")
        return False


def test_report_generation():
    """Test basic report generation."""
    
    print("\n📊 Testing Report Generation...")
    
    try:
        # Test if we can import the reporting modules
        from devops_buddy.reporting.json_reporter import JSONReportGenerator
        from devops_buddy.reporting.html_reporter import HTMLReportGenerator
        
        scan_result = create_test_scan_result()
        
        # Test JSON report
        json_reporter = JSONReportGenerator()
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "test_report.json"
            result_path = json_reporter.generate_scan_report(scan_result, str(json_path))
            
            if Path(result_path).exists():
                file_size = Path(result_path).stat().st_size
                print(f"✅ JSON report generated: {file_size} bytes")
            else:
                print("❌ JSON report file not found")
                return False
        
        # Test HTML report
        html_reporter = HTMLReportGenerator()
        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "test_report.html"
            result_path = html_reporter.generate_scan_report(scan_result, str(html_path))
            
            if Path(result_path).exists():
                file_size = Path(result_path).stat().st_size
                print(f"✅ HTML report generated: {file_size} bytes")
                
                # Show a preview of the HTML content
                with open(result_path, 'r') as f:
                    content = f.read()
                    if "DevOps Buddy Security Report" in content and "test-001" in content:
                        print("✅ HTML report contains expected content")
                    else:
                        print("⚠️  HTML report may be missing some content")
            else:
                print("❌ HTML report file not found")
                return False
        
        return True
        
    except ImportError as e:
        print(f"❌ Report generation modules not available: {e}")
        return False
    except Exception as e:
        print(f"❌ Report generation test failed: {e}")
        return False


def test_data_models():
    """Test core data models."""
    
    print("\n📝 Testing Core Data Models...")
    
    try:
        scan_result = create_test_scan_result()
        
        # Test basic properties
        assert scan_result.total_findings == 2
        assert scan_result.scan_id == "quick-test-001"
        assert scan_result.status == ScanStatus.COMPLETED
        
        # Test findings by severity
        severity_counts = scan_result.findings_by_severity
        assert severity_counts[SeverityLevel.HIGH] == 1
        assert severity_counts[SeverityLevel.CRITICAL] == 1
        
        # Test blocking findings logic
        has_blocking = scan_result.has_blocking_findings(fail_on_critical=True, fail_on_high=False)
        assert has_blocking == True  # Should block due to critical finding
        
        has_blocking_high = scan_result.has_blocking_findings(fail_on_critical=False, fail_on_high=True)
        assert has_blocking_high == True  # Should block due to high finding
        
        print("✅ Core data models working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Data model test failed: {e}")
        return False


def main():
    """Run all quick tests."""
    
    print("🚀 DevOps Buddy Quick Test Suite")
    print("=" * 50)
    
    tests = [
        ("Core Data Models", test_data_models),
        ("GitHub Actions Integration", test_github_actions),
        ("Report Generation", test_report_generation)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                failed += 1
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {test_name}: FAILED - {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! DevOps Buddy is working correctly.")
        print("\n📋 Next Steps:")
        print("1. Try running: python quick_test.py")
        print("2. Generate a GitHub Actions workflow")
        print("3. Test with sample projects")
        print("4. Explore the CLI commands")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 