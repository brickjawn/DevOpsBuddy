"""JSON report generator for DevOps Buddy."""

import json
from typing import Dict, Any
from datetime import datetime

from .base import BaseReportGenerator
from ..core.models import ScanResult, ComplianceReport, SBOM


class JSONReportGenerator(BaseReportGenerator):
    """Generates reports in JSON format."""
    
    @property
    def file_extension(self) -> str:
        return ".json"
    
    def generate_scan_report(self, scan_result: ScanResult, output_path: str, **kwargs) -> str:
        """Generate a JSON scan report."""
        
        output_file = self.ensure_output_directory(output_path)
        
        # Create comprehensive report structure
        report_data = {
            "metadata": {
                "report_type": "security_scan",
                "generated_at": datetime.now().isoformat(),
                "generator": "DevOps Buddy JSON Reporter",
                "version": "1.0.0"
            },
            "scan_info": self.get_report_metadata(scan_result),
            "summary": {
                "total_findings": scan_result.total_findings,
                "findings_by_severity": {
                    severity.value: count 
                    for severity, count in scan_result.findings_by_severity.items()
                },
                "scan_duration_seconds": scan_result.duration_seconds,
                "scan_status": scan_result.status.value,
                "error_count": len(scan_result.errors),
                "warning_count": len(scan_result.warnings)
            },
            "findings": [self._serialize_finding(finding) for finding in scan_result.findings],
            "errors": scan_result.errors,
            "warnings": scan_result.warnings,
            "statistics": {
                "scanned_files_count": scan_result.scanned_files_count,
                "scanned_resources_count": scan_result.scanned_resources_count
            }
        }
        
        # Add configuration if available
        if scan_result.configuration:
            report_data["scan_configuration"] = scan_result.configuration
        
        # Write JSON report
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return str(output_file)
    
    def generate_compliance_report(self, compliance_report: ComplianceReport, output_path: str, **kwargs) -> str:
        """Generate a JSON compliance report."""
        
        output_file = self.ensure_output_directory(output_path)
        
        report_data = {
            "metadata": {
                "report_type": "compliance_assessment",
                "generated_at": datetime.now().isoformat(),
                "generator": "DevOps Buddy JSON Reporter",
                "version": "1.0.0"
            },
            "compliance_info": {
                "report_id": compliance_report.report_id,
                "framework": compliance_report.framework.value,
                "assessment_date": compliance_report.generated_at.isoformat(),
                "assessment_period": compliance_report.assessment_period,
                "target": {
                    "type": compliance_report.target.type,
                    "path": compliance_report.target.path,
                    "cloud_account_id": compliance_report.target.cloud_account_id
                }
            },
            "summary": {
                "total_controls": compliance_report.total_controls,
                "passed_controls": compliance_report.passed_controls,
                "failed_controls": compliance_report.failed_controls,
                "compliance_percentage": compliance_report.compliance_percentage
            },
            "control_results": compliance_report.control_results,
            "recommendations": compliance_report.recommendations,
            "evidence_files": compliance_report.evidence_files,
            "audit_trail": compliance_report.audit_trail
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return str(output_file)
    
    def generate_sbom_report(self, sbom: SBOM, output_path: str, **kwargs) -> str:
        """Generate a JSON SBOM report."""
        
        output_file = self.ensure_output_directory(output_path)
        
        # Check if CycloneDX format is requested
        if kwargs.get("format") == "cyclonedx":
            report_data = self._generate_cyclonedx_format(sbom)
        else:
            # Default DevOps Buddy SBOM format
            report_data = {
                "metadata": {
                    "report_type": "software_bill_of_materials",
                    "generated_at": datetime.now().isoformat(),
                    "generator": "DevOps Buddy JSON Reporter",
                    "version": "1.0.0",
                    "sbom_format": "devops_buddy"
                },
                "sbom_info": {
                    "creation_date": sbom.creation_date.isoformat(),
                    "created_by": sbom.created_by,
                    "format_version": sbom.format_version,
                    "target_name": sbom.target_name,
                    "target_version": sbom.target_version,
                    "target_type": sbom.target_type
                },
                "summary": {
                    "total_components": sbom.total_components,
                    "total_vulnerabilities": sbom.total_vulnerabilities,
                    "vulnerabilities_by_severity": {
                        severity.value: count 
                        for severity, count in sbom.vulnerabilities_by_severity.items()
                    }
                },
                "components": [
                    self._serialize_sbom_component(component) 
                    for component in sbom.components
                ]
            }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return str(output_file)
    
    def _serialize_finding(self, finding) -> Dict[str, Any]:
        """Serialize a finding to JSON-compatible format."""
        
        data = {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "scan_type": finding.scan_type.value,
            "category": finding.category,
            "created_at": finding.created_at.isoformat(),
            "false_positive": finding.false_positive,
            "suppressed": finding.suppressed
        }
        
        # Add optional fields if present
        if finding.location:
            data["location"] = {
                "file_path": finding.location.file_path,
                "line_number": finding.location.line_number,
                "column_number": finding.location.column_number,
                "resource_id": finding.location.resource_id,
                "cloud_region": finding.location.cloud_region
            }
        
        if finding.affected_resource:
            data["affected_resource"] = finding.affected_resource
        
        if finding.cloud_provider:
            data["cloud_provider"] = finding.cloud_provider.value
        
        if finding.rule_id:
            data["rule_id"] = finding.rule_id
        
        if finding.rule_name:
            data["rule_name"] = finding.rule_name
        
        if finding.cve_info:
            data["cve_info"] = {
                "cve_id": finding.cve_info.cve_id,
                "cvss_score": finding.cve_info.cvss_score,
                "cvss_vector": finding.cve_info.cvss_vector,
                "description": finding.cve_info.description,
                "published_date": finding.cve_info.published_date.isoformat() if finding.cve_info.published_date else None,
                "last_modified": finding.cve_info.last_modified.isoformat() if finding.cve_info.last_modified else None,
                "cwe_ids": finding.cve_info.cwe_ids
            }
        
        if finding.risk_score is not None:
            data["risk_score"] = finding.risk_score
        
        if finding.exploitability_score is not None:
            data["exploitability_score"] = finding.exploitability_score
        
        if finding.public_exposure:
            data["public_exposure"] = finding.public_exposure
        
        if finding.remediation:
            data["remediation"] = {
                "description": finding.remediation.description,
                "steps": finding.remediation.steps,
                "code_snippet": finding.remediation.code_snippet,
                "documentation_url": finding.remediation.documentation_url,
                "automated": finding.remediation.automated,
                "estimated_effort": finding.remediation.estimated_effort
            }
        
        if finding.compliance_frameworks:
            data["compliance_frameworks"] = [framework.value for framework in finding.compliance_frameworks]
        
        if finding.context:
            data["context"] = finding.context
        
        return data
    
    def _serialize_sbom_component(self, component) -> Dict[str, Any]:
        """Serialize an SBOM component to JSON-compatible format."""
        
        data = {
            "name": component.name,
            "version": component.version,
            "type": component.type,
            "dependencies": component.dependencies
        }
        
        # Add optional fields
        if component.purl:
            data["purl"] = component.purl
        
        if component.supplier:
            data["supplier"] = component.supplier
        
        if component.license:
            data["license"] = component.license
        
        if component.hash_value:
            data["hash_value"] = component.hash_value
        
        if component.vulnerabilities:
            data["vulnerabilities"] = [
                {
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "cvss_vector": vuln.cvss_vector,
                    "description": vuln.description,
                    "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                    "last_modified": vuln.last_modified.isoformat() if vuln.last_modified else None,
                    "cwe_ids": vuln.cwe_ids
                }
                for vuln in component.vulnerabilities
            ]
        
        return data
    
    def _generate_cyclonedx_format(self, sbom: SBOM) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM."""
        
        # Basic CycloneDX structure
        cyclonedx_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{sbom.target_name}",
            "version": 1,
            "metadata": {
                "timestamp": sbom.creation_date.isoformat(),
                "tools": [
                    {
                        "vendor": "DevOps Buddy",
                        "name": "DevOps Buddy Security Scanner",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": sbom.target_type,
                    "name": sbom.target_name,
                    "version": sbom.target_version or "unknown"
                }
            },
            "components": []
        }
        
        # Convert components to CycloneDX format
        for component in sbom.components:
            cyclonedx_component = {
                "type": component.type,
                "name": component.name,
                "version": component.version
            }
            
            if component.purl:
                cyclonedx_component["purl"] = component.purl
            
            if component.license:
                cyclonedx_component["licenses"] = [{"license": {"name": component.license}}]
            
            if component.supplier:
                cyclonedx_component["supplier"] = {"name": component.supplier}
            
            cyclonedx_sbom["components"].append(cyclonedx_component)
        
        return cyclonedx_sbom 