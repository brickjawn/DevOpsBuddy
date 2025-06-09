"""Cloud misconfiguration scanner for AWS, Azure, and GCP."""

import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from .base import BaseScannerPlugin, CloudScannerMixin
from ..core.models import (
    ScanResult, ScanTarget, ScanType, ScanStatus,
    Finding, CloudProvider, SeverityLevel, Location, Remediation
)
from ..utils.exceptions import CloudProviderError


class CloudMisconfigScanner(BaseScannerPlugin, CloudScannerMixin):
    """Scanner for detecting cloud infrastructure misconfigurations."""
    
    @property
    def scan_type(self) -> ScanType:
        """Return the scan type this plugin handles."""
        return ScanType.CLOUD_MISCONFIG
    
    @property
    def supported_targets(self) -> List[str]:
        """Return list of supported target types."""
        return ["cloud_account", "cloud_resource", "terraform", "cloudformation"]
    
    async def scan(self, target: ScanTarget) -> ScanResult:
        """Perform cloud misconfiguration scan.
        
        Args:
            target: The target to scan (cloud account or IaC files)
            
        Returns:
            ScanResult containing misconfiguration findings
        """
        scan_result = self.create_scan_result(target)
        
        try:
            if not await self.validate_target(target):
                scan_result.status = ScanStatus.FAILED
                scan_result.errors.append("Invalid or inaccessible target")
                return scan_result
            
            # Determine scan approach based on target type
            if target.type == "cloud_account":
                await self._scan_cloud_account(target, scan_result)
            elif target.type in ["terraform", "cloudformation"]:
                await self._scan_iac_files(target, scan_result)
            else:
                scan_result.warnings.append(f"Target type {target.type} not fully implemented")
            
            # Filter findings by severity threshold
            scan_result.findings = self.filter_by_severity_threshold(scan_result.findings)
            
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.now()
            
            self.logger.info(
                f"Cloud misconfiguration scan completed with {len(scan_result.findings)} findings"
            )
            
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(f"Scan failed: {str(e)}")
            scan_result.completed_at = datetime.now()
            self.logger.error("Cloud misconfiguration scan failed", exc_info=e)
        
        return scan_result
    
    async def _scan_cloud_account(self, target: ScanTarget, scan_result: ScanResult) -> None:
        """Scan a cloud account for misconfigurations.
        
        Args:
            target: Cloud account target
            scan_result: Result object to populate
        """
        provider = target.metadata.get("provider", "aws").lower()
        
        if provider == "aws":
            await self._scan_aws_account(target, scan_result)
        elif provider == "azure":
            await self._scan_azure_account(target, scan_result)
        elif provider == "gcp":
            await self._scan_gcp_account(target, scan_result)
        else:
            scan_result.errors.append(f"Unsupported cloud provider: {provider}")
    
    async def _scan_aws_account(self, target: ScanTarget, scan_result: ScanResult) -> None:
        """Scan AWS account for misconfigurations."""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Initialize AWS session
            aws_config = self.get_cloud_credentials("aws")
            session = boto3.Session(
                aws_access_key_id=aws_config.get("access_key_id"),
                aws_secret_access_key=aws_config.get("secret_access_key"),
                region_name=target.cloud_region or aws_config.get("region", "us-east-1")
            )
            
            # Run AWS-specific checks
            await self._check_aws_s3_buckets(session, scan_result)
            await self._check_aws_security_groups(session, scan_result)
            await self._check_aws_iam_policies(session, scan_result)
            await self._check_aws_ec2_instances(session, scan_result)
            
        except (NoCredentialsError, ClientError) as e:
            scan_result.errors.append(f"AWS authentication failed: {str(e)}")
        except ImportError:
            scan_result.errors.append("boto3 library not available for AWS scanning")
        except Exception as e:
            scan_result.errors.append(f"AWS scan failed: {str(e)}")
    
    async def _check_aws_s3_buckets(self, session: Any, scan_result: ScanResult) -> None:
        """Check S3 buckets for misconfigurations."""
        try:
            s3_client = session.client('s3')
            
            # List all buckets
            response = s3_client.list_buckets()
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                # Check bucket ACL
                try:
                    acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                    
                    for grant in acl_response.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        permission = grant.get('Permission')
                        
                        # Check for public read/write access
                        if grantee.get('Type') == 'Group':
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                severity = SeverityLevel.CRITICAL if permission in ['WRITE', 'FULL_CONTROL'] else SeverityLevel.HIGH
                                
                                finding = self.create_finding(
                                    title=f"S3 Bucket with Public {permission} Access",
                                    description=f"S3 bucket '{bucket_name}' allows {permission.lower()} access to {grantee.get('URI', 'unknown group')}",
                                    severity=severity.value,
                                    category="Storage",
                                    cloud_provider=CloudProvider.AWS,
                                    affected_resource=bucket_name,
                                    location=Location(
                                        resource_id=bucket_name,
                                        cloud_region=session.region_name
                                    ),
                                    public_exposure=True,
                                    remediation=Remediation(
                                        description="Remove public access from S3 bucket ACL",
                                        steps=[
                                            "Go to AWS S3 Console",
                                            f"Select bucket '{bucket_name}'",
                                            "Click on 'Permissions' tab",
                                            "Modify bucket ACL to remove public access",
                                            "Enable 'Block all public access' setting"
                                        ],
                                        code_snippet=f"""
# AWS CLI command to block public access
aws s3api put-public-access-block \\
  --bucket {bucket_name} \\
  --public-access-block-configuration \\
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                                        """.strip(),
                                        automated=True,
                                        estimated_effort="5 minutes"
                                    )
                                )
                                scan_result.add_finding(finding)
                
                except Exception as e:
                    self.logger.warning(f"Could not check ACL for bucket {bucket_name}: {e}")
                
                # Check bucket encryption
                try:
                    s3_client.get_bucket_encryption(Bucket=bucket_name)
                except s3_client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        finding = self.create_finding(
                            title="S3 Bucket Without Encryption",
                            description=f"S3 bucket '{bucket_name}' does not have server-side encryption enabled",
                            severity=SeverityLevel.MEDIUM.value,
                            category="Storage",
                            cloud_provider=CloudProvider.AWS,
                            affected_resource=bucket_name,
                            location=Location(
                                resource_id=bucket_name,
                                cloud_region=session.region_name
                            ),
                            remediation=Remediation(
                                description="Enable server-side encryption for S3 bucket",
                                steps=[
                                    "Go to AWS S3 Console",
                                    f"Select bucket '{bucket_name}'",
                                    "Click on 'Properties' tab",
                                    "Enable 'Default encryption'",
                                    "Choose encryption key (AWS managed or customer managed)"
                                ],
                                automated=True,
                                estimated_effort="2 minutes"
                            )
                        )
                        scan_result.add_finding(finding)
                
        except Exception as e:
            self.logger.error(f"Failed to check S3 buckets: {e}")
    
    async def _check_aws_security_groups(self, session: Any, scan_result: ScanResult) -> None:
        """Check EC2 Security Groups for overly permissive rules."""
        try:
            ec2_client = session.client('ec2')
            
            # Get all security groups
            response = ec2_client.describe_security_groups()
            
            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        
                        if cidr == '0.0.0.0/0':  # Open to the world
                            from_port = rule.get('FromPort')
                            to_port = rule.get('ToPort')
                            protocol = rule.get('IpProtocol')
                            
                            # Determine severity based on port
                            if from_port in [22, 3389]:  # SSH or RDP
                                severity = SeverityLevel.CRITICAL
                            elif from_port in [80, 443]:  # HTTP/HTTPS
                                severity = SeverityLevel.MEDIUM
                            else:
                                severity = SeverityLevel.HIGH
                            
                            port_desc = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
                            
                            finding = self.create_finding(
                                title=f"Security Group with Open {port_desc}",
                                description=f"Security group '{sg_name}' ({sg_id}) allows inbound access from 0.0.0.0/0 on {port_desc} ({protocol})",
                                severity=severity.value,
                                category="Network",
                                cloud_provider=CloudProvider.AWS,
                                affected_resource=sg_id,
                                location=Location(
                                    resource_id=sg_id,
                                    cloud_region=session.region_name
                                ),
                                public_exposure=True,
                                remediation=Remediation(
                                    description="Restrict security group inbound rules to specific IP ranges",
                                    steps=[
                                        "Go to AWS EC2 Console",
                                        "Navigate to Security Groups",
                                        f"Select security group '{sg_name}' ({sg_id})",
                                        "Edit inbound rules",
                                        "Replace 0.0.0.0/0 with specific IP ranges or security groups"
                                    ],
                                    automated=True,
                                    estimated_effort="10 minutes"
                                )
                            )
                            scan_result.add_finding(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to check security groups: {e}")
    
    async def _check_aws_iam_policies(self, session: Any, scan_result: ScanResult) -> None:
        """Check IAM policies for overly permissive permissions."""
        try:
            iam_client = session.client('iam')
            
            # Check for users with administrative access
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    username = user['UserName']
                    
                    # Check attached user policies
                    user_policies = iam_client.list_attached_user_policies(UserName=username)
                    
                    for policy in user_policies.get('AttachedPolicies', []):
                        if policy['PolicyName'] == 'AdministratorAccess':
                            finding = self.create_finding(
                                title="IAM User with Administrative Access",
                                description=f"IAM user '{username}' has AdministratorAccess policy attached",
                                severity=SeverityLevel.HIGH.value,
                                category="IAM",
                                cloud_provider=CloudProvider.AWS,
                                affected_resource=username,
                                location=Location(
                                    resource_id=username,
                                    cloud_region=session.region_name
                                ),
                                remediation=Remediation(
                                    description="Apply principle of least privilege to IAM user",
                                    steps=[
                                        "Review user's actual required permissions",
                                        "Create custom policy with minimal required permissions",
                                        "Detach AdministratorAccess policy",
                                        "Attach the custom policy",
                                        "Test to ensure functionality is maintained"
                                    ],
                                    estimated_effort="30 minutes"
                                )
                            )
                            scan_result.add_finding(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to check IAM policies: {e}")
    
    async def _check_aws_ec2_instances(self, session: Any, scan_result: ScanResult) -> None:
        """Check EC2 instances for security issues."""
        try:
            ec2_client = session.client('ec2')
            
            # Get all instances
            response = ec2_client.describe_instances()
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']
                    
                    # Skip terminated instances
                    if state == 'terminated':
                        continue
                    
                    # Check if instance has public IP
                    public_ip = instance.get('PublicIpAddress')
                    if public_ip:
                        # Check if monitoring is enabled
                        monitoring = instance.get('Monitoring', {}).get('State', 'disabled')
                        if monitoring == 'disabled':
                            finding = self.create_finding(
                                title="EC2 Instance Without Detailed Monitoring",
                                description=f"Public-facing EC2 instance '{instance_id}' does not have detailed monitoring enabled",
                                severity=SeverityLevel.LOW.value,
                                category="Monitoring",
                                cloud_provider=CloudProvider.AWS,
                                affected_resource=instance_id,
                                location=Location(
                                    resource_id=instance_id,
                                    cloud_region=session.region_name
                                ),
                                public_exposure=True,
                                remediation=Remediation(
                                    description="Enable detailed monitoring for EC2 instance",
                                    steps=[
                                        "Go to AWS EC2 Console",
                                        f"Select instance '{instance_id}'",
                                        "Click 'Actions' > 'Monitor and troubleshoot' > 'Manage detailed monitoring'",
                                        "Enable detailed monitoring"
                                    ],
                                    automated=True,
                                    estimated_effort="2 minutes"
                                )
                            )
                            scan_result.add_finding(finding)
        
        except Exception as e:
            self.logger.error(f"Failed to check EC2 instances: {e}")
    
    async def _scan_azure_account(self, target: ScanTarget, scan_result: ScanResult) -> None:
        """Scan Azure account for misconfigurations."""
        # Azure implementation would go here
        scan_result.warnings.append("Azure scanning not yet implemented")
    
    async def _scan_gcp_account(self, target: ScanTarget, scan_result: ScanResult) -> None:
        """Scan GCP account for misconfigurations."""
        # GCP implementation would go here
        scan_result.warnings.append("GCP scanning not yet implemented")
    
    async def _scan_iac_files(self, target: ScanTarget, scan_result: ScanResult) -> None:
        """Scan Infrastructure as Code files for misconfigurations."""
        try:
            # Use Checkov for IaC scanning
            import subprocess
            import json
            
            if not target.path:
                scan_result.errors.append("Path required for IaC scanning")
                return
            
            path = Path(target.path)
            if not path.exists():
                scan_result.errors.append(f"Path not found: {target.path}")
                return
            
            # Run Checkov
            cmd = [
                "checkov",
                "-f", str(path) if path.is_file() else None,
                "-d", str(path) if path.is_dir() else None,
                "--output", "json",
                "--quiet"
            ]
            cmd = [arg for arg in cmd if arg is not None]  # Remove None values
            
            self.logger.debug(f"Running Checkov command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0 and result.stderr:
                scan_result.warnings.append(f"Checkov warnings: {result.stderr}")
            
            if result.stdout:
                try:
                    checkov_results = json.loads(result.stdout)
                    self._process_checkov_results(checkov_results, scan_result)
                except json.JSONDecodeError as e:
                    scan_result.errors.append(f"Failed to parse Checkov output: {e}")
            
        except subprocess.TimeoutExpired:
            scan_result.errors.append("Checkov scan timed out")
        except FileNotFoundError:
            scan_result.errors.append("Checkov not found. Please install checkov: pip install checkov")
        except Exception as e:
            scan_result.errors.append(f"IaC scan failed: {str(e)}")
    
    def _process_checkov_results(self, checkov_results: Dict[str, Any], scan_result: ScanResult) -> None:
        """Process Checkov scan results."""
        failed_checks = checkov_results.get('results', {}).get('failed_checks', [])
        
        for check in failed_checks:
            severity_map = {
                'CRITICAL': SeverityLevel.CRITICAL,
                'HIGH': SeverityLevel.HIGH,
                'MEDIUM': SeverityLevel.MEDIUM,
                'LOW': SeverityLevel.LOW
            }
            
            severity = severity_map.get(
                check.get('severity', 'MEDIUM').upper(),
                SeverityLevel.MEDIUM
            )
            
            finding = self.create_finding(
                title=check.get('check_name', 'Unknown Check'),
                description=check.get('description', 'No description available'),
                severity=severity.value,
                category="Infrastructure",
                location=Location(
                    file_path=check.get('file_path'),
                    line_number=check.get('file_line_range', [None])[0]
                ),
                rule_id=check.get('check_id'),
                rule_name=check.get('check_name'),
                remediation=Remediation(
                    description=check.get('guideline', 'See documentation for remediation steps'),
                    documentation_url=check.get('more_info')
                ) if check.get('guideline') or check.get('more_info') else None
            )
            
            scan_result.add_finding(finding) 