"""Main CLI interface for DevOps Buddy security scanner."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, List

import click
import yaml

from ..core.config import Config
from ..core.scanner import SecurityScanner
from ..core.models import ScanTarget, ScanType, SeverityLevel
from ..reporting.base import MultiFormatReportGenerator
from ..integrations.github_actions import GitHubActionsIntegration


@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--quiet', '-q', is_flag=True, help='Suppress output except errors')
@click.pass_context
def cli(ctx, config: Optional[str], verbose: bool, quiet: bool):
    """DevOps Buddy - Automated DevSecOps Security Scanner.
    
    A comprehensive security scanning tool for cloud infrastructure,
    containers, dependencies, and compliance checking.
    """
    # Initialize context
    ctx.ensure_object(dict)
    
    # Load configuration
    try:
        ctx.obj['config'] = Config.load_from_file(config)
        if verbose:
            ctx.obj['config'].log_level = "DEBUG"
        elif quiet:
            ctx.obj['config'].log_level = "ERROR"
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('target_path')
@click.option('--type', '-t', 'target_type', 
              type=click.Choice(['directory', 'file', 'container', 'cloud_account']),
              default='directory',
              help='Type of target to scan')
@click.option('--scanners', '-s', 
              multiple=True,
              type=click.Choice(['cloud_misconfig', 'container_security', 'iac_scanner', 
                               'dependency_scanner', 'sbom_generator', 'kubernetes_security']),
              help='Specific scanners to run (default: all enabled)')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'yaml', 'text', 'sarif', 'html', 'pdf']),
              default='json',
              help='Output format')
@click.option('--severity-threshold', 
              type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              help='Minimum severity level to report')
@click.option('--fail-on-critical', is_flag=True, 
              help='Exit with non-zero code if critical findings are found')
@click.option('--fail-on-high', is_flag=True,
              help='Exit with non-zero code if high severity findings are found')
@click.pass_context
def scan(ctx, target_path: str, target_type: str, scanners: tuple, output: Optional[str],
         output_format: str, severity_threshold: Optional[str], fail_on_critical: bool,
         fail_on_high: bool):
    """Perform a comprehensive security scan on the specified target."""
    
    config = ctx.obj['config']
    
    # Override severity threshold if provided
    if severity_threshold:
        config.scanner.severity_threshold = severity_threshold
    
    # Create scan target
    target = ScanTarget(
        type=target_type,
        path=target_path if target_type in ['directory', 'file'] else None,
        cloud_account_id=target_path if target_type == 'cloud_account' else None
    )
    
    # Determine scan types
    scan_types = None
    if scanners:
        scan_types = [ScanType(scanner) for scanner in scanners]
    
    # Initialize scanner
    scanner = SecurityScanner(config)
    
    try:
        # Run scan
        click.echo(f"Starting security scan of {target_type}: {target_path}")
        
        # Run async scan
        result = asyncio.run(scanner.scan(target, scan_types))
        
        # Print results summary
        click.echo(f"\nScan completed in {result.duration_seconds:.2f} seconds")
        click.echo(f"Total findings: {result.total_findings}")
        
        if result.findings_by_severity:
            click.echo("Findings by severity:")
            for severity, count in result.findings_by_severity.items():
                click.echo(f"  {severity.value}: {count}")
        
        if result.errors:
            click.echo("\nErrors:")
            for error in result.errors:
                click.echo(f"  ❌ {error}")
        
        if result.warnings:
            click.echo("\nWarnings:")
            for warning in result.warnings:
                click.echo(f"  ⚠️  {warning}")
        
        # Output results
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_format in ['html', 'pdf']:
                # Use multi-format report generator
                report_generator = MultiFormatReportGenerator()
                report_path = report_generator.generate_report(output_format, result, str(output_path))
                click.echo(f"\nReport saved to: {report_path}")
            elif output_format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(result.dict(), f, indent=2, default=str)
                click.echo(f"\nResults saved to: {output_path}")
            elif output_format == 'yaml':
                with open(output_path, 'w') as f:
                    yaml.dump(result.dict(), f, default_flow_style=False, default=str)
                click.echo(f"\nResults saved to: {output_path}")
            elif output_format == 'text':
                with open(output_path, 'w') as f:
                    _write_text_report(f, result)
                click.echo(f"\nResults saved to: {output_path}")
            elif output_format == 'sarif':
                # Use GitHub Actions integration for SARIF
                github_integration = GitHubActionsIntegration()
                sarif_content = github_integration.format_output(result, 'sarif')
                with open(output_path, 'w') as f:
                    f.write(sarif_content)
                click.echo(f"\nSARIF results saved to: {output_path}")
        
        # Check for blocking findings
        if result.has_blocking_findings(fail_on_critical, fail_on_high):
            critical_count = result.findings_by_severity.get(SeverityLevel.CRITICAL, 0)
            high_count = result.findings_by_severity.get(SeverityLevel.HIGH, 0)
            
            click.echo(f"\n❌ Scan failed due to blocking findings:")
            if fail_on_critical and critical_count > 0:
                click.echo(f"   Critical findings: {critical_count}")
            if fail_on_high and high_count > 0:
                click.echo(f"   High severity findings: {high_count}")
            
            sys.exit(1)
        else:
            click.echo("\n✅ Scan completed successfully")
            
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('target_path')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['json', 'cyclonedx', 'spdx']),
              default='cyclonedx',
              help='SBOM output format')
@click.option('--include-vulnerabilities', is_flag=True, default=True,
              help='Include vulnerability information in SBOM')
@click.pass_context
def sbom(ctx, target_path: str, output: Optional[str], output_format: str,
         include_vulnerabilities: bool):
    """Generate Software Bill of Materials (SBOM) for the target."""
    
    config = ctx.obj['config']
    
    target = ScanTarget(
        type='directory',
        path=target_path
    )
    
    scanner = SecurityScanner(config)
    
    try:
        click.echo(f"Generating SBOM for: {target_path}")
        
        sbom_result = asyncio.run(scanner.generate_sbom(target, include_vulnerabilities))
        
        click.echo(f"SBOM generated with {sbom_result.total_components} components")
        if include_vulnerabilities:
            click.echo(f"Found {sbom_result.total_vulnerabilities} vulnerabilities")
        
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(sbom_result.dict(), f, indent=2, default=str)
            
            click.echo(f"SBOM saved to: {output_path}")
        else:
            # Print to stdout
            print(json.dumps(sbom_result.dict(), indent=2, default=str))
            
    except Exception as e:
        click.echo(f"❌ SBOM generation failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('target_path')
@click.option('--frameworks', '-f', multiple=True,
              type=click.Choice(['CIS', 'GDPR', 'HIPAA', 'SOC2', 'PCI_DSS']),
              help='Compliance frameworks to check')
@click.option('--output', '-o', help='Output directory for compliance reports')
@click.pass_context
def compliance(ctx, target_path: str, frameworks: tuple, output: Optional[str]):
    """Check compliance against regulatory frameworks."""
    
    config = ctx.obj['config']
    
    target = ScanTarget(
        type='cloud_account',
        cloud_account_id=target_path
    )
    
    scanner = SecurityScanner(config)
    
    try:
        frameworks_list = list(frameworks) if frameworks else None
        
        click.echo(f"Checking compliance for: {target_path}")
        
        reports = asyncio.run(scanner.check_compliance(target, frameworks_list))
        
        for report in reports:
            click.echo(f"\n{report.framework.value} Compliance Report:")
            click.echo(f"  Overall compliance: {report.compliance_percentage:.1f}%")
            click.echo(f"  Passed controls: {report.passed_controls}/{report.total_controls}")
            
            if output:
                output_dir = Path(output)
                output_dir.mkdir(parents=True, exist_ok=True)
                
                report_file = output_dir / f"{report.framework.value.lower()}_compliance_report.json"
                with open(report_file, 'w') as f:
                    json.dump(report.dict(), f, indent=2, default=str)
                
                click.echo(f"  Report saved to: {report_file}")
            
    except Exception as e:
        click.echo(f"❌ Compliance check failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def info(ctx):
    """Display information about available scanners and configuration."""
    
    config = ctx.obj['config']
    scanner = SecurityScanner(config)
    
    info_data = scanner.get_scanner_info()
    
    click.echo("DevOps Buddy Security Scanner")
    click.echo(f"Version: {info_data['version']}")
    click.echo(f"Active scans: {info_data['active_scans']}")
    click.echo(f"Max parallel scans: {info_data['max_parallel_scans']}")
    click.echo(f"Scan timeout: {info_data['scan_timeout']}s")
    click.echo(f"Severity threshold: {info_data['severity_threshold']}")
    
    click.echo("\nAvailable scanners:")
    for scanner_type in info_data['available_scanners']:
        enabled = "✅" if scanner_type in info_data['enabled_scanners'] else "❌"
        click.echo(f"  {enabled} {scanner_type}")
    
    click.echo(f"\nConfiguration loaded from: {config.config_dir}")
    click.echo(f"Reports directory: {config.reports_dir}")
    click.echo(f"Cache directory: {config.cache_dir}")


@cli.command()
@click.argument('project_path')
@click.option('--platform', '-p', 
              type=click.Choice(['github-actions', 'gitlab-ci', 'jenkins']),
              default='github-actions',
              help='CI/CD platform to generate configuration for')
@click.option('--output', '-o', help='Output configuration file path')
@click.option('--scanners', '-s', multiple=True,
              help='Scanners to include in CI/CD pipeline')
@click.option('--fail-on-critical', is_flag=True, default=True,
              help='Configure pipeline to fail on critical findings')
@click.option('--fail-on-high', is_flag=True, default=False,
              help='Configure pipeline to fail on high severity findings')
@click.pass_context
def generate_cicd(ctx, project_path: str, platform: str, output: Optional[str],
                  scanners: tuple, fail_on_critical: bool, fail_on_high: bool):
    """Generate CI/CD pipeline configuration for security scanning."""
    
    try:
        scan_config = {
            'scanners': list(scanners) if scanners else None,
            'fail_on_critical': fail_on_critical,
            'fail_on_high': fail_on_high,
            'cloud_providers': ['aws', 'azure', 'gcp'],  # Default all providers
            'generate_sbom': True,
            'compliance_check': True
        }
        
        if platform == 'github-actions':
            integration = GitHubActionsIntegration()
            config_content = integration.generate_config(project_path, scan_config)
            default_filename = '.github/workflows/devops-buddy.yml'
        else:
            click.echo(f"❌ Platform '{platform}' not yet implemented", err=True)
            sys.exit(1)
        
        output_path = output or default_filename
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write(config_content)
        
        click.echo(f"✅ Generated {platform} configuration: {output_path}")
        click.echo("\nNext steps:")
        click.echo("1. Review and customize the generated configuration")
        click.echo("2. Add required secrets to your repository:")
        
        if 'aws' in scan_config.get('cloud_providers', []):
            click.echo("   - AWS_ACCESS_KEY_ID")
            click.echo("   - AWS_SECRET_ACCESS_KEY")
            click.echo("   - AWS_DEFAULT_REGION")
        
        if 'azure' in scan_config.get('cloud_providers', []):
            click.echo("   - AZURE_CLIENT_ID")
            click.echo("   - AZURE_CLIENT_SECRET")
            click.echo("   - AZURE_TENANT_ID")
        
        if 'gcp' in scan_config.get('cloud_providers', []):
            click.echo("   - GOOGLE_APPLICATION_CREDENTIALS")
        
        click.echo("3. Commit and push the configuration to trigger the workflow")
        
    except Exception as e:
        click.echo(f"❌ Failed to generate CI/CD configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--sample', is_flag=True, help='Generate sample configuration file')
@click.option('--output', '-o', default='devops_buddy.yaml', help='Output configuration file')
def config(sample: bool, output: str):
    """Generate or manage configuration files."""
    
    if sample:
        # Generate sample configuration
        config = Config()
        config.save_to_file(output)
        click.echo(f"Sample configuration saved to: {output}")
        click.echo("Edit the configuration file to customize scanner settings.")
    else:
        click.echo("Use --sample to generate a sample configuration file")


def _write_text_report(file, result):
    """Write scan results in text format."""
    file.write(f"DevOps Buddy Security Scan Report\n")
    file.write(f"================================\n\n")
    file.write(f"Scan ID: {result.scan_id}\n")
    file.write(f"Target: {result.target.path or result.target.url}\n")
    file.write(f"Scan Type: {result.scan_type.value}\n")
    file.write(f"Duration: {result.duration_seconds:.2f} seconds\n")
    file.write(f"Total Findings: {result.total_findings}\n\n")
    
    if result.findings_by_severity:
        file.write("Findings by Severity:\n")
        for severity, count in result.findings_by_severity.items():
            file.write(f"  {severity.value}: {count}\n")
        file.write("\n")
    
    if result.findings:
        file.write("Detailed Findings:\n")
        file.write("-" * 50 + "\n")
        
        for finding in result.findings:
            file.write(f"\n[{finding.severity.value}] {finding.title}\n")
            file.write(f"Category: {finding.category}\n")
            file.write(f"Description: {finding.description}\n")
            
            if finding.location.file_path:
                file.write(f"Location: {finding.location.file_path}")
                if finding.location.line_number:
                    file.write(f":{finding.location.line_number}")
                file.write("\n")
            
            if finding.remediation:
                file.write(f"Remediation: {finding.remediation.description}\n")
            
            file.write("-" * 50 + "\n")


if __name__ == '__main__':
    cli() 