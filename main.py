#!/usr/bin/env python3
"""CloudSentry CLI - OCI Security Posture Monitor."""

import json
import sys
from pathlib import Path

import click

from cloudsentry.config import load_config
from cloudsentry.scanner import Scanner


@click.group()
@click.version_option(version="1.0.0", prog_name="CloudSentry")
def cli():
    """CloudSentry - OCI Security Posture Monitor.

    Scan Oracle Cloud Infrastructure for security misconfigurations,
    store findings in PostgreSQL, and send alerts via Slack.
    """
    pass


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run scan without storing findings or sending alerts",
)
@click.option(
    "--compartment",
    "-C",
    multiple=True,
    help="Specific compartment OCID to scan (can be repeated)",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output findings to JSON file",
)
def scan(config, dry_run, compartment, output):
    """Run a security scan against OCI resources."""
    cfg = load_config(config)

    if not cfg.database.password and not dry_run:
        click.echo("Warning: No database password configured. Running in dry-run mode.")
        dry_run = True

    scanner = Scanner(cfg, dry_run=dry_run)

    compartments = list(compartment) if compartment else None
    results = scanner.run(compartments=compartments)

    if output:
        output_path = Path(output)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        click.echo(f"\nFindings exported to: {output_path}")

    # Exit with non-zero if critical findings
    if results["findings_count"]["CRITICAL"] > 0:
        sys.exit(2)
    elif results["findings_count"]["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file",
)
def init_db(config):
    """Initialize the database schema."""
    from cloudsentry.database.repository import Repository

    cfg = load_config(config)
    if not cfg.database.password:
        click.echo("Error: Database password not configured.")
        sys.exit(1)

    repo = Repository(cfg.database.connection_string)
    repo.init_db()
    click.echo("Database schema initialized successfully.")


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file",
)
@click.option(
    "--severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Filter by severity",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def findings(config, severity, format):
    """List current open findings."""
    from cloudsentry.database.repository import Repository

    cfg = load_config(config)
    if not cfg.database.password:
        click.echo("Error: Database password not configured.")
        sys.exit(1)

    repo = Repository(cfg.database.connection_string)
    open_findings = repo.get_open_findings(severity=severity)

    if format == "json":
        output = [
            {
                "check_id": f.check_id,
                "severity": f.severity,
                "title": f.title,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "description": f.description,
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            }
            for f in open_findings
        ]
        click.echo(json.dumps(output, indent=2))
    else:
        if not open_findings:
            click.echo("No open findings found.")
            return

        click.echo(f"\nOpen Findings: {len(open_findings)}")
        click.echo("-" * 80)
        for f in open_findings:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "white",
            }.get(f.severity, "white")
            click.echo(
                click.style(f"[{f.severity}]", fg=severity_color, bold=True)
                + f" {f.check_id}: {f.title}"
            )
            click.echo(f"  Resource: {f.resource_name or f.resource_id}")
            click.echo(f"  First seen: {f.first_seen}")
            click.echo()


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file",
)
@click.argument("check_id")
@click.argument("resource_id")
def suppress(config, check_id, resource_id):
    """Suppress a finding (mark as accepted risk)."""
    from cloudsentry.database.repository import Repository

    cfg = load_config(config)
    if not cfg.database.password:
        click.echo("Error: Database password not configured.")
        sys.exit(1)

    repo = Repository(cfg.database.connection_string)
    if repo.suppress_finding(check_id, resource_id):
        click.echo(f"Finding suppressed: {check_id} / {resource_id}")
    else:
        click.echo("Finding not found.")
        sys.exit(1)


@cli.command()
@click.option(
    "-c", "--config",
    type=click.Path(exists=True),
    default="config.yaml",
    help="Path to configuration file",
)
def compliance(config):
    """Show compliance score summary."""
    from cloudsentry.database.repository import Repository

    cfg = load_config(config)
    if not cfg.database.password:
        click.echo("Error: Database password not configured.")
        sys.exit(1)

    repo = Repository(cfg.database.connection_string)
    score = repo.get_latest_compliance_score()

    if not score:
        click.echo("No compliance scores found. Run a scan first.")
        return

    click.echo(f"\nCompliance Score: {score['framework']}")
    click.echo("=" * 40)
    click.echo(f"Score: {score['score']:.1f}%")
    click.echo(f"Checks passed: {score['passed_checks']}/{score['total_checks']}")
    click.echo(f"Last updated: {score['created_at']}")


@cli.command()
def checks():
    """List all available security checks."""
    from cloudsentry.checks import ALL_CHECKS

    click.echo("\nAvailable Security Checks:")
    click.echo("=" * 70)

    categories = {}
    for check_cls in ALL_CHECKS:
        check = check_cls()
        category = check.check_id.split("-")[0]
        if category not in categories:
            categories[category] = []
        categories[category].append(check)

    for category, checks_list in sorted(categories.items()):
        click.echo(f"\n{category}:")
        click.echo("-" * 50)
        for check in checks_list:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "white",
            }.get(check.severity.value, "white")
            cis = f" [CIS {check.cis_benchmark}]" if check.cis_benchmark else ""
            click.echo(
                f"  {check.check_id}: "
                + click.style(f"[{check.severity.value}]", fg=severity_color)
                + f" {check.title}{cis}"
            )

    click.echo(f"\nTotal: {len(ALL_CHECKS)} checks")


@cli.command()
def test_slack():
    """Send a test notification to Slack."""
    from cloudsentry.alerts.slack import SlackNotifier
    from cloudsentry.checks.base import Finding, Severity

    cfg = load_config()
    if not cfg.alerts.slack.enabled:
        click.echo("Slack notifications are not enabled in config.")
        sys.exit(1)

    notifier = SlackNotifier(cfg.alerts.slack)

    test_finding = Finding(
        check_id="TEST-001",
        resource_id="test-resource-123",
        resource_type="TestResource",
        severity=Severity.HIGH,
        title="Test Security Finding",
        description="This is a test notification from CloudSentry.",
        remediation="No action required - this is a test.",
        resource_name="test-resource",
    )

    if notifier.send_finding(test_finding):
        click.echo("Test notification sent successfully!")
    else:
        click.echo("Failed to send test notification.")
        sys.exit(1)


if __name__ == "__main__":
    cli()
