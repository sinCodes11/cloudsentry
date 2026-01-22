"""Main scanner orchestration for CloudSentry."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Optional, Dict, Set, Tuple
import uuid

from .config import Config
from .oci_client import OCIClient
from .checks import ALL_CHECKS, Finding, Severity
from .checks.base import BaseCheck
from .database.repository import Repository
from .alerts.slack import SlackNotifier


class Scanner:
    """Orchestrates security scanning across OCI resources."""

    def __init__(self, config: Config, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        self.client = OCIClient(config.oci)
        self.checks = [check() for check in ALL_CHECKS]

        self.repository: Optional[Repository] = None
        self.slack: Optional[SlackNotifier] = None

        if not dry_run:
            if config.database.password:
                self.repository = Repository(config.database.connection_string)
                self.repository.init_db()

            if config.alerts.slack.enabled:
                self.slack = SlackNotifier(config.alerts.slack)

    def run(self, compartments: Optional[List[str]] = None) -> Dict:
        """Execute security scan and return results.

        Args:
            compartments: Optional list of compartment OCIDs to scan.
                         If None, uses configuration.

        Returns:
            Dictionary with scan results and statistics.
        """
        start_time = time.time()

        # Get compartments to scan
        if compartments is None:
            compartments = self.config.oci.compartments
        compartment_ids = self.client.get_compartments(compartments)

        print(f"\n{'='*60}")
        print(f"CloudSentry Security Scan")
        print(f"{'='*60}")
        print(f"Compartments to scan: {len(compartment_ids)}")
        print(f"Checks enabled: {len(self.checks)}")
        print(f"Mode: {'DRY-RUN' if self.dry_run else 'LIVE'}")
        print(f"{'='*60}\n")

        # Create scan record
        scan_id = None
        if self.repository:
            scan_id = self.repository.create_scan()

        # Run checks
        all_findings: List[Finding] = []
        findings_by_check: Dict[str, List[Finding]] = {}

        for check in self.checks:
            check_findings = self._run_check(check, compartment_ids)
            all_findings.extend(check_findings)
            findings_by_check[check.check_id] = check_findings

        # Process findings
        new_findings = 0
        current_finding_keys: Set[Tuple[str, str]] = set()

        for finding in all_findings:
            finding.scan_id = scan_id
            current_finding_keys.add((finding.check_id, finding.resource_id))

            if self.repository:
                is_new = self.repository.upsert_finding(finding, scan_id)
                if is_new:
                    new_findings += 1
                    # Alert on new high/critical findings
                    if self.slack and finding.severity >= Severity.HIGH:
                        self.slack.send_finding(finding)

        # Resolve findings not seen in this scan
        resolved_findings = 0
        if self.repository:
            open_before = len(self.repository.get_open_findings())
            self.repository.resolve_missing_findings(scan_id, current_finding_keys)
            open_after = len(self.repository.get_open_findings())
            resolved_findings = open_before - open_after + new_findings - len(all_findings)
            if resolved_findings < 0:
                resolved_findings = 0

        # Calculate compliance score
        compliance_score = self._calculate_compliance_score(findings_by_check)
        if self.repository and scan_id:
            self.repository.save_compliance_score(
                scan_id=scan_id,
                framework="CIS",
                score=compliance_score["score"],
                total_checks=compliance_score["total_checks"],
                passed_checks=compliance_score["passed_checks"],
            )

        # Complete scan record
        elapsed = time.time() - start_time
        if self.repository and scan_id:
            self.repository.complete_scan(
                scan_id=scan_id,
                findings_count=len(all_findings),
                compartments_scanned=len(compartment_ids),
            )

        # Get findings count by severity
        findings_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for finding in all_findings:
            findings_count[finding.severity.value] += 1

        # Send scan summary
        if self.slack:
            self.slack.send_scan_summary(
                findings_count=findings_count,
                new_findings=new_findings,
                resolved_findings=resolved_findings,
                scan_duration=elapsed,
                compartments_scanned=len(compartment_ids),
            )

        # Print summary
        self._print_summary(
            all_findings,
            findings_count,
            new_findings,
            resolved_findings,
            elapsed,
            len(compartment_ids),
            compliance_score,
        )

        return {
            "scan_id": str(scan_id) if scan_id else None,
            "findings": [f.to_dict() for f in all_findings],
            "findings_count": findings_count,
            "total_findings": len(all_findings),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "compartments_scanned": len(compartment_ids),
            "duration_seconds": elapsed,
            "compliance_score": compliance_score,
        }

    def _run_check(
        self, check: BaseCheck, compartment_ids: List[str]
    ) -> List[Finding]:
        """Run a single check across all compartments."""
        findings = []
        print(f"  Running {check.check_id}: {check.title}...", end="", flush=True)

        for compartment_id in compartment_ids:
            try:
                check_findings = check.run(self.client, compartment_id)
                findings.extend(check_findings)
            except Exception as e:
                # Log but don't fail entire scan
                pass

        status = f" [{len(findings)} findings]" if findings else " [PASS]"
        print(status)
        return findings

    def _calculate_compliance_score(
        self, findings_by_check: Dict[str, List[Finding]]
    ) -> Dict:
        """Calculate CIS compliance score."""
        cis_checks = [c for c in self.checks if c.cis_benchmark]
        total_checks = len(cis_checks)
        passed_checks = sum(
            1 for c in cis_checks if not findings_by_check.get(c.check_id, [])
        )

        score = (passed_checks / total_checks * 100) if total_checks > 0 else 100

        return {
            "framework": "CIS",
            "score": round(score, 2),
            "total_checks": total_checks,
            "passed_checks": passed_checks,
        }

    def _print_summary(
        self,
        findings: List[Finding],
        findings_count: Dict[str, int],
        new_findings: int,
        resolved_findings: int,
        elapsed: float,
        compartments: int,
        compliance_score: Dict,
    ):
        """Print scan summary to console."""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.1f}s")
        print(f"Compartments scanned: {compartments}")
        print(f"\nFindings by Severity:")
        print(f"  CRITICAL: {findings_count['CRITICAL']}")
        print(f"  HIGH:     {findings_count['HIGH']}")
        print(f"  MEDIUM:   {findings_count['MEDIUM']}")
        print(f"  LOW:      {findings_count['LOW']}")
        print(f"  ─────────────")
        print(f"  TOTAL:    {len(findings)}")

        if not self.dry_run:
            print(f"\nChanges:")
            print(f"  New findings:      {new_findings}")
            print(f"  Resolved findings: {resolved_findings}")

        print(f"\nCIS Compliance Score: {compliance_score['score']:.1f}%")
        print(f"  ({compliance_score['passed_checks']}/{compliance_score['total_checks']} checks passed)")

        print(f"{'='*60}\n")

        # Print critical and high findings
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            print("CRITICAL/HIGH FINDINGS:")
            print("-" * 60)
            for f in critical_high[:10]:  # Show first 10
                print(f"[{f.severity.value}] {f.title}")
                print(f"  Resource: {f.resource_name or f.resource_id}")
                print(f"  {f.description}")
                print()
            if len(critical_high) > 10:
                print(f"  ... and {len(critical_high) - 10} more")
            print("-" * 60)


def run_scan(config: Config, dry_run: bool = False) -> Dict:
    """Convenience function to run a scan."""
    scanner = Scanner(config, dry_run=dry_run)
    return scanner.run()
