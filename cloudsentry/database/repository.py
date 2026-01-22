"""Database repository for CloudSentry."""

from datetime import datetime
from typing import List, Optional
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import insert

from .models import Base, Finding, Scan, ComplianceScore
from ..checks.base import Finding as FindingDTO, Severity


class Repository:
    """Database repository for managing findings and scans."""

    def __init__(self, connection_string: str):
        self.engine = create_engine(connection_string)
        self.Session = sessionmaker(bind=self.engine)

    def init_db(self):
        """Create all tables."""
        Base.metadata.create_all(self.engine)

    def create_scan(self) -> uuid.UUID:
        """Create a new scan record."""
        with self.Session() as session:
            scan = Scan()
            session.add(scan)
            session.commit()
            return scan.id

    def complete_scan(
        self,
        scan_id: uuid.UUID,
        findings_count: int,
        compartments_scanned: int,
        status: str = "COMPLETED",
    ):
        """Mark a scan as completed."""
        with self.Session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.completed_at = datetime.utcnow()
                scan.status = status
                scan.findings_count = findings_count
                scan.compartments_scanned = compartments_scanned
                session.commit()

    def upsert_finding(self, finding: FindingDTO, scan_id: uuid.UUID) -> bool:
        """Insert or update a finding. Returns True if new finding."""
        with self.Session() as session:
            # Check if finding exists
            existing = (
                session.query(Finding)
                .filter(
                    Finding.check_id == finding.check_id,
                    Finding.resource_id == finding.resource_id,
                )
                .first()
            )

            if existing:
                # Update existing finding
                existing.last_seen = datetime.utcnow()
                existing.scan_id = scan_id
                existing.description = finding.description
                existing.severity = finding.severity.value
                if existing.status == "RESOLVED":
                    existing.status = "OPEN"  # Re-opened
                    existing.resolved_at = None
                session.commit()
                return False
            else:
                # Create new finding
                db_finding = Finding(
                    check_id=finding.check_id,
                    resource_id=finding.resource_id,
                    resource_type=finding.resource_type,
                    resource_name=finding.resource_name,
                    compartment_id=finding.compartment_id,
                    severity=finding.severity.value,
                    title=finding.title,
                    description=finding.description,
                    remediation=finding.remediation,
                    scan_id=scan_id,
                )
                session.add(db_finding)
                session.commit()
                return True

    def resolve_missing_findings(
        self, scan_id: uuid.UUID, current_finding_keys: set
    ):
        """Mark findings not seen in current scan as resolved."""
        with self.Session() as session:
            open_findings = (
                session.query(Finding)
                .filter(Finding.status == "OPEN")
                .all()
            )
            for finding in open_findings:
                key = (finding.check_id, finding.resource_id)
                if key not in current_finding_keys:
                    finding.status = "RESOLVED"
                    finding.resolved_at = datetime.utcnow()
            session.commit()

    def get_open_findings(self, severity: Optional[str] = None) -> List[Finding]:
        """Get all open findings, optionally filtered by severity."""
        with self.Session() as session:
            query = session.query(Finding).filter(Finding.status == "OPEN")
            if severity:
                query = query.filter(Finding.severity == severity)
            return query.order_by(Finding.severity.desc()).all()

    def get_findings_by_scan(self, scan_id: uuid.UUID) -> List[Finding]:
        """Get all findings for a specific scan."""
        with self.Session() as session:
            return (
                session.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .all()
            )

    def get_finding_counts_by_severity(self) -> dict:
        """Get count of open findings by severity."""
        with self.Session() as session:
            from sqlalchemy import func

            results = (
                session.query(Finding.severity, func.count(Finding.id))
                .filter(Finding.status == "OPEN")
                .group_by(Finding.severity)
                .all()
            )
            return {severity: count for severity, count in results}

    def save_compliance_score(
        self,
        scan_id: uuid.UUID,
        framework: str,
        score: float,
        total_checks: int,
        passed_checks: int,
    ):
        """Save compliance score for a scan."""
        with self.Session() as session:
            compliance = ComplianceScore(
                scan_id=scan_id,
                framework=framework,
                score=score,
                total_checks=total_checks,
                passed_checks=passed_checks,
            )
            session.add(compliance)
            session.commit()

    def get_latest_compliance_score(self, framework: str = "CIS") -> Optional[dict]:
        """Get the most recent compliance score."""
        with self.Session() as session:
            result = (
                session.query(ComplianceScore)
                .filter(ComplianceScore.framework == framework)
                .order_by(ComplianceScore.created_at.desc())
                .first()
            )
            if result:
                return {
                    "framework": result.framework,
                    "score": float(result.score),
                    "total_checks": result.total_checks,
                    "passed_checks": result.passed_checks,
                    "created_at": result.created_at.isoformat(),
                }
            return None

    def suppress_finding(self, check_id: str, resource_id: str) -> bool:
        """Suppress a finding."""
        with self.Session() as session:
            finding = (
                session.query(Finding)
                .filter(
                    Finding.check_id == check_id,
                    Finding.resource_id == resource_id,
                )
                .first()
            )
            if finding:
                finding.status = "SUPPRESSED"
                session.commit()
                return True
            return False
