"""SQLAlchemy models for CloudSentry."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    DateTime,
    ForeignKey,
    Numeric,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Scan(Base):
    """Represents a security scan run."""

    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="RUNNING")  # RUNNING, COMPLETED, FAILED
    findings_count = Column(Integer, default=0)
    compartments_scanned = Column(Integer, default=0)

    findings = relationship("Finding", back_populates="scan")
    compliance_scores = relationship("ComplianceScore", back_populates="scan")

    def __repr__(self):
        return f"<Scan {self.id} status={self.status}>"


class Finding(Base):
    """Represents a security finding."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    check_id = Column(String(50), nullable=False)
    resource_id = Column(String(255), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_name = Column(String(255), nullable=True)
    compartment_id = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(20), default="OPEN")  # OPEN, RESOLVED, SUPPRESSED
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("check_id", "resource_id", name="uq_check_resource"),
    )

    def __repr__(self):
        return f"<Finding {self.check_id} resource={self.resource_id[:30]}...>"


class ComplianceScore(Base):
    """Represents compliance score for a scan."""

    __tablename__ = "compliance_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"))
    framework = Column(String(50), nullable=False)  # CIS, CUSTOM
    score = Column(Numeric(5, 2), nullable=False)
    total_checks = Column(Integer, nullable=False)
    passed_checks = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="compliance_scores")

    def __repr__(self):
        return f"<ComplianceScore {self.framework} score={self.score}>"
