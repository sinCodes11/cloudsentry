"""Base check class and common types for CloudSentry."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional
import uuid


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        return cls[value.upper()]

    def __lt__(self, other):
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """Represents a security finding."""

    check_id: str
    resource_id: str
    resource_type: str
    severity: Severity
    title: str
    description: str
    remediation: str
    compartment_id: Optional[str] = None
    status: str = "OPEN"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    scan_id: Optional[uuid.UUID] = None
    resource_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "compartment_id": self.compartment_id,
            "status": self.status,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "scan_id": str(self.scan_id) if self.scan_id else None,
            "resource_name": self.resource_name,
        }


class BaseCheck(ABC):
    """Base class for all security checks."""

    check_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    resource_type: str = ""

    # CIS benchmark mapping (if applicable)
    cis_benchmark: Optional[str] = None

    @abstractmethod
    def run(self, client, compartment_id: str) -> List[Finding]:
        """Execute the security check and return findings.

        Args:
            client: OCIClient instance
            compartment_id: Compartment OCID to scan

        Returns:
            List of Finding objects for resources that fail the check
        """
        pass

    def create_finding(
        self,
        resource_id: str,
        compartment_id: str,
        resource_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Finding:
        """Create a finding with check defaults."""
        return Finding(
            check_id=self.check_id,
            resource_id=resource_id,
            resource_type=self.resource_type,
            severity=self.severity,
            title=self.title,
            description=description or self.description,
            remediation=self.remediation,
            compartment_id=compartment_id,
            resource_name=resource_name,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} check_id={self.check_id}>"
