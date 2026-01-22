"""Security checks for CloudSentry."""

from .base import BaseCheck, Finding, Severity
from .storage import (
    PublicBucketCheck,
    BucketVersioningCheck,
    BucketLifecycleCheck,
    BucketEncryptionCheck,
    BucketPARCheck,
)
from .network import (
    PermissiveSecurityListCheck,
    PermissiveNSGCheck,
    UnusedSecurityListCheck,
    LoadBalancerWAFCheck,
    VCNFlowLogsCheck,
)
from .compute import (
    PublicIPCheck,
    UnencryptedBootVolumeCheck,
    MonitoringDisabledCheck,
    LegacyShapeCheck,
)
from .iam import (
    MFADisabledCheck,
    OldAPIKeyCheck,
    PermissivePolicyCheck,
    InactiveUserCheck,
)
from .database import (
    AutonomousDBPrivateEndpointCheck,
    DBSystemPublicAccessCheck,
    DBUnencryptedConnectionCheck,
)

ALL_CHECKS = [
    # Storage checks
    PublicBucketCheck,
    BucketVersioningCheck,
    BucketLifecycleCheck,
    BucketEncryptionCheck,
    BucketPARCheck,
    # Network checks
    PermissiveSecurityListCheck,
    PermissiveNSGCheck,
    UnusedSecurityListCheck,
    LoadBalancerWAFCheck,
    VCNFlowLogsCheck,
    # Compute checks
    PublicIPCheck,
    UnencryptedBootVolumeCheck,
    MonitoringDisabledCheck,
    LegacyShapeCheck,
    # IAM checks
    MFADisabledCheck,
    OldAPIKeyCheck,
    PermissivePolicyCheck,
    InactiveUserCheck,
    # Database checks
    AutonomousDBPrivateEndpointCheck,
    DBSystemPublicAccessCheck,
    DBUnencryptedConnectionCheck,
]

__all__ = [
    "BaseCheck",
    "Finding",
    "Severity",
    "ALL_CHECKS",
]
