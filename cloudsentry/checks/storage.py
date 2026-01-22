"""Storage security checks for OCI Object Storage."""

from typing import List

from .base import BaseCheck, Finding, Severity


class PublicBucketCheck(BaseCheck):
    """Check for publicly accessible Object Storage buckets."""

    check_id = "STORAGE-001"
    title = "Public Object Storage Bucket Detected"
    severity = Severity.CRITICAL
    description = "Object Storage bucket is publicly accessible, potentially exposing sensitive data."
    remediation = "Set bucket access type to 'NoPublicAccess' and use IAM policies for authorized access."
    resource_type = "ObjectStorageBucket"
    cis_benchmark = "CIS OCI 2.1.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for bucket in client.list_buckets(compartment_id):
                if bucket.public_access_type != "NoPublicAccess":
                    findings.append(
                        self.create_finding(
                            resource_id=bucket.name,
                            compartment_id=compartment_id,
                            resource_name=bucket.name,
                            description=f"Bucket '{bucket.name}' has public access type: {bucket.public_access_type}",
                        )
                    )
        except Exception as e:
            pass  # Handle permissions or API errors gracefully
        return findings


class BucketVersioningCheck(BaseCheck):
    """Check for buckets without versioning enabled."""

    check_id = "STORAGE-002"
    title = "Bucket Versioning Disabled"
    severity = Severity.MEDIUM
    description = "Object Storage bucket does not have versioning enabled, risking data loss from accidental deletions."
    remediation = "Enable object versioning on the bucket to protect against accidental deletion or modification."
    resource_type = "ObjectStorageBucket"
    cis_benchmark = "CIS OCI 2.1.2"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for bucket in client.list_buckets(compartment_id):
                if bucket.versioning != "Enabled":
                    findings.append(
                        self.create_finding(
                            resource_id=bucket.name,
                            compartment_id=compartment_id,
                            resource_name=bucket.name,
                            description=f"Bucket '{bucket.name}' does not have versioning enabled.",
                        )
                    )
        except Exception:
            pass
        return findings


class BucketLifecycleCheck(BaseCheck):
    """Check for buckets without lifecycle policies."""

    check_id = "STORAGE-003"
    title = "Bucket Missing Lifecycle Policy"
    severity = Severity.LOW
    description = "Object Storage bucket does not have a lifecycle policy, potentially leading to storage cost issues."
    remediation = "Configure a lifecycle policy to manage object retention and optimize storage costs."
    resource_type = "ObjectStorageBucket"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            namespace = client.object_storage.get_namespace().data
            for bucket in client.list_buckets(compartment_id):
                try:
                    rules = client.object_storage.list_object_lifecycle_policies(
                        namespace_name=namespace,
                        bucket_name=bucket.name,
                    ).data
                    if not rules.items:
                        findings.append(
                            self.create_finding(
                                resource_id=bucket.name,
                                compartment_id=compartment_id,
                                resource_name=bucket.name,
                                description=f"Bucket '{bucket.name}' has no lifecycle policies configured.",
                            )
                        )
                except Exception:
                    pass
        except Exception:
            pass
        return findings


class BucketEncryptionCheck(BaseCheck):
    """Check for buckets without customer-managed encryption keys."""

    check_id = "STORAGE-004"
    title = "Bucket Using Default Encryption"
    severity = Severity.MEDIUM
    description = "Object Storage bucket is using Oracle-managed encryption keys instead of customer-managed keys (CMK)."
    remediation = "Configure the bucket to use a customer-managed key from OCI Vault for enhanced control."
    resource_type = "ObjectStorageBucket"
    cis_benchmark = "CIS OCI 2.1.3"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for bucket in client.list_buckets(compartment_id):
                if not bucket.kms_key_id:
                    findings.append(
                        self.create_finding(
                            resource_id=bucket.name,
                            compartment_id=compartment_id,
                            resource_name=bucket.name,
                            description=f"Bucket '{bucket.name}' is not using a customer-managed encryption key.",
                        )
                    )
        except Exception:
            pass
        return findings


class BucketPARCheck(BaseCheck):
    """Check for buckets with overly permissive Pre-Authenticated Requests."""

    check_id = "STORAGE-005"
    title = "Overly Permissive Pre-Authenticated Request"
    severity = Severity.HIGH
    description = "Object Storage bucket has a Pre-Authenticated Request (PAR) with broad access permissions."
    remediation = "Review and restrict PAR permissions. Use time-limited PARs and avoid bucket-level write access."
    resource_type = "ObjectStorageBucket"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            namespace = client.object_storage.get_namespace().data
            for bucket in client.list_buckets(compartment_id):
                try:
                    pars = client.object_storage.list_preauthenticated_requests(
                        namespace_name=namespace,
                        bucket_name=bucket.name,
                    ).data
                    for par in pars:
                        # Flag PARs with write access at bucket level
                        if par.access_type in ["AnyObjectWrite", "AnyObjectReadWrite"]:
                            findings.append(
                                self.create_finding(
                                    resource_id=f"{bucket.name}/{par.id}",
                                    compartment_id=compartment_id,
                                    resource_name=f"{bucket.name} PAR: {par.name}",
                                    description=f"PAR '{par.name}' on bucket '{bucket.name}' has write access: {par.access_type}",
                                )
                            )
                except Exception:
                    pass
        except Exception:
            pass
        return findings
