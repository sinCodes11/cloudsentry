"""IAM security checks for OCI Identity and Access Management."""

from datetime import datetime, timedelta, timezone
from typing import List
import re

from .base import BaseCheck, Finding, Severity


DANGEROUS_POLICY_PATTERNS = [
    r"allow\s+group\s+\S+\s+to\s+manage\s+all-resources\s+in\s+tenancy",
    r"allow\s+any-user\s+to",
    r"allow\s+group\s+\S+\s+to\s+manage\s+\S+\s+in\s+tenancy\s*$",  # No conditions
]


class MFADisabledCheck(BaseCheck):
    """Check for users without MFA enabled."""

    check_id = "IAM-001"
    title = "User Without MFA Enabled"
    severity = Severity.HIGH
    description = "IAM user does not have multi-factor authentication enabled, increasing account compromise risk."
    remediation = "Enable MFA for all IAM users, especially those with console access or administrative privileges."
    resource_type = "User"
    cis_benchmark = "CIS OCI 1.1.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        # IAM is tenancy-level, only run once
        if compartment_id != client.tenancy_id:
            return findings

        try:
            for user in client.list_users():
                # Check if user has MFA enabled
                if not user.is_mfa_activated:
                    # Skip service accounts (no console access)
                    if user.capabilities and not user.capabilities.can_use_console_password:
                        continue

                    findings.append(
                        self.create_finding(
                            resource_id=user.id,
                            compartment_id=compartment_id,
                            resource_name=user.name,
                            description=f"User '{user.name}' does not have MFA enabled.",
                        )
                    )
        except Exception:
            pass
        return findings


class OldAPIKeyCheck(BaseCheck):
    """Check for API keys older than 90 days."""

    check_id = "IAM-002"
    title = "API Key Older Than 90 Days"
    severity = Severity.MEDIUM
    description = "User has an API key that has not been rotated in over 90 days."
    remediation = "Rotate API keys regularly (at least every 90 days) and remove unused keys."
    resource_type = "APIKey"
    cis_benchmark = "CIS OCI 1.2.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        # IAM is tenancy-level, only run once
        if compartment_id != client.tenancy_id:
            return findings

        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        try:
            for user in client.list_users():
                try:
                    for key in client.list_api_keys(user.id):
                        if key.lifecycle_state != "ACTIVE":
                            continue

                        # Check key age
                        key_created = key.time_created
                        if key_created.tzinfo is None:
                            key_created = key_created.replace(tzinfo=timezone.utc)

                        if key_created < threshold:
                            age_days = (datetime.now(timezone.utc) - key_created).days
                            findings.append(
                                self.create_finding(
                                    resource_id=key.key_id,
                                    compartment_id=compartment_id,
                                    resource_name=f"{user.name} - {key.fingerprint[:16]}...",
                                    description=f"API key for user '{user.name}' is {age_days} days old.",
                                )
                            )
                except Exception:
                    pass
        except Exception:
            pass
        return findings


class PermissivePolicyCheck(BaseCheck):
    """Check for overly permissive IAM policies."""

    check_id = "IAM-003"
    title = "Overly Permissive IAM Policy"
    severity = Severity.HIGH
    description = "IAM policy grants overly broad permissions that may violate least privilege principle."
    remediation = "Review and restrict policy statements to only necessary permissions with appropriate conditions."
    resource_type = "Policy"
    cis_benchmark = "CIS OCI 1.3.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for policy in client.list_policies(compartment_id):
                for statement in policy.statements or []:
                    statement_lower = statement.lower()
                    for pattern in DANGEROUS_POLICY_PATTERNS:
                        if re.search(pattern, statement_lower):
                            findings.append(
                                self.create_finding(
                                    resource_id=policy.id,
                                    compartment_id=compartment_id,
                                    resource_name=policy.name,
                                    description=f"Policy '{policy.name}' contains permissive statement: {statement[:100]}...",
                                )
                            )
                            break
        except Exception:
            pass
        return findings


class InactiveUserCheck(BaseCheck):
    """Check for users who haven't logged in for 90+ days."""

    check_id = "IAM-004"
    title = "Inactive User Account"
    severity = Severity.MEDIUM
    description = "User account has been inactive for over 90 days, posing a potential security risk."
    remediation = "Review and disable or remove inactive user accounts to reduce attack surface."
    resource_type = "User"
    cis_benchmark = "CIS OCI 1.1.2"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        # IAM is tenancy-level, only run once
        if compartment_id != client.tenancy_id:
            return findings

        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        try:
            for user in client.list_users():
                # Skip service accounts
                if user.capabilities and not user.capabilities.can_use_console_password:
                    continue

                last_login = user.last_successful_login_time
                if last_login:
                    if last_login.tzinfo is None:
                        last_login = last_login.replace(tzinfo=timezone.utc)

                    if last_login < threshold:
                        days_inactive = (datetime.now(timezone.utc) - last_login).days
                        findings.append(
                            self.create_finding(
                                resource_id=user.id,
                                compartment_id=compartment_id,
                                resource_name=user.name,
                                description=f"User '{user.name}' has been inactive for {days_inactive} days.",
                            )
                        )
                elif user.time_created:
                    # User never logged in
                    created = user.time_created
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)

                    if created < threshold:
                        findings.append(
                            self.create_finding(
                                resource_id=user.id,
                                compartment_id=compartment_id,
                                resource_name=user.name,
                                description=f"User '{user.name}' has never logged in since account creation.",
                            )
                        )
        except Exception:
            pass
        return findings
