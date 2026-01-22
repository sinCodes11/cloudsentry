"""Database security checks for OCI databases."""

from typing import List

from .base import BaseCheck, Finding, Severity


class AutonomousDBPrivateEndpointCheck(BaseCheck):
    """Check for Autonomous Databases without private endpoint."""

    check_id = "DATABASE-001"
    title = "Autonomous DB Without Private Endpoint"
    severity = Severity.HIGH
    description = "Autonomous Database is accessible from the public internet instead of using a private endpoint."
    remediation = "Configure the Autonomous Database to use a private endpoint within your VCN."
    resource_type = "AutonomousDatabase"
    cis_benchmark = "CIS OCI 5.1.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for db in client.list_autonomous_databases(compartment_id):
                if db.lifecycle_state not in ("AVAILABLE", "STOPPED"):
                    continue

                # Check if using private endpoint
                if not db.private_endpoint:
                    findings.append(
                        self.create_finding(
                            resource_id=db.id,
                            compartment_id=compartment_id,
                            resource_name=db.display_name,
                            description=f"Autonomous Database '{db.display_name}' does not use a private endpoint.",
                        )
                    )
        except Exception:
            pass
        return findings


class DBSystemPublicAccessCheck(BaseCheck):
    """Check for DB Systems that are publicly accessible."""

    check_id = "DATABASE-002"
    title = "DB System Publicly Accessible"
    severity = Severity.HIGH
    description = "Database system is configured on a public subnet, potentially exposing it to the internet."
    remediation = "Deploy DB systems on private subnets and use bastion hosts or VPN for access."
    resource_type = "DBSystem"
    cis_benchmark = "CIS OCI 5.1.2"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for db_system in client.list_db_systems(compartment_id):
                if db_system.lifecycle_state not in ("AVAILABLE", "PROVISIONING"):
                    continue

                # Check subnet configuration
                subnet_id = db_system.subnet_id
                if subnet_id:
                    try:
                        subnet = client.network.get_subnet(subnet_id=subnet_id).data
                        # If subnet prohibits public IPs, it's private
                        if not subnet.prohibit_public_ip_on_vnic:
                            findings.append(
                                self.create_finding(
                                    resource_id=db_system.id,
                                    compartment_id=compartment_id,
                                    resource_name=db_system.display_name,
                                    description=f"DB System '{db_system.display_name}' is on a public subnet.",
                                )
                            )
                    except Exception:
                        pass
        except Exception:
            pass
        return findings


class DBUnencryptedConnectionCheck(BaseCheck):
    """Check for databases allowing unencrypted connections."""

    check_id = "DATABASE-003"
    title = "Database Allows Unencrypted Connections"
    severity = Severity.MEDIUM
    description = "Database may allow unencrypted connections, potentially exposing data in transit."
    remediation = "Configure the database to require TLS/SSL for all connections."
    resource_type = "AutonomousDatabase"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for db in client.list_autonomous_databases(compartment_id):
                if db.lifecycle_state not in ("AVAILABLE", "STOPPED"):
                    continue

                # Check mTLS requirement
                # is_mtls_connection_required is True for secure config
                if hasattr(db, "is_mtls_connection_required"):
                    if not db.is_mtls_connection_required:
                        findings.append(
                            self.create_finding(
                                resource_id=db.id,
                                compartment_id=compartment_id,
                                resource_name=db.display_name,
                                description=f"Autonomous Database '{db.display_name}' does not require mTLS connections.",
                            )
                        )
        except Exception:
            pass
        return findings
