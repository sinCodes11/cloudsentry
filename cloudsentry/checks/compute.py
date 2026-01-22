"""Compute security checks for OCI instances and volumes."""

from typing import List

from .base import BaseCheck, Finding, Severity


LEGACY_SHAPES = [
    "VM.Standard1.",
    "VM.Standard2.",
    "BM.Standard1.",
    "BM.Standard2.",
    "VM.DenseIO1.",
    "BM.DenseIO1.",
]


class PublicIPCheck(BaseCheck):
    """Check for instances with public IPs that may be unintended."""

    check_id = "COMPUTE-001"
    title = "Instance With Public IP Address"
    severity = Severity.MEDIUM
    description = "Compute instance has a public IP address, potentially exposing it to internet threats."
    remediation = "Review if public IP is necessary. Use bastion hosts or OCI Bastion service for secure access."
    resource_type = "Instance"
    cis_benchmark = "CIS OCI 4.1.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for instance in client.list_instances(compartment_id):
                # Get VNIC attachments
                vnic_attachments = client.compute.list_vnic_attachments(
                    compartment_id=compartment_id,
                    instance_id=instance.id,
                ).data

                for attachment in vnic_attachments:
                    try:
                        vnic = client.network.get_vnic(vnic_id=attachment.vnic_id).data
                        if vnic.public_ip:
                            findings.append(
                                self.create_finding(
                                    resource_id=instance.id,
                                    compartment_id=compartment_id,
                                    resource_name=instance.display_name,
                                    description=f"Instance '{instance.display_name}' has public IP: {vnic.public_ip}",
                                )
                            )
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        return findings


class UnencryptedBootVolumeCheck(BaseCheck):
    """Check for boot volumes without customer-managed encryption."""

    check_id = "COMPUTE-002"
    title = "Boot Volume Using Default Encryption"
    severity = Severity.MEDIUM
    description = "Boot volume is not encrypted with a customer-managed key (CMK)."
    remediation = "Use OCI Vault to create a CMK and apply it to boot volumes for enhanced encryption control."
    resource_type = "BootVolume"
    cis_benchmark = "CIS OCI 4.2.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            # Get availability domains
            ads = client.get_availability_domains(compartment_id)
            for ad in ads:
                try:
                    for volume in client.list_boot_volumes(compartment_id, ad):
                        if not volume.kms_key_id:
                            findings.append(
                                self.create_finding(
                                    resource_id=volume.id,
                                    compartment_id=compartment_id,
                                    resource_name=volume.display_name,
                                    description=f"Boot volume '{volume.display_name}' is not using a customer-managed encryption key.",
                                )
                            )
                except Exception:
                    pass
        except Exception:
            pass
        return findings


class MonitoringDisabledCheck(BaseCheck):
    """Check for instances without monitoring agent enabled."""

    check_id = "COMPUTE-003"
    title = "Instance Monitoring Disabled"
    severity = Severity.LOW
    description = "Compute instance does not have the monitoring agent enabled, limiting observability."
    remediation = "Enable the OCI Monitoring agent on instances for performance metrics and alerts."
    resource_type = "Instance"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for instance in client.list_instances(compartment_id):
                agent_config = instance.agent_config
                if agent_config:
                    if not agent_config.is_monitoring_disabled:
                        continue  # Monitoring is enabled
                # If no agent_config or monitoring is disabled
                findings.append(
                    self.create_finding(
                        resource_id=instance.id,
                        compartment_id=compartment_id,
                        resource_name=instance.display_name,
                        description=f"Instance '{instance.display_name}' may not have monitoring agent enabled.",
                    )
                )
        except Exception:
            pass
        return findings


class LegacyShapeCheck(BaseCheck):
    """Check for instances using legacy/deprecated shapes."""

    check_id = "COMPUTE-004"
    title = "Instance Using Legacy Shape"
    severity = Severity.LOW
    description = "Compute instance is using a legacy shape that may have reduced performance or support."
    remediation = "Migrate to current generation shapes (VM.Standard.E4, VM.Standard3, VM.Standard.A1) for better performance."
    resource_type = "Instance"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for instance in client.list_instances(compartment_id):
                shape = instance.shape or ""
                is_legacy = any(shape.startswith(prefix) for prefix in LEGACY_SHAPES)
                if is_legacy:
                    findings.append(
                        self.create_finding(
                            resource_id=instance.id,
                            compartment_id=compartment_id,
                            resource_name=instance.display_name,
                            description=f"Instance '{instance.display_name}' uses legacy shape: {shape}",
                        )
                    )
        except Exception:
            pass
        return findings
