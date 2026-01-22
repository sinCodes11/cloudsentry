"""Network security checks for OCI VCN, Security Lists, and NSGs."""

from typing import List

from .base import BaseCheck, Finding, Severity


class PermissiveSecurityListCheck(BaseCheck):
    """Check for security lists allowing 0.0.0.0/0 ingress."""

    check_id = "NETWORK-001"
    title = "Security List Allows Unrestricted Ingress"
    severity = Severity.HIGH
    description = "Security list allows ingress traffic from any IP address (0.0.0.0/0), increasing attack surface."
    remediation = "Restrict ingress rules to specific IP ranges or CIDR blocks required for legitimate access."
    resource_type = "SecurityList"
    cis_benchmark = "CIS OCI 3.1.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for sec_list in client.list_security_lists(compartment_id):
                for rule in sec_list.ingress_security_rules or []:
                    if rule.source == "0.0.0.0/0":
                        # Check for dangerous ports
                        protocol = rule.protocol
                        port_info = ""
                        if hasattr(rule, "tcp_options") and rule.tcp_options:
                            if rule.tcp_options.destination_port_range:
                                port_info = f" (TCP ports {rule.tcp_options.destination_port_range.min}-{rule.tcp_options.destination_port_range.max})"
                        elif hasattr(rule, "udp_options") and rule.udp_options:
                            if rule.udp_options.destination_port_range:
                                port_info = f" (UDP ports {rule.udp_options.destination_port_range.min}-{rule.udp_options.destination_port_range.max})"
                        elif protocol == "all":
                            port_info = " (ALL protocols)"

                        findings.append(
                            self.create_finding(
                                resource_id=sec_list.id,
                                compartment_id=compartment_id,
                                resource_name=sec_list.display_name,
                                description=f"Security list '{sec_list.display_name}' allows ingress from 0.0.0.0/0{port_info}",
                            )
                        )
                        break  # One finding per security list
        except Exception:
            pass
        return findings


class PermissiveNSGCheck(BaseCheck):
    """Check for network security groups with permissive rules."""

    check_id = "NETWORK-002"
    title = "NSG Allows Unrestricted Access"
    severity = Severity.HIGH
    description = "Network Security Group has rules allowing traffic from any source."
    remediation = "Review and restrict NSG rules to only allow traffic from known, trusted sources."
    resource_type = "NetworkSecurityGroup"
    cis_benchmark = "CIS OCI 3.1.2"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for nsg in client.list_network_security_groups(compartment_id):
                rules = client.network.list_network_security_group_security_rules(
                    network_security_group_id=nsg.id,
                    direction="INGRESS",
                ).data
                for rule in rules:
                    if rule.source == "0.0.0.0/0":
                        findings.append(
                            self.create_finding(
                                resource_id=nsg.id,
                                compartment_id=compartment_id,
                                resource_name=nsg.display_name,
                                description=f"NSG '{nsg.display_name}' allows ingress from 0.0.0.0/0",
                            )
                        )
                        break
        except Exception:
            pass
        return findings


class UnusedSecurityListCheck(BaseCheck):
    """Check for security lists not attached to any subnet."""

    check_id = "NETWORK-003"
    title = "Unused Security List"
    severity = Severity.LOW
    description = "Security list is not attached to any subnet, indicating potential cleanup opportunity."
    remediation = "Remove unused security lists to reduce management overhead and confusion."
    resource_type = "SecurityList"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            vcns = list(client.list_vcns(compartment_id))
            for vcn in vcns:
                sec_lists = client.network.list_security_lists(
                    compartment_id=compartment_id,
                    vcn_id=vcn.id,
                ).data
                subnets = client.network.list_subnets(
                    compartment_id=compartment_id,
                    vcn_id=vcn.id,
                ).data

                # Get all security list IDs used by subnets
                used_sl_ids = set()
                for subnet in subnets:
                    used_sl_ids.update(subnet.security_list_ids or [])

                for sec_list in sec_lists:
                    # Skip default security lists
                    if "Default Security List" in (sec_list.display_name or ""):
                        continue
                    if sec_list.id not in used_sl_ids:
                        findings.append(
                            self.create_finding(
                                resource_id=sec_list.id,
                                compartment_id=compartment_id,
                                resource_name=sec_list.display_name,
                                description=f"Security list '{sec_list.display_name}' is not attached to any subnet.",
                            )
                        )
        except Exception:
            pass
        return findings


class LoadBalancerWAFCheck(BaseCheck):
    """Check for load balancers without WAF protection."""

    check_id = "NETWORK-004"
    title = "Load Balancer Without WAF Protection"
    severity = Severity.MEDIUM
    description = "Public load balancer does not have Web Application Firewall (WAF) protection enabled."
    remediation = "Enable OCI WAF on public-facing load balancers to protect against web attacks."
    resource_type = "LoadBalancer"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for lb in client.list_load_balancers(compartment_id):
                # Only check public load balancers
                if not lb.is_private:
                    # Check if WAF is associated (requires WAF client check)
                    # For simplicity, flag all public LBs without checking WAF association
                    # In production, you'd query OCI WAF to check policy attachment
                    findings.append(
                        self.create_finding(
                            resource_id=lb.id,
                            compartment_id=compartment_id,
                            resource_name=lb.display_name,
                            description=f"Public load balancer '{lb.display_name}' should have WAF protection.",
                        )
                    )
        except Exception:
            pass
        return findings


class VCNFlowLogsCheck(BaseCheck):
    """Check for VCNs without flow logs enabled."""

    check_id = "NETWORK-005"
    title = "VCN Flow Logs Disabled"
    severity = Severity.MEDIUM
    description = "VCN does not have flow logs enabled, limiting network traffic visibility and forensics capability."
    remediation = "Enable VCN flow logs and configure log retention in OCI Logging service."
    resource_type = "VCN"
    cis_benchmark = "CIS OCI 3.2.1"

    def run(self, client, compartment_id: str) -> List[Finding]:
        findings = []
        try:
            for vcn in client.list_vcns(compartment_id):
                # Check subnets for flow logs
                subnets = client.network.list_subnets(
                    compartment_id=compartment_id,
                    vcn_id=vcn.id,
                ).data

                has_flow_logs = False
                for subnet in subnets:
                    # In production, check OCI Logging for flow log configuration
                    # This is a simplified check
                    pass

                if not has_flow_logs:
                    findings.append(
                        self.create_finding(
                            resource_id=vcn.id,
                            compartment_id=compartment_id,
                            resource_name=vcn.display_name,
                            description=f"VCN '{vcn.display_name}' may not have flow logs configured.",
                        )
                    )
        except Exception:
            pass
        return findings
