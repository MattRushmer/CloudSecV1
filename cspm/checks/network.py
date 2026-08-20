from azure.mgmt.network import NetworkManagementClient

from ..findings import Finding, Severity
from .base import Check

RISKY_PORTS = {"22", "3389"}
OPEN_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}


class NsgOpenManagementPortsCheck(Check):
    check_id = "NETWORK-001"
    description = "NSGs should not expose SSH/RDP to the internet"
    severity = Severity.CRITICAL

    def run(self, credential, subscription_id):
        client = NetworkManagementClient(credential, subscription_id)
        for nsg in client.network_security_groups.list_all():
            violations = [
                rule
                for rule in (nsg.security_rules or [])
                if self._is_open_management_rule(rule)
            ]
            passed = not violations
            detail = ", ".join(rule.name for rule in violations)
            yield Finding(
                check_id=self.check_id,
                resource_id=nsg.id,
                resource_name=nsg.name,
                severity=self.severity,
                passed=passed,
                message=(
                    "No open management port rules found"
                    if passed
                    else f"Open management port rule(s): {detail}"
                ),
            )

    @staticmethod
    def _is_open_management_rule(rule) -> bool:
        if rule.direction != "Inbound" or rule.access != "Allow":
            return False
        ports = {p.strip() for p in (rule.destination_port_range or "").split(",")}
        source = (rule.source_address_prefix or "").strip().lower()
        return bool(ports & RISKY_PORTS) and source in OPEN_SOURCES
