from azure.mgmt.network import NetworkManagementClient

from ..findings import Finding, Severity
from .base import Check

RISKY_PORTS = {22, 3389}
OPEN_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}


def _risky_ports_in_range(port_range: str) -> set:
    """Return the subset of RISKY_PORTS covered by a single Azure port-range string.

    Azure port ranges are one of: "*" (all ports), "22" (single port), or
    "20-30" (inclusive range) — any of these can cover a risky port without
    literally spelling it out.
    """
    port_range = (port_range or "").strip()
    if port_range == "*":
        return set(RISKY_PORTS)
    if "-" in port_range:
        start_str, _, end_str = port_range.partition("-")
        try:
            start, end = int(start_str), int(end_str)
        except ValueError:
            return set()
        return {port for port in RISKY_PORTS if start <= port <= end}
    try:
        port = int(port_range)
    except ValueError:
        return set()
    return {port} & RISKY_PORTS


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

        # Azure represents ports either as a single `destination_port_range`
        # or, for multi-value rules, as a `destination_port_ranges` list.
        # Either (or both) may be populated depending on how the rule was
        # created, so both must be checked.
        port_ranges = list(rule.destination_port_ranges or [])
        if rule.destination_port_range:
            port_ranges.append(rule.destination_port_range)
        risky_ports = set()
        for port_range in port_ranges:
            risky_ports |= _risky_ports_in_range(port_range)
        if not risky_ports:
            return False

        # Same singular-vs-plural split applies to the source address.
        sources = list(rule.source_address_prefixes or [])
        if rule.source_address_prefix:
            sources.append(rule.source_address_prefix)
        return any(source.strip().lower() in OPEN_SOURCES for source in sources)
