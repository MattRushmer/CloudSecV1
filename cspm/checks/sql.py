import ipaddress
from typing import Iterable

from azure.core.credentials import TokenCredential
from azure.mgmt.sql import SqlManagementClient

from ..findings import Finding, Severity
from ..utils import parse_resource_group
from .base import Check

# Flag a firewall rule as "allows all IPs" if it covers this many addresses
# or more, not just the exact 0.0.0.0-255.255.255.255 pair -- a range
# nudged by a few addresses (e.g. 0.0.0.1-255.255.255.255) is effectively
# just as open.
_IPV4_ADDRESS_SPACE = 2**32
_NEAR_ALL_IPS_THRESHOLD = _IPV4_ADDRESS_SPACE - 1024


class SqlServerOpenFirewallCheck(Check):
    check_id = "SQL-001"
    description = "SQL servers should not allow all IP addresses through the firewall"
    severity = Severity.CRITICAL

    def run(
        self, credential: TokenCredential, subscription_id: str
    ) -> Iterable[Finding]:
        client = SqlManagementClient(credential, subscription_id)
        for server in client.servers.list():
            resource_group = parse_resource_group(server.id)
            rules = client.firewall_rules.list_by_server(resource_group, server.name)
            violations = [rule for rule in rules if self._allows_all_ips(rule)]
            passed = not violations
            detail = ", ".join(rule.name for rule in violations)
            yield Finding(
                check_id=self.check_id,
                resource_id=server.id,
                resource_name=server.name,
                severity=self.severity,
                passed=passed,
                message=(
                    "No firewall rules allow all IP addresses"
                    if passed
                    else f"Firewall rule(s) allow all IPs: {detail}"
                ),
            )

    @staticmethod
    def _allows_all_ips(rule) -> bool:
        try:
            start = ipaddress.IPv4Address(rule.start_ip_address)
            end = ipaddress.IPv4Address(rule.end_ip_address)
        except (ValueError, TypeError):
            return False
        if end < start:
            return False
        span = int(end) - int(start) + 1
        return span >= _NEAR_ALL_IPS_THRESHOLD
