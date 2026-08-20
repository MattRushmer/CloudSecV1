from azure.mgmt.sql import SqlManagementClient

from ..findings import Finding, Severity
from ..utils import parse_resource_group
from .base import Check


class SqlServerOpenFirewallCheck(Check):
    check_id = "SQL-001"
    description = "SQL servers should not allow all IP addresses through the firewall"
    severity = Severity.CRITICAL

    def run(self, credential, subscription_id):
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
        return (
            rule.start_ip_address == "0.0.0.0"
            and rule.end_ip_address == "255.255.255.255"
        )
