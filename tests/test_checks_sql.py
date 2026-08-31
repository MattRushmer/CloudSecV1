from unittest.mock import MagicMock, patch

from cspm.checks.sql import SqlServerOpenFirewallCheck


def _run_check(start_ip, end_ip):
    server = MagicMock(id="/subscriptions/x/resourceGroups/rg1/servers/sql1")
    server.name = "sql1"
    rule = MagicMock(start_ip_address=start_ip, end_ip_address=end_ip)
    rule.name = "rule1"

    with patch("cspm.checks.sql.SqlManagementClient") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.servers.list.return_value = [server]
        mock_client.firewall_rules.list_by_server.return_value = [rule]
        check = SqlServerOpenFirewallCheck()
        return list(check.run(credential=MagicMock(), subscription_id="sub-id"))


def test_flags_exact_allow_all_ips_rule():
    findings = _run_check("0.0.0.0", "255.255.255.255")
    assert findings[0].passed is False


def test_flags_near_total_range():
    # One address short of the full range at each end -- effectively "all IPs".
    findings = _run_check("0.0.0.1", "255.255.255.254")
    assert findings[0].passed is False


def test_passes_narrow_range():
    findings = _run_check("203.0.113.1", "203.0.113.10")
    assert findings[0].passed is True
