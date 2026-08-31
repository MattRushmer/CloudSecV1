from unittest.mock import MagicMock, patch

from cspm.checks.network import NsgOpenManagementPortsCheck


def _rule(
    name="rule1",
    direction="Inbound",
    access="Allow",
    destination_port_range=None,
    destination_port_ranges=None,
    source_address_prefix=None,
    source_address_prefixes=None,
):
    rule = MagicMock(
        direction=direction,
        access=access,
        destination_port_range=destination_port_range,
        destination_port_ranges=destination_port_ranges,
        source_address_prefix=source_address_prefix,
        source_address_prefixes=source_address_prefixes,
    )
    rule.name = name
    return rule


def _run_check(rules):
    nsg = MagicMock(id="/subscriptions/x/nsg1", security_rules=rules)
    nsg.name = "nsg1"
    with patch("cspm.checks.network.NetworkManagementClient") as mock_client_cls:
        mock_client_cls.return_value.network_security_groups.list_all.return_value = [
            nsg
        ]
        check = NsgOpenManagementPortsCheck()
        return list(check.run(credential=MagicMock(), subscription_id="sub-id"))


def test_flags_exact_ssh_port_open_to_internet():
    rule = _rule(destination_port_range="22", source_address_prefix="0.0.0.0/0")
    findings = _run_check([rule])
    assert len(findings) == 1
    assert findings[0].passed is False


def test_flags_port_range_that_contains_rdp():
    rule = _rule(destination_port_range="3300-3400", source_address_prefix="*")
    findings = _run_check([rule])
    assert findings[0].passed is False


def test_flags_wildcard_all_ports():
    rule = _rule(destination_port_range="*", source_address_prefix="Internet")
    findings = _run_check([rule])
    assert findings[0].passed is False


def test_flags_multi_value_port_and_source_lists():
    rule = _rule(
        destination_port_ranges=["80", "22", "443"],
        source_address_prefixes=["10.0.0.0/8", "Any"],
    )
    findings = _run_check([rule])
    assert findings[0].passed is False


def test_passes_when_source_is_restricted():
    rule = _rule(destination_port_range="22", source_address_prefix="10.0.0.0/24")
    findings = _run_check([rule])
    assert findings[0].passed is True


def test_passes_when_no_risky_port_open():
    rule = _rule(destination_port_range="80", source_address_prefix="*")
    findings = _run_check([rule])
    assert findings[0].passed is True


def test_ignores_outbound_and_deny_rules():
    rules = [
        _rule(
            direction="Outbound",
            destination_port_range="22",
            source_address_prefix="*",
        ),
        _rule(access="Deny", destination_port_range="22", source_address_prefix="*"),
    ]
    findings = _run_check(rules)
    assert findings[0].passed is True
