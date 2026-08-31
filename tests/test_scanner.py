from unittest.mock import MagicMock, patch

from cspm.findings import Finding, Severity
from cspm.scanner import run_scan


def _ok_finding():
    return Finding(
        check_id="STORAGE-001",
        resource_id="/subscriptions/x/account1",
        resource_name="account1",
        severity=Severity.HIGH,
        passed=True,
        message="ok",
    )


def test_a_failing_check_does_not_swallow_findings_from_other_checks():
    ok_check = MagicMock()
    ok_check.check_id = "STORAGE-001"
    ok_check.run.return_value = [_ok_finding()]

    broken_check = MagicMock()
    broken_check.check_id = "NETWORK-001"
    broken_check.run.side_effect = RuntimeError("permission denied")

    with patch("cspm.scanner.ALL_CHECKS", [ok_check, broken_check]):
        findings, errors = run_scan(credential=MagicMock(), subscription_id="sub-id")

    assert findings == [_ok_finding()]
    assert len(errors) == 1
    assert errors[0].check_id == "NETWORK-001"
    assert "permission denied" in errors[0].message


def test_all_checks_erroring_reports_errors_not_a_silent_clean_scan():
    broken_check = MagicMock()
    broken_check.check_id = "SQL-001"
    broken_check.run.side_effect = RuntimeError("auth failed")

    with patch("cspm.scanner.ALL_CHECKS", [broken_check]):
        findings, errors = run_scan(credential=MagicMock(), subscription_id="sub-id")

    assert findings == []
    assert len(errors) == 1
