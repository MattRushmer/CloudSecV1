from unittest.mock import MagicMock, patch

from cspm.checks.storage import StorageHttpsOnlyCheck


@patch("cspm.checks.storage.StorageManagementClient")
def test_flags_account_without_https_only(mock_client_cls):
    account = MagicMock(
        id="/subscriptions/x/account1",
        name="account1",
        enable_https_traffic_only=False,
    )
    mock_client_cls.return_value.storage_accounts.list.return_value = [account]

    check = StorageHttpsOnlyCheck()
    findings = list(check.run(credential=MagicMock(), subscription_id="sub-id"))

    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].check_id == "STORAGE-001"


@patch("cspm.checks.storage.StorageManagementClient")
def test_passes_account_with_https_only(mock_client_cls):
    account = MagicMock(
        id="/subscriptions/x/account2",
        name="account2",
        enable_https_traffic_only=True,
    )
    mock_client_cls.return_value.storage_accounts.list.return_value = [account]

    check = StorageHttpsOnlyCheck()
    findings = list(check.run(credential=MagicMock(), subscription_id="sub-id"))

    assert len(findings) == 1
    assert findings[0].passed is True
