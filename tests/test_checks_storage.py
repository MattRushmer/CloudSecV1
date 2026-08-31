from unittest.mock import MagicMock, patch

from cspm.checks.storage import StorageHttpsOnlyCheck, StoragePublicBlobAccessCheck


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


@patch("cspm.checks.storage.StorageManagementClient")
def test_flags_account_with_public_blob_access_allowed(mock_client_cls):
    account = MagicMock(
        id="/subscriptions/x/account3",
        name="account3",
        allow_blob_public_access=True,
    )
    mock_client_cls.return_value.storage_accounts.list.return_value = [account]

    check = StoragePublicBlobAccessCheck()
    findings = list(check.run(credential=MagicMock(), subscription_id="sub-id"))

    assert len(findings) == 1
    assert findings[0].passed is False
    assert findings[0].check_id == "STORAGE-002"


@patch("cspm.checks.storage.StorageManagementClient")
def test_passes_account_with_public_blob_access_disabled(mock_client_cls):
    account = MagicMock(
        id="/subscriptions/x/account4",
        name="account4",
        allow_blob_public_access=False,
    )
    mock_client_cls.return_value.storage_accounts.list.return_value = [account]

    check = StoragePublicBlobAccessCheck()
    findings = list(check.run(credential=MagicMock(), subscription_id="sub-id"))

    assert len(findings) == 1
    assert findings[0].passed is True


@patch("cspm.checks.storage.StorageManagementClient")
def test_passes_account_where_public_blob_access_is_unset(mock_client_cls):
    # Azure defaults allow_blob_public_access to false when unset (None).
    account = MagicMock(
        id="/subscriptions/x/account5",
        name="account5",
        allow_blob_public_access=None,
    )
    mock_client_cls.return_value.storage_accounts.list.return_value = [account]

    check = StoragePublicBlobAccessCheck()
    findings = list(check.run(credential=MagicMock(), subscription_id="sub-id"))

    assert len(findings) == 1
    assert findings[0].passed is True
