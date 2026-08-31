from unittest.mock import MagicMock, patch

from cspm.checks.keyvault import KeyVaultSoftDeleteCheck


def _run_check(enable_soft_delete):
    vault = MagicMock(id="/subscriptions/x/vault1", properties=MagicMock())
    vault.name = "vault1"
    vault.properties.enable_soft_delete = enable_soft_delete
    with patch("cspm.checks.keyvault.KeyVaultManagementClient") as mock_client_cls:
        mock_client_cls.return_value.vaults.list_by_subscription.return_value = [
            vault
        ]
        check = KeyVaultSoftDeleteCheck()
        return list(check.run(credential=MagicMock(), subscription_id="sub-id"))


def test_flags_vault_with_soft_delete_explicitly_disabled():
    findings = _run_check(enable_soft_delete=False)
    assert findings[0].passed is False


def test_passes_vault_with_soft_delete_explicitly_enabled():
    findings = _run_check(enable_soft_delete=True)
    assert findings[0].passed is True


def test_passes_vault_where_soft_delete_is_unset():
    # Azure treats an unset (None) enable_soft_delete as enabled-by-default.
    findings = _run_check(enable_soft_delete=None)
    assert findings[0].passed is True
