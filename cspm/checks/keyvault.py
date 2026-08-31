from typing import Iterable

from azure.core.credentials import TokenCredential
from azure.mgmt.keyvault import KeyVaultManagementClient

from ..findings import Finding, Severity
from .base import Check


class KeyVaultSoftDeleteCheck(Check):
    check_id = "KEYVAULT-001"
    description = "Key Vaults should have soft delete enabled"
    severity = Severity.HIGH

    def run(
        self, credential: TokenCredential, subscription_id: str
    ) -> Iterable[Finding]:
        client = KeyVaultManagementClient(credential, subscription_id)
        for vault in client.vaults.list_by_subscription():
            # Azure documents that when enable_soft_delete is not explicitly
            # set (None), the vault defaults to soft delete ENABLED -- so
            # only an explicit False means it's actually disabled.
            passed = vault.properties.enable_soft_delete is not False
            yield Finding(
                check_id=self.check_id,
                resource_id=vault.id,
                resource_name=vault.name,
                severity=self.severity,
                passed=passed,
                message=(
                    "Soft delete is enabled" if passed else "Soft delete is disabled"
                ),
            )
