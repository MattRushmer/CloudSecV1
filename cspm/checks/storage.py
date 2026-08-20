from azure.mgmt.storage import StorageManagementClient

from ..findings import Finding, Severity
from .base import Check


class StorageHttpsOnlyCheck(Check):
    check_id = "STORAGE-001"
    description = "Storage accounts should require HTTPS (secure transfer)"
    severity = Severity.HIGH

    def run(self, credential, subscription_id):
        client = StorageManagementClient(credential, subscription_id)
        for account in client.storage_accounts.list():
            passed = bool(account.enable_https_traffic_only)
            yield Finding(
                check_id=self.check_id,
                resource_id=account.id,
                resource_name=account.name,
                severity=self.severity,
                passed=passed,
                message=(
                    "HTTPS-only traffic is enforced"
                    if passed
                    else "Secure transfer (HTTPS-only) is disabled"
                ),
            )


class StoragePublicBlobAccessCheck(Check):
    check_id = "STORAGE-002"
    description = "Storage accounts should not allow public blob access"
    severity = Severity.CRITICAL

    def run(self, credential, subscription_id):
        client = StorageManagementClient(credential, subscription_id)
        for account in client.storage_accounts.list():
            passed = not bool(account.allow_blob_public_access)
            yield Finding(
                check_id=self.check_id,
                resource_id=account.id,
                resource_name=account.name,
                severity=self.severity,
                passed=passed,
                message=(
                    "Public blob access is disabled"
                    if passed
                    else "Public blob access is allowed"
                ),
            )
