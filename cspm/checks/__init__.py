from .keyvault import KeyVaultSoftDeleteCheck
from .network import NsgOpenManagementPortsCheck
from .sql import SqlServerOpenFirewallCheck
from .storage import StorageHttpsOnlyCheck, StoragePublicBlobAccessCheck

ALL_CHECKS = [
    StorageHttpsOnlyCheck(),
    StoragePublicBlobAccessCheck(),
    NsgOpenManagementPortsCheck(),
    KeyVaultSoftDeleteCheck(),
    SqlServerOpenFirewallCheck(),
]
