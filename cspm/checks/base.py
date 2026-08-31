from abc import ABC, abstractmethod
from typing import Iterable

from azure.core.credentials import TokenCredential

from ..findings import Finding, Severity


class Check(ABC):
    check_id: str
    description: str
    severity: Severity

    @abstractmethod
    def run(
        self, credential: TokenCredential, subscription_id: str
    ) -> Iterable[Finding]:
        ...
