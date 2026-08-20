from abc import ABC, abstractmethod
from typing import Iterable

from ..findings import Finding, Severity


class Check(ABC):
    check_id: str
    description: str
    severity: Severity

    @abstractmethod
    def run(self, credential, subscription_id: str) -> Iterable[Finding]:
        ...
