from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Finding:
    check_id: str
    resource_id: str
    resource_name: str
    severity: Severity
    passed: bool
    message: str


@dataclass(frozen=True)
class CheckError:
    check_id: str
    message: str
