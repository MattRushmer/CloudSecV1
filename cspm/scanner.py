import logging
from typing import List, Tuple

from azure.core.credentials import TokenCredential

from .checks import ALL_CHECKS
from .findings import CheckError, Finding

logger = logging.getLogger(__name__)


def run_scan(
    credential: TokenCredential, subscription_id: str
) -> Tuple[List[Finding], List[CheckError]]:
    findings: List[Finding] = []
    errors: List[CheckError] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check.run(credential, subscription_id))
        except Exception as exc:
            logger.error("Check %s failed: %s", check.check_id, exc)
            errors.append(CheckError(check_id=check.check_id, message=str(exc)))
    return findings, errors
