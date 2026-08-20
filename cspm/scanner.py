import logging
from typing import List

from .checks import ALL_CHECKS
from .findings import Finding

logger = logging.getLogger(__name__)


def run_scan(credential, subscription_id: str) -> List[Finding]:
    findings: List[Finding] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check.run(credential, subscription_id))
        except Exception as exc:
            logger.error("Check %s failed: %s", check.check_id, exc)
    return findings
