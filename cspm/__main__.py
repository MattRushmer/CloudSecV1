import argparse
import sys

from dotenv import load_dotenv

from .auth import get_credential, get_subscription_id
from .report import export_json, print_report
from .scanner import run_scan


def main() -> int:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Minimal Azure CSPM scanner")
    parser.add_argument(
        "--subscription-id",
        help="Azure subscription ID (overrides AZURE_SUBSCRIPTION_ID)",
    )
    parser.add_argument("--json-out", help="Write findings to this JSON file")
    parser.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="Exit with a non-zero status if any check fails",
    )
    args = parser.parse_args()

    subscription_id = args.subscription_id or get_subscription_id()
    credential = get_credential()

    findings = run_scan(credential, subscription_id)
    print_report(findings)

    if args.json_out:
        export_json(findings, args.json_out)

    if args.fail_on_finding and any(not finding.passed for finding in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
