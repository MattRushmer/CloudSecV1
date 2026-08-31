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

    try:
        subscription_id = args.subscription_id or get_subscription_id()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    credential = get_credential()

    findings, errors = run_scan(credential, subscription_id)
    print_report(findings, errors)

    if args.json_out:
        try:
            export_json(findings, args.json_out, errors)
        except OSError as exc:
            print(f"error: could not write {args.json_out}: {exc}", file=sys.stderr)
            return 1

    # A check that errored out never scanned its resources, so the scan is
    # incomplete — always treat that as a failure, even without
    # --fail-on-finding, rather than reporting a false "all clear".
    if errors:
        return 1
    if args.fail_on_finding and any(not finding.passed for finding in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
