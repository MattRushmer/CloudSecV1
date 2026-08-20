import json
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table

from .findings import Finding

console = Console()


def print_report(findings: List[Finding]) -> None:
    table = Table(title="Azure CSPM Scan Results")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Message")

    for finding in findings:
        status = "[green]PASS[/green]" if finding.passed else "[red]FAIL[/red]"
        table.add_row(
            finding.check_id,
            finding.resource_name,
            finding.severity.value,
            status,
            finding.message,
        )
    console.print(table)

    failed = sum(1 for finding in findings if not finding.passed)
    console.print(f"\n{failed} of {len(findings)} checks failed.")


def export_json(findings: List[Finding], path: str) -> None:
    data = [
        {
            "check_id": finding.check_id,
            "resource_id": finding.resource_id,
            "resource_name": finding.resource_name,
            "severity": finding.severity.value,
            "passed": finding.passed,
            "message": finding.message,
        }
        for finding in findings
    ]
    Path(path).write_text(json.dumps(data, indent=2))
