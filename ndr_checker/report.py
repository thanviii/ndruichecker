"""Report generation: console, JSON, CSV."""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


logger = logging.getLogger(__name__)


def format_console_table(results: List[Dict[str, Any]]) -> str:
    """Format results as a console table, grouped by client."""
    if not results:
        return "No results"

    # Group by client
    by_client = {}
    for result in results:
        client = result["target"]["client"]
        if client not in by_client:
            by_client[client] = []
        by_client[client].append(result)

    lines = []
    lines.append("")
    lines.append("=" * 120)
    lines.append("NDR CONSOLE HEALTH CHECK REPORT")
    lines.append("=" * 120)

    for client in sorted(by_client.keys()):
        lines.append("")
        lines.append(f"CLIENT: {client}")
        lines.append("-" * 120)

        # Header
        header = (
            f"{'Name':<30} "
            f"{'Status':<7} "
            f"{'HTTP Code':<12} "
            f"{'Response (ms)':<15} "
            f"{'Cert Days':<12} "
            f"{'Reason':<40}"
        )
        lines.append(header)
        lines.append("-" * 120)

        # Rows
        for result in by_client[client]:
            name = result["target"]["name"][:29]
            status = result["status"]
            http_status = str(result.get("http_status") or "-")
            response_ms = str(result.get("response_ms") or "-")
            cert_days = str(result.get("cert_days_remaining") or "-")
            reason = (result.get("reason") or "OK")[:39]

            row = (
                f"{name:<30} "
                f"{status:<7} "
                f"{http_status:<12} "
                f"{response_ms:<15} "
                f"{cert_days:<12} "
                f"{reason:<40}"
            )
            lines.append(row)

    lines.append("=" * 120)
    lines.append("")

    return "\n".join(lines)


def write_json_report(results: List[Dict[str, Any]], output_dir: str) -> str:
    """Write timestamped JSON report and latest.json."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = output_path / f"report_{timestamp}.json"

    # Build JSON report
    report = {
        "timestamp": datetime.now().isoformat(),
        "targets_checked": len(results),
        "summary": {
            "up": sum(1 for r in results if r["status"] == "UP"),
            "warn": sum(1 for r in results if r["status"] == "WARN"),
            "down": sum(1 for r in results if r["status"] == "DOWN"),
        },
        "results": [
            {
                "client": r["target"]["client"],
                "name": r["target"]["name"],
                "vendor": r["target"].get("vendor"),
                "url": r["target"]["url"],
                "status": r["status"],
                "http_status": r.get("http_status"),
                "response_ms": r.get("response_ms"),
                "cert_days_remaining": r.get("cert_days_remaining"),
                "reason": r.get("reason"),
            }
            for r in results
        ],
    }

    # Write timestamped report
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Wrote JSON report: {report_file}")

    # Write latest.json
    latest_file = output_path / "latest.json"
    with open(latest_file, "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Wrote latest report: {latest_file}")

    return str(report_file)


def write_csv_report(results: List[Dict[str, Any]], output_dir: str) -> str:
    """Write timestamped CSV report."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = output_path / f"report_{timestamp}.csv"

    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "client",
                "name",
                "vendor",
                "url",
                "status",
                "http_status",
                "response_ms",
                "cert_days_remaining",
                "reason",
            ],
        )
        writer.writeheader()

        for result in results:
            writer.writerow({
                "timestamp": datetime.now().isoformat(),
                "client": result["target"]["client"],
                "name": result["target"]["name"],
                "vendor": result["target"].get("vendor"),
                "url": result["target"]["url"],
                "status": result["status"],
                "http_status": result.get("http_status"),
                "response_ms": result.get("response_ms"),
                "cert_days_remaining": result.get("cert_days_remaining"),
                "reason": result.get("reason"),
            })

    logger.info(f"Wrote CSV report: {csv_file}")
    return str(csv_file)


def print_summary(results: List[Dict[str, Any]]) -> None:
    """Print a summary to console."""
    if not results:
        print("No results to report")
        return

    up = sum(1 for r in results if r["status"] == "UP")
    warn = sum(1 for r in results if r["status"] == "WARN")
    down = sum(1 for r in results if r["status"] == "DOWN")

    print(f"\nSummary: {up} UP, {warn} WARN, {down} DOWN out of {len(results)} checked")

    if down > 0:
        print("\nFailed targets:")
        for r in results:
            if r["status"] == "DOWN":
                print(f"  [FAIL] {r['target']['name']} ({r['target']['client']}): {r.get('reason', 'unknown')}")

    if warn > 0:
        print("\nWarning targets:")
        for r in results:
            if r["status"] == "WARN":
                print(f"  [WARN] {r['target']['name']} ({r['target']['client']}): {r.get('reason', 'warning')}")
