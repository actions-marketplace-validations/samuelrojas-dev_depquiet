"""CLI entry point — `depquiet` or `python -m depquiet`.

Usage:
    depquiet                     # auto-detect, scan, triage
    depquiet --path ./my-app     # scan a specific directory
    depquiet --offline           # skip EPSS API (fully offline)
    depquiet --sarif out.sarif   # write SARIF for GitHub Code Scanning
    depquiet --json              # machine-readable JSON output
    depquiet --epss-threshold 0.05  # custom EPSS threshold
    cat audit.json | depquiet --stdin  # pipe in npm audit / pip-audit JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from depquiet import __version__
from depquiet.engine import scan
from depquiet.output import print_scan_result
from depquiet.sarif import write_sarif


def main(argv: list[str] | None = None) -> int:
    """Run the depquiet CLI. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="depquiet",
        description=(
            "Silence the noise. Surface the signal. Triage vulnerability alerts in seconds."
        ),
    )
    parser.add_argument("--version", action="version", version=f"depquiet {__version__}")
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip EPSS API lookup (fully offline mode)",
    )
    parser.add_argument(
        "--sarif",
        type=Path,
        metavar="FILE",
        help="Write SARIF output to FILE",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON to stdout",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read audit JSON from stdin instead of running a scanner",
    )
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=0.1,
        metavar="N",
        help="EPSS score threshold (default: 0.1 = 10%%)",
    )
    parser.add_argument(
        "--templates",
        type=Path,
        action="append",
        metavar="DIR",
        help="Extra directory of community templates (can be repeated)",
    )

    args = parser.parse_args(argv)

    # Read piped input
    audit_json = None
    if args.stdin:
        try:
            audit_json = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: invalid JSON on stdin", file=sys.stderr)
            return 1

    # Run scan
    result = scan(
        project=args.path,
        epss_threshold=args.epss_threshold,
        skip_epss=args.offline,
        template_dirs=args.templates,
        audit_json=audit_json,
    )

    # Output
    if args.json_output:
        _print_json(result)
    else:
        print_scan_result(result)

    if args.sarif:
        write_sarif(result, args.sarif)

    # Exit code: 1 if any ACTION items, 0 otherwise
    # This makes `depquiet` usable as a CI gate
    if result.action:
        return 1
    return 0


def _print_json(result) -> None:
    """Print machine-readable JSON output."""
    out = {
        "project": result.project_path,
        "package_manager": result.package_manager,
        "total_dependencies": result.total_dependencies,
        "summary": {
            "total": len(result.results),
            "action": len(result.action),
            "review": len(result.review),
            "filtered": len(result.filtered),
            "filter_rate": round(result.filter_rate, 1),
        },
        "results": [],
    }
    for tr in result.results:
        out["results"].append(
            {
                "cve": tr.vuln.cve,
                "package": tr.vuln.package,
                "version": tr.vuln.version,
                "severity": tr.vuln.severity.value,
                "title": tr.vuln.title,
                "verdict": tr.verdict.value,
                "reasons": [r.value for r in tr.reasons],
                "epss_score": tr.epss_score,
                "fix_version": tr.vuln.fix_version,
                "reachable_imports": tr.reachable_imports,
            }
        )

    json.dump(out, sys.stdout, indent=2)
    print()  # trailing newline
