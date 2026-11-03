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
from typing import Any

from depquiet import __version__
from depquiet.config import load_config
from depquiet.engine import scan
from depquiet.models import ScanResult
from depquiet.output import print_scan_result
from depquiet.policy import load_policy
from depquiet.sarif import write_sarif
from depquiet.sbom import write_sbom


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
    parser.add_argument(
        "--sbom",
        type=Path,
        metavar="FILE",
        help="Write CycloneDX 1.5 SBOM to FILE (.json or .xml)",
    )
    parser.add_argument(
        "--sbom-format",
        choices=["json", "xml"],
        default=None,
        metavar="FMT",
        help="SBOM format: json (default) or xml. Inferred from --sbom extension if omitted.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        metavar="FILE",
        help="Path to policy file (default: .depquiet-policy.yaml in project root)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )

    args = parser.parse_args(argv)

    # Load project config file
    config = load_config(args.path, config_path=args.config)

    # CLI flags override config. We detect whether --epss-threshold was
    # explicitly passed so that "0.1" from the default doesn't clobber a
    # config-file value.
    cli_threshold: float | None = None
    if argv is not None:
        # When called programmatically, check if threshold differs from default
        if args.epss_threshold != 0.1:
            cli_threshold = args.epss_threshold
    elif "--epss-threshold" in sys.argv:
        cli_threshold = args.epss_threshold

    merged = config.merge_cli(
        epss_threshold=cli_threshold,
        template_dirs=args.templates,
        offline=args.offline,
    )

    # Read piped input
    audit_json: dict[str, Any] | None = None
    if args.stdin:
        try:
            raw = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: invalid JSON on stdin", file=sys.stderr)
            return 1
        # Dependabot exports are JSON arrays — wrap for the engine
        audit_json = {"alerts": raw} if isinstance(raw, list) else raw

    # Load policy
    policy = load_policy(args.path, policy_path=args.policy)

    # Run scan
    result = scan(
        project=args.path,
        epss_threshold=merged.epss_threshold,
        skip_epss=merged.offline,
        template_dirs=merged.template_dirs or None,
        audit_json=audit_json,
        always_flag=merged.always_flag or None,
        policy=policy,
    )

    # Output
    if args.json_output:
        _print_json(result)
    else:
        print_scan_result(result)

    if args.sarif:
        write_sarif(result, args.sarif)

    if args.sbom:
        sbom_fmt = args.sbom_format
        if sbom_fmt is None:
            sbom_fmt = "xml" if args.sbom.suffix.lower() == ".xml" else "json"
        write_sbom(result, args.sbom, fmt=sbom_fmt)

    # Exit code: 1 if any ACTION items, 0 otherwise
    # This makes `depquiet` usable as a CI gate
    if result.action:
        return 1
    return 0


def _print_json(result: ScanResult) -> None:
    """Print machine-readable JSON output."""
    results_list: list[dict[str, Any]] = []
    out: dict[str, Any] = {
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
        "results": results_list,
    }
    for tr in result.results:
        results_list.append(
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
