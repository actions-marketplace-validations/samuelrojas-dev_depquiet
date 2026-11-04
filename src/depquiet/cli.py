"""CLI entry point — `depquiet` or `python -m depquiet`.

Usage:
    depquiet                     # auto-detect, scan, triage
    depquiet --path ./my-app     # scan a specific directory
    depquiet --offline           # skip EPSS API (fully offline)
    depquiet --sarif out.sarif   # write SARIF for GitHub Code Scanning
    depquiet --json              # machine-readable JSON output
    depquiet --epss-threshold 0.05  # custom EPSS threshold
    cat audit.json | depquiet --stdin  # pipe in npm audit / pip-audit JSON
    depquiet diff base.json head.json  # compare two scans
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from depquiet import __version__
from depquiet.annotations import build_annotations, write_annotations
from depquiet.baseline import apply_baseline, load_baseline
from depquiet.config import load_config
from depquiet.diff import diff_scans, diff_to_json, format_diff, format_diff_markdown
from depquiet.engine import scan
from depquiet.fix import apply_fixes, print_fix_report
from depquiet.html_report import write_html
from depquiet.ignore import apply_ignores, load_ignore, print_ignore_warnings
from depquiet.kev import KevCatalog, apply_kev, fetch_kev_catalog, load_kev_from_file
from depquiet.license import LicenseReport, print_license_report, scan_licenses
from depquiet.models import ScanResult
from depquiet.output import print_scan_result
from depquiet.policy import load_policy
from depquiet.sarif import write_sarif
from depquiet.sbom import write_sbom
from depquiet.summary import write_summary
from depquiet.vex import build_vex, write_vex


def diff_main(argv: list[str]) -> int:
    """Run the `depquiet diff` subcommand. Returns exit code."""
    parser = argparse.ArgumentParser(
        prog="depquiet diff",
        description="Compare two depquiet scans to show new, fixed, and changed findings.",
    )
    parser.add_argument(
        "base",
        type=Path,
        help="Path to the base/before scan JSON (from depquiet --json)",
    )
    parser.add_argument(
        "head",
        type=Path,
        help="Path to the head/after scan JSON (from depquiet --json)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON diff to stdout",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output GitHub-flavored Markdown (for PR comments or step summaries)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        metavar="FILE",
        help="Write Markdown diff summary to FILE (for $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit 1 if any new ACTION findings are detected",
    )
    args = parser.parse_args(argv)

    # Validate input files exist
    for path in (args.base, args.head):
        if not path.is_file():
            print(f"Error: file not found: {path}", file=sys.stderr)
            return 1

    diff = diff_scans(args.base, args.head)

    if args.json_output:
        json.dump(diff_to_json(diff), sys.stdout, indent=2)
        print()  # trailing newline
    elif args.markdown:
        print(format_diff_markdown(diff))
    else:
        print(format_diff(diff))

    # Write summary file (for $GITHUB_STEP_SUMMARY)
    if args.summary:
        md = format_diff_markdown(diff)
        args.summary.write_text(md + "\n", encoding="utf-8")

    if args.fail_on_new and diff.has_new_action:
        return 1
    return 0


def explain_main(argv: list[str]) -> int:
    """Run the `depquiet explain` subcommand. Returns exit code."""
    from depquiet.explain import (
        explain_triage,
        find_cve,
        find_cve_in_json,
        format_explanation,
        format_explanation_json,
    )

    parser = argparse.ArgumentParser(
        prog="depquiet explain",
        description="Explain why a CVE received its verdict.",
    )
    parser.add_argument(
        "cve",
        help="CVE ID to explain (e.g. CVE-2021-44228)",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        metavar="FILE",
        dest="from_json",
        help="Read from a previous depquiet --json output instead of scanning",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON explanation",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )
    args = parser.parse_args(argv)

    tr = None

    if args.from_json:
        # Load from a saved JSON scan
        if not args.from_json.is_file():
            print(f"Error: file not found: {args.from_json}", file=sys.stderr)
            return 1
        try:
            data = json.loads(args.from_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid JSON in {args.from_json}", file=sys.stderr)
            return 1
        tr = find_cve_in_json(data, args.cve)
    else:
        # Run a live scan
        config = load_config(args.path, config_path=args.config)
        merged = config.merge_cli()
        result = scan(
            project=args.path,
            epss_threshold=merged.epss_threshold,
            skip_epss=merged.offline,
            template_dirs=merged.template_dirs or None,
            always_flag=merged.always_flag or None,
        )
        tr = find_cve(result, args.cve)

    if tr is None:
        print(f"CVE not found: {args.cve}", file=sys.stderr)
        print(
            "Hint: the CVE must appear in your project's vulnerability scan.",
            file=sys.stderr,
        )
        return 1

    exp = explain_triage(tr)

    if args.json_output:
        print(format_explanation_json(exp))
    else:
        print(format_explanation(exp))

    return 0


def stats_main(argv: list[str]) -> int:
    """Run the `depquiet stats` subcommand. Returns exit code."""
    from depquiet.stats import (
        compute_stats,
        format_stats,
        format_stats_json,
        stats_from_json,
    )

    parser = argparse.ArgumentParser(
        prog="depquiet stats",
        description="Show aggregate scan statistics.",
    )
    parser.add_argument(
        "--from-json",
        type=Path,
        metavar="FILE",
        dest="from_json",
        help="Read from a previous depquiet --json output instead of scanning",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON statistics",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Number of top packages to show (default: 10)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help="Path to config file (default: .depquiet.yaml in project root)",
    )
    args = parser.parse_args(argv)

    if args.from_json:
        if not args.from_json.is_file():
            print(f"Error: file not found: {args.from_json}", file=sys.stderr)
            return 1
        try:
            data = json.loads(args.from_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid JSON in {args.from_json}", file=sys.stderr)
            return 1
        stats = stats_from_json(data, top_n=args.top)
    else:
        config = load_config(args.path, config_path=args.config)
        merged = config.merge_cli()
        result = scan(
            project=args.path,
            epss_threshold=merged.epss_threshold,
            skip_epss=merged.offline,
            template_dirs=merged.template_dirs or None,
            always_flag=merged.always_flag or None,
        )
        stats = compute_stats(
            result.results,
            result.total_dependencies,
            top_n=args.top,
        )

    if args.json_output:
        print(format_stats_json(stats))
    else:
        print(format_stats(stats))

    return 0


def init_main(argv: list[str]) -> int:
    """Run the `depquiet init` subcommand. Returns exit code."""
    from depquiet.init import init_command

    parser = argparse.ArgumentParser(
        prog="depquiet init",
        description="Generate a .depquiet.yaml config for this project.",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("."),
        help="Project directory (default: current directory)",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Non-interactive mode — accept all defaults",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .depquiet.yaml",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="Write config to FILE instead of <project>/.depquiet.yaml",
    )
    args = parser.parse_args(argv)
    return init_command(args.path, yes=args.yes, force=args.force, output=args.output)


def main(argv: list[str] | None = None) -> int:
    """Run the depquiet CLI. Returns exit code."""
    # Dispatch to subcommands before argparse sees them
    effective = argv if argv is not None else sys.argv[1:]
    if effective and effective[0] == "diff":
        return diff_main(effective[1:])
    if effective and effective[0] == "init":
        return init_main(effective[1:])
    if effective and effective[0] == "explain":
        return explain_main(effective[1:])
    if effective and effective[0] == "stats":
        return stats_main(effective[1:])

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
        "--from-sbom",
        type=Path,
        metavar="FILE",
        dest="from_sbom",
        help=(
            "Read a CycloneDX or SPDX JSON SBOM as input. "
            "Extracts vulnerabilities or queries OSV.dev for advisories."
        ),
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
        choices=["json", "xml", "spdx"],
        default=None,
        metavar="FMT",
        help=(
            "SBOM format: json (CycloneDX, default), xml (CycloneDX), "
            "or spdx (SPDX 2.3 JSON). Inferred from --sbom extension if omitted."
        ),
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
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix ACTION items that have a known fix version",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what --fix would do without changing anything",
    )
    parser.add_argument(
        "--license",
        action="store_true",
        dest="license_scan",
        help="Run license compliance analysis on all dependencies",
    )
    parser.add_argument(
        "--ignore",
        type=Path,
        metavar="FILE",
        help="Path to ignore file (default: .depquiet-ignore in project root)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        metavar="FILE",
        help="Write GitHub-flavored Markdown summary to FILE (for $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        metavar="FILE",
        help=(
            "Path to a previous depquiet --json output. "
            "Only NEW findings not in the baseline trigger ACTION/REVIEW verdicts."
        ),
    )
    parser.add_argument(
        "--kev",
        action="store_true",
        help=(
            "Check vulnerabilities against the CISA Known Exploited Vulnerabilities "
            "(KEV) catalog. KEV-listed CVEs are auto-escalated to ACTION."
        ),
    )
    parser.add_argument(
        "--kev-file",
        type=Path,
        metavar="FILE",
        help="Path to a local KEV catalog JSON file (for air-gapped environments)",
    )
    parser.add_argument(
        "--html",
        type=Path,
        metavar="FILE",
        help="Write a self-contained interactive HTML report to FILE",
    )
    parser.add_argument(
        "--annotations",
        type=Path,
        metavar="FILE",
        help="Write GitHub Check Run annotations JSON to FILE",
    )
    parser.add_argument(
        "--vex",
        type=Path,
        metavar="FILE",
        help="Write an OpenVEX document to FILE (vulnerability exploitability exchange)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "moderate", "low", "none"],
        default=None,
        metavar="SEVERITY",
        help=(
            "Exit 1 only when ACTION items at or above SEVERITY exist "
            "(critical, high, moderate, low, none). Default: low (any ACTION fails)."
        ),
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

    # Detect which CLI flags were explicitly passed (vs argparse defaults)
    _raw = argv if argv is not None else sys.argv[1:]

    def _has(flag: str) -> bool:
        return flag in _raw

    merged = config.merge_cli(
        epss_threshold=cli_threshold,
        template_dirs=args.templates,
        offline=args.offline,
        fail_on=args.fail_on if _has("--fail-on") else None,
        kev=args.kev if _has("--kev") else False,
        kev_file=args.kev_file if _has("--kev-file") else None,
        license_scan=args.license_scan if _has("--license") else False,
        policy=args.policy if _has("--policy") else None,
        ignore=args.ignore if _has("--ignore") else None,
        baseline=args.baseline if _has("--baseline") else None,
        sarif=args.sarif if _has("--sarif") else None,
        html=args.html if _has("--html") else None,
        summary=args.summary if _has("--summary") else None,
        sbom=args.sbom if _has("--sbom") else None,
        sbom_format=args.sbom_format if _has("--sbom-format") else None,
        vex=args.vex if _has("--vex") else None,
        annotations=args.annotations if _has("--annotations") else None,
    )

    # Read piped input or SBOM file
    audit_json: dict[str, Any] | None = None
    if args.from_sbom:
        if not args.from_sbom.is_file():
            print(f"Error: file not found: {args.from_sbom}", file=sys.stderr)
            return 1
        try:
            audit_json = json.loads(args.from_sbom.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"Error: invalid JSON in {args.from_sbom}", file=sys.stderr)
            return 1
    elif args.stdin:
        try:
            raw = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Error: invalid JSON on stdin", file=sys.stderr)
            return 1
        # Dependabot exports are JSON arrays — wrap for the engine
        audit_json = {"alerts": raw} if isinstance(raw, list) else raw

    # Load policy (from CLI, config, or project default)
    policy = load_policy(args.path, policy_path=merged.policy)

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

    # Apply suppressions (from CLI, config, or project default)
    ignore_file = load_ignore(args.path, ignore_path=merged.ignore)
    if ignore_file is not None:
        apply_ignores(result, ignore_file)
        print_ignore_warnings(ignore_file)

    # Apply baseline — demote known findings to FILTERED
    if merged.baseline:
        baseline_keys = load_baseline(merged.baseline)
        bl = apply_baseline(result, baseline_keys)
        if not args.json_output:
            print(
                f"\n📊 Baseline: {bl.known_findings} known findings suppressed, "
                f"{bl.new_findings} new findings remain\n"
            )

    # Apply KEV escalation — auto-escalate actively exploited CVEs
    if merged.kev or merged.kev_file:
        kev_catalog: KevCatalog | None
        if merged.kev_file:
            kev_catalog = load_kev_from_file(merged.kev_file)
        else:
            kev_catalog = fetch_kev_catalog(offline=merged.offline)
        if kev_catalog is not None:
            kev_result = apply_kev(result, kev_catalog)
            if not args.json_output:
                parts = [f"🛡️  KEV: {kev_result.kev_matches} of {kev_result.total_checked}"]
                parts[0] += " CVEs on the CISA KEV catalog"
                if kev_result.escalated > 0:
                    parts.append(f"{kev_result.escalated} escalated to ACTION")
                print("\n" + " — ".join(parts) + "\n")
        elif not args.json_output:
            print("\n⚠️  KEV catalog unavailable (offline with no cache)\n")

    # Output
    if args.json_output:
        _print_json(result)
    else:
        print_scan_result(result)

    if merged.sarif:
        write_sarif(result, merged.sarif)

    if merged.sbom:
        sbom_fmt = merged.sbom_format
        if sbom_fmt is None:
            name_lower = merged.sbom.name.lower()
            if name_lower.endswith(".spdx.json") or name_lower.endswith(".spdx"):
                sbom_fmt = "spdx"
            elif merged.sbom.suffix.lower() == ".xml":
                sbom_fmt = "xml"
            else:
                sbom_fmt = "json"
        write_sbom(result, merged.sbom, fmt=sbom_fmt)

    if merged.summary:
        write_summary(result, merged.summary)

    if merged.html:
        write_html(result, merged.html)

    if merged.annotations:
        ann_report = build_annotations(result)
        write_annotations(ann_report, merged.annotations)

    if merged.vex:
        vex_doc = build_vex(result)
        write_vex(vex_doc, merged.vex)

    # License compliance (from CLI or config)
    if merged.license or args.license_scan:
        license_report = scan_licenses(args.path, package_manager=result.package_manager)
        if args.json_output:
            _print_license_json(license_report)
        else:
            print_license_report(license_report)
        if license_report.has_issues:
            return 1

    # Auto-fix
    if args.fix or args.dry_run:
        fix_report = apply_fixes(result, args.path, dry_run=args.dry_run)
        print_fix_report(fix_report, dry_run=args.dry_run)
        # After fixing, only fail if there are still unfixed ACTION items
        remaining = len(fix_report.failed) + len(fix_report.skipped)
        if remaining > 0:
            return 1
        return 0

    # Exit code: 1 if ACTION items meet the severity threshold
    # --fail-on / config fail_on controls the minimum severity that triggers failure
    if _should_fail(result, merged.fail_on):
        return 1
    return 0


# Severity ordering: critical > high > moderate > low > info
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "moderate": 2,
    "low": 1,
    "info": 0,
}


def _should_fail(result: ScanResult, fail_on: str | None) -> bool:
    """Check whether any ACTION items meet the severity threshold.

    When fail_on is None (default), any ACTION item triggers failure.
    When fail_on is "none", the build never fails on findings.
    Otherwise, only ACTION items at or above the specified severity count.
    """
    if fail_on == "none":
        return False

    if not result.action:
        return False

    if fail_on is None:
        # Default: any ACTION item triggers failure
        return True

    threshold = _SEVERITY_RANK.get(fail_on, 1)
    for tr in result.action:
        rank = _SEVERITY_RANK.get(tr.vuln.severity.value, 0)
        if rank >= threshold:
            return True
    return False


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
        entry: dict[str, Any] = {
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
        if tr.kev_entry is not None:
            entry["kev"] = {
                "date_added": tr.kev_entry.date_added,
                "due_date": tr.kev_entry.due_date,
                "required_action": tr.kev_entry.required_action,
                "ransomware_use": tr.kev_entry.ransomware_use,
            }
        results_list.append(entry)

    json.dump(out, sys.stdout, indent=2)
    print()  # trailing newline


def _print_license_json(report: LicenseReport) -> None:
    """Print machine-readable license JSON to stdout."""
    out: dict[str, Any] = {
        "project": report.project_path,
        "package_manager": report.package_manager,
        "total": len(report.packages),
        "summary": {
            "low": len(report.low),
            "medium": len(report.medium),
            "high": len(report.high),
            "critical": len(report.critical),
            "unknown": len(report.unknown),
        },
        "issues": [
            {
                "package": p.package,
                "version": p.version,
                "license": p.license_id,
                "license_raw": p.license_raw,
                "risk": p.risk.value,
            }
            for p in report.packages
            if p.risk.value in ("high", "critical", "unknown")
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    print()
