"""Terminal output — the first thing users see, and what gets screenshotted.

The output is designed to be emotional: the before/after contrast of
"89 alerts → 3 actionable" is what makes developers share depquiet.
Colors and symbols make it scannable in <5 seconds.
"""

from __future__ import annotations

import sys
from typing import Any

from depquiet.models import FilterReason, ScanResult, epss_percent, is_prerelease, short_title

# ANSI colors — disabled when not a TTY
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"
_CYAN = "\033[96m"


def _c(code: str, text: str) -> str:
    """Wrap text in ANSI color if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def print_scan_result(result: ScanResult) -> None:
    """Print the full triage result to stdout."""
    if not result.scanned:
        print(f"\n{_c(_YELLOW, '⚠️')}  Nothing scanned: {result.note}")
        return
    if result.note:
        print(f"\n{_c(_YELLOW, '⚠️')}  {result.note}")
    if not result.results:
        print(f"\n{_c(_GREEN, '✅')} No vulnerabilities found.")
        return

    total = len(result.results)
    action = sorted(result.action, key=_priority)
    review = sorted(result.review, key=_priority)
    filtered = result.filtered

    # Header
    print()
    print(
        f"{_c(_BOLD, 'depquiet')} scan — {result.package_manager} "
        f"({result.total_dependencies} vulnerable packages)"
    )
    print()

    # Filtered summary
    if filtered:
        pct = result.filter_rate
        print(f"{_c(_GREEN, '✅')} {_c(_BOLD, f'FILTERED: {len(filtered)} alerts')} ({pct:.0f}%)")

        # Group by reason
        by_reason: dict[FilterReason, int] = {}
        for r in filtered:
            for reason in r.reasons:
                by_reason[reason] = by_reason.get(reason, 0) + 1

        reason_labels = {
            FilterReason.UNREACHABLE: "no usage observed in inspected imports or dependency roots",
            FilterReason.TEST_ONLY: "imported only from test code, not from application sources",
            FilterReason.DEV_DEPENDENCY: "development-only paths in available dependency metadata",
            FilterReason.LOW_EPSS: "EPSS below configured threshold — lower remediation priority",
            FilterReason.COMMUNITY_TEMPLATE: "community template — dismissal conditions matched",
        }

        ordered = sorted(by_reason.items(), key=lambda x: (-x[1], x[0].value))
        for i, (reason, count) in enumerate(ordered):
            label = reason_labels.get(reason, reason.value)
            prefix = "└─" if i == len(ordered) - 1 else "├─"
            print(f"   {_c(_DIM, prefix)} {count} {label}")
        if sum(by_reason.values()) > len(filtered):
            print(f"   {_c(_DIM, '(an alert can match more than one reason)')}")

    # Review
    if review:
        print()
        print(f"{_c(_YELLOW, '⚠️')}  {_c(_BOLD, f'REVIEW: {len(review)} alerts')}")
        for r in review:
            epss_str = (
                f"EPSS {epss_percent(r.epss_score)}" if r.epss_score is not None else "no EPSS"
            )
            print(
                f"   {r.vuln.cve:20s} {r.vuln.package:25s} {r.vuln.severity_label:10s} {epss_str}"
            )

    # Action required
    if action:
        print()
        print(f"{_c(_RED, '🔴')} {_c(_BOLD, f'ACTION REQUIRED: {len(action)} alerts')}")
        for r in action:
            epss_str = f"EPSS {epss_percent(r.epss_score)}" if r.epss_score is not None else ""
            fix_str = ""
            if r.vuln.fix_version:
                target = f"{r.vuln.fix_package} " if r.vuln.fix_package else ""
                fix_str = f"FIX: update {target}to {r.vuln.fix_version}"
                if is_prerelease(r.vuln.fix_version):
                    fix_str += " (pre-release)"
            parts = [r.vuln.cve, r.vuln.package]
            if epss_str:
                parts.append(epss_str)
            if fix_str:
                parts.append(fix_str)

            print(f"   {_c(_RED, '•')} {'  '.join(parts)}")

            # Show where it's imported
            if r.dependency_type == "transitive" and r.introduced_by:
                print(f"     {_c(_DIM, 'via ' + ', '.join(r.introduced_by[:3]))}")
            if r.reachable_imports:
                for imp in r.reachable_imports[:3]:
                    print(f"     {_c(_DIM, '→')} {imp}")

            if r.vuln.title:
                print(f"     {_c(_DIM, _one_line(r.vuln.title))}")
            if r.fix_check is not None:
                _print_fix_check(r.fix_check)

    # Summary line
    print()
    parts = []
    if action:
        parts.append(_c(_RED, f"{len(action)} actionable"))
    if review:
        parts.append(_c(_YELLOW, f"{len(review)} review"))
    if filtered:
        parts.append(_c(_GREEN, f"{len(filtered)} filtered"))

    print(f"Total: {total} alerts — {' | '.join(parts)}")
    print(
        "Verdicts come from how each package is used (imports, dependency type, lockfile), "
        "not from whether your code calls the vulnerable function."
    )
    print()


def _print_fix_check(check: Any) -> None:
    also = getattr(check, "also_upgrade", [])
    next_step = getattr(check, "next_step", "")
    if check.status == "resolves":
        if also:
            line = f"fix check: resolves if {', '.join(also)} is upgraded in the same step"
            print(f"     {_c(_GREEN, '✓')} {line}")
            print(f"       {_c(_DIM, check.command)}")
        else:
            line = f"fix check: resolves ({check.command})"
            print(f"     {_c(_GREEN, '✓')} {_c(_DIM, line)}")
        return
    label = "blocked" if check.status == "blocked" else "could not check"
    print(f"     {_c(_YELLOW, '✗')} fix check: {label}: {check.detail[:240]}")
    if next_step:
        print(f"       → {next_step}")


def _one_line(title: str, width: int = 80) -> str:
    """An advisory title or description as one readable line."""
    return short_title(title, width)


_SEVERITY_ORDER = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}


def _priority(r: Any) -> tuple[int, float, int]:
    """Most urgent first: known exploited (KEV), then EPSS, then severity.

    EPSS orders the list; by default it never hides an alert.
    """
    kev = 0 if getattr(r, "kev_entry", None) is not None else 1
    epss = -(r.epss_score if r.epss_score is not None else -1.0)
    severity = _SEVERITY_ORDER.get(r.vuln.severity.value, 2) if r.vuln.severity_known else 2
    return (kev, epss, severity)
