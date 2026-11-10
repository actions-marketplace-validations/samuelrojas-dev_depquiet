"""Terminal output — the first thing users see, and what gets screenshotted.

The output is designed to be emotional: the before/after contrast of
"89 alerts → 3 actionable" is what makes developers share depquiet.
Colors and symbols make it scannable in <5 seconds.
"""

from __future__ import annotations

import sys

from depquiet.models import FilterReason, ScanResult

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
    action = result.action
    review = result.review
    filtered = result.filtered

    # Header
    print()
    print(
        f"{_c(_BOLD, 'depquiet')} scan — {result.package_manager} "
        f"({result.total_dependencies} packages)"
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
            epss_str = f"EPSS {r.epss_score:.0%}" if r.epss_score is not None else "no EPSS"
            print(
                f"   {r.vuln.cve:20s} {r.vuln.package:25s} {r.vuln.severity.value:10s} {epss_str}"
            )

    # Action required
    if action:
        print()
        print(f"{_c(_RED, '🔴')} {_c(_BOLD, f'ACTION REQUIRED: {len(action)} alerts')}")
        for r in action:
            epss_str = f"EPSS {r.epss_score:.0%}" if r.epss_score is not None else ""
            fix_str = ""
            if r.vuln.fix_version:
                target = f"{r.vuln.fix_package} " if r.vuln.fix_package else ""
                fix_str = f"FIX: update {target}to {r.vuln.fix_version}"
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
                print(f"     {_c(_DIM, r.vuln.title[:80])}")

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
    print("Priority reflects dependency triage; product impact remains under investigation.")
    print()
