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
            FilterReason.UNREACHABLE: "unreachable — vulnerable function never imported",
            FilterReason.DEV_DEPENDENCY: "devDependency only — never reaches production",
            FilterReason.LOW_EPSS: "EPSS < 10% — no known exploits in the wild",
            FilterReason.COMMUNITY_TEMPLATE: "community template — confirmed false positive",
        }

        for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
            label = reason_labels.get(reason, reason.value)
            prefix = "└─" if reason == list(by_reason.keys())[-1] else "├─"
            print(f"   {_c(_DIM, prefix)} {count} {label}")

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
            fix_str = f"FIX: update to {r.vuln.fix_version}" if r.vuln.fix_version else ""
            parts = [r.vuln.cve, r.vuln.package]
            if epss_str:
                parts.append(epss_str)
            if fix_str:
                parts.append(fix_str)

            print(f"   {_c(_RED, '•')} {'  '.join(parts)}")

            # Show where it's imported
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

    if filtered:
        print(_c(_DIM, f"You just saved ~{len(filtered) * 2} minutes of triage time."))
    print()
