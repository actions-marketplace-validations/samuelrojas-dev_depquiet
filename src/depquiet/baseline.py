"""Baseline diffing — only flag NEW vulnerabilities not in a previous scan.

Enterprise teams adopting depquiet on existing codebases need a way to avoid
failing CI on day 1 from hundreds of pre-existing findings. The baseline lets
teams say "we accept the current state; only fail on regressions."

Usage:
    # Save current state as baseline
    depquiet --json > .depquiet-baseline.json

    # Only fail on NEW findings not in the baseline
    depquiet --baseline .depquiet-baseline.json
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from depquiet.models import ScanResult, Verdict


@dataclass
class BaselineResult:
    """Result of applying a baseline to a scan."""

    total_before: int
    total_after: int
    new_findings: int
    known_findings: int


def load_baseline(path: Path) -> set[str]:
    """Load a baseline JSON file and return the set of known finding keys.

    The baseline file is a depquiet --json output. Each finding is identified
    by its cve:package key.
    """
    with open(path) as f:
        data = json.load(f)

    keys: set[str] = set()
    for result in data.get("results", []):
        cve = result.get("cve", "")
        package = result.get("package", "")
        if cve and package:
            keys.add(f"{cve}:{package}")
    return keys


def apply_baseline(result: ScanResult, baseline_keys: set[str]) -> BaselineResult:
    """Demote ACTION/REVIEW items that exist in the baseline to FILTERED.

    Only items whose cve:package key appears in the baseline are demoted.
    New findings (not in baseline) keep their original verdict.

    Returns a BaselineResult with counts for reporting.
    """
    total_before = len(result.action) + len(result.review)
    known = 0

    for tr in result.results:
        if tr.verdict in (Verdict.ACTION, Verdict.REVIEW) and tr.vuln.key in baseline_keys:
            tr.verdict = Verdict.FILTERED
            known += 1

    total_after = len(result.action) + len(result.review)
    new_findings = total_after

    return BaselineResult(
        total_before=total_before,
        total_after=total_after,
        new_findings=new_findings,
        known_findings=known,
    )
