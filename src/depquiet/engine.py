"""Scan engine — orchestrates parsers, filters, and triage verdicts.

The engine is the core of depquiet. It:
1. Detects the package manager
2. Runs the appropriate scanner
3. Applies all filters in order
4. Assigns a verdict to each vulnerability
5. Returns a ScanResult with the full triage

Filter order matters for the output (we show the FIRST reason that matched),
but not for correctness — a vulnerability is filtered if ANY filter matches.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from depquiet.filters.devdep import DevDepFilter
from depquiet.filters.epss import EpssFilter
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.filters.templates import TemplateFilter
from depquiet.models import (
    FilterReason,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.parsers.dependabot import DependabotParser
from depquiet.parsers.grype import GrypeParser
from depquiet.parsers.npm import NpmAuditParser
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.snyk import SnykParser
from depquiet.parsers.trivy import TrivyParser


class _Parser(Protocol):
    """Structural type for audit parsers."""

    name: str

    @staticmethod
    def detect(project: Path) -> bool: ...

    @staticmethod
    def parse(audit_json: dict[str, Any], project: Path) -> list[Vulnerability]: ...

    @classmethod
    def scan(cls, project: Path) -> list[Vulnerability]: ...


_PARSERS: list[type[_Parser]] = [
    NpmAuditParser,
    PipAuditParser,
    TrivyParser,
    DependabotParser,
    GrypeParser,
    SnykParser,
]


def detect_package_manager(project: Path) -> str | None:
    """Auto-detect the project's package manager."""
    for parser in _PARSERS:
        if parser.detect(project):
            return parser.name
    return None


def scan(
    project: Path,
    *,
    epss_threshold: float = 0.1,
    skip_epss: bool = False,
    template_dirs: list[Path] | None = None,
    audit_json: dict[str, Any] | None = None,
    always_flag: list[str] | None = None,
) -> ScanResult:
    """Run a full triage scan on a project.

    Args:
        project: Path to the project root.
        epss_threshold: EPSS score below which CVEs are deprioritized.
        skip_epss: Don't query the EPSS API (fully offline mode).
        template_dirs: Extra directories to load community templates from.
        audit_json: Pre-parsed audit JSON (for testing / piped input).

    Returns:
        ScanResult with all vulnerabilities and their triage verdicts.
    """
    # Step 1: Detect and parse
    pm = detect_package_manager(project)
    if pm is None and audit_json is None:
        return ScanResult(
            project_path=str(project),
            package_manager="unknown",
            total_dependencies=0,
            results=[],
        )

    vulns: list[Vulnerability] = []
    if audit_json is not None:
        # Use provided JSON (piped input or testing)
        # Auto-detect format: Trivy has "Results", pip has "dependencies",
        # npm has "vulnerabilities"
        if "Results" in audit_json:
            vulns = TrivyParser.parse(audit_json, project)
        elif "matches" in audit_json:
            vulns = GrypeParser.parse(audit_json, project)
        elif "alerts" in audit_json:
            vulns = DependabotParser.parse(audit_json, project)
        elif "packageManager" in audit_json and isinstance(audit_json.get("vulnerabilities"), list):
            vulns = SnykParser.parse(audit_json, project)
        elif pm == "pip" or "dependencies" in audit_json:
            vulns = PipAuditParser.parse(audit_json, project)
        else:
            vulns = NpmAuditParser.parse(audit_json, project)
    else:
        for parser in _PARSERS:
            if parser.name == pm:
                vulns = parser.scan(project)
                break

    if not vulns:
        return ScanResult(
            project_path=str(project),
            package_manager=pm or "unknown",
            total_dependencies=0,
            results=[],
        )

    # Step 2: Initialize filters
    reachability = ReachabilityFilter(project)
    epss_filter = EpssFilter(threshold=epss_threshold)
    template_filter = TemplateFilter(template_dirs=template_dirs)

    # Step 3: Batch EPSS lookup (one API call for all CVEs)
    if not skip_epss:
        all_cves = [v.cve for v in vulns if v.cve]
        epss_filter.lookup(all_cves)

    # Step 4: Triage each vulnerability
    results: list[TriageResult] = []
    for vuln in vulns:
        reasons: list[FilterReason] = []
        epss_score = None
        epss_percentile = None
        template_id = None
        template_reason = None

        # Skip all filters if package is in always_flag
        _always = set(always_flag) if always_flag else set()
        if vuln.package in _always:
            _epss = epss_filter.get_score(vuln.cve)
            results.append(
                TriageResult(
                    vuln=vuln,
                    verdict=Verdict.ACTION,
                    reasons=[],
                    epss_score=_epss[0] if _epss else None,
                    epss_percentile=_epss[1] if _epss else None,
                    reachable_imports=reachability.find_imports(vuln),
                )
            )
            continue

        # Filter 1: devDependency
        if DevDepFilter.check(vuln):
            reasons.append(FilterReason.DEV_DEPENDENCY)

        # Filter 2: Unreachable (function never imported)
        if reachability.check(vuln):
            reasons.append(FilterReason.UNREACHABLE)

        # Filter 3: Low EPSS score
        epss_data = epss_filter.get_score(vuln.cve)
        if epss_data:
            epss_score, epss_percentile = epss_data
        if epss_filter.check(vuln):
            reasons.append(FilterReason.LOW_EPSS)

        # Filter 4: Community template match
        tmpl = template_filter.find_match(vuln.cve, vuln.package)
        if tmpl:
            reasons.append(FilterReason.COMMUNITY_TEMPLATE)
            template_id = tmpl.id
            template_reason = tmpl.reason

        # Determine verdict
        if reasons:
            verdict = Verdict.FILTERED
        elif epss_score is not None and epss_score < 0.3:
            # Has EPSS but above threshold — worth reviewing
            verdict = Verdict.REVIEW
        elif vuln.severity in (Severity.LOW, Severity.INFO):
            verdict = Verdict.REVIEW
        else:
            verdict = Verdict.ACTION

        # For ACTION items, find where the package is imported
        reachable_imports = []
        if verdict == Verdict.ACTION:
            reachable_imports = reachability.find_imports(vuln)

        results.append(
            TriageResult(
                vuln=vuln,
                verdict=verdict,
                reasons=reasons,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                reachable_imports=reachable_imports,
                template_id=template_id,
                template_reason=template_reason,
            )
        )

    # Sort: ACTION first, then REVIEW, then FILTERED
    order = {Verdict.ACTION: 0, Verdict.REVIEW: 1, Verdict.FILTERED: 2}
    results.sort(key=lambda r: (order[r.verdict], r.vuln.severity.value))

    return ScanResult(
        project_path=str(project),
        package_manager=pm or "unknown",
        total_dependencies=len(set(v.package for v in vulns)),
        results=results,
    )
