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

from depquiet.depgraph import DependencyGraph
from depquiet.filters.devdep import DevDepFilter
from depquiet.filters.epss import EpssFilter
from depquiet.filters.reachability import ReachabilityDecision, ReachabilityFilter
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
from depquiet.parsers.osv import OsvScanner, parse_osv_response, query_osv_batch
from depquiet.parsers.pip import PipAuditParser
from depquiet.parsers.sarif import SarifParser
from depquiet.parsers.sbom import SbomParser, is_cyclonedx, is_spdx
from depquiet.parsers.snyk import SnykParser
from depquiet.parsers.trivy import TrivyParser
from depquiet.policy import Policy
from depquiet.scanners import ScanError, run_npm_audit, run_pip_audit


def _osv_batch_query(
    packages: list[tuple[str, str, str]],
) -> list[Vulnerability]:
    """Query OSV.dev for vulnerabilities matching SBOM packages."""
    if not packages:
        return []
    vulns: list[Vulnerability] = []
    for start in range(0, len(packages), 1000):
        batch = packages[start : start + 1000]
        try:
            response = query_osv_batch(batch)
            vulns.extend(parse_osv_response(response, batch))
        except (OSError, ValueError) as e:
            raise ScanError(f"could not query OSV.dev for the SBOM ({e}).") from e
    return vulns


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
    policy: Policy | None = None,
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
        # No native scanner detected — try OSV.dev lockfile scanning
        if not skip_epss and OsvScanner.detect(project):
            pm = "osv"
        else:
            if OsvScanner.detect(project):
                note = (
                    "found a lockfile, but scanning it queries OSV.dev and --offline is set. "
                    "Drop --offline, or pipe in scanner output with --stdin."
                )
            else:
                note = (
                    f"no supported manifest or lockfile in {project}. Run depquiet in a "
                    "project directory, pass --path, or pipe in scanner output with --stdin."
                )
            return ScanResult(
                project_path=str(project),
                package_manager="unknown",
                total_dependencies=0,
                results=[],
                scanned=False,
                note=note,
            )

    vulns: list[Vulnerability] = []
    scan_note = ""
    if audit_json is not None:
        # Use provided JSON (piped input or testing)
        # Auto-detect format — check SBOMs first, then scanner outputs
        if is_cyclonedx(audit_json) or is_spdx(audit_json):
            pm = pm or "sbom"
            vulns = SbomParser.parse(audit_json, project)
            if not vulns:
                # SBOM has no vulnerability data — extract packages
                # and query OSV.dev for advisories
                packages = SbomParser.extract_packages(audit_json)
                if not packages or skip_epss:
                    note = (
                        "SBOM has no embedded vulnerabilities and querying its packages "
                        "requires OSV.dev; --offline is set."
                        if skip_epss and packages
                        else "SBOM has no embedded vulnerabilities or readable packages to scan."
                    )
                    return ScanResult(str(project), pm, 0, [], scanned=False, note=note)
                try:
                    vulns = _osv_batch_query(packages)
                except ScanError as e:
                    return ScanResult(str(project), pm, 0, [], scanned=False, note=str(e))
        elif "runs" in audit_json and (
            "$schema" in audit_json or audit_json.get("version") == "2.1.0"
        ):
            vulns = SarifParser.parse(audit_json, project)
        elif "Results" in audit_json:
            vulns = TrivyParser.parse(audit_json, project)
        elif "matches" in audit_json:
            vulns = GrypeParser.parse(audit_json, project)
        elif "alerts" in audit_json:
            vulns = DependabotParser.parse(audit_json, project)
        elif "packageManager" in audit_json and isinstance(audit_json.get("vulnerabilities"), list):
            vulns = SnykParser.parse(audit_json, project)
        elif isinstance(audit_json.get("dependencies"), list):
            pm = "pip"
            vulns = PipAuditParser.parse(audit_json, project)
        elif isinstance(audit_json.get("vulnerabilities"), dict):
            pm = "npm"
            vulns = NpmAuditParser.parse(audit_json, project)
        else:
            return ScanResult(
                str(project),
                pm or "unknown",
                0,
                [],
                scanned=False,
                note="unrecognized scanner JSON format; no vulnerability report was read.",
            )
    else:
        try:
            vulns, pm, scan_note = _run_scanner(pm, project, offline=skip_epss)
        except ScanError as e:
            return ScanResult(
                project_path=str(project),
                package_manager=pm or "unknown",
                total_dependencies=0,
                results=[],
                scanned=False,
                note=str(e),
            )

    if not vulns:
        return ScanResult(
            project_path=str(project),
            package_manager=pm or "unknown",
            total_dependencies=0,
            results=[],
            note=scan_note,
        )

    # Step 2: Initialize filters
    reachability = ReachabilityFilter(project)
    graph = DependencyGraph.from_project(project)
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

        # Filter 2 runs first because filter 1 uses its dependency paths.
        # Transitive packages are judged by the direct dependencies that pull
        # them in, never by the app's own imports.
        decision = reachability.decide(vuln, graph)

        # A package may be declared as dev and also be required by a production
        # dependency. Every known root must be dev-only before suppressing it.
        roots = list(decision.introduced_by)
        if graph.directness(vuln.package) == "direct":
            roots.append(vuln.package)
        if graph.is_dev_only(roots) or (DevDepFilter.check(vuln) and not roots):
            reasons.append(FilterReason.DEV_DEPENDENCY)

        if decision.unreachable:
            reasons.append(FilterReason.UNREACHABLE)

        # Filter 3: Low EPSS score
        epss_data = epss_filter.get_score(vuln.cve)
        if epss_data:
            epss_score, epss_percentile = epss_data
        if epss_filter.check(vuln):
            reasons.append(FilterReason.LOW_EPSS)

        # Filter 4: Community template match
        tmpl = template_filter.find_match(
            vuln.cve, vuln.package, project=project, graph=graph, reachability=reachability
        )
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

        # Apply policy override (first matching rule wins)
        policy_id = None
        if policy is not None:
            # Create a temporary TriageResult for policy matching
            _temp = TriageResult(
                vuln=vuln,
                verdict=verdict,
                reasons=reasons,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
            )
            policy_verdict, policy_id = policy.apply(_temp)
            if policy_id is not None:
                verdict = policy_verdict

        # For ACTION items, find where the package is imported
        reachable_imports = []
        if verdict == Verdict.ACTION:
            reachable_imports = _import_sites(reachability, vuln, decision)

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
                dependency_type=decision.dependency_type,
                introduced_by=decision.introduced_by,
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
        note=scan_note,
    )


def _run_scanner(
    pm: str | None, project: Path, *, offline: bool
) -> tuple[list[Vulnerability], str, str]:
    """Run the detected scanner; fall back to OSV.dev lockfile scanning.

    Returns (vulnerabilities, scanner used, note). Raises ScanError when no
    scanner could produce a report, so the caller reports "not scanned"
    instead of "no vulnerabilities".
    """
    runners = {
        "npm": (run_npm_audit, NpmAuditParser.parse, "npm audit"),
        "pip": (run_pip_audit, PipAuditParser.parse, "pip-audit"),
    }
    if pm in runners:
        run, parse, label = runners[pm]
        try:
            return parse(run(project), project), str(pm), ""
        except ScanError as e:
            first = f"{label}: {e}"
        if offline or not OsvScanner.detect(project):
            hint = " OSV.dev fallback is disabled by --offline." if offline else ""
            raise ScanError(
                f"{first}{hint} You can also pipe a scanner's JSON in with --stdin."
            ) from None
        try:
            vulns = OsvScanner.scan_checked(project)
        except ScanError as e:
            raise ScanError(f"{first} OSV.dev fallback failed too: {e}") from None
        return vulns, "osv", f"{first} Scanned lockfiles with OSV.dev instead."
    if pm == "osv":
        return OsvScanner.scan_checked(project), "osv", ""
    raise ScanError(f"no scanner available for {pm or 'this project'}.")


def _import_sites(
    reachability: ReachabilityFilter, vuln: Vulnerability, decision: ReachabilityDecision
) -> list[str]:
    """Where the vulnerable package enters the app: its own imports, or for a
    transitive package, the imports of the direct dependencies that pull it in."""
    sites = reachability.find_imports(vuln)
    for ancestor in decision.imported_ancestors:
        found = reachability.find_imports_for(ancestor)
        if not found:
            found = [f"{ancestor} (run as a command or referenced in project files)"]
        sites += [s for s in found if s not in sites]
    return sites
