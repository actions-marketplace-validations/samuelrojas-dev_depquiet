"""Data models for vulnerability findings and triage verdicts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_str(cls, s: str) -> Severity:
        return cls(s.lower()) if s.lower() in cls._value2member_map_ else cls.MODERATE


class Verdict(Enum):
    """Remediation priority, independent of proven product impact."""

    ACTION = "action"  # Fix this now
    REVIEW = "review"  # Worth looking at, not urgent
    FILTERED = "filtered"  # Deprioritized or suppressed; impact remains unverified


class FilterReason(Enum):
    """Why a vulnerability was filtered out."""

    UNREACHABLE = "unreachable"
    # Imported, but only from test files and test-runner configuration.
    TEST_ONLY = "test_only"
    DEV_DEPENDENCY = "dev_dependency"
    LOW_EPSS = "low_epss"
    COMMUNITY_TEMPLATE = "community_template"
    IGNORED = "ignored"


@dataclass
class ComponentEvidence:
    """A lockfile-resolved candidate, not an observed runtime installation.

    ``range_match`` is matched, not_matched or unknown against an advisory
    range. It never establishes product impact or actual execution.
    """

    ecosystem: str
    package: str
    version: str
    location: str
    lockfile: str
    lockfile_sha256: str
    range_match: str = "unknown"
    reason: str = ""

    @property
    def instance_id(self) -> str:
        identity = {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "location": self.location,
            "lockfile": self.lockfile,
        }
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "component-sha256:" + hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {
            "instance_id": self.instance_id,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "location": self.location,
            "lockfile": self.lockfile,
            "lockfile_sha256": self.lockfile_sha256,
            "range_match": self.range_match,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ComponentEvidence:
        fields = ("ecosystem", "package", "version", "location", "lockfile", "lockfile_sha256")
        if not isinstance(raw, dict) or any(
            not isinstance(raw.get(name), str) or not raw[name] for name in fields
        ):
            raise ValueError("Invalid component evidence: nonempty string fields are required")
        if re.fullmatch(r"[a-fA-F0-9]{64}", raw["lockfile_sha256"]) is None:
            raise ValueError("Invalid component evidence: lockfile SHA-256 is required")
        match = raw.get("range_match", "unknown")
        if not isinstance(match, str) or match not in {"matched", "not_matched", "unknown"}:
            raise ValueError("Invalid component evidence: unknown range-match status")
        reason = raw.get("reason", "")
        if not isinstance(reason, str):
            raise ValueError("Invalid component evidence: reason must be a string")
        component = cls(
            ecosystem=raw["ecosystem"],
            package=raw["package"],
            version=raw["version"],
            location=raw["location"],
            lockfile=raw["lockfile"],
            lockfile_sha256=raw["lockfile_sha256"],
            range_match=match,
            reason=reason,
        )
        if "instance_id" in raw and raw["instance_id"] != component.instance_id:
            raise ValueError("Invalid component evidence: instance ID conflicts with its fields")
        return component


@dataclass
class Vulnerability:
    """A single vulnerability finding from a scanner."""

    cve: str
    package: str
    version: str
    severity: Severity
    title: str = ""
    url: str = ""
    fix_version: str = ""
    # Package to upgrade to get ``fix_version`` when it isn't this package
    # (npm audit: the fix for a transitive package is often a new version of
    # the direct dependency that pulls it in). Empty means this package.
    fix_package: str = ""
    # Which functions in the package are vulnerable (from advisory)
    vulnerable_functions: list[str] = field(default_factory=list)
    # Whether it's a direct or transitive dependency
    is_direct: bool = True
    # Whether it's a devDependency
    is_dev: bool = False
    # Depth in dependency tree (0 = direct)
    depth: int = 0
    # Preserve the scanner's legacy version field while separately identifying
    # ranges and resolved lockfile candidates. Never infer an installed version.
    version_kind: str = "reported"
    advisory_range: str = ""
    components: list[ComponentEvidence] = field(default_factory=list)
    component_notes: list[str] = field(default_factory=list)
    component_resolution_complete: bool = False

    @property
    def key(self) -> str:
        return f"{self.cve}:{self.package}"

    @property
    def fix_label(self) -> str:
        """``4.17.21``, or ``express@4.22.3`` when the fix is upgrading another package."""
        if not self.fix_version:
            return ""
        return f"{self.fix_package}@{self.fix_version}" if self.fix_package else self.fix_version


@dataclass
class DecisionChange:
    """One priority decision, retained when a later rule overrides it."""

    source: str
    previous_verdict: Verdict | None
    verdict: Verdict
    rule_id: str = ""
    reason: str = ""
    path: str = ""
    author: str = ""
    expires: str = ""


@dataclass
class WorkspaceEvidence:
    """Dependency-name analysis in one declared workspace, not instance binding."""

    path: str
    relevance: str = "unknown"
    dependency_type: str = "unknown"
    usage: str = "unknown"
    dev_only: bool = False
    graph_coverage_complete: bool = False
    analysis_coverage_complete: bool = False
    introduced_by: list[str] = field(default_factory=list)
    import_sites: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Any) -> WorkspaceEvidence:
        if not isinstance(raw, dict) or not isinstance(raw.get("path"), str) or not raw["path"]:
            raise ValueError("Invalid workspace evidence: path is required")
        enums = {
            "relevance": {"dependency", "observed", "uncertain", "not_declared", "unknown"},
            "dependency_type": {"direct", "transitive", "unknown"},
            "usage": {"observed", "not_observed", "unknown"},
        }
        for name, allowed in enums.items():
            if not isinstance(raw.get(name), str) or raw[name] not in allowed:
                raise ValueError(f"Invalid workspace evidence: {name}")
        for name in ("dev_only", "graph_coverage_complete", "analysis_coverage_complete"):
            if type(raw.get(name)) is not bool:
                raise ValueError(f"Invalid workspace evidence: {name} must be boolean")
        arrays = {}
        for name in ("introduced_by", "import_sites", "observations"):
            value = raw.get(name, [])
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"Invalid workspace evidence: {name} must contain strings")
            arrays[name] = list(value)
        return cls(
            path=raw["path"],
            relevance=raw["relevance"],
            dependency_type=raw["dependency_type"],
            usage=raw["usage"],
            dev_only=raw["dev_only"],
            graph_coverage_complete=raw["graph_coverage_complete"],
            analysis_coverage_complete=raw["analysis_coverage_complete"],
            introduced_by=arrays["introduced_by"],
            import_sites=arrays["import_sites"],
            observations=arrays["observations"],
        )


@dataclass
class DependencyEvidence:
    """Observations from dependency analysis, not proof of exploitability."""

    analysis: str = "dependency_imports"
    usage: str = "unknown"  # observed | not_observed | unknown
    import_sites: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    # None on legacy saved reports whose coverage was not recorded.
    graph_coverage_complete: bool | None = None
    analysis_coverage_complete: bool | None = None
    workspace_contexts: list[WorkspaceEvidence] = field(default_factory=list)


@dataclass
class TriageResult:
    """Result of triaging a single vulnerability."""

    vuln: Vulnerability
    verdict: Verdict
    reasons: list[FilterReason] = field(default_factory=list)
    epss_score: float | None = None
    epss_percentile: float | None = None
    reachable_imports: list[str] = field(default_factory=list)
    template_id: str | None = None
    template_reason: str | None = None
    kev_entry: Any = None  # KevEntry when CVE is in the CISA KEV catalog
    # "direct", "transitive" or "unknown", from the project's manifests and
    # lockfiles (see depquiet.depgraph); "" when reachability wasn't evaluated.
    dependency_type: str = ""
    # For transitive packages: the direct dependencies that pull them in.
    introduced_by: list[str] = field(default_factory=list)
    evidence: DependencyEvidence = field(default_factory=DependencyEvidence)
    decision_trace: list[DecisionChange] = field(default_factory=list)

    @property
    def reason_summary(self) -> str:
        if not self.reasons:
            return "no automatic filter matched; product impact unverified"
        return ", ".join(r.value.replace("_", " ") for r in self.reasons)


@dataclass
class ScanResult:
    """Aggregate result of a full scan."""

    project_path: str
    package_manager: str
    total_dependencies: int
    results: list[TriageResult]
    # False when nothing was scanned (no supported project found). An empty
    # result must never read as "no vulnerabilities" in that case.
    scanned: bool = True
    note: str = ""
    project_id: str = ""

    @property
    def action(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.ACTION]

    @property
    def review(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.REVIEW]

    @property
    def filtered(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.FILTERED]

    @property
    def filter_rate(self) -> float:
        return len(self.filtered) / len(self.results) * 100 if self.results else 0
