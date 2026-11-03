"""Data models for vulnerability findings and triage verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
    """Triage verdict after all filters run."""

    ACTION = "action"  # Fix this now
    REVIEW = "review"  # Worth looking at, not urgent
    FILTERED = "filtered"  # Safe to ignore


class FilterReason(Enum):
    """Why a vulnerability was filtered out."""

    UNREACHABLE = "unreachable"
    DEV_DEPENDENCY = "dev_dependency"
    LOW_EPSS = "low_epss"
    COMMUNITY_TEMPLATE = "community_template"
    IGNORED = "ignored"


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
    # Which functions in the package are vulnerable (from advisory)
    vulnerable_functions: list[str] = field(default_factory=list)
    # Whether it's a direct or transitive dependency
    is_direct: bool = True
    # Whether it's a devDependency
    is_dev: bool = False
    # Depth in dependency tree (0 = direct)
    depth: int = 0

    @property
    def key(self) -> str:
        return f"{self.cve}:{self.package}"


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

    @property
    def reason_summary(self) -> str:
        if not self.reasons:
            return "reachable, exploitable"
        return ", ".join(r.value.replace("_", " ") for r in self.reasons)


@dataclass
class ScanResult:
    """Aggregate result of a full scan."""

    project_path: str
    package_manager: str
    total_dependencies: int
    results: list[TriageResult]

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
