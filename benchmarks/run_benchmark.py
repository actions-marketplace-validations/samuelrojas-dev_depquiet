"""Run depquiet benchmarks.

Two kinds of scenario:

- **Real** (``fixtures/real-*/``): a project with a lockfile resolved by the
  real package manager and the real audit output for it, captured by
  ``capture_real.py``. These back every number quoted in the README.
- **Synthetic** (``fixtures/*.json``): hand-written audit output for parsers
  we can't capture here (pip-audit, Trivy, Grype images). They have no
  lockfiles, so transitive packages can't be traced and are correctly left
  unfiltered. Useful as regression tests, not as evidence.

Each real scenario gets a per-alert table so every verdict can be checked.

Run:  python -I benchmarks/run_benchmark.py
Output: benchmarks/RESULTS.md, benchmarks/results.json
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from depquiet.engine import scan
from depquiet.models import ScanResult, Verdict

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BENCH_DIR = Path(__file__).resolve().parent

SYNTHETIC = [
    ("npm-express-app", "npm"),
    ("pip-django-app", "pip"),
    ("trivy-node-container", "trivy"),
    ("grype-python-container", "grype"),
]


@dataclass
class BenchResult:
    name: str
    parser: str
    kind: str  # "real" | "synthetic"
    total: int
    action: int
    review: int
    filtered: int
    filter_rate: float
    reasons: dict[str, int]
    elapsed_ms: float
    alerts: list[dict[str, object]] = field(default_factory=list)
    meta: dict[str, object] = field(default_factory=dict)


def _summarize(
    name: str, parser: str, kind: str, result: ScanResult, elapsed: float
) -> BenchResult:
    action = sum(1 for r in result.results if r.verdict == Verdict.ACTION)
    review = sum(1 for r in result.results if r.verdict == Verdict.REVIEW)
    filtered = sum(1 for r in result.results if r.verdict == Verdict.FILTERED)
    total = len(result.results)
    reasons: dict[str, int] = {}
    for r in result.results:
        for reason in r.reasons:
            reasons[reason.value] = reasons.get(reason.value, 0) + 1
    alerts = [
        {
            "package": r.vuln.package,
            "advisory": r.vuln.cve,
            "severity": r.vuln.severity.value,
            "dependency_type": r.dependency_type,
            "introduced_by": r.introduced_by,
            "verdict": r.verdict.value,
            "reasons": [x.value for x in r.reasons],
        }
        for r in sorted(result.results, key=lambda r: (r.vuln.package, r.vuln.cve))
    ]
    return BenchResult(
        name=name,
        parser=parser,
        kind=kind,
        total=total,
        action=action,
        review=review,
        filtered=filtered,
        filter_rate=filtered / total * 100 if total else 0,
        reasons=reasons,
        elapsed_ms=round(elapsed, 2),
        alerts=alerts,
    )


def _timed_scan(project: Path, audit_json: dict[str, object]) -> tuple[ScanResult, float]:
    t0 = time.perf_counter()
    result = scan(project=project, epss_threshold=0.1, skip_epss=True, audit_json=audit_json)
    return result, (time.perf_counter() - t0) * 1000


def run_real(fixture_dir: Path) -> BenchResult:
    audit_json = json.loads((fixture_dir / "audit.json").read_text())
    meta = json.loads((fixture_dir / "meta.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp) / "project"
        shutil.copytree(fixture_dir / "project", project)
        result, elapsed = _timed_scan(project, audit_json)
    r = _summarize(fixture_dir.name, "npm", "real", result, elapsed)
    r.meta = meta
    return r


def run_synthetic(name: str, parser: str) -> BenchResult:
    audit_json = json.loads((FIXTURES / f"{name}.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        project = Path(tmp)
        source = FIXTURES / f"{name}.source.json"
        if source.exists():
            for fname, content in json.loads(source.read_text()).items():
                (project / fname).write_text(content)
        result, elapsed = _timed_scan(project, audit_json)
    return _summarize(name, parser, "synthetic", result, elapsed)


def _summary_table(results: list[BenchResult]) -> list[str]:
    lines = [
        "| Scenario | Parser | Total | Action | Review | Filtered | Filter rate | Time |",
        "|----------|--------|------:|-------:|-------:|---------:|------------:|-----:|",
    ]
    for r in results:
        lines.append(
            f"| {r.name} | {r.parser} | {r.total} | {r.action} | {r.review} "
            f"| {r.filtered} | **{r.filter_rate:.0f}%** | {r.elapsed_ms:.0f}ms |"
        )
    lines += [
        "",
        "| Scenario | Unreachable | Dev-only | Low EPSS | Template |",
        "|----------|------------:|---------:|---------:|---------:|",
    ]
    for r in results:
        lines.append(
            f"| {r.name} "
            f"| {r.reasons.get('unreachable', 0)} "
            f"| {r.reasons.get('dev_dependency', 0)} "
            f"| {r.reasons.get('low_epss', 0)} "
            f"| {r.reasons.get('community_template', 0)} |"
        )
    return lines


def _alert_table(r: BenchResult) -> list[str]:
    lines = [
        "| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |",
        "|---------|----------|----------|------|--------------|---------|--------|",
    ]
    for a in r.alerts:
        via = a["introduced_by"]
        assert isinstance(via, list)
        reasons = a["reasons"]
        assert isinstance(reasons, list)
        lines.append(
            f"| {a['package']} | {a['advisory']} | {a['severity']} | {a['dependency_type']} "
            f"| {', '.join(via) or '-'} | {a['verdict']} "
            f"| {', '.join(str(x).replace('_', ' ') for x in reasons) or '-'} |"
        )
    return lines


def main() -> None:
    real = [run_real(d) for d in sorted(FIXTURES.glob("real-*")) if d.is_dir()]
    synthetic = [run_synthetic(name, parser) for name, parser in SYNTHETIC]

    lines = [
        "# depquiet benchmark results",
        "",
        "Offline mode (no EPSS API), all filters active. Only **real** scenarios back the",
        "numbers in the README.",
        "",
        "## Real projects",
        "",
        "Lockfile resolved and audited by the real package manager (`capture_real.py`).",
        "",
    ]
    lines += _summary_table(real)
    for r in real:
        lines += [
            "",
            f"### {r.name}",
            "",
            f"Captured {r.meta.get('captured_at', '?')} with {r.meta.get('tool', '?')}. "
            "Each row is one alert from `npm audit`.",
            "",
        ]
        lines += _alert_table(r)

    lines += [
        "",
        "## Synthetic fixtures",
        "",
        "Hand-written audit output with no lockfile. Without a lockfile depquiet cannot trace",
        "transitive packages to the dependencies that pull them in, so it does not filter",
        "them on reachability. Kept as parser regression tests, not as evidence.",
        "",
    ]
    lines += _summary_table(synthetic)
    lines += ["", "*Generated by `benchmarks/run_benchmark.py`. Do not edit by hand.*"]

    report = "\n".join(lines) + "\n"
    (BENCH_DIR / "RESULTS.md").write_text(report)

    def as_json(r: BenchResult) -> dict[str, object]:
        return {
            "name": r.name,
            "kind": r.kind,
            "parser": r.parser,
            "total": r.total,
            "action": r.action,
            "review": r.review,
            "filtered": r.filtered,
            "filter_rate_pct": round(r.filter_rate, 1),
            "reasons": r.reasons,
            "elapsed_ms": r.elapsed_ms,
            "alerts": r.alerts,
            "meta": r.meta,
        }

    real_total = sum(r.total for r in real)
    real_filtered = sum(r.filtered for r in real)
    json_out = {
        "scenarios": [as_json(r) for r in real + synthetic],
        "real_overall": {
            "total_alerts": real_total,
            "total_filtered": real_filtered,
            "filter_rate_pct": round(real_filtered / real_total * 100, 1) if real_total else 0,
        },
    }
    (BENCH_DIR / "results.json").write_text(json.dumps(json_out, indent=2) + "\n")

    print(report)
    print(f"Wrote: {BENCH_DIR / 'RESULTS.md'}")
    print(f"Wrote: {BENCH_DIR / 'results.json'}")


if __name__ == "__main__":
    main()
