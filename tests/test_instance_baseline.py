"""Instance acceptance is scoped, conservative, and applied atomically."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from depquiet.baseline import (
    InstanceBaseline,
    ScopedLegacyBaseline,
    apply_baseline,
    create_baseline,
    load_baseline,
)
from depquiet.finding_identity import report_for_scan
from depquiet.models import (
    ComponentEvidence,
    DecisionChange,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)


def _component(
    version: str = "1.0.0",
    location: str = "node_modules/example",
    range_match: str = "matched",
    digest: str = "a" * 64,
) -> ComponentEvidence:
    return ComponentEvidence(
        ecosystem="npm",
        package="example",
        version=version,
        location=location,
        lockfile="package-lock.json",
        lockfile_sha256=digest,
        range_match=range_match,
    )


def _scan(
    *components: ComponentEvidence,
    complete: bool = True,
    scope: str = "org/service",
    advisory_range: str = "<2.0.0",
) -> ScanResult:
    return ScanResult(
        project_path=".",
        project_id=scope,
        package_manager="npm",
        total_dependencies=10,
        results=[
            TriageResult(
                vuln=Vulnerability(
                    cve="GHSA-example",
                    package="example",
                    version=advisory_range,
                    severity=Severity.HIGH,
                    version_kind="advisory_range",
                    advisory_range=advisory_range,
                    components=list(components or [_component()]),
                    component_resolution_complete=complete,
                ),
                verdict=Verdict.ACTION,
            )
        ],
    )


def _load(tmp_path: Path, data: dict[str, Any]) -> InstanceBaseline:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    baseline = load_baseline(path)
    assert isinstance(baseline, InstanceBaseline)
    return baseline


def _baseline(tmp_path: Path, scan: ScanResult | None = None) -> InstanceBaseline:
    return _load(tmp_path, create_baseline(report_for_scan(scan or _scan())))


def test_all_exact_contexts_accepted_and_prior_trace_preserved(tmp_path: Path) -> None:
    scan = _scan(_component(), _component("1.1.0", "node_modules/parent/node_modules/example"))
    prior = DecisionChange("triage", None, Verdict.REVIEW)
    scan.results[0].verdict = Verdict.REVIEW
    scan.results[0].decision_trace.append(prior)
    data = create_baseline(
        report_for_scan(scan), reason="Accepted through the next release", author="security-team"
    )
    baseline = _load(tmp_path, data)

    stats = apply_baseline(scan, baseline, source_path="security/accepted.json")

    assert stats.known_findings == 1
    assert stats.new_findings == 0
    assert scan.results[0].verdict is Verdict.FILTERED
    assert scan.results[0].decision_trace[0] is prior
    trace = scan.results[0].decision_trace[-1]
    assert trace.source == "baseline"
    assert trace.previous_verdict is Verdict.REVIEW
    assert trace.path == "security/accepted.json"
    assert trace.author == "security-team"
    assert trace.rule_id.startswith("baseline:v2:")
    assert all(context_id in trace.rule_id for context_id in baseline.accepted)
    assert "Accepted through the next release" in trace.reason
    assert "impact" not in trace.reason
    assert apply_baseline(scan, baseline).known_findings == 0
    assert len(scan.results[0].decision_trace) == 2


@pytest.mark.parametrize(
    "component,advisory_range",
    [
        (_component("1.1.0"), "<2.0.0"),
        (_component(location="node_modules/parent/node_modules/example"), "<2.0.0"),
        (_component(), "<=1.0.0"),
    ],
)
def test_new_version_location_or_range_stays_visible(
    tmp_path: Path, component: ComponentEvidence, advisory_range: str
) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan(component, advisory_range=advisory_range)
    assert apply_baseline(scan, baseline).known_findings == 0
    assert scan.results[0].verdict is Verdict.ACTION


def test_new_component_in_existing_row_keeps_entire_row_visible(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan(_component(), _component("1.1.0", "node_modules/parent/node_modules/example"))
    assert apply_baseline(scan, baseline).known_findings == 0
    assert not scan.results[0].decision_trace


def test_unrelated_lock_digest_change_does_not_change_acceptance(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan(_component(digest="b" * 64))
    assert apply_baseline(scan, baseline).known_findings == 1


@pytest.mark.parametrize("complete,unknown", [(False, False), (True, True), (False, True)])
def test_partial_or_unknown_context_cannot_be_accepted(
    tmp_path: Path, complete: bool, unknown: bool
) -> None:
    baseline = _baseline(tmp_path)
    candidates = [_component()]
    if unknown:
        candidates.append(
            _component("1.1.0", "node_modules/parent/node_modules/example", "unknown")
        )
    scan = _scan(*candidates, complete=complete)
    data = create_baseline(report_for_scan(scan))
    assert data["accepted"] == []
    assert data["unaccepted"]
    assert all(entry["reason"] for entry in data["unaccepted"])
    assert apply_baseline(scan, baseline).known_findings == 0
    assert scan.results[0].verdict is Verdict.ACTION


def test_all_outside_candidates_remain_visible(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan(_component(range_match="not_matched"))
    data = create_baseline(report_for_scan(scan))
    assert data["accepted"] == []
    assert len(data["unaccepted"]) == 1
    assert "No resolved candidate matches" in data["unaccepted"][0]["reason"]
    assert apply_baseline(scan, baseline).known_findings == 0


def test_nonmatching_inventory_candidate_is_not_an_accepted_context(tmp_path: Path) -> None:
    scan = _scan(
        _component(), _component("3.0.0", "node_modules/parent/node_modules/example", "not_matched")
    )
    data = create_baseline(report_for_scan(scan))
    assert len(data["accepted"]) == 1
    assert data["accepted"][0]["component"]["version"] == "1.0.0"
    assert apply_baseline(scan, _load(tmp_path, data)).known_findings == 1


@pytest.mark.parametrize("scope", ["other/service", ""])
def test_scope_mismatch_or_missing_scope_fails_before_any_change(
    tmp_path: Path, scope: str
) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan(scope=scope)
    before = copy.deepcopy(scan)
    with pytest.raises(ValueError, match="project_id"):
        apply_baseline(scan, baseline)
    assert scan == before


def test_invalid_later_row_fails_without_partial_suppression(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan()
    bad = copy.deepcopy(scan.results[0])
    bad.vuln.cve = "GHSA-another"
    bad.vuln.version_kind = "unsupported"
    scan.results.append(bad)
    before = copy.deepcopy(scan)
    with pytest.raises(ValueError):
        apply_baseline(scan, baseline)
    assert scan == before


def test_reported_python_context_is_unaccepted(tmp_path: Path) -> None:
    scan = _scan()
    scan.package_manager = "python"
    scan.results[0].vuln.version_kind = "reported"
    data = create_baseline(report_for_scan(scan))
    assert data["accepted"] == []
    assert data["unaccepted"][0]["kind"] == "reported"
    assert apply_baseline(scan, _load(tmp_path, data)).known_findings == 0


def test_legacy_npm_report_requires_rescan_for_instance_acceptance() -> None:
    report = report_for_scan(_scan())
    del report["results"][0]["version_kind"]
    with pytest.raises(ValueError, match="rescan"):
        create_baseline(report)


def test_explicit_reported_npm_context_stays_unaccepted(tmp_path: Path) -> None:
    scan = _scan()
    scan.results[0].vuln.version_kind = "reported"
    scan.results[0].vuln.version = "1.0.0"
    data = create_baseline(report_for_scan(scan))
    assert data["accepted"] == []
    assert len(data["unaccepted"]) == 1
    assert data["unaccepted"][0]["kind"] == "reported"
    assert apply_baseline(scan, _load(tmp_path, data)).known_findings == 0
    assert scan.results[0].verdict is Verdict.ACTION
    assert not scan.results[0].decision_trace


@pytest.mark.parametrize("scanned", [False, None, "true", 1])
def test_creation_requires_explicit_complete_scan(scanned: Any) -> None:
    report = report_for_scan(_scan())
    report["scanned"] = scanned
    with pytest.raises(ValueError, match="incomplete"):
        create_baseline(report)


def test_apply_rejects_incomplete_scan(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    scan = _scan()
    scan.scanned = False
    with pytest.raises(ValueError, match="incomplete"):
        apply_baseline(scan, baseline)
    assert scan.results[0].verdict is Verdict.ACTION


def test_explicit_scope_binding_does_not_override_declared_scope() -> None:
    report = report_for_scan(_scan())
    with pytest.raises(ValueError, match="conflicts"):
        create_baseline(report, project_id="other/service")
    report["project_id"] = ""
    assert create_baseline(report, project_id="org/service")["project_id"] == "org/service"


def test_source_hash_distinguishes_bytes_from_canonical_json() -> None:
    report = report_for_scan(_scan())
    canonical = json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    data = create_baseline(report)
    assert data["source_scan_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert data["source_scan_hash_kind"] == "canonical_json"
    data = create_baseline(report, source_scan_sha256="b" * 64)
    assert data["source_scan_sha256"] == "b" * 64
    assert data["source_scan_hash_kind"] == "file_bytes"


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_scan_sha256", "not-a-digest"),
        ("source_scan_hash_kind", "raw-ish"),
        ("reason", 42),
        ("author", None),
        ("project_id", " org/service"),
    ],
)
def test_invalid_v2_metadata_is_rejected(tmp_path: Path, field: str, value: Any) -> None:
    data = create_baseline(report_for_scan(_scan()))
    data[field] = value
    with pytest.raises(ValueError):
        _load(tmp_path, data)


@pytest.mark.parametrize("version", [1, 3, "2", True, None])
def test_present_unknown_schema_version_never_downgrades_to_legacy(
    tmp_path: Path, version: Any
) -> None:
    data = create_baseline(report_for_scan(_scan()))
    data["baseline_schema_version"] = version
    with pytest.raises(ValueError, match="baseline_schema_version"):
        _load(tmp_path, data)


@pytest.mark.parametrize("field", ["context_id", "instance_id", "location", "lockfile_sha256"])
def test_forged_context_or_component_fields_are_rejected(tmp_path: Path, field: str) -> None:
    data = create_baseline(report_for_scan(_scan()))
    entry = data["accepted"][0]
    if field == "context_id":
        entry[field] = "finding-sha256:" + "0" * 64
    else:
        entry["component"][field] = "forged"
    with pytest.raises(ValueError):
        _load(tmp_path, data)


def test_accepted_duplicate_is_rejected(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan()))
    data["accepted"].append(copy.deepcopy(data["accepted"][0]))
    with pytest.raises(ValueError, match="duplicate accepted"):
        _load(tmp_path, data)


def test_duplicate_json_keys_are_rejected_for_v2(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan()))
    raw = json.dumps(data)
    path = tmp_path / "baseline.json"
    path.write_text(raw[:-1] + ', "project_id": "org/service"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON"):
        load_baseline(path)


def test_nested_duplicate_json_keys_are_rejected_for_v2(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan()))
    raw = json.dumps(data).replace('"ecosystem": "npm"', '"ecosystem": "npm", "ecosystem": "npm"')
    path = tmp_path / "baseline.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON"):
        load_baseline(path)


def test_nonfinite_json_values_are_rejected_for_v2(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan()))
    data["unaccepted"] = [{"reason": "informational", "score": float("nan")}]
    with pytest.raises(ValueError, match="non-finite JSON"):
        _load(tmp_path, data)


def test_instance_payload_cannot_silently_downgrade_without_schema_flag(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan()))
    del data["baseline_schema_version"]
    with pytest.raises(ValueError, match="baseline_schema_version"):
        _load(tmp_path, data)


def test_unknown_context_with_consistent_ids_cannot_be_loaded_as_accepted(tmp_path: Path) -> None:
    data = create_baseline(report_for_scan(_scan(_component(range_match="unknown"))))
    context = data["unaccepted"][0]
    data["accepted"] = [
        {
            key: context[key]
            for key in ("context_id", "advisory", "package", "advisory_range", "component")
        }
    ]
    with pytest.raises(ValueError, match="inconsistent"):
        _load(tmp_path, data)


@pytest.mark.parametrize("field", ["accepted", "unaccepted"])
def test_acceptance_lists_are_required(tmp_path: Path, field: str) -> None:
    data = create_baseline(report_for_scan(_scan()))
    del data[field]
    with pytest.raises(ValueError, match="arrays"):
        _load(tmp_path, data)


def test_legacy_baseline_preserves_broad_advisory_package_semantics(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"results": [{"cve": "GHSA-example", "package": "example"}]}))
    baseline = load_baseline(path)
    assert baseline == {"GHSA-example:example"}
    scan = _scan(_component("9.0.0"), scope="")
    assert apply_baseline(scan, baseline).known_findings == 1
    assert scan.results[0].decision_trace[-1].rule_id == "GHSA-example:example"


@pytest.mark.parametrize("scope", ["other/service", ""])
def test_scoped_legacy_baseline_cannot_cross_scope_or_infer_scope(
    tmp_path: Path, scope: str
) -> None:
    path = tmp_path / "legacy-scoped.json"
    path.write_text(
        json.dumps(
            {
                "project_id": "org/service",
                "results": [{"cve": "GHSA-example", "package": "example"}],
            }
        ),
        encoding="utf-8",
    )
    baseline = load_baseline(path)
    scan = _scan(scope=scope)
    before = copy.deepcopy(scan)
    with pytest.raises(ValueError, match="project_id"):
        apply_baseline(scan, baseline)
    assert scan == before


def test_scoped_legacy_baseline_preserves_advisory_package_matching(tmp_path: Path) -> None:
    path = tmp_path / "legacy-scoped.json"
    path.write_text(
        json.dumps(
            {
                "project_id": "org/service",
                "results": [{"cve": "GHSA-example", "package": "example"}],
            }
        ),
        encoding="utf-8",
    )
    baseline = load_baseline(path)
    assert isinstance(baseline, ScopedLegacyBaseline)
    assert baseline == {"GHSA-example:example"}
    assert baseline.project_id == "org/service"
    scan = _scan(_component("9.0.0"))
    assert apply_baseline(scan, baseline).known_findings == 1
    assert scan.results[0].verdict is Verdict.FILTERED
    assert scan.results[0].decision_trace[-1].rule_id == "GHSA-example:example"


@pytest.mark.parametrize("project_id", [" org/service", None, False, []])
def test_scoped_legacy_baseline_validates_declared_project_id(
    tmp_path: Path, project_id: Any
) -> None:
    path = tmp_path / "legacy-scoped.json"
    path.write_text(json.dumps({"project_id": project_id, "results": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="project_id"):
        load_baseline(path)


def test_duplicate_project_scope_cannot_downgrade_scoped_legacy_to_unscoped(tmp_path: Path) -> None:
    path = tmp_path / "legacy-scoped.json"
    path.write_text(
        '{"project_id":"org/service","project_id":"",'
        '"results":[{"cve":"GHSA-example","package":"example"}]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON"):
        load_baseline(path)


def test_unambiguous_empty_legacy_scope_preserves_plain_set(tmp_path: Path) -> None:
    path = tmp_path / "legacy-unscoped.json"
    path.write_text(
        json.dumps({"project_id": "", "results": [{"cve": "GHSA-example", "package": "example"}]}),
        encoding="utf-8",
    )
    baseline = load_baseline(path)
    assert type(baseline) is set
    assert baseline == {"GHSA-example:example"}
