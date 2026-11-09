"""Project-scoped diff behavior for lockfile instances and unresolved contexts."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from depquiet.diff import diff_scans, diff_to_json, format_diff, format_diff_markdown
from depquiet.models import ComponentEvidence

SCOPE = "example/monorepo:service-a"


def _component(
    version: str = "1.2.3",
    location: str = "node_modules/fixture-lib",
    *,
    match: str = "matched",
    digest: str = "a" * 64,
) -> dict:
    return ComponentEvidence(
        "npm", "fixture-lib", version, location, "package-lock.json", digest, range_match=match
    ).to_dict()


def _finding(
    components: list[dict], *, complete: bool = True, notes: list[str] | None = None
) -> dict:
    return {
        "cve": "SYNTHETIC-INSTANCE-DIFF",
        "package": "fixture-lib",
        "version": "<3.0.0",
        "severity": "high",
        "title": "Synthetic instance comparison",
        "verdict": "action",
        "version_kind": "advisory_range",
        "advisory_range": "<3.0.0",
        "components": components,
        "component_resolution_complete": complete,
        "component_notes": notes or [],
    }


def _reported(version: str = "1.2.3") -> dict:
    return {
        "cve": "SYNTHETIC-REPORTED-DIFF",
        "package": "fixture-lib",
        "version": version,
        "severity": "high",
        "verdict": "action",
    }


def _write(
    tmp_path: Path,
    name: str,
    rows: list[dict],
    *,
    scope: str | None = SCOPE,
    manager: str = "npm",
    scanned: bool | None = True,
) -> Path:
    data = {"project": "same/local/path", "package_manager": manager, "results": rows}
    if scope is not None:
        data["project_id"] = scope
    if scanned is not None:
        data["scanned"] = scanned
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("new_version", ["1.2.3", "2.0.0"])
def test_added_location_or_version_is_new_action_context(tmp_path, new_version):
    original = _component()
    introduced = _component(new_version, "node_modules/parent/node_modules/fixture-lib")
    base = _write(tmp_path, "base.json", [_finding([original])])
    head = _write(tmp_path, "head.json", [_finding([original, introduced])])
    result = diff_scans(base, head)
    assert result.identity_mode == "instances" and result.project_id == SCOPE
    assert result.unchanged == 1 and result.has_new_action
    assert len(result.new) == 1 and not result.fixed and not result.changed
    new = result.new[0]
    assert new.instance_id == introduced["instance_id"]
    assert new.version == new_version and new.advisory_range == "<3.0.0"
    assert new.location == introduced["location"] and new.identity_kind == "component"
    output = diff_to_json(result)
    assert output["count_unit"] == "finding_contexts"
    assert output["summary"]["new"] == 1 and output["new"][0]["context_id"] == new.context_id
    assert introduced["location"] in format_diff(result)
    assert introduced["location"] in format_diff_markdown(result)


def test_same_location_new_version_remains_new_not_unchanged(tmp_path):
    base = _write(tmp_path, "base.json", [_finding([_component("1.2.3")])])
    head = _write(tmp_path, "head.json", [_finding([_component("2.0.0")])])
    result = diff_scans(base, head)
    assert result.new[0].version == "2.0.0" and result.fixed[0].version == "1.2.3"
    assert result.has_new_action and result.unchanged == 0
    assert diff_to_json(result)["fixed_meaning"] == "context_absent_from_head"
    assert "Contexts absent from head" in format_diff(result)


def test_reordered_instances_and_raw_lock_hash_change_do_not_create_new_context(tmp_path):
    first = _component()
    second = _component(location="node_modules/parent/node_modules/fixture-lib")
    base = _write(tmp_path, "base.json", [_finding([first, second])])
    head = _write(
        tmp_path,
        "head.json",
        [
            _finding(
                [{**second, "lockfile_sha256": "b" * 64}, {**first, "lockfile_sha256": "b" * 64}]
            )
        ],
    )
    result = diff_scans(base, head)
    assert result.unchanged == 2 and not result.has_changes
    assert "No finding context changes" in format_diff(result)
    assert "No finding context changes" in format_diff_markdown(result)
    assert "scan results are identical" not in format_diff(result)


def test_same_instance_verdict_change_preserves_its_context_and_location(tmp_path):
    row = _finding([_component()])
    base = _write(tmp_path, "base.json", [{**row, "verdict": "review"}])
    head = _write(tmp_path, "head.json", [row])
    result = diff_scans(base, head)
    assert len(result.changed) == 1 and not result.new and not result.fixed
    changed = result.changed[0]
    assert changed.previous_verdict == "review" and changed.verdict == "action"
    assert changed.version == "1.2.3" and changed.context_id and changed.instance_id


def test_distinct_instance_rows_do_not_collapse_to_the_same_legacy_tuple(tmp_path):
    first = _component()
    second = _component(location="node_modules/parent/node_modules/fixture-lib")
    base = _write(tmp_path, "base.json", [_finding([first, second])])
    head = _write(tmp_path, "head.json", [_finding([first]), _finding([second])])
    result = diff_scans(base, head)
    assert result.unchanged == 2 and not result.has_changes


def test_unknown_to_matched_association_changes_context_without_proving_remediation(tmp_path):
    base = _write(tmp_path, "base.json", [_finding([_component(match="unknown")])])
    head = _write(tmp_path, "head.json", [_finding([_component(match="matched")])])
    result = diff_scans(base, head)
    assert len(result.new) == len(result.fixed) == 1 and result.unchanged == 0
    assert result.new[0].instance_id == result.fixed[0].instance_id
    assert result.new[0].context_id != result.fixed[0].context_id
    assert result.new[0].range_match == "matched" and result.fixed[0].range_match == "unknown"
    assert result.unresolved_contexts == 0
    assert "Absent contexts do not prove remediation" in format_diff(result)


def test_partial_resolution_expands_known_candidate_and_visible_unresolved_residual(tmp_path):
    base = _write(tmp_path, "base.json", [])
    head = _write(
        tmp_path, "head.json", [_finding([_component()], complete=False, notes=["Missing node."])]
    )
    result = diff_scans(base, head)
    assert len(result.new) == 2 and result.unresolved_contexts == 1
    residual = next(finding for finding in result.new if finding.identity_kind == "unresolved")
    assert residual.version == "" and residual.advisory_range == "<3.0.0"
    assert residual.range_match == "unknown" and not residual.instance_id
    assert diff_to_json(result)["summary"]["unresolved_contexts"] == 1
    assert "unresolved association" in format_diff(result)


@pytest.mark.parametrize("kind", ["all_outside", "unknown_range", "empty_reported_version"])
def test_uncertainty_is_visible_without_claiming_nonaffected_product(tmp_path, kind):
    manager = "npm"
    if kind == "all_outside":
        row = _finding([_component("3.0.0", match="not_matched")])
    elif kind == "unknown_range":
        row = _finding([_component(match="unknown")])
    else:
        row, manager = _reported(""), "pip"
    base = _write(tmp_path, "base.json", [], manager=manager)
    head = _write(tmp_path, "head.json", [row], manager=manager)
    result = diff_scans(base, head)
    assert len(result.new) == 1 and result.unresolved_contexts == 1
    assert result.new[0].verdict == "action"
    assert "status" not in diff_to_json(result)["new"][0]
    if kind == "all_outside":
        assert result.new[0].identity_kind == "unresolved" and not result.new[0].instance_id


def test_disappearing_uncertain_context_is_only_reported_absent(tmp_path):
    base = _write(tmp_path, "base.json", [_finding([], complete=False)])
    head = _write(tmp_path, "head.json", [_finding([_component()])])
    result = diff_scans(base, head)
    assert result.fixed[0].identity_kind == "unresolved" and len(result.new) == 1
    for output in (format_diff(result), format_diff_markdown(result)):
        assert "Absent contexts do not prove remediation" in output
        assert "Contexts absent from head" in output
        assert "Fixed findings" not in output


@pytest.mark.parametrize("mode", [None, False, True])
def test_different_declared_scopes_are_never_compared_even_in_legacy_mode(tmp_path, mode):
    base = _write(tmp_path, "base.json", [], scope="org/service-a")
    head = _write(tmp_path, "head.json", [], scope="org/service-b")
    with pytest.raises(ValueError, match="different project_id"):
        diff_scans(base, head, instance_aware=mode)


def test_one_missing_scope_needs_explicit_mapping_or_explicit_legacy_mode(tmp_path):
    row = _finding([_component()])
    base = _write(tmp_path, "base.json", [row])
    head = _write(tmp_path, "head.json", [row], scope=None)
    with pytest.raises(ValueError, match="Only one report"):
        diff_scans(base, head)
    with pytest.raises(ValueError, match="both reports"):
        diff_scans(base, head, instance_aware=True)
    mapped = diff_scans(base, head, project_id=SCOPE)
    assert mapped.identity_mode == "instances" and mapped.unchanged == 1
    legacy = diff_scans(base, head, instance_aware=False)
    assert legacy.identity_mode == "legacy" and legacy.unchanged == 1


@pytest.mark.parametrize("mode", [None, False, True])
def test_explicit_mapping_cannot_replace_declared_scope(tmp_path, mode):
    base = _write(tmp_path, "base.json", [])
    head = _write(tmp_path, "head.json", [], scope=None)
    with pytest.raises(ValueError, match="conflicts"):
        diff_scans(base, head, project_id="org/different", instance_aware=mode)


def test_force_instance_mode_cannot_infer_scope_from_checkout_path(tmp_path):
    row = _finding([_component()])
    base = _write(tmp_path, "base.json", [row], scope=None)
    head = _write(tmp_path, "head.json", [row], scope=None)
    with pytest.raises(ValueError, match="project_id"):
        diff_scans(base, head, instance_aware=True)
    result = diff_scans(base, head, project_id=SCOPE, instance_aware=True)
    assert result.unchanged == 1 and result.project_id == SCOPE


def test_legacy_npm_metadata_requires_rescan_or_explicit_legacy_mode(tmp_path):
    base = _write(tmp_path, "base.json", [_reported()])
    head = _write(tmp_path, "head.json", [_reported()])
    with pytest.raises(ValueError, match="rescan or use legacy"):
        diff_scans(base, head)
    result = diff_scans(base, head, instance_aware=False)
    assert result.identity_mode == "legacy" and result.unchanged == 1
    payload = diff_to_json(result)
    assert set(payload) == {"summary", "new", "fixed", "changed"}


@pytest.mark.parametrize(
    "previous, introduced",
    [("1.2.3", "2.0.0"), ("1.2.3+build.1", "1.2.3+build.2")],
)
def test_explicit_reported_versions_in_npm_projects_stay_literal_and_trigger_new_action(
    tmp_path, previous, introduced
):
    original = {**_reported(previous), "version_kind": "reported"}
    additional = {**_reported(introduced), "version_kind": "reported"}
    base = _write(tmp_path, "base.json", [original], manager="npm")
    head = _write(tmp_path, "head.json", [original, additional], manager="npm")

    result = diff_scans(base, head)
    assert result.identity_mode == "instances" and result.project_id == SCOPE
    assert result.unchanged == 1 and result.has_new_action
    assert len(result.new) == 1 and not result.fixed
    new = result.new[0]
    assert new.version == introduced and new.identity_kind == "reported"
    assert new.context_id and not new.instance_id
    assert not new.location and not new.advisory_range and not new.range_match
    assert diff_to_json(result)["new"][0]["version"] == introduced


def test_unscoped_old_reports_keep_legacy_output_and_missing_scanned_support(tmp_path):
    base = _write(tmp_path, "base.json", [_reported()], scope=None, scanned=None)
    head = _write(tmp_path, "head.json", [_reported()], scope=None, scanned=None)
    result = diff_scans(base, head)
    assert result.identity_mode == "legacy" and result.unchanged == 1
    assert "scan results are identical" in format_diff(result)
    assert "project_id" not in diff_to_json(result)


def test_instance_mode_requires_explicit_completion_flag(tmp_path):
    row = _finding([_component()])
    base = _write(tmp_path, "base.json", [row], scanned=None)
    head = _write(tmp_path, "head.json", [row])
    with pytest.raises(ValueError, match="complete scan"):
        diff_scans(base, head)


def test_reported_non_npm_versions_stay_literal_and_project_scoped(tmp_path):
    base = _write(tmp_path, "base.json", [_reported("1.0.0")], manager="pip")
    head = _write(tmp_path, "head.json", [_reported("2.0.0")], manager="pip")
    result = diff_scans(base, head)
    assert result.new[0].version == "2.0.0" and result.fixed[0].version == "1.0.0"
    assert result.new[0].identity_kind == "reported" and not result.new[0].instance_id


@pytest.mark.parametrize(
    "defect",
    [
        "forged_instance",
        "duplicate_component",
        "duplicate_context",
        "conflicting_range",
        "conflicting_package",
    ],
)
def test_invalid_instance_metadata_is_rejected_before_comparison(tmp_path, defect):
    row = _finding([_component()])
    rows = [copy.deepcopy(row)]
    if defect == "forged_instance":
        rows[0]["components"][0]["instance_id"] = "component-sha256:" + "0" * 64
    elif defect == "duplicate_component":
        rows[0]["components"].append(copy.deepcopy(rows[0]["components"][0]))
    elif defect == "duplicate_context":
        rows.append(copy.deepcopy(row))
    elif defect == "conflicting_range":
        rows[0]["advisory_range"] = "<9.0.0"
    else:
        rows[0]["package"] = "different-package"
    base = _write(tmp_path, "base.json", [row])
    head = _write(tmp_path, "head.json", rows)
    with pytest.raises(ValueError):
        diff_scans(base, head)
