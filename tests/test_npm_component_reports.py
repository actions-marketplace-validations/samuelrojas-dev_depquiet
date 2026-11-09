"""Keep scanner range context separate from auditable lockfile candidates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from depquiet.cli import _print_json, main
from depquiet.engine import scan
from depquiet.explain import explain_triage, find_cve_in_json, format_explanation
from depquiet.models import ComponentEvidence


@pytest.fixture
def project_and_audit(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"fixture-lib": "1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "app.js").write_text("require('fixture-lib');\n", encoding="utf-8")
    locations = ["node_modules/fixture-lib", "node_modules/parent/node_modules/fixture-lib"]
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"fixture-lib": "1.0.0"}},
            locations[0]: {"version": "1.0.0"},
            locations[1]: {"version": "2.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    audit = {
        "vulnerabilities": {
            "fixture-lib": {
                "severity": "high",
                "isDirect": True,
                "nodes": locations,
                "via": [
                    {
                        "title": "Invented component-report advisory",
                        "url": "https://example.invalid/advisories/SYNTHETIC-COMPONENT",
                        "range": "<2.0.0",
                    }
                ],
            }
        }
    }
    return tmp_path, audit


def test_json_and_saved_explanation_preserve_resolved_evidence(project_and_audit, capsys):
    project, audit = project_and_audit
    result = scan(project, audit_json=audit, skip_epss=True)
    _print_json(result)
    saved = json.loads(capsys.readouterr().out)
    [row] = saved["results"]
    assert row["version"] == "<2.0.0"  # Existing report identity remains compatible.
    assert row["version_kind"] == "advisory_range"
    assert row["advisory_range"] == "<2.0.0"
    assert row["component_resolution_complete"] is True
    components = {component["version"]: component for component in row["components"]}
    assert set(components) == {"1.0.0", "2.0.0"}
    assert components["1.0.0"]["range_match"] == "matched"
    assert components["2.0.0"]["range_match"] == "not_matched"
    digest = hashlib.sha256((project / "package-lock.json").read_bytes()).hexdigest()
    assert all(component["lockfile_sha256"] == digest for component in components.values())
    assert len({component["instance_id"] for component in components.values()}) == 2
    restored = find_cve_in_json(saved, row["cve"])
    assert restored is not None
    assert [component.to_dict() for component in restored.vuln.components] == row["components"]
    assert explain_triage(restored).to_dict() == explain_triage(result.results[0]).to_dict()
    text = format_explanation(explain_triage(restored))
    assert "Advisory range: <2.0.0" in text
    assert "fixture-lib@1.0.0" in text and "fixture-lib@2.0.0" in text
    assert "Package: fixture-lib@<2.0.0" not in text
    assert row["assessment"]["status"] == "under_investigation"
    assert any("installed" in note for note in row["assessment"]["limitations"])


def test_unresolved_candidates_do_not_invent_versions(project_and_audit):
    project, audit = project_and_audit
    (project / "package-lock.json").unlink()
    [finding] = scan(project, audit_json=audit, skip_epss=True).results
    assert finding.vuln.version_kind == "advisory_range"
    assert finding.vuln.components == []
    assert finding.vuln.component_resolution_complete is False
    assert finding.vuln.component_notes
    assert finding.vuln.version == "<2.0.0"
    explanation = explain_triage(finding)
    assert explanation.assessment["status"] == "under_investigation"
    assert "Component evidence:" in format_explanation(explanation)


@pytest.mark.parametrize("invalid_range", [None, [], 42])
def test_malformed_advisory_range_preserves_candidates_as_unknown(project_and_audit, invalid_range):
    project, audit = project_and_audit
    audit["vulnerabilities"]["fixture-lib"]["via"][0]["range"] = invalid_range
    [finding] = scan(project, audit_json=audit, skip_epss=True).results
    assert finding.vuln.version == ""
    assert len(finding.vuln.components) == 2
    assert {component.range_match for component in finding.vuln.components} == {"unknown"}
    assert finding.vuln.component_resolution_complete is True
    assert any("malformed" in note for note in finding.vuln.component_notes)


def test_partial_resolution_is_not_presented_as_complete(project_and_audit):
    project, audit = project_and_audit
    missing = "node_modules/unresolved-parent/node_modules/fixture-lib"
    audit["vulnerabilities"]["fixture-lib"]["nodes"].append(missing)
    [finding] = scan(project, audit_json=audit, skip_epss=True).results
    assert finding.vuln.component_resolution_complete is False
    assert len(finding.vuln.components) == 2
    assert any(missing in note for note in finding.vuln.component_notes)


def test_instance_identity_tracks_location_not_advisory_or_lockfile_revision():
    component = ComponentEvidence(
        "npm", "fixture-lib", "1.0.0", "node_modules/fixture-lib", "package-lock.json", "a" * 64
    )
    relocated = replace(component, location="node_modules/parent/node_modules/fixture-lib")
    rescored = replace(component, range_match="matched", lockfile_sha256="b" * 64)
    assert component.instance_id != relocated.instance_id
    assert component.instance_id == rescored.instance_id
    assert ComponentEvidence.from_dict(component.to_dict()) == component


def test_forged_saved_instance_identity_is_rejected(project_and_audit, tmp_path, capsys):
    project, audit = project_and_audit
    _print_json(scan(project, audit_json=audit, skip_epss=True))
    saved = json.loads(capsys.readouterr().out)
    saved["results"][0]["components"][0]["version"] = "99.0.0"
    source = tmp_path / "saved.json"
    source.write_text(json.dumps(saved), encoding="utf-8")
    assert main(["explain", "SYNTHETIC-COMPONENT", "--from-json", str(source), "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "instance ID" in output.err
