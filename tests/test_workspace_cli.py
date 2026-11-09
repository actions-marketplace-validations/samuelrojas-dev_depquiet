"""The public CLI preserves workspace boundaries and uncertainty evidence."""

from __future__ import annotations

import io
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from depquiet.cli import main
from depquiet.engine import scan
from depquiet.explain import explain_triage, find_cve_in_json, format_explanation
from depquiet.models import FilterReason, Verdict


def _npm_audit():
    return {
        "vulnerabilities": {
            "fixture-lib": {
                "severity": "high",
                "isDirect": True,
                "isDev": True,
                "via": [
                    {
                        "title": "Synthetic workspace coverage",
                        "url": "https://example.invalid/advisories/TEST-WORKSPACE",
                        "range": "<3.0.0",
                    }
                ],
            }
        }
    }


def _npm_workspace(root: Path):
    (root / "package.json").write_text(
        json.dumps(
            {
                "workspaces": ["apps/region/services/production"],
                "devDependencies": {"fixture-lib": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (root / "root.js").write_text("console.log('root');\n", encoding="utf-8")
    member = root / "apps" / "region" / "services" / "production"
    member.mkdir(parents=True)
    (member / "package.json").write_text(
        json.dumps({"name": "production", "dependencies": {"fixture-lib": "1.0.0"}}),
        encoding="utf-8",
    )
    (member / "app.js").write_text("require('fixture-lib');\n", encoding="utf-8")
    return member


def test_cli_roundtrip_keeps_independent_workspace_evidence(tmp_path, monkeypatch, capsys):
    member = _npm_workspace(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_npm_audit())))
    assert (
        main(
            [
                "--path",
                str(tmp_path),
                "--stdin",
                "--offline",
                "--json",
                "--project-id",
                "fixture/workspace",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    [row] = report["results"]
    assert row["verdict"] == "action"
    assert "dev_dependency" not in row["reasons"]
    assert row["assessment"]["status"] == "under_investigation"
    contexts = {item["path"]: item for item in row["evidence"]["workspace_contexts"]}
    assert contexts["."]["usage"] == "not_observed"
    assert contexts["."]["dev_only"] is True
    production = member.relative_to(tmp_path).as_posix()
    assert contexts[production]["usage"] == "observed"
    assert contexts[production]["dev_only"] is False
    assert contexts[production]["import_sites"] == [str(member / "app.js")]
    assert contexts["."]["import_sites"] == []

    restored = find_cve_in_json(report, row["cve"])
    assert restored is not None
    assert asdict(restored.evidence) == row["evidence"]
    explanation = format_explanation(explain_triage(restored))
    assert f"Workspace {production}: direct; usage=observed" in explanation
    saved = tmp_path / "scan.json"
    saved.write_text(json.dumps(report), encoding="utf-8")
    assert main(["explain", row["cve"], "--from-json", str(saved), "--json"]) == 0
    explained = json.loads(capsys.readouterr().out)
    assert explained["evidence"] == row["evidence"]


def test_unresolved_python_loader_keeps_alert_and_records_location(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="service"\nversion="1.0"\ndependencies=["fixture-lib"]\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from importlib import import_module as load\nimport os\nload(os.environ['PLUGIN'])\n",
        encoding="utf-8",
    )
    audit = {
        "dependencies": [
            {
                "name": "fixture-lib",
                "version": "1.0",
                "vulns": [{"id": "TEST-DYNAMIC", "description": "Synthetic", "fix_versions": []}],
            }
        ]
    }
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert FilterReason.UNREACHABLE not in finding.reasons
    assert finding.evidence.usage == "unknown"
    assert finding.evidence.analysis_coverage_complete is False
    assert any("app.py:3" in note for note in finding.evidence.observations)


def test_missing_declared_member_is_incomplete_analysis_not_empty_scan(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "package.json").write_text(
        json.dumps({"workspaces": ["missing-service"], "devDependencies": {"fixture-lib": "1.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_text("console.log(1);\n", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_npm_audit())))
    assert main(["--path", str(tmp_path), "--stdin", "--offline", "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["scanned"] is True
    [row] = report["results"]
    assert row["verdict"] == "action"
    assert row["evidence"]["graph_coverage_complete"] is False
    assert any("missing-service" in note for note in row["evidence"]["observations"])


@pytest.mark.parametrize(
    "field", ["dev_only", "graph_coverage_complete", "analysis_coverage_complete"]
)
def test_saved_workspace_coverage_cannot_be_a_truthy_string(tmp_path, field):
    _npm_workspace(tmp_path)
    finding = scan(tmp_path, audit_json=_npm_audit(), skip_epss=True).results[0]
    raw = asdict(finding.evidence)
    raw["workspace_contexts"][0][field] = "true"
    report = {
        "results": [
            {
                "cve": "TEST-WORKSPACE",
                "verdict": "action",
                "evidence": raw,
            }
        ]
    }
    with pytest.raises(ValueError, match="workspace evidence"):
        find_cve_in_json(report, "TEST-WORKSPACE")
