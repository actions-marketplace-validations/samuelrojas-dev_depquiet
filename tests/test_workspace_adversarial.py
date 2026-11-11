"""End-to-end regressions reproduced against the pre-workspace engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.engine import scan
from depquiet.models import FilterReason, Verdict


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _json(path: Path, data):
    _write(path, json.dumps(data))


def _npm():
    return {
        "vulnerabilities": {
            "fixture-lib": {
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "title": "Synthetic workspace regression",
                        "url": "https://example.invalid/advisories/TEST-WORKSPACE-ADVERSARIAL",
                    }
                ],
            }
        }
    }


def _pip():
    return {
        "dependencies": [
            {
                "name": "fixture-lib",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "TEST-WORKSPACE-ADVERSARIAL",
                        "description": "Synthetic",
                        "fix_versions": [],
                    }
                ],
            }
        ]
    }


@pytest.mark.parametrize("ecosystem", ["npm", "uv"])
def test_moving_declared_production_member_deeper_preserves_action(tmp_path, ecosystem):
    for depth in ("member", "apps/region/services/deeper/member"):
        project = tmp_path / depth.replace("/", "-")
        member = project / depth
        if ecosystem == "npm":
            _json(
                project / "package.json",
                {
                    "name": "root",
                    "workspaces": [depth],
                    "devDependencies": {"fixture-lib": "1"},
                },
            )
            _json(
                member / "package.json",
                {
                    "name": "production",
                    "dependencies": {"fixture-lib": "1"},
                },
            )
            _write(project / "app.js", "console.log('root');")
            _write(member / "app.js", "require('fixture-lib');")
            audit = _npm()
        else:
            _write(
                project / "pyproject.toml",
                '[project]\nname="root"\n'
                '[dependency-groups]\ndev=["fixture-lib"]\n'
                f'[tool.uv.workspace]\nmembers=["{depth}"]\n',
            )
            _write(
                member / "pyproject.toml",
                '[project]\nname="production"\ndependencies=["fixture-lib"]\n',
            )
            _write(project / "app.py", "print('root')")
            _write(member / "app.py", "import fixture_lib")
            audit = _pip()
        result = scan(project, audit_json=audit, skip_epss=True)
        assert result.scanned
        [finding] = result.results
        assert finding.verdict == Verdict.ACTION
        assert finding.evidence.usage == "observed"
        assert FilterReason.DEV_DEPENDENCY not in finding.reasons
        contexts = {item.path: item for item in finding.evidence.workspace_contexts}
        assert contexts[depth].usage == "observed"
        assert not contexts[depth].dev_only


def test_unrelated_npm_manifest_cannot_classify_a_pypi_name_as_dev_only(tmp_path):
    _write(tmp_path / "pyproject.toml", '[project]\nname="service"\ndependencies=["fixture-lib"]\n')
    _write(tmp_path / "app.py", "import fixture_lib")
    _json(tmp_path / "examples/demo/package.json", {"devDependencies": {"fixture-lib": "1"}})
    [finding] = scan(tmp_path, audit_json=_pip(), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert finding.dependency_type == "direct"
    assert not finding.reasons


def test_unreadable_member_cannot_turn_production_use_into_dev_only(tmp_path, monkeypatch):
    _json(
        tmp_path / "package.json",
        {
            "workspaces": ["packages/*"],
            "devDependencies": {"fixture-lib": "1"},
        },
    )
    manifest = tmp_path / "packages/api/package.json"
    _json(manifest, {"dependencies": {"fixture-lib": "1"}})
    _write(tmp_path / "app.js", "console.log('root');")
    _write(manifest.parent / "app.js", "require('fixture-lib');")
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path == manifest:
            raise PermissionError("synthetic unreadable production declaration")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    result = scan(tmp_path, audit_json=_npm(), skip_epss=True)
    assert result.scanned
    [finding] = result.results
    assert finding.verdict == Verdict.ACTION
    assert finding.evidence.usage == "observed"
    assert finding.evidence.graph_coverage_complete is False
    assert not finding.reasons
    assert any("packages/api/package.json" in note for note in finding.evidence.observations)


@pytest.mark.parametrize("positive", ["source", "command"])
def test_sibling_usage_stays_local_and_keeps_aggregate_alert(tmp_path, positive):
    _json(tmp_path / "package.json", {"name": "root", "workspaces": ["packages/*"]})
    for member in ("a", "b"):
        data = {"name": member, "dependencies": {"fixture-lib": "1"}}
        if member == "b" and positive == "command":
            data["scripts"] = {"start": "fixture-lib"}
        _json(tmp_path / f"packages/{member}/package.json", data)
        _write(tmp_path / f"packages/{member}/app.js", "console.log('unused');")
    if positive == "source":
        _write(tmp_path / "packages/b/app.js", "require('fixture-lib');")
    [finding] = scan(tmp_path, audit_json=_npm(), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    contexts = {item.path: item for item in finding.evidence.workspace_contexts}
    assert contexts["packages/a"].usage == "not_observed"
    assert contexts["packages/a"].import_sites == []
    assert contexts["packages/b"].usage == "observed"
    assert finding.evidence.usage == "observed"


def test_conditional_template_cannot_use_another_members_absence(tmp_path):
    _json(tmp_path / "package.json", {"workspaces": ["packages/*"]})
    for member in ("a", "b"):
        _json(
            tmp_path / f"packages/{member}/package.json",
            {
                "name": member,
                "dependencies": {"fixture-lib": "1"},
            },
        )
        _write(tmp_path / f"packages/{member}/app.js", "console.log('unused');")
    _write(tmp_path / "packages/b/app.js", "require('fixture-lib');")
    templates = tmp_path / "templates"
    _write(
        templates / "conditional.yaml",
        "id: synthetic-workspace-condition\n"
        "cves: [TEST-WORKSPACE-ADVERSARIAL]\npackage: fixture-lib\n"
        "not-imported: [dangerous]\nreason: Synthetic absence condition\n",
    )
    [finding] = scan(tmp_path, audit_json=_npm(), skip_epss=True, template_dirs=[templates]).results
    assert finding.verdict == Verdict.ACTION
    assert FilterReason.COMMUNITY_TEMPLATE not in finding.reasons


def test_nested_workspace_is_excluded_even_when_scan_root_is_relative(tmp_path, monkeypatch):
    _json(tmp_path / "package.json", {"workspaces": ["packages/a", "packages/a/child"]})
    for member in ("packages/a", "packages/a/child"):
        _json(
            tmp_path / member / "package.json",
            {
                "name": member.replace("/", "-"),
                "dependencies": {"fixture-lib": "1"},
            },
        )
        _write(tmp_path / member / "app.js", "console.log('unused');")
    _write(tmp_path / "packages/a/child/app.js", "require('fixture-lib');")
    monkeypatch.chdir(tmp_path)
    [finding] = scan(Path("."), audit_json=_npm(), skip_epss=True).results
    contexts = {item.path: item for item in finding.evidence.workspace_contexts}
    assert contexts["packages/a"].usage == "not_observed"
    assert contexts["packages/a"].import_sites == []
    assert contexts["packages/a/child"].usage == "observed"
    assert finding.verdict == Verdict.ACTION
