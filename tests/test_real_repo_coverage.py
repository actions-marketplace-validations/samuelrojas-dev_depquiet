"""Layouts found in large public repositories must not disable every filter.

Each case here made the dependency graph "incomplete" on a well-known project
(Kong/insomnia, saleor, open-webui, wekan), which kept every alert, including
the ones ``npm audit --omit=dev`` drops. The rules that remain are the ones
that can hide a path to a reported package.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.explain import explain_triage
from depquiet.models import ComponentEvidence, FilterReason, Verdict


def _json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")


def _audit(package: str, nodes: list[str], advisory_range: str = "<2.0.0") -> dict[str, Any]:
    return {
        "vulnerabilities": {
            package: {
                "severity": "high",
                "isDirect": False,
                "nodes": nodes,
                "via": [
                    {
                        "title": "Synthetic",
                        "url": "https://example.invalid/advisories/TEST-REAL-REPO",
                        "range": advisory_range,
                    }
                ],
            }
        }
    }


# -- symlinks ---------------------------------------------------------------


def test_linked_file_that_is_not_a_manifest_keeps_the_graph_complete(tmp_path: Path) -> None:
    _json(tmp_path / "package.json", {"devDependencies": {"tool": "1"}})
    (tmp_path / "AGENTS.md").write_text("notes", encoding="utf-8")
    _symlink(tmp_path / "CLAUDE.md", tmp_path / "AGENTS.md")
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    assert graph.is_dev_only(["tool"])


def test_linked_manifest_still_leaves_the_graph_incomplete(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _json(outside / "package.json", {"dependencies": {"tool": "1"}})
    project = tmp_path / "project"
    _json(project / "package.json", {"devDependencies": {"tool": "1"}})
    _symlink(project / "api" / "package.json", outside / "package.json")
    graph = DependencyGraph.from_project(project)
    assert not graph.coverage_complete
    assert not graph.is_dev_only(["tool"])


def test_linked_directory_still_leaves_the_graph_incomplete(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _json(outside / "package.json", {"dependencies": {"tool": "1"}})
    project = tmp_path / "project"
    _json(project / "package.json", {"devDependencies": {"tool": "1"}})
    _symlink(project / "api", outside)
    graph = DependencyGraph.from_project(project)
    assert not graph.coverage_complete


# -- npm aliases ------------------------------------------------------------


def test_alias_install_is_a_path_to_the_real_package(tmp_path: Path) -> None:
    _json(tmp_path / "package.json", {"dependencies": {"cli": "1"}, "devDependencies": {"t": "1"}})
    _json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"cli": "1"}, "devDependencies": {"t": "1"}},
                "node_modules/cli": {"version": "1.0.0", "dependencies": {"width-cjs": "1"}},
                "node_modules/width-cjs": {"name": "width", "version": "1.0.0"},
                "node_modules/t": {"version": "1.0.0", "dev": True},
            },
        },
    )
    graph = DependencyGraph.from_project(tmp_path)
    # Advisories name ``width``; only the alias appears in ``cli``'s dependencies.
    assert graph.direct_ancestors("width") == {"cli"}
    assert not graph.is_dev_only(sorted(graph.direct_ancestors("width")))


# -- ecosystem scope --------------------------------------------------------


def test_npm_report_ignores_a_crate_with_the_same_name(tmp_path: Path) -> None:
    _json(tmp_path / "package.json", {"devDependencies": {"linter": "1"}})
    _json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"devDependencies": {"linter": "1"}},
                # No ``dev`` flags: the verdict has to come from the graph.
                "node_modules/linter": {"version": "1.0.0", "dependencies": {"glob": "1"}},
                "node_modules/glob": {"version": "1.0.0"},
            },
        },
    )
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = ["glob"]\n\n'
        '[[package]]\nname = "glob"\nversion = "0.3.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text("console.log(1)", encoding="utf-8")
    [finding] = scan(
        tmp_path, audit_json=_audit("glob", ["node_modules/glob"]), skip_epss=True
    ).results
    assert finding.verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in finding.reasons
    assert finding.introduced_by == ["linter"]
    assert finding.vuln.components[0].lock_scope == "production"


# -- lockfile dev flag per copy ---------------------------------------------


def _two_copies(tmp_path: Path, *, dev_copy_flag: dict[str, Any]) -> None:
    _json(
        tmp_path / "package.json",
        {"dependencies": {"uuid": "11"}, "devDependencies": {"runner": "1"}},
    )
    _json(
        tmp_path / "package-lock.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"uuid": "11"}, "devDependencies": {"runner": "1"}},
                "node_modules/uuid": {"version": "11.0.0"},
                "node_modules/runner": {
                    "version": "1.0.0",
                    "dev": True,
                    "dependencies": {"uuid": "1"},
                },
                "node_modules/runner/node_modules/uuid": {"version": "1.0.0", **dev_copy_flag},
            },
        },
    )
    (tmp_path / "index.js").write_text("require('uuid')", encoding="utf-8")


def test_vulnerable_copy_installed_only_for_development_is_filtered(tmp_path: Path) -> None:
    """Production uses uuid 11; the advisory covers the copy a dev tool pins."""
    _two_copies(tmp_path, dev_copy_flag={"dev": True})
    audit = _audit("uuid", ["node_modules/runner/node_modules/uuid"])
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.FILTERED
    assert finding.reasons == [FilterReason.DEV_DEPENDENCY]
    assert finding.vuln.components[0].lock_scope == "development"
    assert any("development-only" in note for note in finding.evidence.observations)
    # ``uuid`` is also a production dependency: the explanation cites the copy.
    signal = next(s for s in explain_triage(finding).signals if s.name == "Dependency type")
    assert signal.effect == "filtered"
    assert "1.0.0 at node_modules/runner/node_modules/uuid" in signal.detail


@pytest.mark.parametrize("flag", [{}, {"devOptional": True}, {"optional": True}, {"dev": "true"}])
def test_copy_not_marked_dev_is_kept(tmp_path: Path, flag: dict[str, Any]) -> None:
    _two_copies(tmp_path, dev_copy_flag=flag)
    audit = _audit("uuid", ["node_modules/runner/node_modules/uuid"])
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert not finding.reasons


def test_one_affected_production_copy_keeps_the_alert(tmp_path: Path) -> None:
    _two_copies(tmp_path, dev_copy_flag={"dev": True})
    audit = _audit(
        "uuid", ["node_modules/uuid", "node_modules/runner/node_modules/uuid"], "<12.0.0"
    )
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert not finding.reasons


def test_unresolved_node_keeps_the_alert(tmp_path: Path) -> None:
    _two_copies(tmp_path, dev_copy_flag={"dev": True})
    audit = _audit(
        "uuid", ["node_modules/runner/node_modules/uuid", "node_modules/gone/node_modules/uuid"]
    )
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert not finding.vuln.component_resolution_complete


def test_lock_scope_round_trips_and_rejects_unknown_values() -> None:
    component = ComponentEvidence(
        ecosystem="npm",
        package="uuid",
        version="1.0.0",
        location="node_modules/uuid",
        lockfile="package-lock.json",
        lockfile_sha256="a" * 64,
        lock_scope="development",
    )
    raw = component.to_dict()
    assert ComponentEvidence.from_dict(raw).lock_scope == "development"
    legacy = {key: value for key, value in raw.items() if key != "lock_scope"}
    assert ComponentEvidence.from_dict(legacy).lock_scope == ""
    with pytest.raises(ValueError, match="lock scope"):
        ComponentEvidence.from_dict({**raw, "lock_scope": "dev"})


# -- workspaces -------------------------------------------------------------


def test_member_using_an_undeclared_root_dev_tool_does_not_make_it_production(
    tmp_path: Path,
) -> None:
    _json(
        tmp_path / "package.json",
        {"name": "root", "workspaces": ["packages/*"], "devDependencies": {"runner": "1"}},
    )
    _json(tmp_path / "packages/app/package.json", {"name": "app", "dependencies": {"lib": "1"}})
    (tmp_path / "packages/app/app.test.js").write_text("require('runner')", encoding="utf-8")
    (tmp_path / "packages/app/index.js").write_text("require('lib')", encoding="utf-8")
    audit = {
        "vulnerabilities": {
            "runner": {
                "severity": "high",
                "isDirect": True,
                "via": [{"title": "Synthetic", "url": "https://example.invalid/TEST-WS-DEV"}],
            }
        }
    }
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in finding.reasons


def test_member_declaring_it_for_production_keeps_the_alert(tmp_path: Path) -> None:
    _json(
        tmp_path / "package.json",
        {"name": "root", "workspaces": ["packages/*"], "devDependencies": {"runner": "1"}},
    )
    _json(tmp_path / "packages/app/package.json", {"name": "app", "dependencies": {"runner": "1"}})
    (tmp_path / "packages/app/index.js").write_text("require('runner')", encoding="utf-8")
    audit = {
        "vulnerabilities": {
            "runner": {
                "severity": "high",
                "isDirect": True,
                "via": [{"title": "Synthetic", "url": "https://example.invalid/TEST-WS-PROD"}],
            }
        }
    }
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert not finding.reasons


# -- scanner choice ---------------------------------------------------------


def test_chosen_scanner_reports_the_other_ecosystem_as_not_scanned(
    tmp_path: Path, monkeypatch
) -> None:
    import depquiet.engine as engine

    _json(tmp_path / "package.json", {"dependencies": {}})
    _json(tmp_path / "package-lock.json", {"lockfileVersion": 3, "packages": {"": {}}})
    (tmp_path / "pyproject.toml").write_text('[project]\nname="svc"\n', encoding="utf-8")
    seen: list[str | None] = []

    def fake(pm, project, *, offline):
        seen.append(pm)
        return [], str(pm), ""

    monkeypatch.setattr(engine, "_run_scanner", fake)
    chosen = scan(tmp_path, skip_epss=True, scanner="pip")
    assert seen == ["pip"]
    assert "npm" in chosen.note and "--scanner npm" in chosen.note
    assert chosen.package_manager == "pip"
