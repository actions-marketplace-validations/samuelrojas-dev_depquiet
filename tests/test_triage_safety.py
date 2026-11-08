"""Regressions for dependencies used outside their declared parent path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.models import FilterReason, Severity, Verdict, Vulnerability


def _npm_project(project: Path, source: str, *, command: bool = False) -> None:
    manifest: dict[str, object] = {"dependencies": {"unused-parent": "1.0.0"}}
    if command:
        manifest["scripts"] = {"start": "child serve"}
    (project / "package.json").write_text(json.dumps(manifest))
    (project / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": manifest,
                    "node_modules/unused-parent": {"dependencies": {"child": "1.0.0"}},
                    "node_modules/child": {"version": "1.0.0"},
                },
            }
        )
    )
    (project / "app.js").write_text(source)


@pytest.mark.parametrize(
    "source,command",
    [
        ("const dep = require('child'); dep.run();\n", False),
        ("import { run } from 'child'; run();\n", False),
        ("const pluginName = 'child';\n", False),
        ("console.log('started by package script');\n", True),
    ],
)
def test_transitive_used_without_its_declared_parent_is_kept(
    tmp_path: Path, source: str, command: bool
) -> None:
    _npm_project(tmp_path, source, command=command)
    audit = {
        "vulnerabilities": {
            "child": {
                "severity": "high",
                "isDirect": False,
                "via": [{"title": "A finding", "url": "https://github.com/advisories/GHSA-test"}],
            }
        }
    }
    [result] = scan(tmp_path, skip_epss=True, audit_json=audit).results
    assert result.verdict == Verdict.ACTION
    assert FilterReason.UNREACHABLE not in result.reasons
    assert result.introduced_by == ["unused-parent"]


def test_python_import_of_transitive_is_kept(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["unused-parent"]\n')
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname="unused-parent"\nversion="1"\n[package.dependencies]\nchild="*"\n'
    )
    (tmp_path / "app.py").write_text("import child\nchild.run()\n")
    graph = DependencyGraph.from_project(tmp_path)
    vuln = Vulnerability("TEST-1", "child", "1", Severity.HIGH)
    decision = ReachabilityFilter(tmp_path).decide(vuln, graph)
    assert decision.dependency_type == "transitive"
    assert decision.unreachable is False


def test_truly_unused_transitive_still_filters(tmp_path: Path) -> None:
    _npm_project(tmp_path, "console.log('no packages');\n")
    vuln = Vulnerability("TEST-1", "child", "1", Severity.HIGH)
    decision = ReachabilityFilter(tmp_path).decide(vuln, DependencyGraph.from_project(tmp_path))
    assert decision.unreachable is True
