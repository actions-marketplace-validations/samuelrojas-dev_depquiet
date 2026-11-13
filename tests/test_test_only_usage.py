"""A dependency imported only from test code is not used by the application.

Motivating case: a project declares ``axios`` under ``dependencies`` but only
its end-to-end tests import it. ``npm audit --omit=dev`` keeps every axios
advisory because the manifest says production; the source says otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.explain import explain_triage
from depquiet.filters.reachability import ReachabilityFilter, is_test_path
from depquiet.models import Severity, Verdict, Vulnerability


def _vuln(package: str) -> Vulnerability:
    return Vulnerability(
        cve="CVE-2025-0001", package=package, version="1.0.0", severity=Severity.HIGH
    )


def _project(tmp: Path, *, scripts: dict[str, str] | None = None) -> Path:
    """express (app code) and axios -> follow-redirects (declared production)."""
    deps = {"express": "^4.19.0", "axios": "^1.6.0"}
    (tmp / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": deps, "scripts": scripts or {}})
    )
    (tmp / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": deps},
                    "node_modules/express": {"version": "4.19.2"},
                    "node_modules/axios": {
                        "version": "1.6.0",
                        "dependencies": {"follow-redirects": "^1.15.0"},
                    },
                    "node_modules/follow-redirects": {"version": "1.15.0"},
                },
            }
        )
    )
    (tmp / "src").mkdir()
    (tmp / "src" / "app.js").write_text("const express = require('express');\nexpress();\n")
    (tmp / "e2e").mkdir()
    (tmp / "e2e" / "server.spec.ts").write_text("import axios from 'axios';\naxios.get('/');\n")
    return tmp


def _decide(project: Path, package: str):  # type: ignore[no-untyped-def]
    return ReachabilityFilter(project).decide(_vuln(package), DependencyGraph.from_project(project))


@pytest.mark.parametrize(
    "path",
    [
        "tests/unit/test_api.py",
        "e2e/src/server.spec.ts",
        "src/__tests__/a.js",
        "src/components/Button.test.tsx",
        "pkg/handler_test.go",
        "conftest.py",
        "jest.preset.js",
        "vitest.config.ts",
    ],
)
def test_test_paths_are_recognized(path: str) -> None:
    assert is_test_path(Path(path))


@pytest.mark.parametrize(
    "path",
    [
        "src/app.js",
        "src/testing/helpers.py",  # a package named "testing" may be application code
        "spec/openapi.js",  # API specifications live in "spec" too
        "src/latest.py",
        "src/contest.py",
        "webpack.config.js",
        "tests.py",  # Django test module at the top level is not a directory rule
    ],
)
def test_application_paths_are_not_tests(path: str) -> None:
    assert not is_test_path(Path(path))


class TestDecision:
    def test_direct_dependency_imported_only_from_tests(self, tmp_path: Path) -> None:
        d = _decide(_project(tmp_path), "axios")
        assert d.test_only is True
        assert d.unreachable is False
        assert d.dependency_type == "direct"

    def test_transitive_follows_its_test_only_parent(self, tmp_path: Path) -> None:
        d = _decide(_project(tmp_path), "follow-redirects")
        assert d.test_only is True
        assert d.imported_ancestors == ["axios"]

    def test_application_import_keeps_it(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        (project / "src" / "client.js").write_text("const axios = require('axios');\n")
        assert _decide(project, "axios").test_only is False
        assert _decide(project, "follow-redirects").test_only is False

    def test_dependency_used_by_the_app_is_untouched(self, tmp_path: Path) -> None:
        d = _decide(_project(tmp_path), "express")
        assert d.test_only is False and d.unreachable is False

    def test_mention_in_application_config_keeps_it(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        (project / "config.yml").write_text("http_client: axios\n")
        assert _decide(project, "axios").test_only is False

    def test_never_imported_stays_unreachable_not_test_only(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        (project / "e2e" / "server.spec.ts").write_text("export {};\n")
        d = _decide(project, "axios")
        assert d.unreachable is True and d.test_only is False

    def test_incomplete_graph_proves_nothing(self, tmp_path: Path) -> None:
        project = _project(tmp_path)
        graph = DependencyGraph.from_project(project)
        graph.coverage_complete = False
        d = ReachabilityFilter(project).decide(_vuln("axios"), graph)
        assert d.test_only is False


class TestScan:
    def _audit(self) -> dict[str, object]:
        def entry(name: str, direct: bool) -> dict[str, object]:
            return {
                "name": name,
                "severity": "high",
                "isDirect": direct,
                "via": [
                    {
                        "source": 1,
                        "name": name,
                        "title": "t",
                        "url": f"https://github.com/advisories/GHSA-{name[:4]}-aaaa-bbbb",
                        "severity": "high",
                        "range": "<9.0.0",
                    }
                ],
                "range": "<9.0.0",
                "nodes": [f"node_modules/{name}"],
                "fixAvailable": True,
            }

        return {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "axios": entry("axios", True),
                "follow-redirects": entry("follow-redirects", False),
                "express": entry("express", True),
            },
        }

    def test_scan_keeps_test_only_for_review_and_application_use_as_action(
        self, tmp_path: Path
    ) -> None:
        # Imported only from tests is no proof production never loads it (an
        # ORM loads its driver by dialect name), so it is reviewed, not hidden.
        result = scan(project=_project(tmp_path), skip_epss=True, audit_json=self._audit())
        by = {r.vuln.package: r for r in result.results}
        assert by["axios"].verdict == Verdict.REVIEW
        assert by["axios"].reasons == []
        assert by["follow-redirects"].verdict == Verdict.REVIEW
        assert by["express"].verdict == Verdict.ACTION
        assert any("test code" in note for note in by["axios"].evidence.observations)

    def test_explanation_names_the_test_files(self, tmp_path: Path) -> None:
        result = scan(project=_project(tmp_path), skip_epss=True, audit_json=self._audit())
        axios = next(r for r in result.results if r.vuln.package == "axios")
        signal = next(s for s in explain_triage(axios).signals if s.name == "Reachability")
        assert signal.value == "test_only"
        assert signal.effect == "review"
        assert "server.spec.ts" in signal.detail


class TestDependencyGroupIncludes:
    def _graph(self, tmp: Path, groups: str) -> DependencyGraph:
        (tmp / "pyproject.toml").write_text(
            '[project]\nname = "app"\nversion = "1"\ndependencies = ["django"]\n\n'
            "[dependency-groups]\n" + groups
        )
        (tmp / "app.py").write_text("import django\n")
        return DependencyGraph.from_project(tmp)

    def test_include_group_is_read(self, tmp_path: Path) -> None:
        graph = self._graph(
            tmp_path, 'dev = [{ include-group = "testing" }, "ruff"]\ntesting = ["pytest"]\n'
        )
        assert graph.coverage_complete is True
        assert graph.is_dev_only(["pytest"]) and graph.is_dev_only(["ruff"])
        assert not graph.is_dev_only(["django"])

    def test_include_of_missing_group_is_incomplete(self, tmp_path: Path) -> None:
        graph = self._graph(tmp_path, 'dev = [{ include-group = "nope" }]\n')
        assert graph.coverage_complete is False
