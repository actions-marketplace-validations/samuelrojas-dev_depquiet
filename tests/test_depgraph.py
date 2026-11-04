"""Tests for v0.28.0 transitive-aware reachability.

The motivating bug: an Express app imports ``express`` but never
``path-to-regexp``. Before v0.28.0 depquiet marked path-to-regexp CVEs as
unreachable, even though Express calls it on every request.
"""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.models import FilterReason, Severity, Verdict, Vulnerability


def _vuln(package: str, **kw: object) -> Vulnerability:
    defaults: dict[str, object] = {
        "cve": "CVE-2024-45296",
        "package": package,
        "version": "0.1.7",
        "severity": Severity.HIGH,
    }
    defaults.update(kw)
    return Vulnerability(**defaults)  # type: ignore[arg-type]


def _express_app(tmp: Path, *, import_express: bool = True, lockfile: bool = True) -> Path:
    """Minimal Express project: express -> path-to-regexp, express -> qs."""
    (tmp / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"express": "^4.19.0", "lodash": "^4.17.0"}})
    )
    if lockfile:
        (tmp / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "app",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"express": "^4.19.0", "lodash": "^4.17.0"}},
                        "node_modules/express": {
                            "version": "4.19.2",
                            "dependencies": {"path-to-regexp": "0.1.7", "qs": "6.11.0"},
                        },
                        "node_modules/path-to-regexp": {"version": "0.1.7"},
                        "node_modules/qs": {
                            "version": "6.11.0",
                            "dependencies": {"side-channel": "^1.0.4"},
                        },
                        "node_modules/side-channel": {"version": "1.0.4"},
                        "node_modules/lodash": {"version": "4.17.20"},
                    },
                }
            )
        )
    src = "const express = require('express');\n" if import_express else "console.log(1);\n"
    (tmp / "app.js").write_text(src + "const app = express();\n")
    return tmp


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------


class TestTransitiveRegression:
    def test_transitive_of_imported_dep_is_reachable(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        rf = ReachabilityFilter(project)
        graph = DependencyGraph.from_project(project)
        d = rf.decide(_vuln("path-to-regexp"), graph)
        assert d.unreachable is False
        assert d.dependency_type == "transitive"
        assert d.introduced_by == ["express"]
        assert d.imported_ancestors == ["express"]

    def test_old_import_check_alone_would_have_filtered_it(self, tmp_path: Path) -> None:
        """Documents the bug: the import primitive says 'not imported'."""
        project = _express_app(tmp_path)
        assert ReachabilityFilter(project).check(_vuln("path-to-regexp")) is True

    def test_deep_transitive_follows_the_chain(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        d = ReachabilityFilter(project).decide(
            _vuln("side-channel"), DependencyGraph.from_project(project)
        )
        assert d.unreachable is False
        assert d.introduced_by == ["express"]

    def test_transitive_of_unused_dep_is_unreachable(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path, import_express=False)
        d = ReachabilityFilter(project).decide(
            _vuln("path-to-regexp"), DependencyGraph.from_project(project)
        )
        assert d.unreachable is True
        assert d.imported_ancestors == []

    def test_unused_direct_dep_still_filtered(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        d = ReachabilityFilter(project).decide(
            _vuln("lodash"), DependencyGraph.from_project(project)
        )
        assert d.unreachable is True
        assert d.dependency_type == "direct"

    def test_direct_dep_also_pulled_by_imported_dep_is_reachable(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        pkg = json.loads((project / "package.json").read_text())
        pkg["dependencies"]["qs"] = "^6.11.0"  # declared but never imported
        (project / "package.json").write_text(json.dumps(pkg))
        d = ReachabilityFilter(project).decide(_vuln("qs"), DependencyGraph.from_project(project))
        assert d.dependency_type == "direct"
        assert d.unreachable is False
        assert d.imported_ancestors == ["express"]

    def test_transitive_without_lockfile_is_not_filtered(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path, import_express=False, lockfile=False)
        d = ReachabilityFilter(project).decide(
            _vuln("path-to-regexp"), DependencyGraph.from_project(project)
        )
        assert d.dependency_type == "unknown"
        assert d.unreachable is False

    def test_no_manifest_at_all_is_not_filtered(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text("console.log(1);\n")
        d = ReachabilityFilter(tmp_path).decide(
            _vuln("lodash"), DependencyGraph.from_project(tmp_path)
        )
        assert d.dependency_type == "unknown"
        assert d.unreachable is False

    def test_scanner_says_transitive_without_graph(self, tmp_path: Path) -> None:
        (tmp_path / "app.js").write_text("console.log(1);\n")
        d = ReachabilityFilter(tmp_path).decide(
            _vuln("qs", is_direct=False), DependencyGraph.from_project(tmp_path)
        )
        assert d.dependency_type == "transitive"
        assert d.unreachable is False

    def test_no_source_files_never_filters(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        (project / "app.js").unlink()
        d = ReachabilityFilter(project).decide(
            _vuln("path-to-regexp"), DependencyGraph.from_project(project)
        )
        assert d.unreachable is False


class TestEngineIntegration:
    def _audit(self) -> dict[str, object]:
        return {
            "auditReportVersion": 2,
            "vulnerabilities": {
                "path-to-regexp": {
                    "name": "path-to-regexp",
                    "severity": "high",
                    "isDirect": False,
                    "via": [
                        {
                            "source": 1,
                            "title": "path-to-regexp outputs backtracking regular expressions",
                            "url": "https://github.com/advisories/GHSA-9wv6-86v2-598j",
                            "range": "<0.1.10",
                        }
                    ],
                    "fixAvailable": {"name": "express", "version": "4.21.0"},
                }
            },
        }

    def test_scan_keeps_path_to_regexp_in_express_app(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path)
        result = scan(project, skip_epss=True, audit_json=self._audit())
        [tr] = result.results
        assert FilterReason.UNREACHABLE not in tr.reasons
        assert tr.verdict == Verdict.ACTION
        assert tr.dependency_type == "transitive"
        assert tr.introduced_by == ["express"]
        # Import site points at where the app imports express.
        assert any(s.endswith("app.js") for s in tr.reachable_imports)

    def test_scan_filters_when_parent_unused(self, tmp_path: Path) -> None:
        project = _express_app(tmp_path, import_express=False)
        result = scan(project, skip_epss=True, audit_json=self._audit())
        [tr] = result.results
        assert FilterReason.UNREACHABLE in tr.reasons


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


class TestNpmLoaders:
    def test_package_lock_v1_requires(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "express": {"version": "4.17.1", "requires": {"qs": "6.7.0"}},
                        "qs": {"version": "6.7.0"},
                    },
                }
            )
        )
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4"}}))
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("qs") == "transitive"
        assert g.direct_ancestors("qs") == {"express"}

    def test_scoped_packages(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"@nestjs/core": "^10"}},
                        "node_modules/@nestjs/core": {"dependencies": {"path-to-regexp": "3.2.0"}},
                        "node_modules/@nestjs/core/node_modules/path-to-regexp": {},
                    }
                }
            )
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("@nestjs/core") == "direct"
        assert g.direct_ancestors("path-to-regexp") == {"@nestjs/core"}

    def test_yarn_v1(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4"}}))
        (tmp_path / "yarn.lock").write_text(
            "# yarn lockfile v1\n\n"
            'express@^4:\n  version "4.19.2"\n  dependencies:\n'
            '    path-to-regexp "0.1.7"\n    qs "6.11.0"\n\n'
            'path-to-regexp@0.1.7:\n  version "0.1.7"\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.direct_ancestors("path-to-regexp") == {"express"}

    def test_yarn_berry(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"@scope/a": "1"}}))
        (tmp_path / "yarn.lock").write_text(
            '__metadata:\n  version: 6\n\n"@scope/a@npm:1":\n  version: 1.0.0\n'
            "  dependencies:\n    b: npm:^2\n\n"
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.direct_ancestors("b") == {"@scope/a"}

    def test_lodash_dot_and_dash_are_distinct_in_npm(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash.merge": "4"}}))
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("lodash.merge") == "direct"
        assert g.directness("lodash-merge") == "unknown"


class TestPythonLoaders:
    def test_pip_compile_via(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "django==4.2.0\n    # via -r requirements.in\n"
            "sqlparse==0.4.4\n    # via django\n"
            "asgiref==3.7.2\n    # via\n    #   django\n    #   channels\n"
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("Django") == "direct"
        assert g.directness("sqlparse") == "transitive"
        assert g.direct_ancestors("sqlparse") == {"django"}
        assert g.direct_ancestors("asgiref") == {"django"}

    def test_pip_freeze_contributes_nothing(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("django==4.2.0\nsqlparse==0.4.4\n")
        g = DependencyGraph.from_project(tmp_path)
        assert g.has_manifest is False
        assert g.directness("sqlparse") == "unknown"

    def test_hand_written_requirements_are_direct(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("django>=4.2\nrequests\n# comment\n-e .\n")
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("django") == "direct"
        assert g.directness("requests") == "direct"

    def test_requirements_in_is_authoritative(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.in").write_text("django\n")
        (tmp_path / "requirements.txt").write_text("django==4.2.0\nsqlparse==0.4.4\n")
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("django") == "direct"

    def test_pyproject_pep621_and_poetry(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["Typing_Extensions>=4", "requests[socks]"]\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "*"\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("typing-extensions") == "direct"
        assert g.directness("typing_extensions") == "direct"
        assert g.directness("requests") == "direct"
        assert g.directness("pytest") == "direct"
        assert g.directness("httpx") == "direct"
        assert g.directness("python") != "direct"

    def test_pyproject_without_deps_is_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n")
        assert DependencyGraph.from_project(tmp_path).has_manifest is False

    def test_pipfile(self, tmp_path: Path) -> None:
        (tmp_path / "Pipfile").write_text('[packages]\nflask = "*"\n[dev-packages]\npytest = "*"\n')
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("flask") == "direct"
        assert g.directness("pytest") == "direct"


class TestOtherEcosystems:
    def test_cargo_lock(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.lock").write_text(
            'version = 3\n\n[[package]]\nname = "myapp"\nversion = "0.1.0"\n'
            'dependencies = ["hyper", "serde 1.0.0"]\n\n'
            '[[package]]\nname = "hyper"\nversion = "0.14.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'dependencies = ["h2"]\n\n'
            '[[package]]\nname = "h2"\nversion = "0.3.0"\nsource = "registry+x"\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("hyper") == "direct"
        assert g.directness("serde") == "direct"
        assert g.direct_ancestors("h2") == {"hyper"}

    def test_gemfile_lock(self, tmp_path: Path) -> None:
        (tmp_path / "Gemfile.lock").write_text(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    rack (2.2.8)\n    sinatra (3.0.0)\n      rack (~> 2.2)\n      tilt (~> 2.0)\n"
            "    tilt (2.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  sinatra (~> 3.0)\n"
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("sinatra") == "direct"
        assert g.direct_ancestors("rack") == {"sinatra"}

    def test_composer(self, tmp_path: Path) -> None:
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": {"php": ">=8.1", "laravel/framework": "^10"}})
        )
        (tmp_path / "composer.lock").write_text(
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "laravel/framework",
                            "require": {"php": "^8.1", "guzzlehttp/guzzle": "^7"},
                        }
                    ]
                }
            )
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("laravel/framework") == "direct"
        assert g.direct_ancestors("guzzlehttp/guzzle") == {"laravel/framework"}
        assert g.directness("php") != "direct"

    def test_nuget_lock_keeps_original_case(self, tmp_path: Path) -> None:
        (tmp_path / "packages.lock.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "dependencies": {
                        "net8.0": {
                            "Microsoft.AspNetCore.App": {
                                "type": "Direct",
                                "dependencies": {"System.Text.Json": "8.0.0"},
                            },
                            "System.Text.Json": {"type": "Transitive"},
                        }
                    },
                }
            )
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("System.Text.Json") == "transitive"
        assert g.direct_ancestors("System.Text.Json") == {"Microsoft.AspNetCore.App"}

    def test_pubspec_lock(self, tmp_path: Path) -> None:
        (tmp_path / "pubspec.lock").write_text(
            'packages:\n  http:\n    dependency: "direct main"\n    version: "1.1.0"\n'
            '  meta:\n    dependency: transitive\n    version: "1.9.0"\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("http") == "direct"
        assert g.directness("meta") == "transitive"
        assert g.direct_ancestors("meta") == set()

    def test_go_mod(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text(
            "module example.com/app\n\ngo 1.22\n\n"
            "require github.com/gin-gonic/gin v1.9.1\n\n"
            "require (\n\tgolang.org/x/net v0.17.0 // indirect\n"
            "\tgithub.com/spf13/cobra v1.8.0\n)\n"
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("github.com/gin-gonic/gin") == "direct"
        assert g.directness("github.com/spf13/cobra") == "direct"
        assert g.directness("golang.org/x/net") == "transitive"

    def test_go_indirect_never_filtered(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text(
            "module a\n\nrequire golang.org/x/net v0.17.0 // indirect\n"
        )
        (tmp_path / "main.go").write_text('package main\n\nimport "fmt"\n')
        d = ReachabilityFilter(tmp_path).decide(
            _vuln("golang.org/x/net"), DependencyGraph.from_project(tmp_path)
        )
        assert d.unreachable is False

    def test_pom_xml(self, tmp_path: Path) -> None:
        (tmp_path / "pom.xml").write_text(
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
            "<dependency><groupId>com.fasterxml.jackson.core</groupId>"
            "<artifactId>jackson-databind</artifactId></dependency>"
            "</dependencies></project>"
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("com.fasterxml.jackson.core:jackson-databind") == "direct"


class TestRobustness:
    def test_malformed_files_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{not json")
        (tmp_path / "Cargo.lock").write_text("[[[")
        (tmp_path / "pom.xml").write_text("<project>")
        (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1"}}))
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("a") == "direct"

    def test_node_modules_is_not_scanned(self, tmp_path: Path) -> None:
        nested = tmp_path / "node_modules" / "evil"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps({"dependencies": {"qs": "1"}}))
        assert DependencyGraph.from_project(tmp_path).directness("qs") == "unknown"

    def test_monorepo_subpackage(self, tmp_path: Path) -> None:
        sub = tmp_path / "packages" / "api"
        sub.mkdir(parents=True)
        (sub / "package.json").write_text(json.dumps({"dependencies": {"express": "4"}}))
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("express") == "direct"
        assert any("api" in s for s in g.sources)

    def test_cycle_terminates(self, tmp_path: Path) -> None:
        g = DependencyGraph(has_manifest=True)
        g.add_direct("a")
        g.add_edge("a", "b")
        g.add_edge("b", "c")
        g.add_edge("c", "b")
        assert g.direct_ancestors("c") == {"a"}

    def test_missing_project_dir(self, tmp_path: Path) -> None:
        assert DependencyGraph.from_project(tmp_path / "nope").has_manifest is False


class TestExplainAndOutput:
    def _tr(self, **kw: object):  # type: ignore[no-untyped-def]
        from depquiet.models import TriageResult

        defaults: dict[str, object] = {"vuln": _vuln("path-to-regexp"), "verdict": Verdict.ACTION}
        defaults.update(kw)
        return TriageResult(**defaults)  # type: ignore[arg-type]

    def _reach(self, tr) -> object:  # type: ignore[no-untyped-def]
        from depquiet.explain import explain_triage

        [sig] = [s for s in explain_triage(tr).signals if s.name == "Reachability"]
        return sig

    def test_transitive_reachable_names_parent(self) -> None:
        tr = self._tr(
            dependency_type="transitive", introduced_by=["express"], reachable_imports=["app.js"]
        )
        sig = self._reach(tr)
        assert sig.value == "reachable"  # type: ignore[attr-defined]
        assert "pulled in by express" in sig.detail  # type: ignore[attr-defined]

    def test_transitive_unreachable_names_unused_parents(self) -> None:
        tr = self._tr(
            verdict=Verdict.FILTERED,
            reasons=[FilterReason.UNREACHABLE],
            dependency_type="transitive",
            introduced_by=["express"],
        )
        sig = self._reach(tr)
        assert sig.effect == "filtered"  # type: ignore[attr-defined]
        assert "(express)" in sig.detail  # type: ignore[attr-defined]

    def test_unknown_explains_why_not_filtered(self) -> None:
        sig = self._reach(self._tr(verdict=Verdict.REVIEW, dependency_type="unknown"))
        assert sig.value == "unknown"  # type: ignore[attr-defined]
        assert "not filtered" in sig.detail  # type: ignore[attr-defined]

    def test_transitive_without_path(self) -> None:
        sig = self._reach(self._tr(verdict=Verdict.REVIEW, dependency_type="transitive"))
        assert sig.value == "transitive"  # type: ignore[attr-defined]
        assert "no lockfile path" in sig.detail  # type: ignore[attr-defined]

    def test_json_roundtrip_through_explain(self) -> None:
        from depquiet.explain import find_cve_in_json

        data = {
            "results": [
                {
                    "cve": "CVE-2024-45296",
                    "package": "path-to-regexp",
                    "verdict": "action",
                    "reasons": [],
                    "dependency_type": "transitive",
                    "introduced_by": ["express"],
                }
            ]
        }
        tr = find_cve_in_json(data, "cve-2024-45296")
        assert tr is not None
        assert tr.dependency_type == "transitive"
        assert tr.introduced_by == ["express"]

    def test_cli_json_includes_dependency_fields(self, tmp_path: Path, capsys, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        import io

        from depquiet.cli import main

        project = _express_app(tmp_path)
        audit = TestEngineIntegration()._audit()
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(audit)))
        main(["--path", str(project), "--offline", "--json", "--stdin"])
        out = capsys.readouterr().out
        parsed = json.loads(out[out.index("{") :])
        [entry] = parsed["results"]
        assert entry["dependency_type"] == "transitive"
        assert entry["introduced_by"] == ["express"]


class TestDevOnlyTransitive:
    def _project(self, tmp: Path) -> Path:
        (tmp / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "4"},
                    "devDependencies": {"nodemon": "2", "jest": "29"},
                }
            )
        )
        (tmp / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {
                            "dependencies": {"express": "4"},
                            "devDependencies": {"nodemon": "2", "jest": "29"},
                        },
                        "node_modules/express": {"dependencies": {"debug": "2"}},
                        "node_modules/nodemon": {"dependencies": {"semver": "5", "debug": "3"}},
                        "node_modules/jest": {"dependencies": {"semver": "7"}},
                    }
                }
            )
        )
        (tmp / "app.js").write_text("const express = require('express');\n")
        return tmp

    def test_graph_dev_only(self, tmp_path: Path) -> None:
        g = DependencyGraph.from_project(self._project(tmp_path))
        assert g.is_dev_only(["nodemon", "jest"]) is True
        assert g.is_dev_only(["nodemon", "express"]) is False
        assert g.is_dev_only([]) is False

    def test_declared_both_prod_and_dev_is_prod(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"a": "1"}})
        )
        assert DependencyGraph.from_project(tmp_path).is_dev_only(["a"]) is False

    def _audit(self, pkg: str) -> dict[str, object]:
        return {
            "vulnerabilities": {
                pkg: {
                    "severity": "high",
                    "isDirect": False,
                    "via": [
                        {"title": "x", "url": "https://github.com/advisories/GHSA-1", "range": "*"}
                    ],
                }
            }
        }

    def test_transitive_only_through_dev_deps_is_dev(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        [tr] = scan(project, skip_epss=True, audit_json=self._audit("semver")).results
        assert FilterReason.DEV_DEPENDENCY in tr.reasons
        assert tr.introduced_by == ["jest", "nodemon"]

    def test_transitive_shared_with_prod_is_not_dev(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        [tr] = scan(project, skip_epss=True, audit_json=self._audit("debug")).results
        assert FilterReason.DEV_DEPENDENCY not in tr.reasons
        assert FilterReason.UNREACHABLE not in tr.reasons
        assert tr.verdict == Verdict.ACTION

    def test_explain_says_why_dev(self, tmp_path: Path) -> None:
        from depquiet.explain import explain_triage

        project = self._project(tmp_path)
        [tr] = scan(project, skip_epss=True, audit_json=self._audit("semver")).results
        [sig] = [s for s in explain_triage(tr).signals if s.name == "Dependency type"]
        assert sig.value == "devDependency"
        assert "Only pulled in by devDependencies" in sig.detail

    def test_pyproject_groups_are_dev(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname="x"\ndependencies=["flask"]\n'
            '[project.optional-dependencies]\nfast=["orjson"]\n'
            '[dependency-groups]\ntest=["pytest"]\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.is_dev_only(["pytest"]) is True
        assert g.is_dev_only(["orjson"]) is False
        assert g.is_dev_only(["flask"]) is False


class TestFixPackage:
    """npm audit's fix for a transitive package is usually a new parent version."""

    def _audit(self) -> dict[str, object]:
        return {
            "vulnerabilities": {
                "qs": {
                    "severity": "high",
                    "isDirect": False,
                    "via": [{"title": "qs DoS", "url": "https://github.com/advisories/GHSA-q"}],
                    "fixAvailable": {"name": "express", "version": "4.22.3"},
                },
                "lodash": {
                    "severity": "high",
                    "isDirect": True,
                    "via": [{"title": "proto", "url": "https://github.com/advisories/GHSA-l"}],
                    "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                },
            }
        }

    def test_parser_records_parent_fix(self, tmp_path: Path) -> None:
        from depquiet.parsers.npm import NpmAuditParser

        vulns = {v.package: v for v in NpmAuditParser.parse(self._audit(), tmp_path)}
        assert vulns["qs"].fix_package == "express"
        assert vulns["qs"].fix_label == "express@4.22.3"
        assert vulns["lodash"].fix_package == ""
        assert vulns["lodash"].fix_label == "4.17.21"

    def test_fix_dry_run_upgrades_parent_not_transitive(self, tmp_path: Path) -> None:
        from depquiet.fix import apply_fixes

        project = _express_app(tmp_path)
        (project / "app.js").write_text(
            "const express = require('express');\nconst _ = require('lodash');\n"
        )
        result = scan(project, skip_epss=True, audit_json=self._audit())
        report = apply_fixes(result, project, dry_run=True)
        packages = sorted(f.package for f in report.fixed)
        assert packages == ["express", "lodash"]
        assert all("qs@" not in (f.message or "") for f in report.fixed)

    def test_human_output_names_parent(self, tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
        from depquiet.output import print_scan_result

        project = _express_app(tmp_path)
        print_scan_result(scan(project, skip_epss=True, audit_json=self._audit()))
        out = capsys.readouterr().out
        assert "FIX: update express to 4.22.3" in out


class TestExecutedDependencies:
    """A dependency run as a command is in use even though nothing imports it."""

    def _project(self, tmp: Path, scripts: dict[str, str] | None = None) -> Path:
        (tmp / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "4", "pm2": "5"},
                    "scripts": scripts if scripts is not None else {"start": "pm2 start app.js"},
                }
            )
        )
        (tmp / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"express": "4", "pm2": "5"}},
                        "node_modules/express": {},
                        "node_modules/pm2": {
                            "bin": {"pm2": "bin/pm2", "pm2-runtime": "bin/pm2-runtime"},
                            "dependencies": {"axios": "0.21"},
                        },
                        "node_modules/axios": {},
                    }
                }
            )
        )
        (tmp / "app.js").write_text("const express = require('express');\n")
        return tmp

    def _decide(self, project: Path, pkg: str):  # type: ignore[no-untyped-def]
        return ReachabilityFilter(project).decide(_vuln(pkg), DependencyGraph.from_project(project))

    def test_direct_dep_run_in_scripts_is_reachable(self, tmp_path: Path) -> None:
        d = self._decide(self._project(tmp_path), "pm2")
        assert d.dependency_type == "direct"
        assert d.unreachable is False

    def test_transitive_of_executed_dep_is_reachable(self, tmp_path: Path) -> None:
        d = self._decide(self._project(tmp_path), "axios")
        assert d.unreachable is False
        assert d.imported_ancestors == ["pm2"]

    def test_alternate_bin_name(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, {"start": "pm2-runtime ecosystem.config.js"})
        assert self._decide(project, "axios").unreachable is False

    def test_bin_by_path(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, {"start": "./node_modules/.bin/pm2 start app.js"})
        assert self._decide(project, "axios").unreachable is False

    def test_not_run_anywhere_is_unreachable(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, {"start": "node app.js"})
        assert self._decide(project, "pm2").unreachable is True
        assert self._decide(project, "axios").unreachable is True

    def test_dockerfile_cmd(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, {})
        (project / "Dockerfile").write_text('FROM node:20\nCMD ["pm2-runtime", "app.js"]\n')
        assert self._decide(project, "axios").unreachable is False

    def test_procfile(self, tmp_path: Path) -> None:
        project = self._project(tmp_path, {})
        (project / "Procfile").write_text("web: pm2 start app.js --no-daemon\n")
        assert self._decide(project, "pm2").unreachable is False

    def test_name_fallback_without_lockfile_bins(self, tmp_path: Path) -> None:
        project = self._project(tmp_path)
        (project / "package-lock.json").unlink()
        g = DependencyGraph.from_project(project)
        assert g.is_executed("pm2") is True
        assert g.is_executed("express") is False

    def test_scoped_package_name_fallback(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"@acme/tool": "1"}, "scripts": {"x": "tool run"}})
        )
        assert DependencyGraph.from_project(tmp_path).is_executed("@acme/tool") is True

    def test_executed_dev_tool_is_still_dev_only(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "4"},
                    "devDependencies": {"eslint": "8"},
                    "scripts": {"lint": "eslint ."},
                }
            )
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {"dependencies": {"express": "4"}, "devDependencies": {"eslint": "8"}},
                        "node_modules/eslint": {
                            "bin": {"eslint": "bin/eslint.js"},
                            "dependencies": {"minimatch": "3"},
                        },
                    }
                }
            )
        )
        (tmp_path / "app.js").write_text("require('express');\n")
        audit = {
            "vulnerabilities": {
                "minimatch": {
                    "severity": "high",
                    "isDirect": False,
                    "via": [{"title": "ReDoS", "url": "https://github.com/advisories/GHSA-m"}],
                }
            }
        }
        [tr] = scan(tmp_path, skip_epss=True, audit_json=audit).results
        assert tr.reasons == [FilterReason.DEV_DEPENDENCY]  # dev-only, but not "unreachable"
