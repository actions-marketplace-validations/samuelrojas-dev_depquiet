"""Tests for v0.30.0 Python name mapping, uv.lock/poetry.lock, and usage rules.

The bugs these cover: advisories name distributions (Django, PyYAML,
llama-index-core) while code imports modules (django, yaml, llama_index), so
real dependencies looked unused and their alerts were filtered.
"""

from __future__ import annotations

from pathlib import Path

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.models import FilterReason, Severity, Vulnerability
from depquiet.pynames import import_candidates


def _vuln(package: str) -> Vulnerability:
    return Vulnerability(cve="PYSEC-1", package=package, version="1", severity=Severity.HIGH)


def _unreachable(project: Path, package: str) -> bool:
    graph = DependencyGraph.from_project(project)
    return ReachabilityFilter(project).decide(_vuln(package), graph).unreachable


def _pyproject(tmp: Path, deps: list[str], dev: list[str] | None = None) -> None:
    lines = ['[project]\nname = "app"\ndependencies = [' + ", ".join(f'"{d}"' for d in deps) + "]"]
    if dev:
        lines.append("[dependency-groups]\ndev = [" + ", ".join(f'"{d}"' for d in dev) + "]")
    (tmp / "pyproject.toml").write_text("\n".join(lines) + "\n")


class TestImportCandidates:
    def test_case_insensitive(self) -> None:
        assert "django" in import_candidates("Django")
        assert "jinja2" in import_candidates("Jinja2")

    def test_known_mismatches(self) -> None:
        assert "yaml" in import_candidates("PyYAML")
        assert "pil" in import_candidates("Pillow")
        assert "bs4" in import_candidates("beautifulsoup4")
        assert "jwt" in import_candidates("PyJWT")
        assert "dateutil" in import_candidates("python-dateutil")

    def test_namespace_prefixes(self) -> None:
        assert "llama_index" in import_candidates("llama-index-core")
        assert "ingredient_parser" in import_candidates("ingredient-parser-nlp")
        assert "google" in import_candidates("google-cloud-storage")

    def test_framework_app_labels(self) -> None:
        assert "allauth" in import_candidates("django-allauth")

    def test_project_venv_metadata(self, tmp_path: Path) -> None:
        site = tmp_path / ".venv" / "lib" / "python3.12" / "site-packages"
        info = site / "weird_dist-1.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: weird-dist\n\n")
        (info / "top_level.txt").write_text("totally_other\n")
        assert "totally_other" in import_candidates("weird-dist", tmp_path)

    def test_record_fallback(self, tmp_path: Path) -> None:
        site = tmp_path / "venv" / "lib" / "python3.11" / "site-packages"
        info = site / "rec-2.0.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text("Name: rec\n\n")
        (info / "RECORD").write_text("recmod/__init__.py,,\nrec-2.0.dist-info/METADATA,,\n")
        assert "recmod" in import_candidates("rec", tmp_path)


class TestPythonImports:
    def test_capitalized_distribution_is_imported(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["Django", "PyYAML"])
        (tmp_path / "app.py").write_text("import django\nimport yaml\n")
        assert _unreachable(tmp_path, "Django") is False
        assert _unreachable(tmp_path, "PyYAML") is False

    def test_genuinely_unused_still_filtered(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["Django", "PyYAML"])
        (tmp_path / "app.py").write_text("import django\n")
        assert _unreachable(tmp_path, "PyYAML") is True

    def test_import_sites_found_for_capitalized_name(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("from PIL import Image\n")
        assert ReachabilityFilter(tmp_path).find_imports_for("Pillow")


class TestUvLock:
    LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "django" }, { name = "celery", extra = ["redis"] }]

[package.optional-dependencies]
pg = [{ name = "psycopg" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "django"
version = "5.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "sqlparse" }, { name = "asgiref" }]

[[package]]
name = "celery"
version = "5.4"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "billiard" }]

[package.optional-dependencies]
redis = [{ name = "redis" }]

[[package]]
name = "pytest"
version = "8.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]
"""

    def test_directness_and_edges(self, tmp_path: Path) -> None:
        (tmp_path / "uv.lock").write_text(self.LOCK)
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("Django") == "direct"
        assert g.directness("psycopg") == "direct"
        assert g.directness("sqlparse") == "transitive"
        assert g.direct_ancestors("sqlparse") == {"django"}
        assert g.direct_ancestors("redis") == {"celery"}
        assert g.is_dev_only(["pytest"]) is True
        assert g.is_dev_only(["django"]) is False

    def test_transitive_of_imported_dep_kept(self, tmp_path: Path) -> None:
        (tmp_path / "uv.lock").write_text(self.LOCK)
        (tmp_path / "app.py").write_text("from django.db import models\n")
        assert _unreachable(tmp_path, "sqlparse") is False

    def test_dev_tool_transitive_is_dev_only(self, tmp_path: Path) -> None:
        (tmp_path / "uv.lock").write_text(self.LOCK)
        (tmp_path / "app.py").write_text("import django\n")
        audit = {
            "dependencies": [
                {"name": "pluggy", "version": "1", "vulns": [{"id": "PYSEC-9", "aliases": []}]}
            ]
        }
        [tr] = scan(tmp_path, skip_epss=True, audit_json=audit).results
        assert FilterReason.DEV_DEPENDENCY in tr.reasons
        assert tr.introduced_by == ["pytest"]


class TestPoetryLock:
    def test_edges_with_pyproject_directs(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[tool.poetry.dependencies]\npython = "^3.11"\nJinja2 = "*"\n'
            '[tool.poetry.group.dev.dependencies]\nmkdocs-material = "*"\n'
        )
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "jinja2"\nversion = "3.1"\n\n'
            '[package.dependencies]\nMarkupSafe = ">=2.0"\n\n'
            '[[package]]\nname = "mkdocs-material"\nversion = "9"\n\n'
            '[package.dependencies]\npymdown-extensions = "*"\n'
        )
        g = DependencyGraph.from_project(tmp_path)
        assert g.directness("jinja2") == "direct"
        assert g.direct_ancestors("markupsafe") == {"Jinja2"}
        assert g.direct_ancestors("pymdown_extensions") == {"mkdocs-material"}
        assert g.is_dev_only(["mkdocs-material"]) is True


class TestUsedWithoutImport:
    def test_installed_apps_string(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["Django", "django-allauth"])
        (tmp_path / "settings.py").write_text('INSTALLED_APPS = ["allauth", "allauth.account"]\n')
        assert _unreachable(tmp_path, "django-allauth") is False

    def test_service_script_runs_package(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["celery", "flower"])
        (tmp_path / "app.py").write_text("import celery\n")
        svc = tmp_path / "docker" / "svc-flower"
        svc.mkdir(parents=True)
        (svc / "run").write_text("#!/bin/sh\nexec celery --app paperless flower\n")
        assert _unreachable(tmp_path, "flower") is False

    def test_database_url_names_driver(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["sqlalchemy", "psycopg2-binary"])
        (tmp_path / "db.py").write_text('URL = "postgresql+psycopg2://u@h/db"\n')
        assert _unreachable(tmp_path, "psycopg2-binary") is False

    def test_docs_and_manifests_do_not_count(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["flower"])
        (tmp_path / "app.py").write_text("print(1)\n")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "conf.yml").write_text("monitor: flower\n")
        (tmp_path / "README.md").write_text("Run flower for monitoring\n")
        (tmp_path / "requirements.txt").write_text("flower>=2\n")
        assert _unreachable(tmp_path, "flower") is True

    def test_implicit_plugin_of_used_framework(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["fastapi", "python-multipart"])
        (tmp_path / "main.py").write_text("from fastapi import FastAPI, Form\n")
        assert _unreachable(tmp_path, "python-multipart") is False

    def test_implicit_plugin_of_unused_framework(self, tmp_path: Path) -> None:
        _pyproject(tmp_path, ["fastapi", "python-multipart"])
        (tmp_path / "main.py").write_text("print('no web here')\n")
        assert _unreachable(tmp_path, "python-multipart") is True


class TestScanSpeed:
    def test_each_file_parsed_once(self, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        """Many alerts over many files must not re-read every file per alert."""
        import depquiet.filters.reachability as r

        _pyproject(tmp_path, [f"pkg{i}" for i in range(30)])
        for i in range(40):
            (tmp_path / f"m{i}.py").write_text(f"import pkg{i % 30}\n")
        reads = {"n": 0}
        real = Path.read_text

        def counting(self: Path, *a, **k):  # type: ignore[no-untyped-def]
            if self.suffix == ".py":
                reads["n"] += 1
            return real(self, *a, **k)

        monkeypatch.setattr(r, "_TEXT_CACHE", {})
        monkeypatch.setattr(Path, "read_text", counting)
        audit = {
            "dependencies": [
                {"name": f"pkg{i}", "version": "1", "vulns": [{"id": f"PYSEC-{i}", "aliases": []}]}
                for i in range(30)
            ]
        }
        scan(tmp_path, skip_epss=True, audit_json=audit)
        assert reads["n"] <= 40
