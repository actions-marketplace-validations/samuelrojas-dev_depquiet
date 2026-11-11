"""A dependency group is a named list; only its name says what it is for.

zulip/zulip has no ``[project].dependencies``. Everything its servers run is
in ``[dependency-groups] prod``, which ``dev`` includes. Treating every group
as development-only filtered all 43 of its pip-audit alerts, among them
``social-auth-core`` and ``pyasn1`` in the login path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from depquiet.depgraph import DependencyGraph, _is_dev_group
from depquiet.engine import scan
from depquiet.models import FilterReason, Verdict


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _pip(name: str) -> dict[str, Any]:
    return {
        "dependencies": [
            {
                "name": name,
                "version": "1.0",
                "vulns": [{"id": f"TEST-{name.upper()}", "fix_versions": [], "description": "x"}],
            }
        ]
    }


@pytest.mark.parametrize(
    "name", ["dev", "test", "tests", "docs", "lint", "typing", "db-test", "docs_build", "Dev"]
)
def test_tooling_group_names(name: str) -> None:
    assert _is_dev_group(name)


@pytest.mark.parametrize(
    "name", ["prod", "production", "release-tools", "server", "runtime", "main", "devices", ""]
)
def test_other_group_names_are_production(name: str) -> None:
    assert not _is_dev_group(name)


PYPROJECT = (
    '[project]\nname = "server"\nversion = "0"\n'
    '[dependency-groups]\nprod = ["auth-core", "django"]\ndocs = ["sphinx"]\n'
    'dev = [{ include-group = "prod" }, { include-group = "docs" }, "scrapy"]\n'
)


def _lock() -> str:
    def pkg(name: str, *deps: str) -> str:
        listed = ", ".join(f'{{ name = "{d}" }}' for d in deps)
        return (
            f'[[package]]\nname = "{name}"\nversion = "1.0"\n'
            'source = { registry = "https://pypi.org/simple" }\n'
            + (f"dependencies = [{listed}]\n" if deps else "")
            + "\n"
        )

    groups = (
        'prod = [{ name = "auth-core" }, { name = "django" }]\n'
        'docs = [{ name = "sphinx" }]\n'
        'dev = [{ name = "auth-core" }, { name = "django" }, { name = "sphinx" }, '
        '{ name = "scrapy" }]\n'
    )
    return (
        'version = 1\n\n[[package]]\nname = "server"\nversion = "0"\nsource = { virtual = "." }\n\n'
        "[package.dev-dependencies]\n"
        + groups
        + "\n"
        + pkg("auth-core", "asn")
        + pkg("asn")
        + pkg("django")
        + pkg("sphinx")
        + pkg("scrapy", "filelock")
        + pkg("filelock")
    )


@pytest.mark.parametrize("with_lock", [True, False])
def test_production_group_is_not_development_only(tmp_path: Path, with_lock: bool) -> None:
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    if with_lock:
        _write(tmp_path / "uv.lock", _lock())
    _write(tmp_path / "server/app.py", "import django\nimport auth_core\n")
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.is_dev_only(["auth-core"])
    assert graph.is_dev_only(["scrapy"])
    assert graph.is_dev_only(["sphinx"])

    [kept] = scan(tmp_path, audit_json=_pip("auth-core"), skip_epss=True).results
    assert kept.verdict == Verdict.ACTION
    assert not kept.reasons
    [tool] = scan(tmp_path, audit_json=_pip("scrapy"), skip_epss=True).results
    assert tool.verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in tool.reasons


def test_transitive_of_a_production_group_is_kept(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", PYPROJECT)
    _write(tmp_path / "uv.lock", _lock())
    _write(tmp_path / "server/app.py", "import django\nimport auth_core\n")
    [asn] = scan(tmp_path, audit_json=_pip("asn"), skip_epss=True).results
    assert asn.verdict == Verdict.ACTION
    assert asn.introduced_by == ["auth-core"]
    [lock_only] = scan(tmp_path, audit_json=_pip("filelock"), skip_epss=True).results
    assert lock_only.verdict == Verdict.FILTERED
    assert lock_only.introduced_by == ["scrapy"]


def test_poetry_group_names(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[tool.poetry]\nname = "svc"\nversion = "0"\n'
        '[tool.poetry.dependencies]\npython = "^3.12"\n'
        '[tool.poetry.group.worker.dependencies]\ncelery = "*"\n'
        '[tool.poetry.group.test.dependencies]\npytest = "*"\n',
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.is_dev_only(["celery"])
    assert graph.is_dev_only(["pytest"])
