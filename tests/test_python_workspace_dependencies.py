"""Python projects whose pyproject.toml does not spell out their dependencies.

Found on pydantic/pydantic-ai: every workspace member declares
``dynamic = ["dependencies", "optional-dependencies"]``, so the member graphs
were empty. The root lists ``fastmcp`` in a development group while a member
ships it as an extra, and 0.33.0 filtered its alerts as development-only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from depquiet.depgraph import DependencyGraph
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


def _registry(name: str, *deps: str) -> str:
    listed = ", ".join(f'{{ name = "{d}" }}' for d in deps)
    return (
        f'[[package]]\nname = "{name}"\nversion = "1.0"\n'
        f'source = {{ registry = "https://pypi.org/simple" }}\n'
        + (f"dependencies = [{listed}]\n" if deps else "")
        + "\n"
    )


DYNAMIC = 'dynamic = ["version", "dependencies", "optional-dependencies"]\n'


def _workspace(tmp_path: Path, *, lock: bool = True) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "suite"\n' + DYNAMIC + '[tool.uv.workspace]\nmembers = ["harness"]\n'
        '[dependency-groups]\ndev = ["plugin"]\n',
    )
    _write(tmp_path / "harness/pyproject.toml", '[project]\nname = "suite-harness"\n' + DYNAMIC)
    _write(tmp_path / "harness/suite_harness/__init__.py", "import plugin\n")
    if lock:
        _write(
            tmp_path / "uv.lock",
            'version = 1\n\n[manifest]\nmembers = ["suite", "suite-harness"]\n\n'
            '[[package]]\nname = "suite"\nversion = "0"\nsource = { virtual = "." }\n'
            'dependencies = [{ name = "suite-harness" }]\n\n'
            '[package.dev-dependencies]\ndev = [{ name = "plugin" }]\n\n'
            '[[package]]\nname = "suite-harness"\nversion = "0"\n'
            'source = { editable = "harness" }\n\n'
            '[package.optional-dependencies]\nstack = [{ name = "plugin" }]\n\n'
            + _registry("plugin", "leaf")
            + _registry("leaf"),
        )


def test_member_dependencies_come_from_the_lock_when_pyproject_is_dynamic(tmp_path: Path) -> None:
    _workspace(tmp_path)
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    harness = graph.workspace_graphs["harness"]
    assert harness.directness("plugin") == "direct"
    assert not harness.is_dev_only(["plugin"])
    assert harness.direct_ancestors("leaf") == {"plugin"}
    assert graph.workspace_graphs["."].is_dev_only(["plugin"])


def test_dev_group_in_root_does_not_outvote_a_members_extra(tmp_path: Path) -> None:
    """The 0.33.0 false dismissal: root says dev, a member ships it."""
    _workspace(tmp_path)
    for package in ("plugin", "leaf"):
        [finding] = scan(tmp_path, audit_json=_pip(package), skip_epss=True).results
        assert finding.verdict == Verdict.ACTION, package
        assert FilterReason.DEV_DEPENDENCY not in finding.reasons


def test_dynamic_dependencies_without_a_lock_leave_the_graph_incomplete(tmp_path: Path) -> None:
    _workspace(tmp_path, lock=False)
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    assert any("dynamic dependencies" in note for note in graph.coverage_observations)
    [finding] = scan(tmp_path, audit_json=_pip("plugin"), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert not finding.reasons


def test_single_project_with_dynamic_dependencies_and_no_lock(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndynamic = ["dependencies"]\n'
        '[dependency-groups]\ndev = ["tool"]\n',
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert not graph.coverage_complete
    # ``tool`` may also be one of the unknown production dependencies.
    [finding] = scan(tmp_path, audit_json=_pip("tool"), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION


def test_hatch_hook_dependencies_are_read_from_the_file(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\n' + DYNAMIC + "[dependency-groups]\n"
        'dev = ["tool"]\n'
        "[tool.hatch.metadata.hooks.uv-dynamic-versioning]\n"
        'dependencies = ["core=={{ version }}", "httpx>=0.27"]\n'
        "[tool.hatch.metadata.hooks.uv-dynamic-versioning.optional-dependencies]\n"
        'cli = ["rich>=13"]\n',
    )
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    assert {"core", "httpx", "rich"} <= graph.prod_direct
    assert graph.is_dev_only(["tool"])


def test_setuptools_requirements_files_resolve_dynamic_dependencies(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndynamic = ["dependencies"]\n'
        '[tool.setuptools.dynamic]\ndependencies = { file = ["requirements.txt"] }\n',
    )
    _write(tmp_path / "requirements.txt", "requests==2.0\n")
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    assert "requests" in graph.prod_direct


def test_setuptools_file_that_is_missing_or_includes_others_stays_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndynamic = ["dependencies"]\n'
        '[tool.setuptools.dynamic]\ndependencies = { file = ["deps/prod.txt"] }\n',
    )
    assert not DependencyGraph.from_project(tmp_path).coverage_complete
    _write(tmp_path / "deps/prod.txt", "-r base.txt\nrequests\n")
    assert not DependencyGraph.from_project(tmp_path).coverage_complete
    _write(tmp_path / "deps/prod.txt", "requests>=2  # http\n")
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete and "requests" in graph.prod_direct


def test_setuptools_attr_stays_unknown(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndynamic = ["dependencies"]\n'
        '[tool.setuptools.dynamic]\ndependencies = { attr = "app.deps" }\n',
    )
    assert not DependencyGraph.from_project(tmp_path).coverage_complete


def test_dependents_of_the_project_do_not_inherit_its_dev_groups(tmp_path: Path) -> None:
    """A plugin that depends on the project does not install the project's linters."""
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndependencies = ["requests"]\n'
        '[project.optional-dependencies]\nstore = ["app-plugin"]\n'
        '[dependency-groups]\ndev = ["pre-commit"]\n',
    )
    _write(
        tmp_path / "uv.lock",
        'version = 1\n\n[[package]]\nname = "app"\nversion = "0"\nsource = { editable = "." }\n'
        'dependencies = [{ name = "requests" }]\n\n'
        '[package.optional-dependencies]\nstore = [{ name = "app-plugin" }]\n\n'
        '[package.dev-dependencies]\ndev = [{ name = "pre-commit" }]\n\n'
        + _registry("app-plugin", "app")
        + _registry("pre-commit", "virtualenv")
        + _registry("virtualenv")
        + _registry("requests"),
    )
    _write(tmp_path / "app/__init__.py", "import requests\nimport app_plugin\n")
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.direct_ancestors("virtualenv") == {"pre-commit"}
    [finding] = scan(tmp_path, audit_json=_pip("virtualenv"), skip_epss=True).results
    assert finding.verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in finding.reasons
    assert finding.introduced_by == ["pre-commit"]


def test_root_listed_as_a_workspace_member_is_supported(tmp_path: Path) -> None:
    _write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "app"\ndependencies = ["requests"]\n'
        '[tool.uv.workspace]\nmembers = [".", "./libs/core"]\n',
    )
    _write(tmp_path / "libs/core/pyproject.toml", '[project]\nname = "core"\ndependencies = []\n')
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete, graph.coverage_observations
    assert set(graph.workspace_graphs) == {".", "libs/core"}
