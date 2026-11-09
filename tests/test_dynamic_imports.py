"""Static loader evidence and conservative absence checks within a source scope."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.filters.dynamic_imports import js_dynamic_imports, python_dynamic_imports
from depquiet.filters.reachability import ReachabilityFilter
from depquiet.models import Severity, Vulnerability


def _vuln(package: str = "example-lib", *, functions: bool = False) -> Vulnerability:
    return Vulnerability(
        "SYNTHETIC-DYNAMIC-IMPORT",
        package,
        "1.0.0",
        Severity.HIGH,
        vulnerable_functions=["dangerous"] if functions else [],
    )


def _graph() -> DependencyGraph:
    graph = DependencyGraph(has_manifest=True)
    graph.add_direct("example-lib")
    graph.add_direct("parent")
    graph.add_edge("parent", "child")
    return graph


@pytest.mark.parametrize(
    "source",
    [
        "__import__('example_lib.helpers')",
        "loader = __import__\nloader('example_lib')",
        "import builtins as b\nb.__import__('example_lib')",
        "from builtins import __import__ as load\nload('example_lib')",
        "import importlib as il\nil.import_module('example_lib.helpers')",
        "from importlib import import_module as load\nload('example_lib')",
        "import importlib as il\nload = il.import_module\nload(name='example_lib')",
        "import importlib\nimportlib.import_module('.views', package='example_lib')",
    ],
)
def test_literal_python_loader_aliases_supply_real_import_sites(tmp_path: Path, source: str):
    app = tmp_path / "app.py"
    app.write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.source_coverage_complete and filter_.analysis_coverage_complete
    assert filter_.check(_vuln()) is False
    assert filter_.decide(_vuln(), _graph()).unreachable is False
    assert filter_.find_imports(_vuln()) == [str(app)]
    assert any(
        "app.py:" in item and "literal" in item for item in filter_.dynamic_import_observations
    )


@pytest.mark.parametrize(
    "source,line",
    [
        ("import importlib as il\nmodule = il.import_module(plugin_name)", 2),
        ("from importlib import import_module as load\nload(name=plugin_name)", 2),
        ("import builtins as b\nb.__import__(plugin_name)", 2),
        ("loader = __import__\nloader(*module_args)", 2),
        ("import importlib\nimportlib.import_module('.views', package=package_name)", 2),
        ("from importlib import import_module as load\ndef run(load):\n    load('other_lib')", 3),
        ("import importlib as il\nil = injected_loader\nil.import_module('other_lib')", 3),
    ],
)
def test_unresolved_python_loaders_block_absence_claims(tmp_path: Path, source: str, line: int):
    app = tmp_path / "plugins.py"
    app.write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.source_coverage_complete is True
    assert filter_.analysis_coverage_complete is False
    assert filter_.check(_vuln()) is False
    assert filter_.check(_vuln(functions=True)) is False
    assert filter_.decide(_vuln(), _graph()).unreachable is False
    assert filter_.decide(_vuln("child"), _graph()).unreachable is False
    assert filter_.references_absent(["dangerous"]) is False
    assert filter_.find_imports(_vuln()) == []
    assert any(
        f"plugins.py:{line}" in item and "unresolved" in item
        for item in filter_.analysis_coverage_observations
    )


def test_python_comments_and_strings_are_not_loader_calls(tmp_path: Path):
    source = '# __import__(plugin)\ntext = "importlib.import_module(plugin)"\n'
    assert python_dynamic_imports(source) == ()
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete is True
    assert filter_.check(_vuln()) is True


@pytest.mark.parametrize(
    "source",
    [
        "if config:\n    load = injected\nelse:\n"
        "    from importlib import import_module as load\nload('other')",
        "from importlib import import_module as load\nimport custom as load\nload('other')",
        "from importlib import import_module as load\nfor load in injected:\n    load('other')",
        "import importlib\nimportlib.import_module = injected\nimportlib.import_module('other')",
    ],
)
def test_rebound_or_conditional_loader_cannot_gain_literal_certainty(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete is False
    assert filter_.check(_vuln()) is False
    assert filter_.references_absent(["dangerous"]) is False


@pytest.mark.parametrize(
    "source",
    [
        "require('example-lib/subpath');",
        "import('example-lib');",
        "require(`example-lib`);",
        "module.require('example-lib');",
        "import /* comment */ ('example-lib', { with: { type: 'json' } });",
    ],
)
def test_literal_js_loaders_supply_import_sites(tmp_path: Path, source: str):
    app = tmp_path / "app.ts"
    app.write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete
    assert filter_.check(_vuln()) is False
    assert filter_.find_imports(_vuln()) == [str(app)]


@pytest.mark.parametrize(
    "source",
    [
        "require(process.env.PLUGIN);",
        "import(getPlugin());",
        "module.require(plugin);",
        "require(`./plugins/${name}`);",
        "const rendered = `${require(plugin)}`;",
        "import('prefix-' + plugin);",
    ],
)
def test_js_nonliteral_loaders_leave_explicit_uncertainty(tmp_path: Path, source: str):
    (tmp_path / "plugins.js").write_text("// bootstrap\n" + source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.source_coverage_complete is True
    assert filter_.analysis_coverage_complete is False
    assert filter_.check(_vuln()) is False
    assert filter_.decide(_vuln("child"), _graph()).unreachable is False
    assert filter_.references_absent(["dangerous"]) is False
    assert filter_.find_imports(_vuln()) == []
    assert any("plugins.js:2" in item for item in filter_.analysis_coverage_observations)


@pytest.mark.parametrize(
    "source",
    [
        'const text = "require(plugin)"; // import(plugin)\n/* require(other) */',
        "const text = `require(plugin)`;",
        r"const pattern = /require\(plugin\)|import\(name\)/g;",
        r"const pattern = /[/'\"]require\(name\)/;",
        r"const makePattern = () => /require\(plugin\)/;",
        r"if (condition) /require\(plugin\)/.test(text);",
        "obj.import(plugin); obj.require(plugin); obj?.require(plugin); import.meta.url;",
        "const methods = { require(name) { return name; }, import(name) {} };",
    ],
)
def test_js_lexical_nonloaders_do_not_create_uncertainty(tmp_path: Path, source: str):
    assert js_dynamic_imports(source) == ()
    (tmp_path / "app.js").write_text(source, encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete is True
    assert filter_.check(_vuln()) is True
    assert filter_.dynamic_import_observations == []


def test_positive_usage_coexists_with_unresolved_dynamic_loader(tmp_path: Path):
    app = tmp_path / "app.js"
    app.write_text("require('example-lib');\nrequire(plugin);", encoding="utf-8")
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.find_imports(_vuln()) == [str(app)]
    assert filter_.is_used("example-lib", _graph())
    assert filter_.analysis_coverage_complete is False
    observations = filter_.dynamic_import_observations
    assert any("literal" in item and "app.js:1" in item for item in observations)
    assert any("unresolved" in item and "app.js:2" in item for item in observations)


@pytest.mark.parametrize("relative", [False, True])
def test_excluded_workspace_sources_and_mentions_are_not_read(
    tmp_path: Path, monkeypatch, relative: bool
):
    (tmp_path / "app.js").write_text("console.log('parent');", encoding="utf-8")
    child = tmp_path / "packages" / "child"
    child.mkdir(parents=True)
    (child / "plugins.py").write_text("__import__(plugin)", encoding="utf-8")
    (child / "settings.ini").write_text("plugin = example-lib", encoding="utf-8")
    original = Path.read_text

    def read(path: Path, *args, **kwargs):
        assert not path.is_relative_to(child), "excluded workspace was read"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    excluded = child.relative_to(tmp_path) if relative else child
    filter_ = ReachabilityFilter(tmp_path, exclude_roots=[excluded])
    assert filter_.analysis_coverage_complete is True
    assert filter_.check(_vuln()) is True
    assert filter_.is_used("example-lib", _graph()) is False
    assert filter_.references_absent(["dangerous"]) is True
    assert filter_.dynamic_import_observations == []
    assert any("scope excludes" in item for item in filter_.analysis_coverage_observations)


@pytest.mark.parametrize("kind", ["symlink", "outside"])
def test_source_links_cannot_read_outside_or_justify_absence(
    tmp_path: Path, monkeypatch, kind: str
):
    source = tmp_path / "linked.py"
    source.write_text("__import__(plugin)", encoding="utf-8")
    original_read = Path.read_text
    original_link = Path.is_symlink
    original_resolve = Path.resolve

    def read(path: Path, *args, **kwargs):
        assert path != source, "linked source must not be read"
        return original_read(path, *args, **kwargs)

    def link(path: Path):
        return path == source if kind == "symlink" else original_link(path)

    def resolve(path: Path, *args, **kwargs):
        return (
            tmp_path.parent / "outside.py"
            if path == source and kind == "outside"
            else original_resolve(path, *args, **kwargs)
        )

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(Path, "is_symlink", link)
    monkeypatch.setattr(Path, "resolve", resolve)
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete is False
    assert filter_.check(_vuln()) is False
    assert filter_.references_absent(["dangerous"]) is False
    assert filter_.find_imports(_vuln()) == []
    assert any("linked.py" in item for item in filter_.analysis_coverage_observations)


def test_read_failures_and_dynamic_uncertainty_share_analysis_observations(
    tmp_path: Path, monkeypatch
):
    source = tmp_path / "plugins.js"
    source.write_text("require(plugin);", encoding="utf-8")
    blocked = tmp_path / "private.py"
    blocked.write_text("print('private')", encoding="utf-8")
    original = Path.read_text
    calls: dict[Path, int] = {}

    def read(path: Path, *args, **kwargs):
        calls[path] = calls.get(path, 0) + 1
        if path == blocked:
            raise PermissionError(errno.EACCES, "synthetic read denied", str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    filter_ = ReachabilityFilter(tmp_path)
    for _ in range(3):
        assert filter_.source_coverage_complete is False
        assert filter_.analysis_coverage_complete is False
        assert filter_.check(_vuln()) is False
        assert filter_.references_absent(["dangerous"]) is False
    assert calls == {source: 1, blocked: 1}
    assert len(filter_.source_coverage_observations) == 1
    assert any("plugins.js:1" in item for item in filter_.analysis_coverage_observations)
    assert any("PermissionError" in item for item in filter_.analysis_coverage_observations)


def test_graph_coverage_failure_blocks_direct_and_transitive_absence(tmp_path: Path):
    (tmp_path / "app.js").write_text("console.log('unused');", encoding="utf-8")
    graph = _graph()
    graph.coverage_complete = False
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.analysis_coverage_complete is True
    assert filter_.decide(_vuln(), graph).unreachable is False
    assert filter_.decide(_vuln("child"), graph).unreachable is False
