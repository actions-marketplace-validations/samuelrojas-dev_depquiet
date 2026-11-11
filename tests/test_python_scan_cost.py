"""A Python scan parses each source file once, whatever the number of questions.

0.33.0 re-parsed every candidate file for every package and every alert when
checking which imports name a package. On PrefectHQ/prefect (1,900 files, one
vulnerable package, hundreds of dependency roots) triage went from seconds to
more than eight minutes.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import pytest

import depquiet.filters.reachability as reachability
from depquiet.engine import scan
from depquiet.filters.dynamic_imports import python_dynamic_imports
from depquiet.models import Verdict


def _pip(*names: str) -> dict[str, Any]:
    return {
        "dependencies": [
            {
                "name": name,
                "version": "1.0",
                "vulns": [{"id": f"TEST-{name.upper()}", "fix_versions": [], "description": "x"}],
            }
            for name in names
        ]
    }


def _project(tmp_path: Path, files: int, roots: list[str]) -> None:
    deps = ", ".join(f'"{name}"' for name in roots)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "site"\ndependencies = [{deps}]\n', encoding="utf-8"
    )
    for index in range(files):
        (tmp_path / f"mod_{index}.py").write_text(
            f"import acme\nfrom acme.cloud import thing_{index}\n", encoding="utf-8"
        )


def test_each_file_is_parsed_once_per_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import depquiet.pynames as pynames

    monkeypatch.setattr(pynames, "_running_environment", lambda: {})
    # Twelve packages that all match ``import acme`` only by name prefix, the
    # case that sends every file through the dotted-path check.
    roots = [f"acme-cloud-part{n}" for n in range(12)]
    _project(tmp_path, files=30, roots=roots)
    parsed: list[str] = []
    real = reachability._parse_python

    def counting(source: str):
        parsed.append(source)
        return real(source)

    monkeypatch.setattr(reachability, "_parse_python", counting)
    reachability._ast_imports.cache_clear()
    result = scan(tmp_path, audit_json=_pip(*roots), skip_epss=True)
    assert len(result.results) == 12
    assert all(r.verdict == Verdict.ACTION for r in result.results)
    assert len(parsed) == len(set(parsed)) == 30


def test_scanned_projects_syntax_warnings_stay_out_of_the_output(tmp_path: Path) -> None:
    _project(tmp_path, files=1, roots=["acme"])
    # An invalid escape sequence: a SyntaxWarning when this file is compiled.
    (tmp_path / "legacy.py").write_text(
        'import acme\nimport importlib\nPATTERN = "\\d+\\.py"\nimportlib.import_module("acme")\n',
        encoding="utf-8",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        result = scan(tmp_path, audit_json=_pip("acme"), skip_epss=True)
    [finding] = result.results
    assert finding.verdict == Verdict.ACTION


def test_unparsable_file_still_counts_through_the_regex_fallback(tmp_path: Path) -> None:
    _project(tmp_path, files=0, roots=["acme"])
    (tmp_path / "py2.py").write_text('import acme\nprint "python 2"\n', encoding="utf-8")
    [finding] = scan(tmp_path, audit_json=_pip("acme"), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert [Path(site).name for site in finding.reachable_imports] == ["py2.py"]


@pytest.mark.parametrize(
    "source",
    [
        "import importlib\nimportlib.import_module(name)\n",
        "from importlib import import_module as load\nload(name)\n",
        "__import__(name)\n",
        "import builtins\nbuiltins.__import__(name)\n",
    ],
)
def test_loader_shortcut_does_not_hide_a_dynamic_import(source: str) -> None:
    python_dynamic_imports.cache_clear()
    assert [o.target for o in python_dynamic_imports(source)] == [None]


def test_file_without_a_loader_name_has_no_dynamic_imports() -> None:
    python_dynamic_imports.cache_clear()
    assert python_dynamic_imports("import os\nos.getcwd()\n") == ()
