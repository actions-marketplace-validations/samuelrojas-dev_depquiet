"""Unreadable or unenumerated source is uncertainty, not evidence of absence."""

from __future__ import annotations

import errno
import json
from collections import Counter
from pathlib import Path

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.engine import scan
from depquiet.filters import reachability
from depquiet.filters.reachability import ReachabilityFilter, _source_files
from depquiet.models import FilterReason, Severity, Verdict, Vulnerability


def _project(project: Path, *, dev: bool = False) -> None:
    section = "devDependencies" if dev else "dependencies"
    (project / "package.json").write_text(json.dumps({section: {"example-lib": "1"}}))


def _audit() -> dict:
    return {
        "vulnerabilities": {
            "example-lib": {
                "severity": "high",
                "isDirect": True,
                "via": [{"title": "Test finding", "url": "https://example.com/advisories/TEST-1"}],
            }
        }
    }


def _vuln(*, functions: bool = False) -> Vulnerability:
    return Vulnerability(
        "TEST-1",
        "example-lib",
        "1",
        Severity.HIGH,
        vulnerable_functions=["dangerous"] if functions else [],
    )


def _deny_read(monkeypatch, blocked: Path) -> Counter:
    calls: Counter = Counter()
    original = reachability._read_text

    def read(path: Path) -> str:
        calls[path] += 1
        if path == blocked:
            raise PermissionError(errno.EACCES, "source read denied", str(path))
        return original(path)

    monkeypatch.setattr(reachability, "_read_text", read)
    return calls


@pytest.mark.parametrize(
    "name,source",
    [("private.py", "import example_lib\n"), ("private.js", "require('example-lib');\n")],
)
def test_read_failure_cannot_justify_unreachable(
    tmp_path: Path, monkeypatch, name: str, source: str
) -> None:
    _project(tmp_path)
    blocked = tmp_path / name
    blocked.write_text(source)
    (tmp_path / "unrelated.js").write_text("console.log('hello');\n")
    _deny_read(monkeypatch, blocked)
    result = scan(tmp_path, audit_json=_audit(), skip_epss=True)
    [finding] = result.results
    assert result.scanned is True
    assert finding.verdict == Verdict.ACTION
    assert FilterReason.UNREACHABLE not in finding.reasons
    assert finding.evidence.usage == "unknown"
    assert finding.evidence.import_sites == []
    assert any(
        name in observation
        and "PermissionError" in observation
        and "source read denied" in observation
        for observation in finding.evidence.observations
    )


@pytest.mark.parametrize("functions", [False, True])
def test_check_decide_and_template_reference_checks_share_incomplete_coverage(
    tmp_path: Path, monkeypatch, functions: bool
) -> None:
    _project(tmp_path)
    blocked = tmp_path / "private.py"
    blocked.write_text("import example_lib\n")
    (tmp_path / "readable.py").write_text("print(1)\n")
    _deny_read(monkeypatch, blocked)
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.check(_vuln(functions=functions)) is False
    assert (
        filter_.decide(
            _vuln(functions=functions), DependencyGraph.from_project(tmp_path)
        ).unreachable
        is False
    )
    assert filter_.references_absent(["dangerous"]) is False
    assert filter_.source_coverage_complete is False


def test_positive_usage_stays_observed_with_read_failure_elsewhere(
    tmp_path: Path, monkeypatch
) -> None:
    _project(tmp_path)
    blocked = tmp_path / "private.py"
    blocked.write_text("import something_else\n")
    visible = tmp_path / "public.js"
    visible.write_text("require('example-lib');\n")
    _deny_read(monkeypatch, blocked)
    [finding] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert finding.evidence.usage == "observed"
    assert finding.evidence.import_sites == [str(visible)]
    assert any(
        "private.py" in item and "PermissionError" in item for item in finding.evidence.observations
    )


def test_failed_and_successful_source_reads_are_cached_for_each_filter(
    tmp_path: Path, monkeypatch
) -> None:
    _project(tmp_path)
    blocked = tmp_path / "private.py"
    blocked.write_text("import example_lib\n")
    readable = tmp_path / "public.js"
    readable.write_text("require('other-package');\n")
    calls = _deny_read(monkeypatch, blocked)
    discovery_calls = 0
    original = reachability._source_files

    def discover(*args, **kwargs):
        nonlocal discovery_calls
        discovery_calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(reachability, "_source_files", discover)
    filter_ = ReachabilityFilter(tmp_path)
    graph = DependencyGraph.from_project(tmp_path)
    for package in ["example-lib", "other-package", "third-package"]:
        vuln = Vulnerability("TEST-1", package, "1", Severity.HIGH)
        filter_.decide(vuln, graph)
        filter_.find_imports(vuln)
        filter_.is_used(package, graph)
        filter_.references_absent(["dangerous"])
    assert discovery_calls == 1
    assert calls[blocked] == calls[readable] == 1
    assert len(filter_.source_coverage_observations) == 1


def test_complete_source_still_reports_not_observed(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / "public.js").write_text("console.log('hello');\n")
    [finding] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    # A declared production dependency nobody imports is reviewed, not dismissed.
    assert finding.verdict == Verdict.REVIEW
    assert finding.reasons == []
    assert finding.evidence.usage == "not_observed"


def test_no_sources_without_enumeration_error_is_unknown(tmp_path: Path) -> None:
    _project(tmp_path)
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.source_coverage_complete is True
    assert filter_.source_coverage_observations == []
    assert filter_.check(_vuln()) is False
    assert filter_.references_absent(["dangerous"]) is False
    [finding] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    assert finding.evidence.usage == "unknown"
    assert FilterReason.UNREACHABLE not in finding.reasons


@pytest.mark.parametrize("with_readable_source", [False, True])
def test_enumeration_failure_cannot_establish_source_absence(
    tmp_path: Path, monkeypatch, with_readable_source: bool
) -> None:
    _project(tmp_path)
    if with_readable_source:
        (tmp_path / "public.js").write_text("console.log('hello');\n")
    original = reachability.os.walk
    inaccessible = tmp_path / "private"

    def walk(top, *args, onerror=None, **kwargs):
        if onerror is not None:
            onerror(PermissionError(errno.EACCES, "directory listing denied", str(inaccessible)))
        yield from original(top, *args, onerror=onerror, **kwargs)

    monkeypatch.setattr(reachability.os, "walk", walk)
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.source_coverage_complete is False
    assert filter_.check(_vuln()) is False
    assert filter_.references_absent(["dangerous"]) is False
    [finding] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION
    assert finding.evidence.usage == "unknown"
    assert finding.evidence.import_sites == []
    assert any(
        "private" in item and "directory listing denied" in item
        for item in finding.evidence.observations
    )


def test_standalone_source_discovery_preserves_legacy_result(tmp_path: Path) -> None:
    source = tmp_path / "public.py"
    source.write_text("print(1)\n")
    assert _source_files(tmp_path, {".py"}) == [source]


def test_skipped_vendor_source_does_not_create_coverage_failure(
    tmp_path: Path, monkeypatch
) -> None:
    _project(tmp_path)
    (tmp_path / "public.js").write_text("console.log('hello');\n")
    vendor = tmp_path / "node_modules" / "example-lib"
    vendor.mkdir(parents=True)
    blocked = vendor / "private.js"
    blocked.write_text("require('example-lib');\n")
    calls = _deny_read(monkeypatch, blocked)
    filter_ = ReachabilityFilter(tmp_path)
    assert filter_.check(_vuln()) is True
    assert filter_.source_coverage_complete is True
    assert calls[blocked] == 0


def test_dev_filter_remains_independent_of_source_uncertainty(tmp_path: Path, monkeypatch) -> None:
    _project(tmp_path, dev=True)
    blocked = tmp_path / "private.js"
    blocked.write_text("require('example-lib');\n")
    _deny_read(monkeypatch, blocked)
    result = scan(tmp_path, audit_json=_audit(), skip_epss=True)
    [finding] = result.results
    assert result.scanned is True
    assert finding.verdict == Verdict.FILTERED
    assert finding.reasons == [FilterReason.DEV_DEPENDENCY]
    assert finding.evidence.usage == "unknown"


def _deny_stat_during_mentions(monkeypatch, blocked: Path) -> None:
    original_mentions = reachability._mention_words
    original_stat = Path.stat

    def mentions(*args, **kwargs):
        def stat(path: Path, *stat_args, **stat_kwargs):
            if path == blocked:
                raise PermissionError(errno.EACCES, "source metadata denied", str(path))
            return original_stat(path, *stat_args, **stat_kwargs)

        # Inventory preflight completes normally. Only mention collection loses
        # access to this path's metadata; no fragile global call counts.
        with monkeypatch.context() as phase:
            phase.setattr(Path, "stat", stat)
            return original_mentions(*args, **kwargs)

    monkeypatch.setattr(reachability, "_mention_words", mentions)


def test_metadata_failure_during_mentions_does_not_bypass_coverage_guard(
    tmp_path: Path, monkeypatch
) -> None:
    _project(tmp_path)
    settings = tmp_path / "settings.py"
    settings.write_text("PLUGINS = ['example_lib']\n")
    [control] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    assert control.verdict == Verdict.ACTION
    assert control.evidence.usage == "observed"

    _deny_stat_during_mentions(monkeypatch, settings)
    result = scan(tmp_path, audit_json=_audit(), skip_epss=True)
    [finding] = result.results
    assert result.scanned is True
    assert finding.verdict == Verdict.ACTION
    assert FilterReason.UNREACHABLE not in finding.reasons
    assert finding.evidence.usage == "unknown"
    assert finding.evidence.import_sites == []
    assert any(
        "inspect source metadata settings.py" in observation
        and "PermissionError" in observation
        and "source metadata denied" in observation
        for observation in finding.evidence.observations
    )
    assert not any("enumerate source directory" in item for item in finding.evidence.observations)


def test_mention_metadata_errors_outside_included_sources_preserve_scope(
    tmp_path: Path, monkeypatch
) -> None:
    _project(tmp_path)
    (tmp_path / "public.js").write_text("console.log('hello');\n")
    config = tmp_path / "optional.ini"
    config.write_text("value = unimportant\n")
    _deny_stat_during_mentions(monkeypatch, config)
    [finding] = scan(tmp_path, audit_json=_audit(), skip_epss=True).results
    assert finding.verdict == Verdict.REVIEW
    assert finding.evidence.usage == "not_observed"
    assert not any("optional.ini" in item for item in finding.evidence.observations)
