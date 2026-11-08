"""Regressions for version contexts and operational errors in saved-scan diffs."""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

import depquiet.cli as cli
from depquiet.cli import main
from depquiet.diff import diff_scans, diff_to_json, format_diff, format_diff_markdown


def _finding(version: str, verdict: str = "action") -> dict:
    return {
        "cve": "SYNTHETIC-MULTIVERSION",
        "package": "fixture-lib",
        "version": version,
        "severity": "high",
        "title": "Synthetic version-context regression",
        "verdict": verdict,
    }


def _write(tmp_path: Path, name: str, report: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _scan(tmp_path: Path, name: str, findings: list[dict], *, legacy: bool = False) -> Path:
    data: dict = {"results": findings}
    if not legacy:
        data["scanned"] = True
    return _write(tmp_path, name, data)


def test_second_affected_version_is_new_and_triggers_action_gate(tmp_path, capsys):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = _scan(tmp_path, "head.json", [_finding("1.0.0"), _finding("2.0.0")])

    result = diff_scans(base, head)
    assert [finding.version for finding in result.new] == ["2.0.0"]
    assert result.unchanged == 1 and not result.fixed and not result.changed
    assert result.has_new_action
    assert main(["diff", str(base), str(head), "--json", "--fail-on-new"]) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["new"][0]["version"] == "2.0.0"


def test_removing_one_version_keeps_other_context_visible(tmp_path):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0"), _finding("2.0.0")])
    head = _scan(tmp_path, "head.json", [_finding("2.0.0")])

    result = diff_scans(base, head)
    assert [finding.version for finding in result.fixed] == ["1.0.0"]
    assert result.unchanged == 1 and not result.new and not result.changed


def test_version_replacement_is_two_distinct_reported_contexts(tmp_path):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = _scan(tmp_path, "head.json", [_finding("2.0.0")])

    result = diff_scans(base, head)
    assert [finding.version for finding in result.new] == ["2.0.0"]
    assert [finding.version for finding in result.fixed] == ["1.0.0"]
    assert not result.changed and result.unchanged == 0


def test_changed_verdict_is_attached_to_correct_version_and_shown_in_reports(tmp_path):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0"), _finding("2.0.0", "review")])
    head = _scan(tmp_path, "head.json", [_finding("2.0.0"), _finding("1.0.0")])

    result = diff_scans(base, head)
    assert result.unchanged == 1 and len(result.changed) == 1
    changed = result.changed[0]
    assert changed.version == "2.0.0" and changed.previous_verdict == "review"
    assert "fixture-lib@2.0.0" in format_diff(result)
    assert "fixture-lib@2.0.0" in format_diff_markdown(result)
    assert diff_to_json(result)["changed"][0]["version"] == "2.0.0"


def test_version_ranges_remain_literal_and_legacy_reports_remain_supported(tmp_path):
    base = _scan(tmp_path, "base.json", [_finding("<2.0.0")], legacy=True)
    head = _scan(tmp_path, "head.json", [_finding("1.0.0")], legacy=True)

    result = diff_scans(base, head)
    assert result.fixed[0].version == "<2.0.0"
    assert result.new[0].version == "1.0.0"
    assert result.unchanged == 0


@pytest.mark.parametrize("side", ["base", "head"])
def test_incomplete_scan_on_either_side_never_produces_diff(tmp_path, side):
    paths = {
        name: _scan(tmp_path, f"{name}.json", [_finding("1.0.0")]) for name in ("base", "head")
    }
    paths[side] = _write(tmp_path, f"{side}.json", {"scanned": False, "results": []})
    with pytest.raises(ValueError, match="incomplete scan"):
        diff_scans(paths["base"], paths["head"])


@pytest.mark.parametrize(
    "report, diagnostic",
    [
        ([], "JSON object"),
        ({}, "results must be an array"),
        ({"results": {}}, "results must be an array"),
        ({"results": None}, "results must be an array"),
        ({"scanned": 1, "results": []}, "scanned must be a boolean"),
        ({"scanned": "false", "results": []}, "scanned must be a boolean"),
        ({"scanned": None, "results": []}, "scanned must be a boolean"),
        ({"results": [None]}, "must be an object"),
        ({"results": [{**_finding("1.0.0"), "version": []}]}, "must be strings"),
        ({"results": [{**_finding("1.0.0"), "verdict": []}]}, "invalid verdict"),
        ({"results": [_finding("1.0.0", "clean")]}, "invalid verdict"),
    ],
)
def test_invalid_report_structure_is_rejected(tmp_path, report, diagnostic):
    base = _scan(tmp_path, "base.json", [])
    head = _write(tmp_path, "head.json", report)
    with pytest.raises(ValueError, match=diagnostic):
        diff_scans(base, head)


@pytest.mark.parametrize("second_verdict", ["action", "filtered"])
def test_duplicate_exact_identity_is_rejected_without_last_row_winning(tmp_path, second_verdict):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = _scan(tmp_path, "head.json", [_finding("1.0.0"), _finding("1.0.0", second_verdict)])
    with pytest.raises(ValueError, match="duplicate finding identity"):
        diff_scans(base, head)


def test_duplicate_completion_flag_cannot_hide_incomplete_report(tmp_path):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = tmp_path / "head.json"
    head.write_text('{"scanned": false, "scanned": true, "results": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        diff_scans(base, head)


@pytest.mark.parametrize("existing_summary", [False, True])
@pytest.mark.parametrize("side", ["base", "head"])
def test_invalid_diff_cli_has_no_success_output_and_preserves_summary(
    tmp_path, capsys, existing_summary, side
):
    paths = {
        name: _scan(tmp_path, f"{name}.json", [_finding("1.0.0")]) for name in ("base", "head")
    }
    paths[side] = _write(tmp_path, f"{side}.json", {"scanned": False, "results": []})
    summary = tmp_path / "summary.md"
    if existing_summary:
        summary.write_text("existing summary must survive\n", encoding="utf-8")

    code = main(
        ["diff", str(paths["base"]), str(paths["head"]), "--json", "--summary", str(summary)]
    )
    output = capsys.readouterr()
    assert code == 2 and output.out == ""
    assert "incomplete scan" in output.err
    if existing_summary:
        assert summary.read_text(encoding="utf-8") == "existing summary must survive\n"
    else:
        assert not summary.exists()


def test_malformed_json_diff_cli_exits_operational_error(tmp_path, capsys):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = tmp_path / "head.json"
    head.write_text("{not JSON", encoding="utf-8")
    assert main(["diff", str(base), str(head), "--json"]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "cannot compare scans" in output.err


def test_unreadable_scan_cli_exits_operational_error(tmp_path, capsys):
    base = _scan(tmp_path, "base.json", [])
    head = _scan(tmp_path, "head.json", [])
    with patch("depquiet.cli.diff_scans", side_effect=PermissionError("synthetic unreadable scan")):
        assert main(["diff", str(base), str(head)]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "synthetic unreadable scan" in output.err


@pytest.mark.parametrize(
    "field, value",
    [
        ("severity", ["high"]),
        ("title", None),
        ("fix_version", 2),
        ("fix_package", {}),
        ("epss_score", "0.1"),
        ("epss_score", True),
        ("epss_score", float("nan")),
        ("epss_score", float("inf")),
        ("epss_score", 10**400),
    ],
)
def test_invalid_optional_fields_never_emit_diff_artifact(tmp_path, capsys, field, value):
    base = _scan(tmp_path, "base.json", [])
    head = _scan(tmp_path, "head.json", [{**_finding("1.0.0"), field: value}])
    summary = tmp_path / "summary.md"
    summary.write_text("existing summary\n", encoding="utf-8")

    assert main(["diff", str(base), str(head), "--json", "--summary", str(summary)]) == 2
    output = capsys.readouterr()
    assert output.out == "" and field in output.err
    assert summary.read_text(encoding="utf-8") == "existing summary\n"


@pytest.mark.parametrize("field", ["cve", "package"])
def test_modern_report_requires_nonempty_identity_before_counting_absent_findings(
    tmp_path, capsys, field
):
    base = _scan(tmp_path, "base.json", [_finding("1.0.0")])
    head = _scan(tmp_path, "head.json", [{**_finding("1.0.0"), field: "  "}])
    summary = tmp_path / "summary.md"
    summary.write_text("existing summary\n", encoding="utf-8")

    assert main(["diff", str(base), str(head), "--json", "--summary", str(summary)]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "must be nonempty" in output.err
    assert summary.read_text(encoding="utf-8") == "existing summary\n"


def test_optional_null_epss_score_is_valid(tmp_path, capsys):
    base = _scan(tmp_path, "base.json", [])
    head = _scan(tmp_path, "head.json", [{**_finding("1.0.0"), "epss_score": None}])
    assert main(["diff", str(base), str(head), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["new"][0]["version"] == "1.0.0"


@pytest.mark.parametrize("failure", ["write", "replace"])
def test_summary_io_failures_preserve_existing_bytes_and_remove_only_temporary_file(
    tmp_path, monkeypatch, capsys, failure
):
    base = _scan(tmp_path, "base.json", [])
    head = _scan(tmp_path, "head.json", [_finding("1.0.0")])
    summary = tmp_path / "summary.md"
    original = b"existing summary bytes\r\n\xff"
    summary.write_bytes(original)
    created = []

    if failure == "write":
        original_factory = cli.tempfile.NamedTemporaryFile

        @contextmanager
        def interrupted_file(*args, **kwargs):
            with original_factory(*args, **kwargs) as stream:
                created.append(Path(stream.name))

                class InterruptedWriter:
                    name = stream.name

                    def write(self, text):
                        stream.write(text[:20])
                        stream.flush()
                        raise OSError("synthetic write failure after partial output")

                yield InterruptedWriter()

        monkeypatch.setattr(cli.tempfile, "NamedTemporaryFile", interrupted_file)
    else:

        def refused_replace(source, destination):
            created.append(Path(source))
            assert Path(source).read_text(encoding="utf-8").startswith("##")
            assert destination == summary
            raise PermissionError("synthetic replace failure")

        monkeypatch.setattr(cli.os, "replace", refused_replace)

    code = main(["diff", str(base), str(head), "--json", "--summary", str(summary)])
    output = capsys.readouterr()
    assert code == 2 and output.out == ""
    assert "synthetic" in output.err
    assert summary.read_bytes() == original
    assert len(created) == 1 and not created[0].exists()
    assert base.exists() and head.exists()
