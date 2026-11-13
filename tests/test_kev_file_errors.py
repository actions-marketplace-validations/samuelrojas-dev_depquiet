"""A KEV file that cannot be read must stop the run, not read as "none exploited"."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from depquiet.cli import main
from depquiet.kev import load_kev_from_file

AUDIT = {
    "dependencies": [
        {
            "name": "pkg",
            "version": "1.0",
            "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["1.1"], "aliases": ["CVE-2026-1"]}],
        }
    ]
}


@pytest.mark.parametrize("content", ["", "{}", '{"vulnerabilities": "x"}', "not json"])
def test_unreadable_catalog_raises(tmp_path: Path, content: str):
    f = tmp_path / "kev.json"
    f.write_text(content)
    with pytest.raises(ValueError):
        load_kev_from_file(f)


@pytest.mark.parametrize("content", [None, "", "{}"])
def test_cli_exits_2_on_a_bad_kev_file(tmp_path, monkeypatch, capsys, content):
    f = tmp_path / "kev.json"
    if content is not None:
        f.write_text(content)
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(AUDIT)))
    code = main(["--path", str(tmp_path), "--stdin", "--offline", "--kev-file", str(f)])
    assert code == 2
    assert "cannot read KEV file" in capsys.readouterr().err


def test_cli_warns_on_stderr_when_kev_is_unavailable_in_json_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("depquiet.cli.fetch_kev_catalog", lambda **_: None)
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(AUDIT)))
    main(["--path", str(tmp_path), "--stdin", "--offline", "--kev", "--json"])
    out = capsys.readouterr()
    json.loads(out.out)  # stdout stays one JSON document
    assert "KEV was not checked" in out.err
