"""Inputs the user names but depquiet cannot read must never pass silently.

Scan input that cannot be read is exit 2 (1 means "findings", which a CI step
may tolerate). Policy, ignore and config files that yield nothing say so.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from depquiet.cli import main


@pytest.mark.parametrize("content", [None, "", "not json", "[1, 2]", '"text"'])
def test_from_sbom_unreadable_is_exit_2(tmp_path: Path, capsys, content):
    f = tmp_path / "sbom.json"
    if content is not None:
        f.write_text(content)
    assert main(["--path", str(tmp_path), "--offline", "--from-sbom", str(f)]) == 2
    assert "Error:" in capsys.readouterr().err


@pytest.mark.parametrize("content", ["not json", '"text"', "42"])
def test_stdin_unreadable_is_exit_2(tmp_path: Path, monkeypatch, capsys, content):
    monkeypatch.setattr("sys.stdin", io.StringIO(content))
    assert main(["--path", str(tmp_path), "--offline", "--stdin"]) == 2
    assert "Error:" in capsys.readouterr().err


AUDIT = {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": []}]}


@pytest.mark.parametrize(
    ("flag", "message"),
    [
        ("--policy", "no rules read"),
        ("--ignore", "no entries read"),
        ("--config", "no settings read"),
    ],
)
def test_file_that_yields_nothing_warns(tmp_path, monkeypatch, capsys, flag, message):
    f = tmp_path / "file.yaml"
    f.write_text("[1, 2]\n")
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(tmp_path), "--offline", "--stdin", flag, str(f)])
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--policy", "--ignore", "--config"])
def test_comment_only_file_does_not_warn(tmp_path, monkeypatch, capsys, flag):
    f = tmp_path / "file.yaml"
    f.write_text("# nothing yet\n")
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(AUDIT)))
    main(["--path", str(tmp_path), "--offline", "--stdin", flag, str(f)])
    assert "read from" not in capsys.readouterr().err
