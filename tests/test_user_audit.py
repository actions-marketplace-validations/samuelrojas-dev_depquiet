"""Fixes from using the released 0.41.0 the way a new user would."""

from __future__ import annotations

from pathlib import Path

from depquiet.fix import FixResult, _manual_lines
from depquiet.fixcheck import _explain
from depquiet.output import _one_line

FIXTURES = Path(__file__).parent / "fixtures"


def test_uv_graphical_error_keeps_the_cause() -> None:
    # uv 0.11 prints the cause tree with "╰─▶", not "cause:"; only the last
    # line ("we can conclude that ... unsatisfiable") was shown before.
    text = (FIXTURES / "uv_lock_error_graphical.txt").read_text(encoding="utf-8")
    assert _explain(text) == (
        "Because your project depends on requests==2.31.0 and requests==2.33.0, "
        "we can conclude that your project's requirements are unsatisfiable."
    )


def test_advisory_titles_lose_markdown_and_are_cut_at_a_word() -> None:
    title = (
        "### Impact  urllib3's [streaming API](https://urllib3.readthedocs.io/x) is "
        "designed for the efficient handling of large HTTP responses"
    )
    line = _one_line(title)
    assert "#" not in line and "](" not in line and "`" not in line
    assert line.startswith("urllib3's streaming API is designed")
    assert line.endswith("…") and len(line) <= 80
    assert not line[:-1].endswith(" ")
    assert _one_line("Short title") == "Short title"


def test_manual_fixes_are_one_line_per_package() -> None:
    items = [
        FixResult("requests", "2.31.0", "2.32.0", "PYSEC-1", False, ""),
        FixResult("requests", "2.31.0", "2.33.0", "PYSEC-2", False, ""),
        FixResult("flask", "2.2.0", "3.1.3", "PYSEC-3", False, ""),
    ]
    lines = _manual_lines(items)
    assert lines == [
        "requests 2.31.0: require requests>=2.33.0 where the project pins requests, "
        "then reinstall (2 advisories: PYSEC-1, PYSEC-2)",
        "flask 2.2.0: require flask>=3.1.3 where the project pins flask, then reinstall "
        "(1 advisory: PYSEC-3)",
    ]


def test_explain_says_why_there_is_no_epss_score() -> None:
    from depquiet.explain import explain_triage
    from depquiet.models import Severity, TriageResult, Verdict, Vulnerability

    vuln = Vulnerability(
        cve="PYSEC-2026-1999",
        package="urllib3",
        version="1.26.20",
        severity=Severity.MODERATE,
        aliases=["CVE-2025-50181"],
    )
    signal = next(
        s
        for s in explain_triage(TriageResult(vuln=vuln, verdict=Verdict.ACTION)).signals
        if s.name == "EPSS score"
    )
    assert "EPSS scores CVE ids" in signal.detail and "CVE-2025-50181" in signal.detail


def test_help_shows_examples_and_subcommands(capsys) -> None:
    import pytest

    from depquiet.cli import main

    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for text in (
        "depquiet explain <ID>",
        "depquiet diff OLD.json NEW.json",
        "--fix-plan plan.diff",
    ):
        assert text in out
