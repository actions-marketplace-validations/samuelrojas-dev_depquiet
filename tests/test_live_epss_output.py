"""Output problems seen running 0.42.1 on a real pip-audit project with live EPSS."""

from __future__ import annotations

import pytest

from depquiet.models import epss_percent, short_title
from depquiet.parsers.pip import PipAuditParser

# PYSEC-2026-1996 as pip-audit reports it: Markdown with a long link up front.
DETAILS = (
    "### Impact\n\nurllib3's [streaming API](https://urllib3.readthedocs.io/en/2.6.2/"
    "advanced-usage.html#streaming-and-i-o) is designed for the efficient handling of "
    "large HTTP responses by reading the content in chunks."
)


def test_title_is_cleaned_before_it_is_cut():
    title = short_title(DETAILS)
    assert title.startswith("urllib3's streaming API is designed for the efficient handling")
    assert "](" not in title and "###" not in title


def test_long_title_is_cut_at_a_word():
    title = short_title("word " * 60, 40)
    assert len(title) <= 40 and title.endswith("…") and not title.endswith(" …")


def test_pip_parser_keeps_a_readable_title(tmp_path):
    report = {
        "dependencies": [
            {
                "name": "urllib3",
                "version": "1.26.4",
                "vulns": [
                    {
                        "id": "PYSEC-2026-1996",
                        "fix_versions": ["2.6.3"],
                        "aliases": ["CVE-2026-21441"],
                        "description": DETAILS,
                    }
                ],
            }
        ]
    }
    vulns = PipAuditParser.parse(report, tmp_path)
    assert "is designed for" in vulns[0].title


@pytest.mark.parametrize(
    ("score", "shown"),
    [
        (0.85, "85%"),
        (0.04, "4%"),
        (0.01, "1%"),
        (0.004, "0.4%"),
        (0.001, "0.1%"),
        (0.0002, "<0.1%"),
    ],
)
def test_epss_never_rounds_to_zero(score, shown):
    assert epss_percent(score) == shown
