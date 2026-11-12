"""Template conditions must have source evidence; bundled files ship in wheels."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from depquiet.engine import scan
from depquiet.filters.templates import TemplateFilter
from depquiet.models import FilterReason, Verdict


def _project(project: Path, source: str = "console.log('hello');\n") -> None:
    (project / "package.json").write_text('{"dependencies":{"lodash":"4.17.0"}}')
    (project / "app.js").write_text(source)


def test_bundled_templates_are_conditional() -> None:
    templates = TemplateFilter()
    assert templates.count == len(
        list((Path(__file__).parents[1] / "templates/dismiss").glob("*.yaml"))
    )
    assert templates.count >= 20
    assert all(template.not_imported for template in templates._templates)


def test_conditional_template_requires_project() -> None:
    assert TemplateFilter().find_match("CVE-2020-8203", "lodash") is None


def test_conditional_template_requires_source(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"lodash":"4.17.0"}}')
    assert TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path) is None


def test_conditional_template_requires_known_relationship(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("console.log('hello');\n")
    assert TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path) is None


@pytest.mark.parametrize(
    "source",
    [
        "const _ = require('lodash'); _.merge({}, input);\n",
        "const _ = require('lodash'); _.get(input, 'x');\n",
        "const fn = require('lodash/merge'); fn({}, input);\n",
    ],
)
def test_conditional_template_keeps_used_package(tmp_path: Path, source: str) -> None:
    _project(tmp_path, source)
    assert TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path) is None


def test_not_imported_checks_names_in_source(tmp_path: Path) -> None:
    _project(tmp_path, "function merge(a, b) { return a; }\n")
    assert TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path) is None


def test_conditional_template_matches_inspectable_unused_dependency(tmp_path: Path) -> None:
    _project(tmp_path)
    match = TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path)
    assert match is not None


def test_unreadable_source_does_not_match(tmp_path: Path) -> None:
    _project(tmp_path)
    with patch("depquiet.filters.reachability._read_text", side_effect=OSError("unreadable")):
        assert TemplateFilter().find_match("CVE-2020-8203", "lodash", project=tmp_path) is None


def test_template_does_not_filter_transitive_of_used_parent(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4.19.2"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"express": "4.19.2"}},
                    "node_modules/express": {"dependencies": {"qs": "6.11.0"}},
                    "node_modules/qs": {"version": "6.11.0"},
                }
            }
        )
    )
    (tmp_path / "app.js").write_text("const express = require('express'); express();\n")
    audit = {
        "vulnerabilities": {
            "qs": {
                "severity": "high",
                "isDirect": False,
                "via": [
                    {
                        "title": "Prototype pollution",
                        "url": "https://github.com/advisories/CVE-2022-24999",
                    }
                ],
            }
        }
    }
    [result] = scan(tmp_path, skip_epss=True, audit_json=audit).results
    assert result.verdict == Verdict.ACTION
    assert FilterReason.COMMUNITY_TEMPLATE not in result.reasons


def test_template_directories_are_not_mutated(tmp_path: Path) -> None:
    directories = [tmp_path]
    TemplateFilter(directories)
    assert directories == [tmp_path]


def test_explicit_custom_dismissal_still_matches(tmp_path: Path) -> None:
    (tmp_path / "custom.yaml").write_text("id: custom\ncves: [CUSTOM-1]\nreason: accepted risk\n")
    match = TemplateFilter([tmp_path]).find_match("CUSTOM-1", "some-package")
    assert match is not None
    assert match.id == "custom"


def test_builtin_template_reasons_state_only_what_is_checked():
    """A dismissal reason must not make technical claims depquiet never verified.

    Earlier reasons said qs was "mitigated by Express 4.x defaults" and that the
    node-forge CVEs were a "timing attack"; neither was checked, and both were
    wrong.
    """
    from depquiet.filters.templates import TemplateFilter

    templates = TemplateFilter()
    for template in templates._templates:
        assert "That is all depquiet checked" in template.reason, template.id
        assert template.not_imported, template.id
    ids = [t.id for t in templates._templates]
    assert len(ids) == len(set(ids))
    cves = [(t.package, c) for t in templates._templates for c in t.cves]
    assert len(cves) == len(set(cves)), "two built-in templates for the same CVE"
