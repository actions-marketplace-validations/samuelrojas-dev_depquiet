"""A production dependency that is declared but never imported is not dismissed.

Found while measuring the unused-dependency filter on Python projects: pretix
declares ``oauthlib`` and never imports it, but imports ``oauth2_provider``
(django-oauth-toolkit), which uses it. Without a lockfile depquiet cannot see
that edge, and 0.36 filtered the alert as unreachable. The same holds with a
lockfile when another library loads a package it does not declare
(``transformers`` and ``accelerate``, Django and its database driver).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from depquiet.engine import scan
from depquiet.explain import explain_triage
from depquiet.models import FilterReason, Verdict


def _pip(name: str) -> dict[str, Any]:
    return {
        "dependencies": [
            {
                "name": name,
                "version": "1.0",
                "vulns": [
                    {"id": f"TEST-{name.upper()}", "fix_versions": ["2.0"], "description": "x"}
                ],
            }
        ]
    }


def _django_project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "shop"\nversion = "0"\n'
        'dependencies = ["django-oauth-toolkit", "oauthlib"]\n'
        '[dependency-groups]\ndev = ["black"]\n',
        encoding="utf-8",
    )
    (tmp_path / "shop").mkdir()
    (tmp_path / "shop" / "views.py").write_text(
        "from oauth2_provider.models import Application\n", encoding="utf-8"
    )
    return tmp_path


def test_declared_unimported_production_dependency_is_reviewed(tmp_path: Path) -> None:
    [finding] = scan(_django_project(tmp_path), audit_json=_pip("oauthlib"), skip_epss=True).results
    assert finding.verdict == Verdict.REVIEW
    assert finding.reasons == []
    assert finding.evidence.observations[0].startswith(
        "Declared as a production dependency but never imported"
    )
    signal = next(s for s in explain_triage(finding).signals if s.name == "Reachability")
    assert (signal.value, signal.effect) == ("declared_unused", "review")


def test_declared_unimported_dev_dependency_is_still_filtered(tmp_path: Path) -> None:
    [finding] = scan(_django_project(tmp_path), audit_json=_pip("black"), skip_epss=True).results
    assert finding.verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in finding.reasons


def test_imported_package_is_unchanged(tmp_path: Path) -> None:
    project = _django_project(tmp_path)
    [finding] = scan(project, audit_json=_pip("django-oauth-toolkit"), skip_epss=True).results
    assert finding.verdict == Verdict.ACTION


def test_npm_declared_unimported_is_reviewed(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"sequelize": "6", "pg": "8"}}), encoding="utf-8"
    )
    # sequelize loads "pg" itself from the dialect name; the app never requires it.
    (tmp_path / "db.js").write_text(
        "const { Sequelize } = require('sequelize');\n"
        "module.exports = new Sequelize(process.env.DATABASE_URL, { dialect: 'postgres' });\n",
        encoding="utf-8",
    )
    audit = {
        "vulnerabilities": {
            "pg": {
                "severity": "high",
                "isDirect": True,
                "via": [{"title": "Synthetic", "url": "https://example.invalid/TEST-PG"}],
            }
        }
    }
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.REVIEW
    assert FilterReason.UNREACHABLE not in finding.reasons
