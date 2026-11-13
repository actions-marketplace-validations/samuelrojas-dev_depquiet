"""Paths that hid real alerts, found by a black-box audit (v0.42.2).

Each case is a project where the vulnerable package runs in production
without the project importing it: an ORM loads its database driver from a
dialect name, requests loads certifi, PyJWT loads cryptography. depquiet
keeps those for review when nothing imports them; a test import or a
community template must not turn that into a dismissal.
"""

from __future__ import annotations

import json
from pathlib import Path

from depquiet.engine import scan
from depquiet.models import FilterReason, Verdict


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _npm(package: str) -> dict[str, object]:
    return {
        "auditReportVersion": 2,
        "vulnerabilities": {
            package: {
                "name": package,
                "severity": "high",
                "isDirect": True,
                "via": [
                    {
                        "source": 1,
                        "name": package,
                        "title": "t",
                        "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                        "severity": "high",
                        "range": "<9.0.0",
                    }
                ],
                "range": "<9.0.0",
                "nodes": [f"node_modules/{package}"],
                "fixAvailable": True,
            }
        },
    }


def _pip(package: str, advisory: str, aliases: list[str]) -> dict[str, object]:
    return {
        "dependencies": [
            {
                "name": package,
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": advisory,
                        "fix_versions": ["99.0"],
                        "aliases": aliases,
                        "description": "x",
                    }
                ],
            }
        ]
    }


def _pyproject(*deps: str) -> str:
    listed = ", ".join(f'"{d}==1.0.0"' for d in deps)
    return f'[project]\nname = "x"\nversion = "1"\ndependencies = [{listed}]\n'


def _only(result):  # type: ignore[no-untyped-def]
    [finding] = result.results
    return finding


def test_orm_driver_imported_only_by_a_test_is_reviewed_not_filtered(tmp_path: Path) -> None:
    project = _write(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"sequelize": "1.0.0", "pg": "1.0.0"}}),
            "db.js": "const { Sequelize } = require('sequelize');\n"
            "new Sequelize('db', 'u', 'p', { dialect: 'postgres' });\n",
            "__tests__/db.test.js": "require('pg');\n",
        },
    )
    finding = _only(scan(project=project, skip_epss=True, audit_json=_npm("pg")))
    assert finding.verdict == Verdict.REVIEW
    assert FilterReason.TEST_ONLY not in finding.reasons
    assert any("Imported only from test code" in o for o in finding.evidence.observations)


def test_crypto_backend_imported_only_by_a_test_is_reviewed(tmp_path: Path) -> None:
    project = _write(
        tmp_path,
        {
            "pyproject.toml": _pyproject("pyjwt", "cryptography"),
            "auth.py": "import jwt\n",
            "tests/test_c.py": "import cryptography\n",
        },
    )
    audit = _pip("cryptography", "PYSEC-2099-1", ["CVE-2099-0001"])
    assert _only(scan(project=project, skip_epss=True, audit_json=audit)).verdict == Verdict.REVIEW


def test_community_template_does_not_dismiss_a_dependency_another_library_loads(
    tmp_path: Path,
) -> None:
    # requests loads certifi on every HTTPS call; nothing imports certifi.
    project = _write(
        tmp_path,
        {"pyproject.toml": _pyproject("requests", "certifi"), "app.py": "import requests\n"},
    )
    for advisory, aliases in (("CVE-2024-39689", []), ("PYSEC-2099-2", ["CVE-2024-39689"])):
        audit = _pip("certifi", advisory, aliases)
        finding = _only(scan(project=project, skip_epss=True, audit_json=audit))
        assert finding.verdict == Verdict.REVIEW
        assert FilterReason.COMMUNITY_TEMPLATE not in finding.reasons
        assert any("certifi-root-ca" in o for o in finding.evidence.observations)


def test_stale_lockfile_dev_flag_does_not_override_the_manifest(tmp_path: Path) -> None:
    lock = {
        "name": "x",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "x", "version": "1.0.0", "devDependencies": {"lodash": "1.0.0"}},
            "node_modules/lodash": {"version": "1.0.0", "dev": True},
        },
    }
    project = _write(
        tmp_path,
        {
            "package.json": json.dumps(
                {"name": "x", "version": "1.0.0", "dependencies": {"lodash": "1.0.0"}}
            ),
            "package-lock.json": json.dumps(lock),
            "src/a.js": "require('lodash');\n",
        },
    )
    finding = _only(scan(project=project, skip_epss=True, audit_json=_npm("lodash")))
    assert finding.verdict == Verdict.ACTION
    assert FilterReason.DEV_DEPENDENCY not in finding.reasons
