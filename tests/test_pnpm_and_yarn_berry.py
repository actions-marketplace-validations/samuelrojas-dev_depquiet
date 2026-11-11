"""pnpm and Yarn Berry projects: lockfile reading, graph, and ``pnpm audit`` input.

Before this, a pnpm project was "no supported project", ``pnpm audit --json``
piped in was an unrecognized format, and a Yarn Berry lockfile yielded no
packages at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from depquiet.depgraph import DependencyGraph
from depquiet.engine import detect_package_manager, scan
from depquiet.models import FilterReason, Verdict
from depquiet.parsers.osv import OsvScanner, parse_lockfiles
from depquiet.parsers.pnpm import PnpmAuditParser
from depquiet.pnpm_lock import parse_pnpm_lock
from depquiet.scanners import ScanError, run_pnpm_audit

PNPM_V9 = """\
---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 12.0.0
        version: 12.0.0

packages:

  pnpm@12.0.0:
    resolution: {integrity: sha512-aaa}

snapshots:

  pnpm@12.0.0: {}

---
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    devDependencies:
      vitest:
        specifier: ^3.0.0
        version: 3.0.0(@types/node@22.0.0)
      '@scope/tool':
        specifier: ^1.0.0
        version: 1.0.0

  packages/app:
    dependencies:
      express:
        specifier: ^4.0.0
        version: 4.19.0
      width-cjs:
        specifier: npm:width@^4.0.0
        version: width@4.2.3
      shared:
        specifier: workspace:*
        version: link:../shared
    devDependencies:
      express-dev-only:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  '@scope/tool@1.0.0':
    resolution: {integrity: sha512-bbb}
    engines: {node: '>=18'}

  express@4.19.0:
    resolution: {integrity: sha512-ccc}
    deprecated: this text wraps
      onto a second line: with a colon
      and a third

  qs@6.5.0:
    resolution: {integrity: sha512-ddd}

  vitest@3.0.0:
    resolution: {integrity: sha512-eee}
    peerDependencies:
      '@types/node': '>=18'
    peerDependenciesMeta:
      '@types/node':
        optional: true

  width@4.2.3:
    resolution: {integrity: sha512-fff}

  xlsx@https://cdn.example.invalid/xlsx-0.20.3.tgz:
    resolution: {tarball: https://cdn.example.invalid/xlsx-0.20.3.tgz}
    version: 0.20.3

  express-dev-only@1.0.0:
    resolution: {integrity: sha512-ggg}

snapshots:

  '@scope/tool@1.0.0':
    dependencies:
      qs: 6.5.0

  express@4.19.0:
    dependencies:
      qs: 6.5.0
      cli-width: width@4.2.3
    optionalDependencies:
      xlsx: https://cdn.example.invalid/xlsx-0.20.3.tgz

  qs@6.5.0: {}

  vitest@3.0.0(@types/node@22.0.0):
    dependencies:
      '@scope/tool': 1.0.0

  width@4.2.3: {}

  xlsx@https://cdn.example.invalid/xlsx-0.20.3.tgz: {}

  express-dev-only@1.0.0: {}
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# -- lockfile reader --------------------------------------------------------


def test_v9_lock_packages_importers_and_edges(tmp_path: Path) -> None:
    lock = parse_pnpm_lock(_write(tmp_path / "pnpm-lock.yaml", PNPM_V9))
    assert sorted(lock.packages) == [
        ("@scope/tool", "1.0.0"),
        ("express", "4.19.0"),
        ("express-dev-only", "1.0.0"),
        ("pnpm", "12.0.0"),
        ("qs", "6.5.0"),
        ("vitest", "3.0.0"),
        ("width", "4.2.3"),
    ]
    assert lock.importers["."] == {"pnpm": True, "vitest": True, "@scope/tool": True}
    # The alias and the package it installs are both production dependencies.
    assert lock.importers["packages/app"] == {
        "express": False,
        "width-cjs": False,
        "width": False,
        "shared": False,
        "express-dev-only": True,
    }
    assert lock.edges["express"] == {"qs", "cli-width", "width", "xlsx"}
    assert lock.edges["vitest"] == {"@types/node", "@scope/tool"}


def test_v6_lock_with_top_level_dependencies(tmp_path: Path) -> None:
    text = """\
lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.0.0
    version: 4.19.0

devDependencies:
  jest:
    specifier: ^29.0.0
    version: 29.0.0

packages:

  /express@4.19.0:
    resolution: {integrity: sha512-a}
    dependencies:
      qs: 6.5.0
    dev: false

  /@babel/core@7.0.0(supports-color@8.0.0):
    resolution: {integrity: sha512-b}
    dev: true

  /jest@29.0.0:
    resolution: {integrity: sha512-c}
    dependencies:
      '@babel/core': 7.0.0(supports-color@8.0.0)
    dev: true

  /qs@6.5.0:
    resolution: {integrity: sha512-d}
    dev: false
"""
    lock = parse_pnpm_lock(_write(tmp_path / "pnpm-lock.yaml", text))
    assert ("@babel/core", "7.0.0") in lock.packages
    assert lock.importers["."] == {"express": False, "jest": True}
    assert lock.edges["jest"] == {"@babel/core"}


def test_v5_lock_keys(tmp_path: Path) -> None:
    text = """\
lockfileVersion: 5.4

specifiers:
  express: ^4.0.0

dependencies:
  express: 4.19.0

packages:

  /express/4.19.0:
    resolution: {integrity: sha512-a}
    dependencies:
      qs: 6.5.0
    dev: false

  /@scope/peer-user/2.0.0_react@18.0.0:
    resolution: {integrity: sha512-b}
    dev: false

  /qs/6.5.0:
    resolution: {integrity: sha512-c}
    dev: false
"""
    lock = parse_pnpm_lock(_write(tmp_path / "pnpm-lock.yaml", text))
    assert sorted(lock.packages) == [
        ("@scope/peer-user", "2.0.0"),
        ("express", "4.19.0"),
        ("qs", "6.5.0"),
    ]
    assert lock.importers["."] == {"express": False}


def test_unsupported_layout_is_an_error_not_a_partial_read(tmp_path: Path) -> None:
    text = "lockfileVersion: '9.0'\npackages:\n\tfoo@1.0.0:\n    resolution: {}\n"
    with pytest.raises(ValueError, match="tab"):
        parse_pnpm_lock(_write(tmp_path / "pnpm-lock.yaml", text))
    text = "lockfileVersion: '9.0'\npackages:\n  foo@1.0.0: {a: 1}\n"
    with pytest.raises(ValueError, match="block mapping"):
        parse_pnpm_lock(_write(tmp_path / "pnpm-lock.yaml", text))


# -- graph ------------------------------------------------------------------


def test_pnpm_graph_separates_development_and_production_paths(tmp_path: Path) -> None:
    _write(tmp_path / "pnpm-lock.yaml", PNPM_V9)
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.coverage_complete
    assert graph.is_dev_only(["vitest"])
    assert graph.is_dev_only(["express-dev-only"])
    assert not graph.is_dev_only(["express"])
    # qs is reached from vitest's tooling and from express: production wins.
    roots = sorted(graph.direct_ancestors("qs"))
    assert roots == ["@scope/tool", "express", "vitest"]
    assert not graph.is_dev_only(roots)
    # Reached through an alias only.
    assert "express" in graph.direct_ancestors("width")


def test_pnpm_project_is_detected(tmp_path: Path) -> None:
    _write(tmp_path / "pnpm-lock.yaml", PNPM_V9)
    assert detect_package_manager(tmp_path) == "pnpm"
    assert ("qs", "6.5.0", "npm") in parse_lockfiles(tmp_path)


# -- pnpm audit input -------------------------------------------------------


def _advisory(
    package: str, ghsa: str, findings: list[dict[str, Any]], **extra: Any
) -> dict[str, Any]:
    return {
        "findings": findings,
        "module_name": package,
        "title": f"{package} issue",
        "severity": "high",
        "vulnerable_versions": "<9.0.0",
        "patched_versions": ">=9.0.0",
        "github_advisory_id": ghsa,
        "url": f"https://github.com/advisories/{ghsa}",
        **extra,
    }


def _audit(*advisories: dict[str, Any]) -> dict[str, Any]:
    return {"advisories": {str(i): a for i, a in enumerate(advisories, 1)}, "metadata": {}}


def test_parse_pnpm_audit(tmp_path: Path) -> None:
    audit = _audit(
        _advisory(
            "qs",
            "GHSA-aaaa-bbbb-cccc",
            [{"version": "6.5.0", "paths": [".>express>qs"], "dev": False}],
        ),
        _advisory(
            "vitest",
            "GHSA-dddd-eeee-ffff",
            [{"version": "3.0.0", "paths": [".>vitest"], "dev": True}],
            patched_versions="<0.0.0",
        ),
    )
    qs, vitest = PnpmAuditParser.parse(audit, tmp_path)
    assert (qs.cve, qs.package, qs.fix_version) == ("GHSA-aaaa-bbbb-cccc", "qs", "9.0.0")
    assert not qs.is_direct and not qs.scanner_dev_only
    assert qs.advisory_range == "<9.0.0" and qs.version_kind == "advisory_range"
    assert any("6.5.0" in note for note in qs.component_notes)
    assert vitest.is_direct and vitest.scanner_dev_only and vitest.fix_version == ""


@pytest.mark.parametrize(
    "findings",
    [
        [],
        [{"version": "1.0.0", "paths": [".>a"], "dev": "true"}],
        [{"version": "1.0.0", "paths": [".>a"]}],
        [
            {"version": "1.0.0", "paths": [".>a"], "dev": True},
            {"version": "2.0.0", "paths": [".>b>a"], "dev": False},
        ],
    ],
)
def test_dev_only_needs_an_explicit_flag_on_every_finding(
    tmp_path: Path, findings: list[dict[str, Any]]
) -> None:
    [vuln] = PnpmAuditParser.parse(
        _audit(_advisory("a", "GHSA-1111-2222-3333", findings)), tmp_path
    )
    assert not vuln.scanner_dev_only


def test_piped_pnpm_audit_is_triaged(tmp_path: Path) -> None:
    _write(tmp_path / "pnpm-lock.yaml", PNPM_V9)
    _write(tmp_path / "packages/app/index.js", "require('express')")
    audit = _audit(
        _advisory(
            "qs",
            "GHSA-aaaa-bbbb-cccc",
            [{"version": "6.5.0", "paths": ["packages__app>express>qs"], "dev": False}],
        ),
        _advisory(
            "vitest",
            "GHSA-dddd-eeee-ffff",
            [{"version": "3.0.0", "paths": [".>vitest"], "dev": True}],
        ),
    )
    result = scan(tmp_path, audit_json=audit, skip_epss=True)
    assert result.package_manager == "pnpm"
    by_package = {r.vuln.package: r for r in result.results}
    assert by_package["qs"].verdict == Verdict.ACTION
    assert "express" in by_package["qs"].introduced_by
    assert by_package["vitest"].verdict == Verdict.FILTERED
    assert FilterReason.DEV_DEPENDENCY in by_package["vitest"].reasons


def test_scanner_dev_flag_filters_a_dev_copy_of_a_production_name(tmp_path: Path) -> None:
    """qs 6.5.0 is production here by name; pnpm says the affected copy is dev-only."""
    _write(tmp_path / "pnpm-lock.yaml", PNPM_V9)
    _write(tmp_path / "packages/app/index.js", "require('express')")
    audit = _audit(
        _advisory(
            "qs",
            "GHSA-aaaa-bbbb-cccc",
            [{"version": "6.5.0", "paths": [".>@scope/tool>qs"], "dev": True}],
        )
    )
    [finding] = scan(tmp_path, audit_json=audit, skip_epss=True).results
    assert finding.verdict == Verdict.FILTERED
    assert finding.reasons == [FilterReason.DEV_DEPENDENCY]
    assert any("scanner reports" in note for note in finding.evidence.observations)


def test_advisories_report_without_pnpm_lock_is_read_as_npm(tmp_path: Path) -> None:
    audit = _audit(
        _advisory(
            "a", "GHSA-1111-2222-3333", [{"version": "1.0.0", "paths": [".>a"], "dev": False}]
        )
    )
    result = scan(tmp_path, audit_json=audit, skip_epss=True)
    assert result.scanned and result.package_manager == "npm"
    assert [r.vuln.package for r in result.results] == ["a"]


def test_missing_pnpm_is_a_scan_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import depquiet.scanners as scanners

    monkeypatch.setattr(scanners.shutil, "which", lambda name: None)
    with pytest.raises(ScanError, match="pnpm is not installed"):
        run_pnpm_audit(tmp_path)


def test_pnpm_audit_error_payload_is_a_scan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import depquiet.scanners as scanners

    class Done:
        returncode = 1
        stdout = json.dumps({"error": {"code": "ERR_PNPM_BROKEN_LOCKFILE", "message": "broken"}})
        stderr = ""

    monkeypatch.setattr(scanners.shutil, "which", lambda name: "/usr/bin/pnpm")
    monkeypatch.setattr(scanners.subprocess, "run", lambda *a, **k: Done())
    with pytest.raises(ScanError, match="broken"):
        run_pnpm_audit(tmp_path)


# -- Yarn -------------------------------------------------------------------

YARN_BERRY = """\
# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 10
  cacheKey: 10c0

"@scope/pkg@npm:^1.0.0, @scope/pkg@npm:^1.1.0":
  version: 1.2.0
  resolution: "@scope/pkg@npm:1.2.0"
  dependencies:
    leaf: "npm:^2.0.0"
  checksum: 10c0/abc
  languageName: node
  linkType: hard

"cli@npm:^3.0.0":
  version: 3.0.0
  resolution: "cli@npm:3.0.0"
  dependencies:
    width-cjs: "npm:width@^4.2.0"
  languageName: node
  linkType: hard

"leaf@npm:^2.0.0":
  version: 2.0.1
  resolution: "leaf@npm:2.0.1"
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  dependencies:
    cli: "npm:^3.0.0"
  languageName: unknown
  linkType: soft

"width-cjs@npm:width@^4.2.0":
  version: 4.2.3
  resolution: "width@npm:4.2.3"
  dependencies:
    ansi: "npm:^5.0.0"
  languageName: node
  linkType: hard
"""


def test_yarn_berry_packages(tmp_path: Path) -> None:
    _write(tmp_path / "yarn.lock", YARN_BERRY)
    assert sorted(parse_lockfiles(tmp_path)) == [
        ("@scope/pkg", "1.2.0", "npm"),
        ("cli", "3.0.0", "npm"),
        ("leaf", "2.0.1", "npm"),
        # The registry package, not the alias it is installed under.
        ("width", "4.2.3", "npm"),
    ]


def test_yarn_v1_packages_still_parse(tmp_path: Path) -> None:
    _write(
        tmp_path / "yarn.lock",
        '# yarn lockfile v1\n\n"@scope/pkg@^1.0.0":\n  version "1.2.0"\n  resolved "https://x"\n\n'
        'leaf@^2.0.0, leaf@^2.0.1:\n  version "2.0.1"\n',
    )
    assert sorted(parse_lockfiles(tmp_path)) == [
        ("@scope/pkg", "1.2.0", "npm"),
        ("leaf", "2.0.1", "npm"),
    ]


def test_yarn_alias_is_a_path_to_the_real_package(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", json.dumps({"dependencies": {"cli": "^3.0.0"}}))
    _write(tmp_path / "yarn.lock", YARN_BERRY)
    graph = DependencyGraph.from_project(tmp_path)
    assert graph.direct_ancestors("width") == {"cli"}
    # The aliased entry's own dependencies belong to the real package too.
    assert graph.direct_ancestors("ansi") == {"cli"}


# -- no silent partial scans ------------------------------------------------


def test_unreadable_lockfile_is_not_skipped_silently(tmp_path: Path) -> None:
    _write(tmp_path / "yarn.lock", YARN_BERRY)
    _write(tmp_path / "pnpm-lock.yaml", "packages:\n\tbroken@1.0.0:\n")
    unreadable: list[str] = []
    assert parse_lockfiles(tmp_path, unreadable)
    assert len(unreadable) == 1 and unreadable[0].startswith("pnpm-lock.yaml")
    with pytest.raises(ScanError, match=r"could not read pnpm-lock\.yaml"):
        OsvScanner.scan_checked(tmp_path)
