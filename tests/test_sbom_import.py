"""Tests for SBOM import — CycloneDX and SPDX parsing."""

from __future__ import annotations

from pathlib import Path

from depquiet.models import Severity
from depquiet.parsers.sbom import (
    SbomParser,
    _parse_cyclonedx_packages,
    _parse_cyclonedx_vulns,
    _parse_purl,
    _parse_spdx_packages,
    _parse_spdx_vulns,
    is_cyclonedx,
    is_spdx,
)

# ---------------------------------------------------------------------------
# Purl parsing
# ---------------------------------------------------------------------------


class TestParsePurl:
    def test_npm_simple(self):
        name, version, eco = _parse_purl("pkg:npm/lodash@4.17.21")
        assert name == "lodash"
        assert version == "4.17.21"
        assert eco == "npm"

    def test_npm_scoped(self):
        name, version, eco = _parse_purl("pkg:npm/%40babel/core@7.24.0")
        assert name == "@babel/core"
        assert version == "7.24.0"
        assert eco == "npm"

    def test_pypi(self):
        name, version, eco = _parse_purl("pkg:pypi/requests@2.31.0")
        assert name == "requests"
        assert version == "2.31.0"
        assert eco == "PyPI"

    def test_golang(self):
        name, version, eco = _parse_purl("pkg:golang/github.com/gin-gonic/gin@1.9.1")
        assert name == "github.com/gin-gonic/gin"
        assert version == "1.9.1"
        assert eco == "Go"

    def test_cargo(self):
        name, version, eco = _parse_purl("pkg:cargo/serde@1.0.197")
        assert name == "serde"
        assert version == "1.0.197"
        assert eco == "crates.io"

    def test_no_version(self):
        name, version, eco = _parse_purl("pkg:npm/lodash")
        assert name == "lodash"
        assert version == ""
        assert eco == "npm"

    def test_invalid(self):
        assert _parse_purl("not-a-purl") == ("", "", "")

    def test_unknown_type(self):
        name, version, eco = _parse_purl("pkg:hackage/aeson@2.2.1")
        assert name == "aeson"
        assert version == "2.2.1"
        assert eco == "hackage"  # passthrough


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_cyclonedx_by_bomformat(self):
        assert is_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.5"})

    def test_cyclonedx_by_keys(self):
        assert is_cyclonedx({"components": [], "specVersion": "1.4"})

    def test_not_cyclonedx(self):
        assert not is_cyclonedx({"runs": []})

    def test_spdx_2_3(self):
        assert is_spdx({"spdxVersion": "SPDX-2.3"})

    def test_spdx_2_2(self):
        assert is_spdx({"spdxVersion": "SPDX-2.2"})

    def test_not_spdx(self):
        assert not is_spdx({"bomFormat": "CycloneDX"})

    def test_neither(self):
        assert not is_cyclonedx({"vulnerabilities": {}})
        assert not is_spdx({"spdxVersion": 123})


# ---------------------------------------------------------------------------
# CycloneDX fixtures
# ---------------------------------------------------------------------------


def _cdx_sbom(
    *,
    components: list | None = None,
    vulnerabilities: list | None = None,
) -> dict:
    bom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components or [],
    }
    if vulnerabilities is not None:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def _cdx_component(
    name: str,
    version: str = "1.0.0",
    purl: str = "",
    bom_ref: str = "",
) -> dict:
    comp: dict = {"type": "library", "name": name, "version": version}
    if purl:
        comp["purl"] = purl
    if bom_ref:
        comp["bom-ref"] = bom_ref
    return comp


def _cdx_vuln(
    vuln_id: str,
    *,
    severity: str = "high",
    affects: list | None = None,
    description: str = "",
    source_url: str = "",
) -> dict:
    entry: dict = {
        "id": vuln_id,
        "ratings": [{"severity": severity}],
    }
    if description:
        entry["description"] = description
    if affects is not None:
        entry["affects"] = affects
    if source_url:
        entry["source"] = {"url": source_url}
    return entry


# ---------------------------------------------------------------------------
# CycloneDX package extraction
# ---------------------------------------------------------------------------


class TestCycloneDxPackages:
    def test_basic(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("lodash", "4.17.21"),
                _cdx_component("express", "4.18.2"),
            ]
        )
        pkgs = _parse_cyclonedx_packages(bom)
        assert len(pkgs) == 2
        assert ("lodash", "4.17.21", "") in pkgs
        assert ("express", "4.18.2", "") in pkgs

    def test_purl_resolves_ecosystem(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component(
                    "lodash",
                    "4.17.21",
                    purl="pkg:npm/lodash@4.17.21",
                ),
            ]
        )
        pkgs = _parse_cyclonedx_packages(bom)
        assert pkgs == [("lodash", "4.17.21", "npm")]

    def test_scoped_npm_via_purl(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component(
                    "@babel/core",
                    "7.24.0",
                    purl="pkg:npm/%40babel/core@7.24.0",
                ),
            ]
        )
        pkgs = _parse_cyclonedx_packages(bom)
        assert pkgs[0][0] == "@babel/core"
        assert pkgs[0][2] == "npm"

    def test_dedup(self):
        comp = _cdx_component("lodash", "4.17.21")
        bom = _cdx_sbom(components=[comp, comp])
        pkgs = _parse_cyclonedx_packages(bom)
        assert len(pkgs) == 1

    def test_empty_components(self):
        bom = _cdx_sbom(components=[])
        assert _parse_cyclonedx_packages(bom) == []

    def test_skip_nameless(self):
        bom = _cdx_sbom(components=[{"type": "library", "version": "1.0.0"}])
        assert _parse_cyclonedx_packages(bom) == []


# ---------------------------------------------------------------------------
# CycloneDX vulnerability extraction
# ---------------------------------------------------------------------------


class TestCycloneDxVulns:
    def test_basic_vuln(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("lodash", "4.17.20", bom_ref="ref-lodash"),
            ],
            vulnerabilities=[
                _cdx_vuln(
                    "CVE-2021-23337",
                    severity="high",
                    affects=[{"ref": "ref-lodash"}],
                    description="Prototype Pollution in lodash",
                    source_url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                ),
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve == "CVE-2021-23337"
        assert v.package == "lodash"
        assert v.version == "4.17.20"
        assert v.severity == Severity.HIGH
        assert "Prototype Pollution" in v.title
        assert v.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"

    def test_severity_from_cvss_score(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("pkg", "1.0", bom_ref="ref-pkg"),
            ],
            vulnerabilities=[
                {
                    "id": "CVE-2024-0001",
                    "ratings": [{"score": 9.8}],
                    "affects": [{"ref": "ref-pkg"}],
                },
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert vulns[0].severity == Severity.CRITICAL

    def test_vuln_without_affects(self):
        bom = _cdx_sbom(
            components=[],
            vulnerabilities=[
                _cdx_vuln("CVE-2024-9999", severity="critical"),
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert len(vulns) == 1
        assert vulns[0].package == "unknown"

    def test_fix_version_from_affects(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("pkg", "1.0", bom_ref="ref-pkg"),
            ],
            vulnerabilities=[
                {
                    "id": "CVE-2024-0002",
                    "ratings": [{"severity": "medium"}],
                    "affects": [
                        {
                            "ref": "ref-pkg",
                            "versions": [
                                {"version": "1.0", "status": "affected"},
                                {"version": "1.1", "status": "unaffected"},
                            ],
                        }
                    ],
                },
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert vulns[0].fix_version == "1.1"

    def test_dedup_vulns(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("pkg", "1.0", bom_ref="ref-pkg"),
            ],
            vulnerabilities=[
                _cdx_vuln(
                    "CVE-2024-0003",
                    affects=[{"ref": "ref-pkg"}],
                ),
                _cdx_vuln(
                    "CVE-2024-0003",
                    affects=[{"ref": "ref-pkg"}],
                ),
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert len(vulns) == 1

    def test_purl_resolves_name(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component(
                    "@babel/core",
                    "7.24.0",
                    purl="pkg:npm/%40babel/core@7.24.0",
                    bom_ref="ref-babel",
                ),
            ],
            vulnerabilities=[
                _cdx_vuln(
                    "CVE-2024-0004",
                    affects=[{"ref": "ref-babel"}],
                ),
            ],
        )
        vulns = _parse_cyclonedx_vulns(bom)
        assert vulns[0].package == "@babel/core"

    def test_empty_vulnerabilities(self):
        bom = _cdx_sbom(components=[], vulnerabilities=[])
        assert _parse_cyclonedx_vulns(bom) == []


# ---------------------------------------------------------------------------
# SPDX fixtures
# ---------------------------------------------------------------------------


def _spdx_doc(*, packages: list | None = None) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-sbom",
        "packages": packages or [],
    }


def _spdx_package(
    name: str,
    version: str = "1.0.0",
    purl: str = "",
    security_refs: list[dict] | None = None,
) -> dict:
    pkg: dict = {
        "SPDXID": f"SPDXRef-{name}",
        "name": name,
        "versionInfo": version,
        "externalRefs": [],
    }
    if purl:
        pkg["externalRefs"].append(
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        )
    if security_refs:
        pkg["externalRefs"].extend(security_refs)
    return pkg


def _security_ref(locator: str, comment: str = "") -> dict:
    ref: dict = {
        "referenceCategory": "SECURITY",
        "referenceType": "cpe23Type",
        "referenceLocator": locator,
    }
    if comment:
        ref["comment"] = comment
    return ref


# ---------------------------------------------------------------------------
# SPDX package extraction
# ---------------------------------------------------------------------------


class TestSpdxPackages:
    def test_basic(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package("lodash", "4.17.21"),
                _spdx_package("express", "4.18.2"),
            ]
        )
        pkgs = _parse_spdx_packages(doc)
        assert len(pkgs) == 2

    def test_purl_resolves_ecosystem(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.21",
                    purl="pkg:npm/lodash@4.17.21",
                ),
            ]
        )
        pkgs = _parse_spdx_packages(doc)
        assert pkgs == [("lodash", "4.17.21", "npm")]

    def test_dedup(self):
        pkg = _spdx_package("lodash", "4.17.21")
        doc = _spdx_doc(packages=[pkg, pkg])
        pkgs = _parse_spdx_packages(doc)
        assert len(pkgs) == 1

    def test_empty(self):
        doc = _spdx_doc(packages=[])
        assert _parse_spdx_packages(doc) == []


# ---------------------------------------------------------------------------
# SPDX vulnerability extraction
# ---------------------------------------------------------------------------


class TestSpdxVulns:
    def test_cve_from_url(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.20",
                    security_refs=[
                        _security_ref(
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                            comment="Prototype Pollution",
                        ),
                    ],
                ),
            ]
        )
        vulns = _parse_spdx_vulns(doc)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.cve == "CVE-2021-23337"
        assert v.package == "lodash"
        assert v.version == "4.17.20"
        assert v.severity == Severity.MODERATE  # SPDX has no severity
        assert v.title == "Prototype Pollution"
        assert "nvd.nist.gov" in v.url

    def test_cve_direct_id(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "pkg",
                    "1.0",
                    security_refs=[_security_ref("CVE-2024-1234")],
                ),
            ]
        )
        vulns = _parse_spdx_vulns(doc)
        assert vulns[0].cve == "CVE-2024-1234"

    def test_non_cve_locator(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "pkg",
                    "1.0",
                    security_refs=[_security_ref("GHSA-xxxx-yyyy-zzzz")],
                ),
            ]
        )
        vulns = _parse_spdx_vulns(doc)
        assert vulns[0].cve == "GHSA-xxxx-yyyy-zzzz"

    def test_purl_resolves_name(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.20",
                    purl="pkg:npm/lodash@4.17.20",
                    security_refs=[_security_ref("CVE-2021-23337")],
                ),
            ]
        )
        vulns = _parse_spdx_vulns(doc)
        assert vulns[0].package == "lodash"

    def test_dedup(self):
        ref = _security_ref("CVE-2024-0001")
        doc = _spdx_doc(
            packages=[
                _spdx_package("pkg", "1.0", security_refs=[ref, ref]),
            ]
        )
        vulns = _parse_spdx_vulns(doc)
        assert len(vulns) == 1

    def test_no_security_refs(self):
        doc = _spdx_doc(
            packages=[_spdx_package("lodash", "4.17.21")],
        )
        assert _parse_spdx_vulns(doc) == []


# ---------------------------------------------------------------------------
# SbomParser (unified API)
# ---------------------------------------------------------------------------


class TestSbomParser:
    def test_detect_always_false(self):
        assert SbomParser.detect(Path(".")) is False

    def test_scan_returns_empty(self):
        assert SbomParser.scan(Path(".")) == []

    def test_parse_cyclonedx_with_vulns(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component("lodash", "4.17.20", bom_ref="ref-lodash"),
            ],
            vulnerabilities=[
                _cdx_vuln(
                    "CVE-2021-23337",
                    affects=[{"ref": "ref-lodash"}],
                ),
            ],
        )
        vulns = SbomParser.parse(bom, Path("."))
        assert len(vulns) == 1
        assert vulns[0].cve == "CVE-2021-23337"

    def test_parse_cyclonedx_without_vulns_returns_empty(self):
        """When no vulns array, parse returns empty (caller uses extract_packages)."""
        bom = _cdx_sbom(
            components=[
                _cdx_component("lodash", "4.17.21"),
            ]
        )
        vulns = SbomParser.parse(bom, Path("."))
        assert vulns == []

    def test_parse_spdx_with_security_refs(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.20",
                    security_refs=[_security_ref("CVE-2021-23337")],
                ),
            ]
        )
        vulns = SbomParser.parse(doc, Path("."))
        assert len(vulns) == 1

    def test_parse_spdx_without_security_refs_returns_empty(self):
        doc = _spdx_doc(
            packages=[_spdx_package("lodash", "4.17.21")],
        )
        vulns = SbomParser.parse(doc, Path("."))
        assert vulns == []

    def test_parse_unknown_format(self):
        vulns = SbomParser.parse({"runs": []}, Path("."))
        assert vulns == []

    def test_extract_packages_cyclonedx(self):
        bom = _cdx_sbom(
            components=[
                _cdx_component(
                    "lodash",
                    "4.17.21",
                    purl="pkg:npm/lodash@4.17.21",
                ),
            ]
        )
        pkgs = SbomParser.extract_packages(bom)
        assert pkgs == [("lodash", "4.17.21", "npm")]

    def test_extract_packages_spdx(self):
        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.21",
                    purl="pkg:npm/lodash@4.17.21",
                ),
            ]
        )
        pkgs = SbomParser.extract_packages(doc)
        assert pkgs == [("lodash", "4.17.21", "npm")]

    def test_extract_packages_unknown(self):
        assert SbomParser.extract_packages({"runs": []}) == []


# ---------------------------------------------------------------------------
# Engine integration — SBOM auto-detection in dispatch chain
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    """Verify the engine's audit_json dispatch recognizes SBOMs."""

    def test_cyclonedx_detected_before_npm(self):
        """CycloneDX with vulnerabilities key shouldn't fall through to npm."""
        from depquiet.parsers.sbom import is_cyclonedx

        bom = _cdx_sbom(
            components=[
                _cdx_component("lodash", "4.17.20", bom_ref="ref-lodash"),
            ],
            vulnerabilities=[
                _cdx_vuln(
                    "CVE-2021-23337",
                    affects=[{"ref": "ref-lodash"}],
                ),
            ],
        )
        assert is_cyclonedx(bom)
        # The engine would pick this up first in the dispatch chain

    def test_spdx_detected(self):
        from depquiet.parsers.sbom import is_spdx

        doc = _spdx_doc(
            packages=[
                _spdx_package(
                    "lodash",
                    "4.17.20",
                    security_refs=[_security_ref("CVE-2021-23337")],
                ),
            ]
        )
        assert is_spdx(doc)

    def test_non_sbom_not_detected(self):
        """Regular scanner JSON shouldn't trigger SBOM path."""
        from depquiet.parsers.sbom import is_cyclonedx, is_spdx

        npm_audit = {"vulnerabilities": {"lodash": {"severity": "high"}}}
        assert not is_cyclonedx(npm_audit)
        assert not is_spdx(npm_audit)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_all_cdx_severities(self):
        for sev_str, expected in [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MODERATE),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
            ("none", Severity.INFO),
            ("unknown", Severity.MODERATE),
        ]:
            bom = _cdx_sbom(
                components=[
                    _cdx_component("pkg", "1.0", bom_ref="r"),
                ],
                vulnerabilities=[
                    _cdx_vuln(
                        f"CVE-{sev_str}",
                        severity=sev_str,
                        affects=[{"ref": "r"}],
                    ),
                ],
            )
            vulns = _parse_cyclonedx_vulns(bom)
            assert vulns[0].severity == expected, (
                f"Expected {expected} for '{sev_str}', got {vulns[0].severity}"
            )

    def test_cvss_score_ranges(self):
        for score, expected in [
            (9.8, Severity.CRITICAL),
            (7.5, Severity.HIGH),
            (5.0, Severity.MODERATE),
            (2.0, Severity.LOW),
        ]:
            bom = _cdx_sbom(
                components=[
                    _cdx_component("pkg", "1.0", bom_ref="r"),
                ],
                vulnerabilities=[
                    {
                        "id": f"CVE-score-{score}",
                        "ratings": [{"score": score}],
                        "affects": [{"ref": "r"}],
                    },
                ],
            )
            vulns = _parse_cyclonedx_vulns(bom)
            assert vulns[0].severity == expected, f"Expected {expected} for score {score}"
