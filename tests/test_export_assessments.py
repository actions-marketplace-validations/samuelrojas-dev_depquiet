"""Exported impact assessments require evidence beyond triage priority."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from depquiet.assessment import assess_finding
from depquiet.baseline import apply_baseline
from depquiet.engine import scan
from depquiet.models import FilterReason, ScanResult, Severity, TriageResult, Verdict, Vulnerability
from depquiet.policy import Policy, PolicyRule
from depquiet.sbom import generate_cyclonedx_json, generate_cyclonedx_xml, write_sbom
from depquiet.spdx import generate_spdx_json, write_spdx
from depquiet.vex import build_vex, vex_to_json

NS = {"c": "http://cyclonedx.org/schema/bom/1.5"}


def _finding(
    package: str = "example", version: str = "1", verdict: Verdict = Verdict.ACTION
) -> TriageResult:
    return TriageResult(Vulnerability("CVE-2026-1234", package, version, Severity.HIGH), verdict)


def _result(*findings: TriageResult, scanned: bool = True) -> ScanResult:
    return ScanResult("/app", "npm", len(findings), list(findings), scanned=scanned)


def _assert_unverified_exports(result: ScanResult) -> None:
    [finding] = result.results
    expected_detail = assess_finding(finding).detail
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert statement["status"] == "under_investigation"
    assert statement["status_notes"] == expected_detail
    assert not {"justification", "impact_statement", "action_statement"} & statement.keys()

    [vulnerability] = generate_cyclonedx_json(result)["vulnerabilities"]
    assert vulnerability["analysis"] == {"state": "in_triage", "detail": expected_detail}
    [triage] = vulnerability["properties"]
    context = json.loads(triage["value"])
    assert context["priority"] == finding.verdict.value
    assert context["reasons"] == [reason.value for reason in finding.reasons]

    xml = ET.fromstring(generate_cyclonedx_xml(result))
    assert xml.findtext("c:vulnerabilities/c:vulnerability/c:analysis/c:state", namespaces=NS) == (
        "in_triage"
    )
    assert xml.findtext("c:vulnerabilities/c:vulnerability/c:analysis/c:detail", namespaces=NS) == (
        expected_detail
    )
    spdx = generate_spdx_json(result)
    security_refs = [
        ref for ref in spdx["packages"][0]["externalRefs"] if ref["referenceCategory"] == "SECURITY"
    ]
    assert security_refs[0]["comment"] == expected_detail


@pytest.mark.parametrize("reason", [None, *FilterReason])
@pytest.mark.parametrize("verdict", list(Verdict))
def test_no_priority_or_filter_signal_proves_impact(reason, verdict) -> None:
    finding = _finding(verdict=verdict)
    if reason is not None:
        finding.reasons = [reason]
    finding.epss_score = 0.01
    result = _result(finding)
    _assert_unverified_exports(result)
    assert finding.verdict == verdict
    assert finding.reasons == ([reason] if reason else [])


def test_baseline_acceptance_is_not_non_affectedness() -> None:
    finding = _finding()
    result = _result(finding)
    apply_baseline(result, {finding.vuln.key}, source_path="accepted.json")
    assert finding.verdict == Verdict.FILTERED
    _assert_unverified_exports(result)
    assert "baseline" in vex_to_json(build_vex(result))["statements"][0]["status_notes"]


def test_policy_dismissal_is_not_non_affectedness(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies":{"example":"1"}}')
    (tmp_path / "app.js").write_text("require('example');\n")
    audit = {
        "vulnerabilities": {
            "example": {
                "severity": "high",
                "isDirect": True,
                "via": [
                    {"title": "Finding", "url": "https://example.com/advisories/CVE-2026-1234"}
                ],
            }
        }
    }
    policy = Policy([PolicyRule("accept-for-now", Verdict.FILTERED, packages=["example"])])
    result = scan(tmp_path, audit_json=audit, skip_epss=True, policy=policy)
    assert result.results[0].verdict == Verdict.FILTERED
    _assert_unverified_exports(result)
    notes = vex_to_json(build_vex(result))["statements"][0]["status_notes"]
    assert "policy" in notes
    assert "accept-for-now" in notes


@pytest.mark.parametrize(
    "generate", [build_vex, generate_cyclonedx_json, generate_cyclonedx_xml, generate_spdx_json]
)
def test_incomplete_scan_cannot_export_clean_document(generate) -> None:
    with pytest.raises(ValueError, match="incomplete scan"):
        generate(_result(scanned=False))


@pytest.mark.parametrize("fmt", ["json", "xml", "spdx"])
def test_incomplete_scan_does_not_create_sbom_file(tmp_path: Path, fmt: str) -> None:
    output = tmp_path / f"bom.{fmt}"
    with pytest.raises(ValueError, match="incomplete scan"):
        write_sbom(_result(scanned=False), output, fmt=fmt)
    assert not output.exists()


def test_incomplete_scan_does_not_overwrite_spdx(tmp_path: Path) -> None:
    output = tmp_path / "bom.spdx.json"
    output.write_text("existing artifact")
    with pytest.raises(ValueError, match="incomplete scan"):
        write_spdx(_result(scanned=False), output)
    assert output.read_text() == "existing artifact"


def test_same_advisory_retains_each_package_version_and_priority() -> None:
    first = _finding("first", "1", Verdict.ACTION)
    second = _finding("second", "2", Verdict.FILTERED)
    second.reasons = [FilterReason.LOW_EPSS]
    third = _finding("second", "3", Verdict.REVIEW)
    result = _result(first, second, third)
    packages = [("first", "1", "npm"), ("second", "2", "npm"), ("second", "3", "npm")]
    bom = generate_cyclonedx_json(result, packages)
    assert len(bom["vulnerabilities"]) == 1
    [vulnerability] = bom["vulnerabilities"]
    references = {component["bom-ref"] for component in bom["components"]}
    assert {affected["ref"] for affected in vulnerability["affects"]} == references
    assert references == {"pkg:npm/first@1", "pkg:npm/second@2", "pkg:npm/second@3"}
    contexts = [json.loads(prop["value"]) for prop in vulnerability["properties"]]
    assert {(context["ref"], context["priority"]) for context in contexts} == {
        ("pkg:npm/first@1", "action"),
        ("pkg:npm/second@2", "filtered"),
        ("pkg:npm/second@3", "review"),
    }
    for finding in result.results:
        assert assess_finding(finding).detail in vulnerability["analysis"]["detail"]
    assert len(build_vex(result).statements) == 3


def test_xml_affects_resolve_to_inventory_components() -> None:
    result = _result(_finding("first", "1"), _finding("second", "2"))
    root = ET.fromstring(generate_cyclonedx_xml(result, [("first", "1", "npm")]))
    components = root.findall("c:components/c:component", NS)
    references = {component.attrib["bom-ref"] for component in components}
    assert references == {"pkg:npm/first@1", "pkg:generic/second@2"}
    vulnerabilities = root.findall("c:vulnerabilities/c:vulnerability", NS)
    assert len(vulnerabilities) == 1
    affected = vulnerabilities[0].findall("c:affects/c:target/c:ref", NS)
    assert {target.text for target in affected} == references
    assert len(vulnerabilities[0].findall("c:properties/c:property", NS)) == 2


def test_missing_inventory_context_is_added_without_changing_other_versions() -> None:
    result = _result(_finding("example", "1"))
    bom = generate_cyclonedx_json(result, [("example", "2", "npm")])
    assert {component["bom-ref"] for component in bom["components"]} == {
        "pkg:npm/example@2",
        "pkg:generic/example@1",
    }
    assert bom["vulnerabilities"][0]["affects"] == [{"ref": "pkg:generic/example@1"}]


def test_moderate_severity_uses_cyclonedx_medium_value() -> None:
    finding = _finding()
    finding.vuln.severity = Severity.MODERATE
    bom = generate_cyclonedx_json(_result(finding))
    assert bom["vulnerabilities"][0]["ratings"][0]["severity"] == "medium"


def test_spdx_partial_inventory_retains_each_advisory_context() -> None:
    result = _result(_finding("first", "1"), _finding("second", "2"))
    document = generate_spdx_json(result, [("first", "1", "npm")])
    assert {package["name"] for package in document["packages"]} == {"first", "second"}
    for package in document["packages"]:
        refs = [ref for ref in package["externalRefs"] if ref["referenceCategory"] == "SECURITY"]
        assert len(refs) == 1
        assert "CVE-2026-1234" in refs[0]["referenceLocator"]
