"""Advisory ranges never masquerade as resolved npm component versions."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

import pytest

from depquiet.models import (
    ComponentEvidence,
    ScanResult,
    Severity,
    TriageResult,
    Verdict,
    Vulnerability,
)
from depquiet.parsers.npm import NpmAuditParser
from depquiet.sbom import generate_cyclonedx_json, generate_cyclonedx_xml
from depquiet.spdx import generate_spdx_json
from depquiet.vex import build_vex, vex_to_json

NS = {"c": "http://cyclonedx.org/schema/bom/1.5"}
LOCK_HASH = "a" * 64


def _component(
    version: str, match: str, *, location: str = "node_modules/body-parser"
) -> ComponentEvidence:
    return ComponentEvidence(
        "npm",
        "body-parser",
        version,
        location,
        "package-lock.json",
        LOCK_HASH,
        range_match=match,
        reason=f"Comparison result: {match}.",
    )


def _finding(
    components: list[ComponentEvidence], *, advisory: str = "GHSA-test-one", range_: str = "<1.20.3"
) -> TriageResult:
    return TriageResult(
        Vulnerability(
            advisory,
            "body-parser",
            range_,
            Severity.HIGH,
            url=f"https://github.com/advisories/{advisory}",
            version_kind="advisory_range",
            advisory_range=range_,
            components=components,
            component_resolution_complete=bool(components),
        ),
        Verdict.ACTION,
    )


def _result(*findings: TriageResult) -> ScanResult:
    return ScanResult("/app", "npm", 2, list(findings))


def _security_refs(package: dict) -> list[dict]:
    return [ref for ref in package["externalRefs"] if ref["referenceCategory"] == "SECURITY"]


def test_inventory_keeps_two_concrete_versions_and_associates_only_range_match() -> None:
    inside = _component("1.20.2", "matched")
    outside = _component(
        "1.20.3", "not_matched", location="node_modules/express/node_modules/body-parser"
    )
    result = _result(_finding([inside, outside]))
    packages = [("body-parser", "1.20.2", "npm"), ("body-parser", "1.20.3", "npm")]
    bom = generate_cyclonedx_json(result, packages)
    assert {component["version"] for component in bom["components"]} == {"1.20.2", "1.20.3"}
    assert {component["bom-ref"] for component in bom["components"]} == {
        inside.instance_id,
        outside.instance_id,
    }
    [vulnerability] = bom["vulnerabilities"]
    assert vulnerability["affects"] == [{"ref": inside.instance_id}]
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert "not an installed version" in vulnerability["analysis"]["detail"]
    for component in bom["components"]:
        evidence = json.loads(component["properties"][0]["value"])
        assert evidence["lockfile"] == "package-lock.json"
        assert evidence["lockfile_sha256"] == LOCK_HASH
        assert evidence["location"]
        assert "range_match" not in evidence
        assert "reason" not in evidence

    spdx = generate_spdx_json(result, packages)
    by_version = {package["versionInfo"]: package for package in spdx["packages"]}
    assert len(_security_refs(by_version["1.20.2"])) == 1
    assert _security_refs(by_version["1.20.3"]) == []
    associated = _security_refs(by_version["1.20.2"])[0]
    assert associated["referenceType"] == "advisory"
    assert '"range_match": "matched"' in associated["comment"]
    assert LOCK_HASH in by_version["1.20.2"]["comment"]

    [statement] = vex_to_json(build_vex(result))["statements"]
    assert statement["status"] == "under_investigation"
    assert statement["products"][0]["subcomponents"] == [
        {"@id": inside.instance_id, "identifiers": {"purl": "pkg:npm/body-parser@1.20.2"}}
    ]
    assert outside.location in statement["status_notes"]
    assert "range match: not_matched" in statement["status_notes"]
    assert not {"impact_statement", "justification", "action_statement"} & statement.keys()


def test_both_matching_versions_are_associated_in_each_format() -> None:
    first = _component("1.19.0", "matched")
    second = _component(
        "1.20.2", "matched", location="node_modules/express/node_modules/body-parser"
    )
    result = _result(_finding([first, second]))
    bom = generate_cyclonedx_json(result)
    assert {item["ref"] for item in bom["vulnerabilities"][0]["affects"]} == {
        first.instance_id,
        second.instance_id,
    }
    spdx = generate_spdx_json(result)
    assert len(spdx["packages"]) == 2
    assert all(len(_security_refs(package)) == 1 for package in spdx["packages"])
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert {item["@id"] for item in statement["products"][0]["subcomponents"]} == {
        first.instance_id,
        second.instance_id,
    }


def test_uncertain_association_is_preserved_as_unknown_not_impact() -> None:
    uncertain = _component("1.20.2", "unknown")
    result = _result(_finding([uncertain], range_="unsupported-range"))
    bom = generate_cyclonedx_json(result)
    vulnerability = bom["vulnerabilities"][0]
    assert vulnerability["affects"] == [{"ref": uncertain.instance_id}]
    [association] = [json.loads(prop["value"]) for prop in vulnerability["properties"]]
    assert association["advisory"] == "GHSA-test-one"
    assert association["range_match"] == "unknown"
    assert association["component_evidence"]["range_match"] == "unknown"
    assert vulnerability["analysis"]["state"] == "in_triage"
    assert "range match: unknown" in vulnerability["analysis"]["detail"]
    package = generate_spdx_json(result)["packages"][0]
    assert '"range_match": "unknown"' in _security_refs(package)[0]["comment"]
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert statement["status"] == "under_investigation"
    assert "range match: unknown" in statement["status_notes"]


@pytest.mark.parametrize("name", ["body-parser", "@scope/parser"])
def test_unresolved_npm_uses_unversioned_identity_without_inventing_installation(name: str) -> None:
    finding = _finding([])
    finding.vuln.package = name
    finding.vuln.component_notes = ["No lockfile was available."]
    result = _result(finding)
    expected_purl = "pkg:npm/" + name.replace("@", "%40")
    bom = generate_cyclonedx_json(result)
    [component] = bom["components"]
    assert "version" not in component
    assert component["purl"] == component["bom-ref"] == expected_purl
    vulnerability = bom["vulnerabilities"][0]
    assert vulnerability["affects"] == [{"ref": expected_purl}]
    assert "No lockfile was available" in vulnerability["analysis"]["detail"]
    assert "association is unknown" in vulnerability["analysis"]["detail"]

    package = generate_spdx_json(result)["packages"][0]
    assert "versionInfo" not in package
    assert package["externalRefs"][0]["referenceLocator"] == expected_purl
    assert "Version unresolved" in package["comment"]
    assert '"range_match": "unknown"' in _security_refs(package)[0]["comment"]

    xml = ET.fromstring(generate_cyclonedx_xml(result))
    component_xml = xml.find("c:components/c:component", NS)
    assert component_xml is not None
    assert component_xml.find("c:version", NS) is None
    assert component_xml.findtext("c:purl", namespaces=NS) == expected_purl
    [statement] = vex_to_json(build_vex(result))["statements"]
    assert statement["products"][0]["subcomponents"][0]["@id"] == expected_purl
    assert "not an installed version" in statement["status_notes"]


def test_all_candidates_outside_range_keep_advisory_without_associating_them() -> None:
    outside = _component("1.20.3", "not_matched")
    result = _result(_finding([outside]))
    bom = generate_cyclonedx_json(result)
    assert len(bom["components"]) == 1
    assert bom["vulnerabilities"][0]["affects"] == []
    assert "all are outside" in bom["vulnerabilities"][0]["analysis"]["detail"]
    context = json.loads(bom["vulnerabilities"][0]["properties"][0]["value"])
    assert "ref" not in context
    assert context["advisory"] == "GHSA-test-one"
    assert context["priority"] == "action"
    spdx = generate_spdx_json(result)
    assert _security_refs(spdx["packages"][0]) == []
    assert "GHSA-test-one" in spdx["annotations"][0]["comment"]
    assert "under investigation" in spdx["annotations"][0]["comment"]
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert statement["status"] == "under_investigation"
    assert "subcomponents" not in statement["products"][0]
    assert "all are outside" in statement["status_notes"]


@pytest.mark.parametrize("second_match", ["not_matched", "unknown"])
def test_range_matching_remains_per_advisory_not_inventory_last_writer(second_match: str) -> None:
    first_evidence = _component("1.20.2", "matched")
    second_evidence = replace(
        first_evidence, range_match=second_match, reason="Second advisory comparison."
    )
    result = _result(
        _finding([first_evidence], advisory="GHSA-first", range_="<1.20.3"),
        _finding([second_evidence], advisory="GHSA-second", range_="<1.20.0"),
    )
    bom = generate_cyclonedx_json(result)
    assert len(bom["components"]) == 1
    by_advisory = {vulnerability["id"]: vulnerability for vulnerability in bom["vulnerabilities"]}
    assert by_advisory["GHSA-first"]["affects"] == [{"ref": first_evidence.instance_id}]
    assert by_advisory["GHSA-second"]["affects"] == (
        [] if second_match == "not_matched" else [{"ref": first_evidence.instance_id}]
    )
    second_context = json.loads(by_advisory["GHSA-second"]["properties"][0]["value"])
    assert second_context["range_match"] == second_match
    inventory_evidence = json.loads(bom["components"][0]["properties"][0]["value"])
    assert "range_match" not in inventory_evidence
    assert "reason" not in inventory_evidence
    spdx = generate_spdx_json(result)
    refs = _security_refs(spdx["packages"][0])
    assert refs[0]["referenceLocator"].endswith("GHSA-first")
    if second_match == "not_matched":
        assert len(refs) == 1
        assert "GHSA-second" in spdx["annotations"][0]["comment"]
    else:
        assert len(refs) == 2
        assert '"range_match": "unknown"' in refs[1]["comment"]
        assert '"range_match": "matched"' in refs[0]["comment"]


def test_same_version_at_two_locations_preserves_distinct_instances() -> None:
    first = _component("1.20.2", "matched")
    second = replace(first, location="packages/api/node_modules/body-parser")
    result = _result(_finding([first, second]))
    bom = generate_cyclonedx_json(result, [("body-parser", "1.20.2", "npm")])
    assert len(bom["components"]) == 2
    assert len({component["bom-ref"] for component in bom["components"]}) == 2
    assert {component["purl"] for component in bom["components"]} == {"pkg:npm/body-parser@1.20.2"}
    assert len({package["SPDXID"] for package in generate_spdx_json(result)["packages"]}) == 2


def test_xml_preserves_component_provenance_and_advisory_association_from_json() -> None:
    first = _component("1.20.2", "unknown")
    second = _component(
        "1.20.3", "not_matched", location="node_modules/express/node_modules/body-parser"
    )
    result = _result(_finding([first, second]))
    bom = generate_cyclonedx_json(result)
    xml = ET.fromstring(generate_cyclonedx_xml(result))
    for component in xml.findall("c:components/c:component", NS):
        counterpart = next(
            item for item in bom["components"] if item["bom-ref"] == component.attrib["bom-ref"]
        )
        assert component.findtext("c:version", namespaces=NS) == counterpart["version"]
        assert component.findtext("c:purl", namespaces=NS) == counterpart["purl"]
        properties = component.findall("c:properties/c:property", NS)
        assert [
            {"name": prop.attrib["name"], "value": prop.text} for prop in properties
        ] == counterpart["properties"]
    xml_vuln = xml.find("c:vulnerabilities/c:vulnerability", NS)
    assert xml_vuln is not None
    assert [target.text for target in xml_vuln.findall("c:affects/c:target/c:ref", NS)] == [
        first.instance_id
    ]
    assert (
        xml_vuln.findtext("c:analysis/c:detail", namespaces=NS)
        == bom["vulnerabilities"][0]["analysis"]["detail"]
    )


def test_legacy_reported_version_keeps_existing_component_identity() -> None:
    finding = TriageResult(
        Vulnerability("TEST-1", "body-parser", "1.20.2", Severity.HIGH), Verdict.ACTION
    )
    result = _result(finding)
    bom = generate_cyclonedx_json(result)
    assert bom["components"][0]["purl"] == "pkg:generic/body-parser@1.20.2"
    assert bom["components"][0]["version"] == "1.20.2"
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert statement["products"][0]["subcomponents"] == [{"@id": "pkg:generic/body-parser@1.20.2"}]
    assert generate_spdx_json(result)["packages"][0]["versionInfo"] == "1.20.2"


@pytest.mark.parametrize("with_lock", [True, False])
def test_npm_parser_to_exports_keeps_reported_range_separate_from_component_versions(
    tmp_path: Path, with_lock: bool
) -> None:
    nodes = ["node_modules/body-parser", "node_modules/express/node_modules/body-parser"]
    if with_lock:
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        nodes[0]: {"version": "1.20.2"},
                        nodes[1]: {"version": "1.20.3"},
                    },
                }
            ),
            encoding="utf-8",
        )
    audit = {
        "vulnerabilities": {
            "body-parser": {
                "severity": "high",
                "isDirect": True,
                "nodes": nodes,
                "via": [
                    {
                        "source": 1,
                        "title": "Advisory",
                        "range": "<1.20.3",
                        "url": "https://github.com/advisories/GHSA-test-one",
                    }
                ],
            }
        }
    }
    [vulnerability] = NpmAuditParser.parse(audit, tmp_path)
    assert vulnerability.version == "<1.20.3"
    assert vulnerability.version_kind == "advisory_range"
    result = _result(TriageResult(vulnerability, Verdict.ACTION))
    bom = generate_cyclonedx_json(result)
    spdx = generate_spdx_json(result)
    vex = vex_to_json(build_vex(result))
    if with_lock:
        assert {component["version"] for component in bom["components"]} == {"1.20.2", "1.20.3"}
        assert {package["versionInfo"] for package in spdx["packages"]} == {"1.20.2", "1.20.3"}
        assert len(bom["vulnerabilities"][0]["affects"]) == 1
        assert len(vex["statements"][0]["products"][0]["subcomponents"]) == 1
    else:
        assert "version" not in bom["components"][0]
        assert "versionInfo" not in spdx["packages"][0]
        assert (
            vex["statements"][0]["products"][0]["subcomponents"][0]["@id"] == "pkg:npm/body-parser"
        )


@pytest.mark.parametrize("known_match", ["matched", "not_matched"])
def test_partial_resolution_retains_unversioned_unknown_alongside_known_candidates(
    known_match: str,
) -> None:
    known = _component("1.20.2" if known_match == "matched" else "1.20.3", known_match)
    finding = _finding([known])
    finding.vuln.component_resolution_complete = False
    finding.vuln.component_notes = ["A second reported node was absent from the lockfile."]
    result = _result(finding)
    bom = generate_cyclonedx_json(result)
    expected_refs = {"pkg:npm/body-parser"}
    if known_match == "matched":
        expected_refs.add(known.instance_id)
    assert {item["ref"] for item in bom["vulnerabilities"][0]["affects"]} == expected_refs
    assert {component.get("version") for component in bom["components"]} == {known.version, None}
    contexts = [json.loads(prop["value"]) for prop in bom["vulnerabilities"][0]["properties"]]
    residual = next(context for context in contexts if context["ref"] == "pkg:npm/body-parser")
    assert residual["range_match"] == "unknown"
    assert residual["component_resolution_complete"] is False
    assert "incomplete" in residual["reason"]
    assert "second reported node" in bom["vulnerabilities"][0]["analysis"]["detail"]

    spdx = generate_spdx_json(result)
    unresolved_package = next(
        package for package in spdx["packages"] if "versionInfo" not in package
    )
    known_package = next(
        package for package in spdx["packages"] if package.get("versionInfo") == known.version
    )
    assert len(_security_refs(unresolved_package)) == 1
    assert len(_security_refs(known_package)) == int(known_match == "matched")
    assert "annotations" not in spdx
    statement = vex_to_json(build_vex(result))["statements"][0]
    assert {
        component["@id"] for component in statement["products"][0]["subcomponents"]
    } == expected_refs
    assert "Component resolution is incomplete" in statement["status_notes"]


def test_build_metadata_is_percent_encoded_only_in_exported_purls() -> None:
    version = "1.2.3+build.1"
    evidence = ComponentEvidence(
        "npm",
        "@scope/pkg",
        version,
        "node_modules/@scope/pkg",
        "package-lock.json",
        LOCK_HASH,
        "unknown",
        "Prerelease/build context remains under review.",
    )
    finding = _finding([evidence], range_="^1.2.0")
    finding.vuln.package = "@scope/pkg"
    result = _result(finding)
    instance_id = evidence.instance_id
    expected_purl = "pkg:npm/%40scope/pkg@1.2.3%2Bbuild.1"

    component = generate_cyclonedx_json(result)["components"][0]
    assert component["purl"] == expected_purl
    assert component["version"] == version
    assert component["bom-ref"] == instance_id
    provenance = json.loads(component["properties"][0]["value"])
    assert provenance["version"] == version
    assert provenance["instance_id"] == instance_id

    xml = ET.fromstring(generate_cyclonedx_xml(result))
    xml_component = xml.find("c:components/c:component", NS)
    assert xml_component is not None
    assert xml_component.findtext("c:purl", namespaces=NS) == expected_purl
    assert xml_component.findtext("c:version", namespaces=NS) == version
    assert xml_component.attrib["bom-ref"] == instance_id

    spdx_package = generate_spdx_json(result)["packages"][0]
    assert spdx_package["versionInfo"] == version
    assert spdx_package["externalRefs"][0]["referenceLocator"] == expected_purl
    subcomponent = vex_to_json(build_vex(result))["statements"][0]["products"][0]["subcomponents"][
        0
    ]
    assert subcomponent == {"@id": instance_id, "identifiers": {"purl": expected_purl}}
    assert evidence.version == version
    assert evidence.instance_id == instance_id
