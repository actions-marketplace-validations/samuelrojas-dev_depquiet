"""Version/range correlation in frozen audits; no upstream code is executed.

These are input-correlation regressions, not human labels or impact assessments.
"""

import hashlib
import json
from pathlib import Path

import pytest

from depquiet.models import ScanResult, TriageResult, Verdict
from depquiet.parsers.npm import NpmAuditParser
from depquiet.sbom import generate_cyclonedx_json

FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/repo-node-express-boilerplate"


@pytest.mark.parametrize(
    "advisory,package,matching,outside",
    [
        ("GHSA-3xgq-45jj-v275", "cross-spawn", "6.0.5", "7.0.3"),
        ("GHSA-2g4f-4pwh-qvx6", "ajv", "6.12.6", "8.6.1"),
    ],
)
def test_frozen_package_nodes_are_not_all_associated_with_each_advisory(
    advisory, package, matching, outside
):
    audit = json.loads((FIXTURE / "audit.json").read_text(encoding="utf-8"))
    findings = NpmAuditParser.parse(audit, FIXTURE)
    finding = next(item for item in findings if item.cve == advisory)
    assert finding.package == package
    assert finding.version_kind == "advisory_range"
    assert finding.component_resolution_complete is True
    candidates = {item.version: item for item in finding.components}
    assert set(candidates) == {matching, outside}
    assert candidates[matching].range_match == "matched"
    assert candidates[outside].range_match == "not_matched"
    digest = hashlib.sha256((FIXTURE / "package-lock.json").read_bytes()).hexdigest()
    assert all(item.lockfile_sha256 == digest for item in finding.components)

    report = ScanResult(str(FIXTURE), "npm", 2, [TriageResult(finding, Verdict.ACTION)])
    bom = generate_cyclonedx_json(report)
    inventory = {item["bom-ref"]: item for item in bom["components"]}
    assert set(inventory) == {item.instance_id for item in finding.components}
    assert {item["version"] for item in inventory.values()} == {matching, outside}
    [vulnerability] = bom["vulnerabilities"]
    assert vulnerability["affects"] == [{"ref": candidates[matching].instance_id}]
    assert vulnerability["analysis"]["state"] == "in_triage"
