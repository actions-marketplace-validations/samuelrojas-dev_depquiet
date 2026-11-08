# Assessment contract

depquiet's remediation priority is separate from a verified statement about
whether a software product is affected. This distinction applies to all generated
reports, including after user suppressions or KEV escalation.

## Priority and impact

The existing `verdict` is a workflow decision: `action`, `review`, or `filtered`.
It controls the existing gates. `filtered` means deprioritized or suppressed; it
does not certify a false positive or a non-affected product.

Automatic `assessment.status` is `under_investigation`, with scope
`dependency_triage`. The current engine inspects package metadata, dependencies,
imports, references and priority signals. It does not construct a complete
vulnerable-function call graph, verify deployment contents, or establish a
product-specific mitigation. No configuration option in this milestone turns a
priority rule into a verified impact statement.

EPSS estimates exploitation probability; it does not establish the impact or
controls of a particular deployment. A KEV entry indicates observed exploitation
of an advisory, not proof that a particular application executes its vulnerable
behavior. [FIRST EPSS FAQ](https://www.first.org/epss/faq).

## Additive JSON fields

Scan JSON retains the existing fields and adds `scanned` and `note`. Each finding
adds:

- `assessment`: status, analysis scope, observed facts and explicit limitations.
- `evidence`: the analysis method, usage observation, actual import locations and
  textual observations. Usage is `observed`, `not_observed`, or `unknown` within
  the inspected sources; none asserts runtime execution or absence of impact.
- `decision_trace`: ordered priority decisions, with source, previous/current
  verdict, rule ID, reason, path, author and expiry where available.
- Template metadata, scanner direct/dev flags, and EPSS percentile when available.

Evidence is collected for all findings before suppressions and survives them.
Configuration/command references are observations, not fabricated file locations.
JSON can be reloaded with `depquiet explain --from-json`; old JSON defaults to an
unverified assessment without inventing historical evidence.

The decision history records engine rules, `always_flag`, policy overrides,
ignore entries, baseline acceptance, and subsequent KEV escalations. A later
escalation does not erase an earlier suppression or leave it presented as the
current priority. Baseline identity remains `advisory:package` for compatibility;
it does not distinguish installed versions.

## Export behavior

Automatic OpenVEX statements use `under_investigation`, include document version,
the required vulnerability `name` and `status_notes`, and do not invent
`justification`, `impact_statement` or
`action_statement` from a triage verdict. Applications explicitly constructing
the public VEX statement types remain responsible for their supplied assessments.
[OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

CycloneDX JSON and XML use `in_triage` and record context separately. Multiple
package/version occurrences of the same advisory retain their component
references and priorities. SPDX annotations retain the same qualified assessment.
Incomplete scans cannot generate VEX, SBOM or SARIF artifacts through these APIs.
[CycloneDX 1.5 reference](https://cyclonedx.org/docs/1.5/json/).

SARIF continues to include ACTION/REVIEW findings and omit FILTERED findings by
the existing workflow policy; this is not a complete inventory of suppressed
findings. Use scan JSON, VEX or SBOM to audit all retained input findings. SARIF's
included results carry assessment, evidence and history properties.

## Measuring correctness

The [reference evaluator](../benchmarks/reference/README.md) compares a saved scan
to separately recorded expectations for a pinned snapshot. It rejects silent
coverage gaps and reports explicit denominators. Two synthetic examples exercise
the contract. A separate [upstream reference set](../benchmarks/reference/real/README.md)
contains ten selected contexts from four real npm/Python projects: five `retain`,
five `unknown`, and no `filter` labels. Agent curation and evidence checks are
recorded; human review and independent external validation are pending.

The upstream harness binds exact Git commit blobs, frozen audit/overlay bytes and
the report's snapshot hash without executing upstream code or installing its
dependencies. Selection is fixed in the snapshot before evaluation, independent
of labels and verdicts. Missing selected findings still fail the gate; unselected
findings are explicitly outside its scope. This establishes a small retention
regression check, not full-project label coverage, precision, recall, safe
dismissal rates, exploitability, or comparative performance. Locked dependencies
are not asserted to be installed in a deployment. All automatic impact
assessments remain `under_investigation`.
