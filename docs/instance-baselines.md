# Project-scoped baselines and scan diffs

An advisory can describe several copies of a dependency. Baseline v2 and instance
diffs preserve each exact lockfile version and location, so adding another copy
does not inherit acceptance simply because an advisory/package is already known.
This is dependency evidence and priority acceptance; it does not establish an
installation, vulnerable-function execution, remediation or product impact.

## Explicit project scope

Set a stable logical identifier on every scan of the same project:

```bash
depquiet --project-id team/service --json > scan.json
```

Or configure `project_id: team/service` in `.depquiet.yaml`. CLI values override
configuration. IDs are case-sensitive, nonempty strings up to 256 characters,
without surrounding whitespace or control characters. Absence is allowed for
legacy scans; an explicitly empty/invalid configuration or option is rejected.
JSON reports record the ID; depquiet does not infer it from a directory, Git remote
or repository owner. The caller controls scope and report provenance. An ID is
not an ownership or authentication mechanism.

`--project-id` on `baseline create` or `diff` can bind a missing report ID. It
cannot override a conflicting declared ID. Reusing the same logical ID across
unrelated projects defeats this isolation; choose and retain the scope deliberately.

## Create and apply baseline v2

Review a completed saved report before creating acceptance:

```bash
depquiet baseline create scan.json -o accepted-v2.json \
  --reason "Reviewed dependency debt, remediation tracked in SEC-123" \
  --author "Dependency security team"
depquiet --project-id team/service --baseline accepted-v2.json --fail-on high
```

The report must declare `scanned: true`. Scans containing ACTION findings can
exit 1 while still producing a completed JSON report; operational failures exit 2.
Baseline creation writes atomically after validation, reports counts on stderr
and leaves stdout empty. It cannot overwrite its source scan. Invalid inputs or
write failures exit 2 and preserve an existing destination.

The document records:

| Field | Meaning |
| --- | --- |
| `baseline_schema_version` | Integer `2`; unknown versions are rejected. |
| `project_id` | Explicit scope of every accepted context. |
| `accepted` | Advisory/package/range plus complete component evidence and recomputable context ID. |
| `unaccepted` | Contexts that cannot be accepted, with reasons. |
| `reason`, `author` | Metadata supplied by the caller; not authenticated identity or approval. |
| `source_scan_sha256` | SHA-256 of the exact source file bytes for CLI creation. |
| `source_scan_hash_kind` | `file_bytes` for CLI creation; the library can use `canonical_json`. |

Initial v2 acceptance supports npm component evidence only. Every reported node
must resolve and every associated candidate must have a known `matched` range
comparison. A partial finding, any unknown comparison, an all-outside-range
finding or another scanner's reported-version context remains unaccepted.
Creation can succeed with zero accepted contexts; inspect both arrays.

On application, the current scan must be complete and declare the same project
ID. Every context in a finding must be eligible and present in `accepted` before
ACTION/REVIEW becomes FILTERED. One new candidate keeps the whole advisory row
visible. Validation finishes before any priority changes. Baseline decisions
retain reason, author, source path and exact context IDs in the decision trace.
Automatic product-impact assessments remain under investigation.

## Identity and provenance

A component instance ID hashes ecosystem, package, literal exact version, node
location and relative lockfile path. The finding context adds project scope,
advisory, advisory range and range-match status. A version, location, lockfile
path, advisory range or status change creates a new context. Advisory aliases and
semantically equivalent range strings are not normalized.

The lockfile content hash and explanatory prose are provenance, not part of the
resolved component context identity. An unrelated lockfile edit therefore does
not reactivate an otherwise identical accepted context. Its latest evidence still
retains the new hash. Acceptance files and reports are caller-controlled inputs;
their hashes are not signatures and do not authenticate the original scanner.

Partial resolution keeps known component contexts plus an explicit unresolved
context. That context has no installed version or instance ID. Its fingerprint
includes uncertainty evidence, so changes in notes or candidate coverage can
appear as changed context presence. A complete report whose candidates are all
outside the range also retains an unresolved advisory context for conservative
comparison. No such context can become a v2 acceptance.

## Compare scoped reports

```bash
depquiet diff base.json head.json --instances --fail-on-new --json
# Bind both reports only if their scope was absent:
depquiet diff base.json head.json --instances --project-id team/service
```

Both reports need `scanned: true`. Typed npm evidence expands into component and
unresolved contexts. Other scanners compare literal reported versions within the
project scope; this does not make them eligible for initial v2 acceptance.

JSON instance output records `identity_mode`, `project_id`, `count_unit`,
`fixed_meaning`, per-context identities/locations and `summary.unresolved_contexts`.
That count includes unresolved contexts, unknown component comparisons and empty
reported versions in the head report. Counts describe contexts, not unique CVEs
or scanner rows. Text and Markdown also show scope, locations and uncertainty.
`fixed` means absent from the head report; it does not prove a fix. Replacing a
version can yield one absent context and one new context.

`--fail-on-new` exits 1 when a new ACTION context appears, including another copy
under an existing advisory. Invalid, incomplete, duplicate or incompatible inputs
exit 2 before successful output or summary replacement. A missing file retains
the legacy diff exit code 1.

## Compatibility and migration

| Inputs or mode | Behavior |
| --- | --- |
| Two reports with the same nonempty project ID | Automatically use instance mode. |
| Two reports without a project ID | Use legacy advisory/package/reported-version identities. |
| One scoped and one unscoped report | Require explicit scope binding or `--legacy-identities`. |
| Conflicting declared IDs | Reject in every mode, including explicit legacy. |
| `--instances` | Require complete reports and usable instance context; missing scope needs explicit binding. |
| `--legacy-identities` | Explicitly compare legacy reported-version identities; no npm component expansion. |
| Existing scan JSON used directly as a baseline | Retain broad advisory/package acceptance, with any declared scope enforced. |

Older npm-project reports without `version_kind` lack explicit version semantics
and cannot acquire exact instances through scope binding alone. Rescan for
instance mode, or explicitly choose legacy comparison. New reports from Trivy,
SARIF and other parsers can explicitly declare `version_kind: reported` even in
an npm project; these retain literal reported-version contexts without becoming
v2 acceptances. Legacy comparison still accepts structurally valid
reports without `scanned`; missing completion metadata is not verification.

There is no automatic conversion of legacy baseline acceptance. Generate a new
scoped scan, review its evidence and create a separate v2 document. Legacy
advisory/package acceptance can suppress new versions and locations; do not
describe it as exact-instance acceptance. Keep compatibility use explicit in CI.

## Validation scope

Offline regressions cover duplicate versions/locations, range/state changes,
unrelated lockfile edits, partial/unknown evidence, scope mismatch, legacy
compatibility and failures before output or priority mutation. These tests verify
identity and acceptance contracts. They do not measure scanner accuracy on real
projects or validate a product-impact claim.
