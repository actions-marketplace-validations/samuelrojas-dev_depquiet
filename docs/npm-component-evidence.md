# npm component evidence

npm audit reports package-level node locations and per-advisory version ranges.
Those are different observations. A node in a package's list may be outside one
of its advisory ranges. depquiet preserves the original finding context and
records lockfile candidates separately, without observing an installation.

## Additive report fields

Existing `version` values and advisory/package row counts remain compatible.
For npm, the original field is explicitly qualified:

| Field | Meaning |
| --- | --- |
| `version_kind` | `advisory_range` for npm audit input; other existing producers default to `reported`. |
| `advisory_range` | The scanner's range, also retained in the legacy `version` field. |
| `components` | Resolved lockfile candidates; every candidate has an exact version and a reported node location. |
| `component_resolution_complete` | Every unique reported node location was resolved. Independent of range matching. |
| `component_notes` | Missing, invalid, ambiguous or unsupported context. |

Each candidate contains `ecosystem`, `package`, `version`, `location`, `lockfile`,
`lockfile_sha256`, `instance_id`, `range_match`, and `reason`. Range status is
`matched`, `not_matched` or `unknown`. It concerns version constraints only;
none of these states establishes product impact or vulnerable-function execution.
New reports also carry `lock_scope`: `development` when the lockfile entry has
`"dev": true`, otherwise `production`. Reports saved before 0.33 have no such
field and are read as unknown.

## Development-only copies

One package name is often installed several times: `uuid` 11 for the
application and `uuid` 8 nested under a test runner. An advisory that covers
only the old range concerns only the nested copy. When every reported location
resolves (`component_resolution_complete`) and every copy whose `range_match` is
not `not_matched` has `lock_scope: development`, the alert is filtered as a
development dependency. This is the per-copy decision `npm audit --omit=dev`
makes, read from the same flag, and it does not depend on the name-level graph.

`devOptional` and `optional` copies are installed for production unless optional
dependencies are omitted, so they count as production. A copy with an unknown
range match counts as affected. A missing or unresolved location keeps the alert.
The usual limit of a development label applies: a bundler can ship a
`devDependencies` package inside a production artifact, and neither npm nor
depquiet sees that.

The instance ID hashes canonical ecosystem/name/version/location/relative-lockfile
fields. Different locations remain separate even for the same version. Advisory
matching and the lockfile content hash are evidence, not part of that identity.
IDs are scoped by the report's project context and relative paths; they do not
attest repository ownership or authenticate an external report.

`depquiet explain --from-json report.json ADVISORY` restores this evidence and
shows the advisory range separately from candidates. Saved instance IDs are
checked against their fields; old reports without metadata remain supported.

## Resolution and matching boundaries

The resolver reads and hashes one lockfile snapshot per parsed audit report.
`npm-shrinkwrap.json` takes precedence over `package-lock.json`; an unreadable or
malformed preferred file is not silently replaced with a different input.
Package-lock formats 1, 2 and 3 are supported. The original raw bytes determine
SHA-256; source provenance describes the supplied project, not a claim that an
external scanner used that exact file unless the caller separately binds them.
[npm lockfile documentation](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/).

Only reported audit nodes are resolved. Unsafe/missing locations, conflicting
names, links and non-exact versions remain unresolved with notes. The resolver
does not inspect node_modules, run package code, install packages or use Node.
Partial evidence is retained alongside the unresolved context.

The bounded stdlib matcher supports its tested stable-version subset of npm
comparators, AND/OR, caret/tilde, wildcards and hyphen ranges. Valid prerelease
semantics currently remain `unknown`, as do invalid, unsupported or oversized
inputs. Build metadata is retained in identities. This is not complete
node-semver compatibility. Independent development checks use pinned
[node-semver](https://github.com/npm/node-semver#ranges); Node is not a runtime or
CI dependency for the committed offline reference tests.

## Export behavior

CycloneDX inventory includes all resolved candidates, including versions outside
an advisory. Component provenance is independent of advisory association. Each
advisory records its own range status, including when several advisories refer
to the same instance.

- `matched` and `unknown` candidates retain advisory associations under investigation.
- `not_matched` candidates remain inventory entries without that advisory's component association.
- Missing resolution creates an npm identity without a version. Partial resolution
  preserves that unknown identity in addition to the resolved eligible candidates.
- If resolution is complete and all versions are outside the range, the scanner's
  advisory context stays in the document/product notes; no outside version is linked.

CycloneDX JSON/XML use stable instance references and structured association
properties. SPDX records provenance/comments and advisory SECURITY references.
OpenVEX lists eligible subcomponents with PURLs and qualified status notes.
Automatic impact remains `under_investigation` / `in_triage` in all formats.

PURLs encode version data, including `+` in build metadata, while preserving
the standard's literal-colon exception. Raw version fields and instance IDs
retain the original version string. [PURL specification](https://github.com/package-url/purl-spec/blob/main/docs/specification/standard/Clause-5-Package-URL-Specification.md).

## Baselines and diffs

This metadata does not change triage priorities or turn range matches into impact
assessments. The reference corpus keeps its original advisory-context selections
and labels. [Baseline v2 and scoped diffs](instance-baselines.md) now use these
instance IDs together with explicit `project_id`, advisory and range/status
context. New candidate versions or locations remain visible. Unknown and partial
resolution cannot become v2 acceptance. Existing baseline files retain their
broad advisory/package semantics; unscoped saved diffs retain literal
advisory/package/reported-version matching. Migration is explicit.
