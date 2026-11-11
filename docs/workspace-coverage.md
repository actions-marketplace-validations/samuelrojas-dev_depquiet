# Workspace and dynamic-import coverage

Dependency declarations, commands and source imports are observations about
dependency usage. They do not prove installation, deployed production contents,
vulnerable-function execution or product impact. Automatic assessments remain
under investigation.

## Declared workspace support

Discovery starts at the supplied project root. Initial support covers:

- npm `package.json` with a `workspaces` array, or an object containing `packages`.
- Python `pyproject.toml` with `[tool.uv.workspace]` members and exclude patterns.

See the upstream [npm](https://docs.npmjs.com/cli/using-npm/workspaces/) and
[uv](https://docs.astral.sh/uv/concepts/projects/workspaces/) workspace contracts.
depquiet implements a bounded subset for static triage; it does not run either
package manager, install members or execute their code.

Relative literal paths and segment patterns `*`, `?`, `**` are supported. `**`
must occupy an entire segment. Absolute paths, `..`, backslashes, negation,
brace/extglob expressions and character classes are rejected as unsupported or
unsafe. Discovery permits up to 128 patterns, 20,000 visited directory/pattern
states per expansion, 4,096 scopes including root, and 128 directory levels.
Hitting a limit produces incomplete coverage. These are resource boundaries,
not silent successful truncation. A member pattern matching no directories, or
a matched member missing its manifest, remains visible as incomplete evidence.

The root scope `.` and every declared member have local graphs loaded from their
own root manifests/command files. Arbitrary nested example manifests are not new
workspace scopes. Member paths can be deep; declared discovery does not use the
legacy depth-3 limit. A parent's source scope excludes its declared child scopes
before reading source or mention files. The root owns the remaining included
source tree. Explicit exclusions define scope and are recorded without becoming
read errors.

uv excludes remove matching members from declared discovery; this does not make
their files a separately analyzed workspace. Other workspace systems, parent-root
autodetection and undeclared members are not supported by this initial path.
Without a root declaration, the legacy bounded manifest discovery remains in
use, now with explicit read/parse/enumeration failures. Inspect `workspace_contexts`
to distinguish the two modes; an empty list is not proof that no monorepo exists.

## Shared locks and ambiguity

Local direct/production declarations and commands stay local. Shared lockfile
edges and executable names are restricted to the closure reachable from those
local direct roots; foreign lockfile roots never become local direct roots.
A reference to another workspace package contributes that member's production
dependencies as edges, without exporting its development tools as runtime roots.

These graphs are keyed by dependency names, not exact lock nodes. Where one name
stands for several things, its node carries the union of their edges and
declarations:

- several locked versions of a package contribute the dependencies of each;
- two members with the same package name contribute the production
  dependencies of both;
- an edge to an optional or peer package that was never installed leads nowhere;
- an npm alias (`"x-cjs": "npm:x@^4"`) is linked to the package it installs.

A union can only add paths from a declared dependency to a reported package, so
development-only and absence decisions, which need every path to agree, stay
conservative and the graph remains complete. Until 0.33 each of these marked the
graph incomplete, which disabled every graph-based filter on most large
monorepos. What still leaves it incomplete is input that could hide a path:
unreadable or malformed manifests and lockfiles, unsupported workspace patterns,
missing members, and symbolic links that stand in for a manifest, a lockfile or a
directory that may hold one. A linked file that cannot be a graph source (a
README, a translation file) is skipped without consequence.

A report from a native scanner covers one ecosystem, and the graph is then built
from that ecosystem's manifests and lockfiles only: an npm advisory for `glob`
is not traced through a `Cargo.lock` path to the crate of the same name.
Multi-ecosystem inputs (SBOM, Trivy, Grype, OSV) keep the merged graph, in which
a production declaration in any ecosystem wins.
Preferred shrinkwrap takes precedence over package-lock for shared npm graphs.
Mixed/unsupported layouts and other lockfile semantics can still remain unknown.

## Dynamic loaders

Python AST analysis recognizes `__import__`, `importlib.import_module` and their
direct imported/assigned aliases, including aliases through `builtins`. A literal
module string supplies positive import evidence. Relative `import_module` targets
need a resolvable literal `package`. Nonliteral arguments, shadowed/rebound loader
bindings and conditional loader selection remain unknown. Expressions are not
evaluated and no module is imported by the analyzer.

The JavaScript/TypeScript helper lexically recognizes bare `require(...)`,
`import(...)` and conventional `module.require(...)`. It distinguishes literal
targets from variable/expression targets and inspects code inside template
substitutions, while skipping comments, strings and recognized regex literals.
It is not a complete parser. Arbitrary `createRequire` aliases, custom loader
wrappers, cross-file bindings and interprocedural dataflow are outside this scope.

Recognized unresolved loaders have a file/line and reason. They block unreachable
and conditional source-reference-absence decisions in that source scope. A known
import can coexist with an unknown loader; positive usage remains observed.
Python AST failures retain the previous regex import fallback. Neither this
fallback nor `analysis_coverage_complete: true` certifies complete language or
runtime coverage. The flag describes the declared heuristics and inspected scope.

Source reads, enumeration, excluded child boundaries and unsupported linked
sources are recorded separately from dynamic-loader observations. The analyzer
does not follow included-source symlinks/junctions outside the intended scope;
potentially relevant skipped links leave analysis uncertain.

## Conservative aggregation

Scanner rows do not authenticate which workspace installation they describe.
depquiet therefore considers each local name relationship, positive usage and
uncertain scope without assigning a candidate to one workspace by guesswork.
Per-workspace graph and source checks run independently. A positive or uncertain
relevant context keeps an aggregate absence claim from winning. Development-only
classification requires graph coverage to be complete and every member that
declares the package, directly or through a dependency, to reach it only from
development dependencies. A member that uses a package without declaring it
(a test importing the root's `vitest`) does not turn it into a production
dependency: it gets the package from the declaring member's install, which a
production install omits. Workspace mode does not use scanner dev metadata as a
substitute for missing local declarations.

For npm audit input there is a second, independent source: the lockfile marks
each installed copy that exists only for `devDependencies`. When every reported
copy inside the advisory's range carries that mark, the alert is development-only
regardless of the name-level graph. See
[npm component evidence](npm-component-evidence.md#development-only-copies).

Source uncertainty blocks source-absence decisions; valid development-only graph
metadata remains an independent priority signal. Graph uncertainty blocks that
development-only classification in turn.

Conditional templates must satisfy the same condition in every relevant context
with complete coverage. Explicit unconditional templates, policies, ignores,
baselines, EPSS and KEV retain their separate priority rules; a coverage gap does
not disable those independently configured signals. Acceptance and lower priority
do not establish non-affectedness.

## Saved evidence

Each finding's `evidence` adds:

| Field | Meaning |
| --- | --- |
| `graph_coverage_complete` | Whether inspected graph inputs/discovery permit graph-based decisions. |
| `analysis_coverage_complete` | Whether inspected source scope and recognized loaders permit absence-based decisions. |
| `workspace_contexts` | Local `path`, relevance, dependency type, usage, dev-only result, coverage, roots, import sites and observations. |

Relevance is `dependency`, `observed`, `uncertain` or `not_declared`. It is a
selection explanation, not an affectedness classification. Top-level import sites
preserve positive observations. Coverage notes and dynamic loader file/line
evidence remain in `observations`. Saved `depquiet explain --from-json` restores
these fields and displays workspace/coverage evidence.

Legacy saved reports without the new coverage fields restore `null` (unknown)
and an empty context list. No old file is silently upgraded to verified coverage.
`scanned: true` still means the scanner report completed; incomplete contextual
analysis is represented by these evidence fields rather than pretending the
vulnerability inventory itself failed or was empty.

## Validation scope

Offline regressions cover deep npm/uv members, root-dev/member-production use,
shared-lock pruning, dev-tool export isolation, member/manifest failures, namespace
collisions, source exclusions, dynamic aliases/targets, read-cache failures and
saved CLI explanations. These verify conservative decision contracts. They are
not a measurement of scanner precision or safe noise reduction on real projects.
