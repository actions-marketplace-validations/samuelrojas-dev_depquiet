"""Filter: community templates for known false positives.

Templates are YAML files that encode community knowledge about specific CVEs
that are commonly flagged but rarely exploitable. The nuclei project proved
that community-driven templates create a powerful network effect.

Template format:
    id: CVE-2024-48930-lodash-merge
    dismiss-if:
      not-imported: ["lodash.defaultsDeep", "lodash.merge"]
    reason: "Only defaultsDeep/merge are affected. Other lodash functions are safe."
    author: "@contributor"
    cves:
      - CVE-2024-48930

A template matches when ALL conditions in dismiss-if are met.
Conditions:
  - not-imported: function/module names absent from readable source; the package
    and its dependency ancestors must also be unused
  - package: exact package name this template applies to
"""

from __future__ import annotations

# Inline YAML parser — avoids external dependency for v1.
# Templates are simple enough to parse with basic string handling.
# Will switch to PyYAML when the template format grows.
from dataclasses import dataclass, field
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from depquiet.depgraph import DependencyGraph
from depquiet.filters.reachability import ReachabilityFilter


@dataclass
class Template:
    """A community dismissal template."""

    id: str
    reason: str
    cves: list[str] = field(default_factory=list)
    package: str = ""
    not_imported: list[str] = field(default_factory=list)
    author: str = ""

    def matches_cve(self, cve: str) -> bool:
        return cve in self.cves

    def matches_package(self, package: str) -> bool:
        return not self.package or self.package == package


def strip_comment(line: str) -> str:
    """Drop a ``#`` comment that starts the line or follows whitespace, outside quotes."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line


def _parse_yaml_simple(text: str) -> dict[str, object]:
    """Minimal YAML-subset parser for template files.

    Handles flat key: value, key: [list], and multi-line lists with - prefix.
    Good enough for templates; no external deps needed.
    """
    result: dict[str, object] = {}
    current_key = ""
    current_list: list[str] = []
    in_list = False

    for line in text.split("\n"):
        # A trailing comment is not part of the value: left in, ``kev: true  # x``
        # read as not-true and ``[lodash]  # x`` as a package named that.
        stripped = strip_comment(line).strip()
        if not stripped:
            continue

        if stripped.startswith("- ") and in_list:
            val = stripped[2:].strip().strip('"').strip("'")
            current_list.append(val)
            continue

        if in_list and current_key:
            result[current_key] = current_list
            in_list = False

        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()

            if val.startswith("[") and val.endswith("]"):
                # Inline list: ["a", "b"]
                items = val[1:-1].split(",")
                result[key] = [i.strip().strip('"').strip("'") for i in items if i.strip()]
            elif val:
                result[key] = val.strip('"').strip("'")
            else:
                # Could be start of a list or a nested mapping
                current_key = key
                current_list = []
                in_list = True

    if in_list and current_key:
        result[current_key] = current_list

    return result


def _load_template(path: Traversable) -> Template | None:
    """Load a single template from a YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
        data = _parse_yaml_simple(text)

        # Also check for top-level not-imported (flattened format)
        not_imported: list[str] = []
        raw_imports = data.get("not-imported", [])
        if isinstance(raw_imports, str):
            not_imported = [raw_imports]
        elif isinstance(raw_imports, list):
            not_imported = [str(x) for x in raw_imports]

        cves: list[str] = []
        raw_cves = data.get("cves", [])
        if isinstance(raw_cves, str):
            cves = [raw_cves]
        elif isinstance(raw_cves, list):
            cves = [str(x) for x in raw_cves]

        return Template(
            id=str(data.get("id", path.name.rsplit(".", 1)[0])),
            reason=str(data.get("reason", "")),
            cves=cves,
            package=str(data.get("package", "")),
            not_imported=not_imported,
            author=str(data.get("author", "")),
        )
    except (OSError, ValueError):
        return None


class TemplateFilter:
    """Load and apply community dismissal templates."""

    def __init__(self, template_dirs: list[Path] | None = None):
        self._templates: list[Template] = []
        # Wheels carry the same source templates as package resources. The
        # repository path supports editable installs without copying files.
        bundled = files("depquiet").joinpath("_templates", "dismiss")
        if not bundled.is_dir():
            bundled = Path(__file__).parent.parent.parent.parent / "templates" / "dismiss"
        self._load_dir(bundled)
        dirs = list(template_dirs or [])
        for d in dirs:
            self._load_dir(d)

    def _load_dir(self, path: Traversable) -> None:
        """Load all templates from a directory."""
        if not path.is_dir():
            return
        for f in sorted(path.iterdir(), key=lambda entry: entry.name):
            if f.is_file() and f.name.endswith((".yaml", ".yml")):
                tmpl = _load_template(f)
                if tmpl:
                    self._templates.append(tmpl)

    def find_match(
        self,
        cve: str,
        package: str,
        *,
        project: Path | None = None,
        graph: DependencyGraph | None = None,
        reachability: ReachabilityFilter | None = None,
        allow_conditional: bool = True,
    ) -> Template | None:
        """Find a matching template whose conditions have project evidence.

        Conditional templates cannot establish what an imported library calls
        internally. Keep the alert when the package or an ancestor is in use,
        its dependency relationship is unknown, or source cannot be inspected.
        Custom templates without conditions remain explicit dismissal rules.
        """
        for tmpl in self._templates:
            if tmpl.matches_cve(cve) and tmpl.matches_package(package):
                if not tmpl.not_imported:
                    return tmpl
                if project is None or not allow_conditional:
                    continue
                project_graph = (
                    graph if graph is not None else DependencyGraph.from_project(project)
                )
                if not project_graph.coverage_complete:
                    continue
                source = reachability if reachability is not None else ReachabilityFilter(project)
                kind = project_graph.directness(package)
                ancestors = project_graph.direct_ancestors(package)
                if kind == "unknown" or (kind == "transitive" and not ancestors):
                    continue
                if source.is_used(package, project_graph) or any(
                    source.is_used(parent, project_graph) for parent in ancestors
                ):
                    continue
                if source.references_absent(tmpl.not_imported):
                    return tmpl
        return None

    @property
    def count(self) -> int:
        return len(self._templates)
