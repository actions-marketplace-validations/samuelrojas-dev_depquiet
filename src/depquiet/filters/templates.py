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
  - not-imported: list of function/module names — dismisses if NONE appear in source
  - package: exact package name this template applies to
  - severity-below: only dismiss if severity is below this level
"""

from __future__ import annotations

# Inline YAML parser — avoids external dependency for v1.
# Templates are simple enough to parse with basic string handling.
# Will switch to PyYAML when the template format grows.
from dataclasses import dataclass, field
from pathlib import Path


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
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
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


def _load_template(path: Path) -> Template | None:
    """Load a single template from a YAML file."""
    try:
        text = path.read_text()
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
            id=str(data.get("id", path.stem)),
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
        dirs = template_dirs or []
        # Always include bundled templates
        bundled = Path(__file__).parent.parent.parent.parent / "templates" / "dismiss"
        if bundled.is_dir():
            dirs.insert(0, bundled)
        for d in dirs:
            self._load_dir(d)

    def _load_dir(self, path: Path) -> None:
        """Load all templates from a directory."""
        if not path.is_dir():
            return
        for f in sorted(path.iterdir()):
            if f.suffix in (".yaml", ".yml"):
                tmpl = _load_template(f)
                if tmpl:
                    self._templates.append(tmpl)

    def find_match(self, cve: str, package: str) -> Template | None:
        """Find a template that matches this CVE and package."""
        for tmpl in self._templates:
            if tmpl.matches_cve(cve) and tmpl.matches_package(package):
                return tmpl
        return None

    @property
    def count(self) -> int:
        return len(self._templates)
