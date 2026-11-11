"""Read ``pnpm-lock.yaml`` without a YAML dependency.

pnpm writes its lockfile itself, in one regular shape: block mappings indented
by two spaces, one key per line. That shape is all this reads, by indentation.
Anything else in the three sections it needs (a tab, a flow mapping where a
block is expected, an odd indent) raises ``ValueError``, so a file this cannot
follow is reported as unreadable instead of yielding a partial package list.

Layouts covered:

- v9: ``importers`` (direct dependencies per workspace project), ``packages``
  (one entry per name@version) and ``snapshots`` (the dependency edges, keyed
  by name@version plus a peer suffix).
- v6-v8: no ``snapshots``; edges live under ``packages``, keys start with ``/``.
- v5: keys are ``/name/version``; a single project may list its direct
  dependencies at the top level instead of under ``importers``.
- pnpm 10+ may put a second YAML document first, holding pnpm itself
  (``packageManagerDependencies``). Every document is read; that tooling is
  recorded as a development dependency.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Sections of an importer, and whether a production install includes them.
_IMPORTER_SECTIONS = {
    "dependencies": False,
    "optionalDependencies": False,
    "devDependencies": True,
    "packageManagerDependencies": True,
    "configDependencies": True,
}
# Peer dependencies are edges too: the resolved peer is installed alongside.
_EDGE_SECTIONS = {"dependencies", "optionalDependencies", "peerDependencies"}
_VERSION = re.compile(r"^\d+\.\d+")
# ``alias: real-name@1.2.3`` (v9) or ``alias: /real-name@1.2.3`` / ``/real-name/1.2.3``.
_ALIAS_TARGET = re.compile(r"^/?((?:@[^/@\s(]+/)?[A-Za-z_][^/@\s(]*)[@/]\d")


@dataclass
class PnpmLock:
    """What the triage needs from a pnpm lockfile."""

    # (name, exact version) of every locked registry package.
    packages: list[tuple[str, str]] = field(default_factory=list)
    # importer path -> {dependency name: is development-only}
    importers: dict[str, dict[str, bool]] = field(default_factory=dict)
    # package name -> names it depends on (union over its locked versions)
    edges: dict[str, set[str]] = field(default_factory=dict)


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _split_key(line: str) -> tuple[str, str]:
    """Split ``key: value`` where the key may be quoted and contain colons."""
    if line[:1] in "'\"":
        end = line.find(line[0], 1)
        if end < 0 or line[end + 1 : end + 2] != ":":
            raise ValueError(f"unsupported pnpm lock line: {line[:80]!r}")
        return line[1:end], line[end + 2 :].strip()
    # A key ends at the first ``: `` or at a final ``:``; a colon elsewhere
    # belongs to it (``xlsx@https://host/x.tgz:``).
    key, sep, value = line.partition(": ")
    if sep:
        return key.strip(), value.strip()
    if line.endswith(":"):
        return line[:-1].strip(), ""
    raise ValueError(f"unsupported pnpm lock line: {line[:80]!r}")


def _package_identity(key: str) -> tuple[str, str]:
    """``/@scope/name@1.2.3(peer@1)`` -> (``@scope/name``, ``1.2.3``).

    Returns an empty version for entries that are not registry packages
    (``file:``, git URLs, tarball paths): they still carry edges.
    """
    key = key.split("(", 1)[0]
    body = key[1:] if key.startswith("/") else key
    head, slash, tail = body.rpartition("/")
    if key.startswith("/") and slash and _VERSION.match(tail):
        # v5: /name/1.2.3 or /@scope/name/1.2.3_peer@1
        return head, tail.split("_", 1)[0]
    at = body.rfind("@")
    if at <= 0:
        return body, ""
    name, version = body[:at], body[at + 1 :]
    if not _VERSION.match(version):
        return (name if ":" not in name else ""), ""
    return name, version


def parse_pnpm_lock(path: Path) -> PnpmLock:
    lock = PnpmLock()
    seen: set[tuple[str, str]] = set()
    section = ""  # top-level key
    entry = ""  # importer path, or package name for packages/snapshots
    sub = ""  # section inside the entry
    dep = ""  # importer dependency whose details follow
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("---"):
            section = entry = sub = ""
            continue
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        if stripped.startswith("\t"):
            raise ValueError(f"line {number}: tab indentation is not supported")
        if indent == 0:
            section, _value = _split_key(stripped)
            entry = sub = ""
            continue
        if section in _IMPORTER_SECTIONS:
            # v5/v6 single project: direct dependencies at the top level.
            if indent == 2:
                name, _value = _split_key(stripped)
                lock.importers.setdefault(".", {})
                _declare(lock.importers["."], name, _IMPORTER_SECTIONS[section])
            continue
        if section not in {"importers", "packages", "snapshots"}:
            continue
        if indent == 2:
            key, value = _split_key(stripped)
            sub = dep = ""
            if section == "importers":
                entry = key
                lock.importers.setdefault(entry, {})
            else:
                entry, version = _package_identity(key)
                if entry and version and (entry, version) not in seen:
                    seen.add((entry, version))
                    lock.packages.append((entry, version))
                if entry:
                    lock.edges.setdefault(entry, set())
            if value not in ("", "{}"):
                raise ValueError(f"line {number}: expected a block mapping")
        elif indent == 4:
            sub, _value = _split_key(stripped)
            dep = ""
        elif not entry:
            continue
        # Deeper lines are read only inside the sections that hold names;
        # elsewhere they can be wrapped text (``deprecated:`` messages).
        elif section == "importers" and sub in _IMPORTER_SECTIONS:
            dev = _IMPORTER_SECTIONS[sub]
            if indent == 6:
                dep, value = _split_key(stripped)
                _declare(lock.importers[entry], dep, dev)
                _declare_alias(lock.importers[entry], dep, value, dev)
            elif indent == 8 and dep:
                key, value = _split_key(stripped)
                if key == "version":
                    _declare_alias(lock.importers[entry], dep, value, dev)
        elif section != "importers" and sub in _EDGE_SECTIONS and indent == 6:
            name, value = _split_key(stripped)
            lock.edges[entry].add(name)
            target = _ALIAS_TARGET.match(_unquote(value))
            if target and target.group(1) != name:
                lock.edges[entry].add(target.group(1))
    return lock


def _declare_alias(importer: dict[str, bool], name: str, value: str, dev: bool) -> None:
    """``alias: real@1.2.3``: the project also depends on the real package."""
    target = _ALIAS_TARGET.match(_unquote(value))
    if target and target.group(1) != name:
        _declare(importer, target.group(1), dev)


def _declare(importer: dict[str, bool], name: str, dev: bool) -> None:
    # Listed for production anywhere wins over a development listing.
    importer[name] = importer.get(name, True) and dev
