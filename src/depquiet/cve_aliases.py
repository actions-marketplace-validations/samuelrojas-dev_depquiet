"""Find the CVE id of advisories that scanners report without one.

EPSS scores and the CISA KEV catalog are keyed by CVE id. pip-audit and
uv audit give the CVE as an alias, but ``npm audit`` reports only the GitHub
advisory (GHSA) id, so without this step EPSS and KEV silently never apply
to npm projects. OSV.dev lists each advisory's aliases:

    https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx

Lookups run in parallel, are cached on disk, and never fail the scan: an
advisory whose CVE cannot be found stays as it is, and the caller reports
how many were left unchecked.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from depquiet.models import Vulnerability

_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_DEFAULT_CACHE = Path.home() / ".cache" / "depquiet" / "cve-aliases.json"
# An advisory can get its CVE assigned later, so "no CVE" is only kept a week.
_NEGATIVE_TTL = 7 * 24 * 3600
_MAX_LOOKUPS = 300
_WORKERS = 8


def _needs_lookup(vuln: Vulnerability) -> bool:
    return not vuln.cve_id and vuln.cve.upper().startswith(("GHSA-", "PYSEC-"))


def _fetch(advisory: str, timeout: int) -> list[str] | None:
    """The advisory's CVE ids ([] when it has none), or None when the lookup failed."""
    req = urllib.request.Request(_OSV_VULN_URL + advisory, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return [] if e.code == 404 else None  # OSV does not know it: no alias to find
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    found = [a for a in data.get("aliases") or [] if isinstance(a, str)]
    return [a for a in found if a.upper().startswith("CVE-")]


def _read_cache(path: Path) -> dict[str, dict[str, object]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_cache(path: Path, cache: dict[str, dict[str, object]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # a cache that cannot be written only costs the next run time


def resolve_cve_aliases(
    vulns: list[Vulnerability],
    *,
    timeout: int = 10,
    cache_path: Path | None = None,
    now: float | None = None,
) -> int:
    """Add the CVE id to every advisory reported without one. Returns how many lookups failed.

    The CVE is appended to ``vuln.aliases``, where EPSS, KEV and templates
    already look.
    """
    wanted = list(dict.fromkeys(v.cve for v in vulns if _needs_lookup(v)))
    if not wanted:
        return 0
    path = cache_path or _DEFAULT_CACHE
    moment = time.time() if now is None else now
    cache = _read_cache(path)
    known: dict[str, list[str]] = {}
    for advisory in wanted:
        entry = cache.get(advisory)
        if not isinstance(entry, dict):
            continue
        stored = entry.get("cves")
        cached = [c for c in stored if isinstance(c, str)] if isinstance(stored, list) else []
        at = entry.get("at")
        age = moment - float(at) if isinstance(at, (int, float)) else _NEGATIVE_TTL
        if cached or age < _NEGATIVE_TTL:
            known[advisory] = cached

    pending = [a for a in wanted if a not in known]
    todo = pending[:_MAX_LOOKUPS]
    failed = len(pending) - len(todo)
    if todo:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            fetched = list(pool.map(lambda a: _fetch(a, timeout), todo))
        for advisory, found in zip(todo, fetched, strict=True):
            if found is None:
                failed += 1
                continue
            known[advisory] = found
            cache[advisory] = {"cves": found, "at": moment}
        _write_cache(path, cache)

    for vuln in vulns:
        if _needs_lookup(vuln):
            for cve in known.get(vuln.cve, []):
                if cve not in vuln.aliases:
                    vuln.aliases.append(cve)
    return failed
