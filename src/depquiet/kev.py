"""CISA Known Exploited Vulnerabilities (KEV) catalog integration.

The KEV catalog lists CVEs with confirmed active exploitation, maintained
by CISA under Binding Operational Directive 22-01. Federal agencies must
remediate KEV-listed CVEs within the stated deadline; any organization
should treat them as top priority.

This module fetches the catalog, caches it locally, and matches scan
results against it — auto-escalating KEV-listed findings to ACTION.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.error import URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from depquiet.models import ScanResult

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cache lives for 24 hours before re-fetching
_CACHE_TTL_SECONDS = 86400

# Default cache location: ~/.cache/depquiet/kev.json
_DEFAULT_CACHE_DIR = Path.home() / ".cache" / "depquiet"


@dataclass
class KevEntry:
    """A single entry from the KEV catalog."""

    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    due_date: str
    required_action: str
    ransomware_use: bool
    description: str = ""


@dataclass
class KevCatalog:
    """The full KEV catalog with lookup capabilities."""

    entries: dict[str, KevEntry]
    catalog_version: str = ""
    date_released: str = ""

    def lookup(self, cve_id: str) -> KevEntry | None:
        """Check if a CVE is in the KEV catalog."""
        return self.entries.get(cve_id)

    @property
    def count(self) -> int:
        return len(self.entries)


def _parse_catalog(data: dict[str, Any]) -> KevCatalog:
    """Parse the raw KEV JSON feed into a KevCatalog."""
    entries: dict[str, KevEntry] = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor=vuln.get("vendorProject", ""),
            product=vuln.get("product", ""),
            name=vuln.get("vulnerabilityName", ""),
            date_added=vuln.get("dateAdded", ""),
            due_date=vuln.get("dueDate", ""),
            required_action=vuln.get("requiredAction", ""),
            ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            description=vuln.get("shortDescription", ""),
        )
    return KevCatalog(
        entries=entries,
        catalog_version=data.get("catalogVersion", ""),
        date_released=data.get("dateReleased", ""),
    )


def _read_cache(cache_path: Path) -> KevCatalog | None:
    """Read the cached KEV catalog if it exists and is fresh."""
    if not cache_path.exists():
        return None
    try:
        stat = cache_path.stat()
        age = time.time() - stat.st_mtime
        if age > _CACHE_TTL_SECONDS:
            return None
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        return _parse_catalog(data)
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _write_cache(cache_path: Path, data: dict[str, Any]) -> None:
    """Write the KEV catalog to the cache file."""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass  # Cache write failure is non-fatal


def fetch_kev_catalog(
    *,
    cache_dir: Path | None = None,
    offline: bool = False,
    timeout: int = 15,
) -> KevCatalog | None:
    """Fetch the CISA KEV catalog, using a local cache when possible.

    Args:
        cache_dir: Directory for the cache file. None uses the default.
        offline: If True, only use the cache — don't fetch from the network.
        timeout: HTTP request timeout in seconds.

    Returns:
        KevCatalog if available, None if offline and no cache exists.
    """
    cache_path = (cache_dir or _DEFAULT_CACHE_DIR) / "kev.json"

    # Try cache first
    cached = _read_cache(cache_path)
    if cached is not None:
        return cached

    if offline:
        # In offline mode, try to read even an expired cache
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                return _parse_catalog(data)
            except (json.JSONDecodeError, OSError):
                pass
        return None

    # Fetch from CISA
    try:
        req = Request(KEV_FEED_URL, headers={"User-Agent": "depquiet"})
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, json.JSONDecodeError):
        # Network failure — fall back to expired cache
        if cache_path.exists():
            try:
                data = json.loads(cache_path.read_text(encoding="utf-8"))
                return _parse_catalog(data)
            except (json.JSONDecodeError, OSError):
                pass
        return None

    _write_cache(cache_path, data)
    return _parse_catalog(data)


def load_kev_from_file(path: Path) -> KevCatalog:
    """Load a KEV catalog from a local JSON file (for testing / air-gapped use)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return _parse_catalog(data)


@dataclass
class KevResult:
    """Summary of KEV matching against scan results."""

    total_checked: int
    kev_matches: int
    escalated: int  # Findings promoted from REVIEW/FILTERED to ACTION


def apply_kev(
    result: ScanResult,
    catalog: KevCatalog,
) -> KevResult:
    """Match scan results against the KEV catalog.

    KEV-listed CVEs are auto-escalated to ACTION verdict regardless of
    other filters. This reflects the reality that actively exploited
    vulnerabilities demand immediate remediation.

    Args:
        result: The ScanResult to enrich.
        catalog: The KEV catalog to match against.

    Returns:
        KevResult with match statistics.
    """
    from depquiet.models import Verdict

    total_checked = 0
    kev_matches = 0
    escalated = 0

    for tr in result.results:
        if not tr.vuln.cve:
            continue
        total_checked += 1
        entry = catalog.lookup(tr.vuln.cve)
        if entry is None:
            continue

        kev_matches += 1
        # Store KEV data on the triage result for output enrichment
        tr.kev_entry = entry

        # Auto-escalate to ACTION if not already
        if tr.verdict != Verdict.ACTION:
            tr.verdict = Verdict.ACTION
            escalated += 1

    return KevResult(
        total_checked=total_checked,
        kev_matches=kev_matches,
        escalated=escalated,
    )
