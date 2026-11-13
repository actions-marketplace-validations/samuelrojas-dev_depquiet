"""Filter: EPSS score — real-world exploit probability.

EPSS (Exploit Prediction Scoring System) from FIRST.org gives every CVE a
probability score (0-1) of being exploited in the wild within the next 30 days.
The score estimates observed exploitation activity in the next 30 days.
It does not establish product impact, existing mitigations or the absence
of exploits, even when the probability is low.

The EPSS API is free, public, no auth needed:
  https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX

By default EPSS only orders the report: it is a probability over the whole
internet, not a statement about one project, so a low score is no reason to
hide an alert. With an explicit threshold (``--epss-threshold`` or
``epss_threshold`` in the config), alerts scoring below it are filtered.

Lookups use the advisory's CVE id, its own or an alias: pip-audit, uv audit
and npm audit name advisories by PYSEC or GHSA ids, which EPSS does not cover.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from depquiet.models import FilterReason, Vulnerability

_EPSS_API = "https://api.first.org/data/v1/epss"
_DEFAULT_THRESHOLD: float | None = None  # off: EPSS orders, it does not filter


class EpssFilter:
    """Look up EPSS scores and filter low-probability CVEs."""

    reason = FilterReason.LOW_EPSS

    def __init__(self, threshold: float | None = _DEFAULT_THRESHOLD, cache_dir: Path | None = None):
        self._threshold = threshold
        self._cache: dict[str, tuple[float, float]] = {}  # cve -> (score, percentile)
        self._cache_dir = cache_dir

    def lookup(self, cves: list[str]) -> dict[str, tuple[float, float]]:
        """Batch-lookup EPSS scores for a list of CVEs.

        Returns {cve: (score, percentile)} for each CVE found.
        Only queries CVEs that look like CVE-YYYY-NNNNN (EPSS doesn't cover GHSA IDs).
        """
        # Filter to real CVE IDs
        real_cves = [c for c in cves if c.startswith("CVE-")]
        if not real_cves:
            return {}

        # Check cache first
        uncached = [c for c in real_cves if c not in self._cache]

        if uncached:
            # EPSS API accepts comma-separated CVEs
            # Batch in groups of 30 to avoid URL length limits
            for i in range(0, len(uncached), 30):
                batch = uncached[i : i + 30]
                self._fetch_batch(batch)

        return {c: self._cache[c] for c in real_cves if c in self._cache}

    def _fetch_batch(self, cves: list[str]) -> None:
        """Fetch EPSS scores for a batch of CVEs."""
        cve_param = ",".join(cves)
        url = f"{_EPSS_API}?cve={cve_param}"

        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                score = float(entry.get("epss", 0))
                percentile = float(entry.get("percentile", 0))
                self._cache[cve_id] = (score, percentile)
        except (urllib.error.URLError, json.JSONDecodeError, ValueError, OSError):
            # Network error — don't filter (conservative)
            pass

    def check(self, vuln: Vulnerability) -> bool:
        """Return True if the CVE has a low EPSS score (safe to deprioritize).

        Only filters if we successfully got the EPSS score AND it's below threshold.
        No score → don't filter (conservative).
        """
        if self._threshold is None or vuln.cve_id not in self._cache:
            return False
        score, _ = self._cache[vuln.cve_id]
        return score < self._threshold

    def get_score(self, cve: str) -> tuple[float, float] | None:
        """Return (score, percentile) for a CVE, or None if unknown."""
        return self._cache.get(cve)
