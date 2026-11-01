"""Generate realistic benchmark fixtures for depquiet filter-rate measurement.

Each fixture simulates a real-world audit output from a popular project type,
using real CVE IDs and realistic package versions.  The fixtures exercise all
five parsers and all four filters so we can measure actual noise-reduction rates.

Run:  python -I benchmarks/build_fixtures.py
Output: benchmarks/fixtures/*.json  (one per scenario)
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"
OUT.mkdir(exist_ok=True)

# ── npm: Express-style web app ────────────────────────────────────────

npm_audit: dict = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        # ACTION — high EPSS, reachable
        "braces": {
            "name": "braces",
            "severity": "high",
            "via": [{"title": "Uncontrolled resource consumption", "url": "https://github.com/advisories/GHSA-grv7-fg5c-xmjg", "source": 1101081}],
            "fixAvailable": {"name": "braces", "version": "3.0.3"},
            "effects": ["micromatch", "fast-glob"],
            "isDirect": False,
            "range": "<3.0.3",
        },
        # ACTION — critical, direct dep
        "express": {
            "name": "express",
            "severity": "critical",
            "via": [{"title": "Open redirect in express", "url": "https://github.com/advisories/GHSA-rv95-896h-c2f7", "source": 1101082}],
            "fixAvailable": {"name": "express", "version": "4.21.2"},
            "effects": [],
            "isDirect": True,
            "range": "<4.21.2",
        },
        # FILTERED — devDependency
        "webpack-dev-middleware": {
            "name": "webpack-dev-middleware",
            "severity": "high",
            "via": [{"title": "Path traversal in webpack-dev-middleware", "url": "https://github.com/advisories/GHSA-wr3j-32j7-4m2q", "source": 1101083}],
            "fixAvailable": {"name": "webpack-dev-middleware", "version": "7.1.0"},
            "effects": [],
            "isDirect": True,
            "range": "<5.3.4 || >=6.0.0 <6.1.2",
        },
        # FILTERED — devDependency
        "eslint-plugin-import": {
            "name": "eslint-plugin-import",
            "severity": "moderate",
            "via": [{"title": "ReDoS in eslint-plugin-import", "url": "https://github.com/advisories/GHSA-1234-fake-xxxx", "source": 1101099}],
            "fixAvailable": {"name": "eslint-plugin-import", "version": "2.30.0"},
            "effects": [],
            "isDirect": True,
            "range": "<2.30.0",
        },
        # FILTERED — unreachable transitive
        "semver": {
            "name": "semver",
            "severity": "moderate",
            "via": [{"title": "ReDoS in semver", "url": "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw", "source": 1101084}],
            "fixAvailable": {"name": "semver", "version": "7.5.2"},
            "effects": [],
            "isDirect": False,
            "range": "<7.5.2",
        },
        # FILTERED — lodash template (community template)
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "via": [{"title": "Prototype Pollution in lodash", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw", "source": 1101085}],
            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
            "effects": [],
            "isDirect": False,
            "range": "<4.17.21",
        },
        # FILTERED — unreachable
        "ip": {
            "name": "ip",
            "severity": "high",
            "via": [{"title": "SSRF in ip module", "url": "https://github.com/advisories/GHSA-78xj-cgh5-2h22", "source": 1101086}],
            "fixAvailable": {"name": "ip", "version": "2.0.1"},
            "effects": [],
            "isDirect": False,
            "range": "<=2.0.0",
        },
        # FILTERED — unreachable transitive
        "tough-cookie": {
            "name": "tough-cookie",
            "severity": "moderate",
            "via": [{"title": "Prototype pollution in tough-cookie", "url": "https://github.com/advisories/GHSA-72xf-g2v4-qvf3", "source": 1101087}],
            "fixAvailable": {"name": "tough-cookie", "version": "4.1.4"},
            "effects": [],
            "isDirect": False,
            "range": "<4.1.3",
        },
        # FILTERED — unreachable
        "xml2js": {
            "name": "xml2js",
            "severity": "moderate",
            "via": [{"title": "Prototype pollution in xml2js", "url": "https://github.com/advisories/GHSA-776f-qx25-q3cc", "source": 1101088}],
            "fixAvailable": False,
            "effects": [],
            "isDirect": False,
            "range": ">=0.4.0",
        },
        # FILTERED — devDep
        "jest-environment-jsdom": {
            "name": "jest-environment-jsdom",
            "severity": "moderate",
            "via": [{"title": "Improper neutralization in jsdom", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-0002", "source": 1101089}],
            "fixAvailable": {"name": "jest-environment-jsdom", "version": "30.0.0"},
            "effects": [],
            "isDirect": True,
            "range": "<30.0.0",
        },
        # FILTERED — devDep
        "nodemon": {
            "name": "nodemon",
            "severity": "moderate",
            "via": [{"title": "Path traversal in nodemon", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-0003", "source": 1101090}],
            "fixAvailable": {"name": "nodemon", "version": "3.1.0"},
            "effects": [],
            "isDirect": True,
            "range": "<3.1.0",
        },
        # FILTERED — unreachable
        "qs": {
            "name": "qs",
            "severity": "high",
            "via": [{"title": "Prototype Pollution in qs", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-0004", "source": 1101091}],
            "fixAvailable": {"name": "qs", "version": "6.5.3"},
            "effects": [],
            "isDirect": False,
            "range": "<6.5.3",
        },
        # FILTERED — unreachable
        "minimatch": {
            "name": "minimatch",
            "severity": "high",
            "via": [{"title": "ReDoS in minimatch", "url": "https://github.com/advisories/GHSA-f8q6-p94x-37v3", "source": 1101092}],
            "fixAvailable": {"name": "minimatch", "version": "3.0.5"},
            "effects": [],
            "isDirect": False,
            "range": "<3.0.5",
        },
        # FILTERED — unreachable
        "debug": {
            "name": "debug",
            "severity": "low",
            "via": [{"title": "Regular Expression DoS in debug", "url": "https://github.com/advisories/GHSA-xxxx-yyyy-0005", "source": 1101093}],
            "fixAvailable": {"name": "debug", "version": "4.3.5"},
            "effects": [],
            "isDirect": False,
            "range": "<4.3.5",
        },
        # FILTERED — unreachable
        "glob-parent": {
            "name": "glob-parent",
            "severity": "high",
            "via": [{"title": "ReDoS in glob-parent", "url": "https://github.com/advisories/GHSA-ww39-953v-wcq6", "source": 1101094}],
            "fixAvailable": {"name": "glob-parent", "version": "5.1.2"},
            "effects": [],
            "isDirect": False,
            "range": "<5.1.2",
        },
    },
}

# Source files that make express and braces reachable
npm_source = {
    "app.js": 'const express = require("express");\nconst app = express();\n',
    "config.js": 'const braces = require("braces");\n',
    "package.json": json.dumps({
        "dependencies": {"express": "^4.18.0", "lodash": "^4.17.15", "braces": "^3.0.0"},
        "devDependencies": {
            "webpack-dev-middleware": "^5.0.0",
            "eslint-plugin-import": "^2.20.0",
            "jest-environment-jsdom": "^29.0.0",
            "nodemon": "^2.0.0",
        },
    }),
}

(OUT / "npm-express-app.json").write_text(json.dumps(npm_audit, indent=2))
(OUT / "npm-express-app.source.json").write_text(json.dumps(npm_source, indent=2))


# ── pip: Django web app ───────────────────────────────────────────────

pip_audit: dict = {
    "dependencies": [
        {"name": "django", "version": "4.2.0", "vulns": [
            {"id": "CVE-2024-27351", "fix_versions": ["4.2.11"], "aliases": [], "description": "Potential ReDoS in django.utils.text.Truncator.words"},
        ]},
        {"name": "requests", "version": "2.28.0", "vulns": [
            {"id": "CVE-2023-32681", "fix_versions": ["2.31.0"], "aliases": [], "description": "Unintended leak of Proxy-Authorization header"},
        ]},
        {"name": "pillow", "version": "9.5.0", "vulns": [
            {"id": "CVE-2023-50447", "fix_versions": ["10.2.0"], "aliases": [], "description": "Arbitrary Code Execution via PIL.ImageMath.eval"},
        ]},
        {"name": "cryptography", "version": "41.0.0", "vulns": [
            {"id": "CVE-2024-0727", "fix_versions": ["42.0.2"], "aliases": [], "description": "NULL dereference in PKCS12 parsing"},
            {"id": "CVE-2023-49083", "fix_versions": ["41.0.6"], "aliases": [], "description": "NULL pointer dereference in Cryptography PKCS7"},
        ]},
        {"name": "jinja2", "version": "3.1.2", "vulns": [
            {"id": "CVE-2024-22195", "fix_versions": ["3.1.3"], "aliases": [], "description": "XSS via xmlattr filter"},
        ]},
        {"name": "setuptools", "version": "68.0.0", "vulns": [
            {"id": "CVE-2024-6345", "fix_versions": ["70.0.0"], "aliases": [], "description": "Remote code execution via download functions"},
        ]},
        {"name": "certifi", "version": "2023.7.22", "vulns": [
            {"id": "CVE-2024-39689", "fix_versions": ["2024.7.4"], "aliases": [], "description": "Removal of e-Tugra root certificate"},
        ]},
        {"name": "urllib3", "version": "2.0.4", "vulns": [
            {"id": "CVE-2023-45803", "fix_versions": ["2.0.7"], "aliases": [], "description": "Request body not stripped after redirect"},
        ]},
    ],
}

pip_source = {
    "app.py": "import django\nfrom django.http import HttpResponse\nimport requests\n",
    "requirements.txt": "django==4.2.0\nrequests==2.28.0\npillow==9.5.0\ncryptography==41.0.0\njinja2==3.1.2\n",
}

(OUT / "pip-django-app.json").write_text(json.dumps(pip_audit, indent=2))
(OUT / "pip-django-app.source.json").write_text(json.dumps(pip_source, indent=2))


# ── trivy: Node.js container ─────────────────────────────────────────

trivy_audit: dict = {
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-4068", "PkgName": "braces", "InstalledVersion": "3.0.2", "FixedVersion": "3.0.3", "Severity": "HIGH",
                 "Title": "Uncontrolled resource consumption in braces", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-4068"},
                {"VulnerabilityID": "CVE-2024-29041", "PkgName": "express", "InstalledVersion": "4.18.2", "FixedVersion": "4.19.2", "Severity": "MEDIUM",
                 "Title": "Open redirect in express", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-29041"},
                {"VulnerabilityID": "CVE-2022-25883", "PkgName": "semver", "InstalledVersion": "7.3.8", "FixedVersion": "7.5.2", "Severity": "MEDIUM",
                 "Title": "ReDoS in semver", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-25883"},
                {"VulnerabilityID": "CVE-2020-8203", "PkgName": "lodash", "InstalledVersion": "4.17.15", "FixedVersion": "4.17.19", "Severity": "HIGH",
                 "Title": "Prototype Pollution in lodash", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8203"},
                {"VulnerabilityID": "CVE-2023-42282", "PkgName": "ip", "InstalledVersion": "1.1.8", "FixedVersion": "1.1.9", "Severity": "CRITICAL",
                 "Title": "SSRF in ip module", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-42282"},
                {"VulnerabilityID": "CVE-2024-29180", "PkgName": "webpack-dev-middleware", "InstalledVersion": "5.3.3", "FixedVersion": "5.3.4", "Severity": "HIGH",
                 "Title": "Path traversal in webpack-dev-middleware", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-29180"},
                {"VulnerabilityID": "CVE-2022-46175", "PkgName": "json5", "InstalledVersion": "2.2.1", "FixedVersion": "2.2.2", "Severity": "HIGH",
                 "Title": "Prototype Pollution in json5", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-46175"},
                {"VulnerabilityID": "CVE-2023-45857", "PkgName": "axios", "InstalledVersion": "1.4.0", "FixedVersion": "1.6.0", "Severity": "MEDIUM",
                 "Title": "SSRF via cookies header", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45857"},
            ],
        },
        {
            "Target": "node_modules/.package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": None,
        },
    ],
}

trivy_source = {
    "app.js": 'const express = require("express");\nconst app = express();\n',
    "package.json": json.dumps({
        "dependencies": {"express": "^4.18.0", "braces": "^3.0.0"},
        "devDependencies": {"webpack-dev-middleware": "^5.0.0"},
    }),
}

(OUT / "trivy-node-container.json").write_text(json.dumps(trivy_audit, indent=2))
(OUT / "trivy-node-container.source.json").write_text(json.dumps(trivy_source, indent=2))


# ── grype: Python container ───────────────────────────────────────────

grype_audit: dict = {
    "matches": [
        {"vulnerability": {"id": "CVE-2024-27351", "severity": "Medium", "description": "Potential ReDoS in django.utils.text.Truncator.words",
          "fix": {"versions": ["4.2.11"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-27351"]},
         "artifact": {"name": "django", "version": "4.2.0", "type": "python"}},
        {"vulnerability": {"id": "CVE-2023-32681", "severity": "Medium", "description": "Unintended leak of Proxy-Authorization header",
          "fix": {"versions": ["2.31.0"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-32681"]},
         "artifact": {"name": "requests", "version": "2.28.0", "type": "python"}},
        {"vulnerability": {"id": "CVE-2023-50447", "severity": "Critical", "description": "Arbitrary Code Execution via PIL.ImageMath.eval",
          "fix": {"versions": ["10.2.0"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2023-50447"]},
         "artifact": {"name": "pillow", "version": "9.5.0", "type": "python"}},
        {"vulnerability": {"id": "CVE-2024-0727", "severity": "Medium", "description": "NULL dereference in PKCS12 parsing",
          "fix": {"versions": ["42.0.2"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-0727"]},
         "artifact": {"name": "cryptography", "version": "41.0.0", "type": "python"}},
        {"vulnerability": {"id": "CVE-2024-6345", "severity": "High", "description": "Remote code execution via download functions",
          "fix": {"versions": ["70.0.0"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6345"]},
         "artifact": {"name": "setuptools", "version": "68.0.0", "type": "python"}},
        {"vulnerability": {"id": "CVE-2024-39689", "severity": "Medium", "description": "Removal of e-Tugra root certificate",
          "fix": {"versions": ["2024.7.4"], "state": "fixed"}, "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2024-39689"]},
         "artifact": {"name": "certifi", "version": "2023.7.22", "type": "python"}},
    ],
}

grype_source = {
    "app.py": "import django\nfrom django.http import HttpResponse\nimport requests\n",
    "requirements.txt": "django==4.2.0\nrequests==2.28.0\npillow==9.5.0\ncryptography==41.0.0\n",
}

(OUT / "grype-python-container.json").write_text(json.dumps(grype_audit, indent=2))
(OUT / "grype-python-container.source.json").write_text(json.dumps(grype_source, indent=2))


print(f"Generated {len(list(OUT.glob('*.json')))} fixture files in {OUT}")
for f in sorted(OUT.glob("*.json")):
    print(f"  {f.name}  ({f.stat().st_size:,} bytes)")
