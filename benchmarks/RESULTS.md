# depquiet benchmark results

Offline mode (no EPSS API), all filters active. Only **real** scenarios back the
numbers in the README.

## Real projects

Lockfile resolved and audited by the real package manager (`capture_real.py`).

| Scenario | Parser | Total | Action | Review | Filtered | Filter rate | Time |
|----------|--------|------:|-------:|-------:|---------:|------------:|-----:|
| real-npm-express | npm | 29 | 13 | 3 | 13 | **45%** | 441ms |

| Scenario | Unreachable | Dev-only | Low EPSS | Template |
|----------|------------:|---------:|---------:|---------:|
| real-npm-express | 13 | 8 | 0 | 0 |

### real-npm-express

Captured 2026-11-04T20:38:08Z with npm 10.9.9. Each row is one alert from `npm audit`.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| body-parser | GHSA-27r3-jxmh-p828 | high | transitive | express | action | - |
| body-parser | GHSA-qwcr-r2fm-qrc7 | high | transitive | express | action | - |
| body-parser | GHSA-v422-hmwv-36x6 | high | transitive | express | action | - |
| braces | GHSA-grv7-fg5c-xmjg | high | direct | jest-environment-jsdom, nodemon | action | - |
| cookie | GHSA-pxg6-pf52-xh8x | low | transitive | express | review | - |
| cross-spawn | GHSA-3xgq-45jj-v275 | high | transitive | eslint-plugin-import, nodemon | filtered | dev dependency, unreachable |
| express | GHSA-qw6h-vgh9-j6wx | high | direct | - | action | - |
| express | GHSA-rv95-896h-c2vc | high | direct | - | action | - |
| flatted | GHSA-25h7-pfq9-p65f | high | transitive | eslint-plugin-import | filtered | dev dependency, unreachable |
| flatted | GHSA-rf6f-7fwh-wjgh | high | transitive | eslint-plugin-import | filtered | dev dependency, unreachable |
| got | GHSA-pfrx-2q88-qq97 | moderate | transitive | nodemon | filtered | dev dependency, unreachable |
| lodash | GHSA-29mw-wpgm-hmr9 | high | direct | eslint-plugin-import | filtered | unreachable |
| lodash | GHSA-35jh-r3h4-6jhm | high | direct | eslint-plugin-import | filtered | unreachable |
| lodash | GHSA-p6mc-m468-83gw | high | direct | eslint-plugin-import | filtered | unreachable |
| lodash | GHSA-r5fr-rjxr-66jc | high | direct | eslint-plugin-import | filtered | unreachable |
| lodash | GHSA-xxjr-mmjv-4gpg | high | direct | eslint-plugin-import | filtered | unreachable |
| path-to-regexp | GHSA-37ch-88jc-xwx2 | high | transitive | express | action | - |
| path-to-regexp | GHSA-9wv6-86v2-598j | high | transitive | express | action | - |
| path-to-regexp | GHSA-rhx6-c78j-4q9w | high | transitive | express | action | - |
| qs | GHSA-4mjr-xmp4-gh2g | moderate | transitive | express | action | - |
| qs | GHSA-6pq8-jhm2-2vcw | moderate | transitive | express | action | - |
| qs | GHSA-6rw7-vpxm-498p | moderate | transitive | express | action | - |
| qs | GHSA-w7fw-mjwx-w883 | moderate | transitive | express | action | - |
| send | GHSA-m6fv-jmcg-4jfg | low | transitive | express | review | - |
| serve-static | GHSA-cm22-4g7w-348p | low | transitive | express | review | - |
| tmp | GHSA-52f5-9888-hmc6 | high | transitive | eslint-plugin-import | filtered | dev dependency, unreachable |
| tmp | GHSA-ph9p-34f9-6g65 | high | transitive | eslint-plugin-import | filtered | dev dependency, unreachable |
| webpack-dev-middleware | GHSA-g84c-rxfj-3j2c | high | direct | - | filtered | dev dependency, unreachable |
| webpack-dev-middleware | GHSA-wr3j-pwj9-hqq6 | high | direct | - | filtered | dev dependency, unreachable |

## Public repositories

Open-source projects at a pinned commit. npm projects: `npm audit` on their own
lockfile (for yarn projects, the lockfile npm derives from `yarn.lock`). Python
projects: `pip-audit --no-deps` on every version pinned in `uv.lock`/`poetry.lock`.

| Scenario | Parser | Total | Action | Review | Filtered | Filter rate | Time |
|----------|--------|------:|-------:|-------:|---------:|------------:|-----:|
| repo-hackathon-starter | npm | 2 | 0 | 0 | 2 | **100%** | 49ms |
| repo-mealie | pip-audit | 229 | 201 | 0 | 28 | **12%** | 1445ms |
| repo-node-express-boilerplate | npm | 163 | 140 | 5 | 18 | **11%** | 82ms |
| repo-node-express-realworld | npm | 95 | 51 | 3 | 41 | **43%** | 53ms |
| repo-paperless-ngx | pip-audit | 17 | 17 | 0 | 0 | **0%** | 1517ms |

| Scenario | Unreachable | Dev-only | Low EPSS | Template |
|----------|------------:|---------:|---------:|---------:|
| repo-hackathon-starter | 0 | 2 | 0 | 0 |
| repo-mealie | 0 | 28 | 0 | 0 |
| repo-node-express-boilerplate | 0 | 18 | 0 | 0 |
| repo-node-express-realworld | 0 | 41 | 0 | 0 |
| repo-paperless-ngx | 0 | 0 | 0 | 0 |

### repo-hackathon-starter

[sahat/hackathon-starter](https://github.com/sahat/hackathon-starter/tree/fb53b17c28c99e6fbcd78106930c6e9b403eb9ec) at `fb53b17` (2026-11-02), audited 2026-11-04T20:56:45Z with npm 10.9.9.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| glob | GHSA-3g3m-2fjr-6pw4 | moderate | transitive | c8, mocha | filtered | dev dependency |
| minimatch | GHSA-g3hv-75wg-m249 | moderate | transitive | @eslint/js, c8, eslint, eslint-config-prettier, eslint-plugin-chai-friendly, mocha | filtered | dev dependency |

### repo-mealie

[mealie-recipes/mealie](https://github.com/mealie-recipes/mealie/tree/01713b04163e9524b2665ad8089148b6d2f90233) at `01713b0` (2025-10-31), audited 2026-11-04T21:29:38Z with pip-audit 2.10.1 from `poetry.lock`.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| anyio | PYSEC-2026-4024 | moderate | transitive | fastapi, httpx, openai, uvicorn | action | - |
| anyio | PYSEC-2026-4025 | moderate | transitive | fastapi, httpx, openai, uvicorn | action | - |
| apprise | PYSEC-2026-4200 | moderate | direct | - | action | - |
| authlib | CVE-2026-116672 | moderate | direct | - | action | - |
| authlib | CVE-2026-96760 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-1201 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-188 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-2116 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-2117 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-2118 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-2119 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-25 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-287 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4354 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4355 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4356 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4357 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4358 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4359 | moderate | direct | - | action | - |
| authlib | PYSEC-2026-4360 | moderate | direct | - | action | - |
| certifi | PYSEC-2023-135 | moderate | transitive | apprise, extruct, fastapi, httpx, mkdocs-material, openai, recipe-scrapers, requests | action | - |
| certifi | PYSEC-2024-230 | moderate | transitive | apprise, extruct, fastapi, httpx, mkdocs-material, openai, recipe-scrapers, requests | action | - |
| certifi | PYSEC-2026-4320 | moderate | transitive | apprise, extruct, fastapi, httpx, mkdocs-material, openai, recipe-scrapers, requests | action | - |
| cryptography | GHSA-537c-gmf6-5ccf | moderate | transitive | authlib | action | - |
| cryptography | GHSA-h4gh-qq45-vh27 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2024-225 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-1283 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-1285 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-2141 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-35 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-3553 | moderate | transitive | authlib | action | - |
| cryptography | PYSEC-2026-3554 | moderate | transitive | authlib | action | - |
| filelock | CVE-2026-112909 | moderate | transitive | pre-commit | filtered | dev dependency |
| filelock | CVE-2026-112910 | moderate | transitive | pre-commit | filtered | dev dependency |
| filelock | PYSEC-2026-1374 | moderate | transitive | pre-commit | filtered | dev dependency |
| filelock | PYSEC-2026-1375 | moderate | transitive | pre-commit | filtered | dev dependency |
| h11 | PYSEC-2026-348 | moderate | transitive | fastapi, httpx, openai, uvicorn | action | - |
| idna | PYSEC-2024-60 | moderate | transitive | apprise, extruct, fastapi, httpx, mkdocs-material, openai, recipe-scrapers, requests, uvicorn | action | - |
| idna | PYSEC-2026-215 | moderate | transitive | apprise, extruct, fastapi, httpx, mkdocs-material, openai, recipe-scrapers, requests, uvicorn | action | - |
| lxml | PYSEC-2026-87 | moderate | direct | extruct, recipe-scrapers | action | - |
| lxml-html-clean | PYSEC-2024-160 | moderate | transitive | extruct, recipe-scrapers | action | - |
| lxml-html-clean | PYSEC-2026-2201 | moderate | transitive | extruct, recipe-scrapers | action | - |
| lxml-html-clean | PYSEC-2026-2202 | moderate | transitive | extruct, recipe-scrapers | action | - |
| lxml-html-clean | PYSEC-2026-2614 | moderate | transitive | extruct, recipe-scrapers | action | - |
| mako | PYSEC-2026-2617 | moderate | transitive | alembic | action | - |
| markdown | PYSEC-2026-89 | moderate | transitive | apprise, mkdocs-material | action | - |
| mkdocs-material | PYSEC-2026-3864 | moderate | direct | - | action | - |
| nltk | PYSEC-2026-2085 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-2235 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-2236 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-2237 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3582 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3583 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3584 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3657 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3722 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3723 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3724 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3728 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3729 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3730 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3731 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3732 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3733 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3734 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3735 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3736 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3737 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3738 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3739 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3740 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3741 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3748 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3749 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3750 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3751 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3752 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3868 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3869 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3870 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3871 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3954 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-3955 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-597 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-96 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-97 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-98 | moderate | transitive | ingredient-parser-nlp | action | - |
| nltk | PYSEC-2026-99 | moderate | transitive | ingredient-parser-nlp | action | - |
| oauthlib | PYSEC-2026-4114 | moderate | transitive | apprise | action | - |
| orjson | PYSEC-2026-107 | moderate | direct | fastapi | action | - |
| pillow | CVE-2026-112390 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112391 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112393 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112395 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112399 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112400 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112401 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112404 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112406 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112891 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112892 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112893 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112894 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112895 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112897 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112899 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-112900 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-96638 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-96640 | moderate | direct | pillow-heif | action | - |
| pillow | CVE-2026-96778 | moderate | direct | pillow-heif | action | - |
| pillow | GHSA-78g4-xqwv-q3g8 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-165 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2249 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2250 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2251 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2252 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2253 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2254 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2255 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2256 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2257 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-2874 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3451 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3452 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3453 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3454 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3493 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3494 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3495 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-3496 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4326 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4327 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4328 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4329 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4330 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4331 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4332 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4333 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4334 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4335 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4336 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4337 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4338 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4339 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4340 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4341 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4342 | moderate | direct | pillow-heif | action | - |
| pillow | PYSEC-2026-4343 | moderate | direct | pillow-heif | action | - |
| pillow-heif | PYSEC-2026-2258 | moderate | direct | - | action | - |
| pyasn1 | CVE-2026-119194 | moderate | transitive | python-ldap | action | - |
| pyasn1 | CVE-2026-119195 | moderate | transitive | python-ldap | action | - |
| pyasn1 | CVE-2026-119196 | moderate | transitive | python-ldap | action | - |
| pyasn1 | CVE-2026-119197 | moderate | transitive | python-ldap | action | - |
| pyasn1 | PYSEC-2026-2263 | moderate | transitive | python-ldap | action | - |
| pyasn1 | PYSEC-2026-3455 | moderate | transitive | python-ldap | action | - |
| pyasn1 | PYSEC-2026-3456 | moderate | transitive | python-ldap | action | - |
| pyasn1 | PYSEC-2026-3457 | moderate | transitive | python-ldap | action | - |
| pygments | PYSEC-2026-2987 | moderate | transitive | mkdocs-material, pytest, pytest-asyncio, rich | filtered | dev dependency |
| pyjwt | GHSA-pxh4-856f-4h89 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2025-183 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-120 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-175 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-176 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-177 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-178 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-179 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4140 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4141 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4144 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4145 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4147 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4148 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4149 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4152 | moderate | direct | - | action | - |
| pyjwt | PYSEC-2026-4183 | moderate | direct | - | action | - |
| pylint | CVE-2026-114608 | moderate | direct | - | action | - |
| pymdown-extensions | PYSEC-2026-1825 | moderate | transitive | mkdocs-material | filtered | dev dependency |
| pymdown-extensions | PYSEC-2026-2999 | moderate | transitive | mkdocs-material | filtered | dev dependency |
| pymdown-extensions | PYSEC-2026-3609 | moderate | transitive | mkdocs-material | filtered | dev dependency |
| pymdown-extensions | PYSEC-2026-3654 | moderate | transitive | mkdocs-material | filtered | dev dependency |
| pytest | PYSEC-2026-1845 | moderate | direct | pytest-asyncio | action | - |
| python-dotenv | PYSEC-2026-2270 | moderate | direct | pydantic-settings, uvicorn | action | - |
| python-multipart | PYSEC-2026-1852 | moderate | direct | fastapi | action | - |
| python-multipart | PYSEC-2026-3036 | moderate | direct | fastapi | action | - |
| python-multipart | PYSEC-2026-3037 | moderate | direct | fastapi | action | - |
| python-multipart | PYSEC-2026-3038 | moderate | direct | fastapi | action | - |
| python-multipart | PYSEC-2026-3039 | moderate | direct | fastapi | action | - |
| python-multipart | PYSEC-2026-3040 | moderate | direct | fastapi | action | - |
| requests | PYSEC-2026-2275 | moderate | direct | apprise, extruct, mkdocs-material, recipe-scrapers | action | - |
| setuptools | GHSA-xmj3-9gf7-h52w | moderate | transitive | pre-commit | filtered | dev dependency |
| setuptools | PYSEC-2025-49 | moderate | transitive | pre-commit | filtered | dev dependency |
| setuptools | PYSEC-2026-3447 | moderate | transitive | pre-commit | filtered | dev dependency |
| soupsieve | PYSEC-2026-3071 | moderate | transitive | beautifulsoup4, extruct, recipe-scrapers | action | - |
| soupsieve | PYSEC-2026-3072 | moderate | transitive | beautifulsoup4, extruct, recipe-scrapers | action | - |
| soupsieve | PYSEC-2026-4170 | moderate | transitive | beautifulsoup4, extruct, recipe-scrapers | action | - |
| soupsieve | PYSEC-2026-4171 | moderate | transitive | beautifulsoup4, extruct, recipe-scrapers | action | - |
| starlette | PYSEC-2026-161 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-1941 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-1942 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-2280 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-2281 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-248 | moderate | transitive | fastapi | action | - |
| starlette | PYSEC-2026-249 | moderate | transitive | fastapi | action | - |
| urllib3 | PYSEC-2023-192 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2023-212 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-141 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-1994 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-1995 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-1996 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-1998 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-1999 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-4175 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| urllib3 | PYSEC-2026-4177 | moderate | transitive | apprise, extruct, mkdocs-material, recipe-scrapers, requests | action | - |
| virtualenv | CVE-2026-113714 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113715 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113717 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113718 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113720 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113722 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113723 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113725 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113726 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113732 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | CVE-2026-113776 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | PYSEC-2026-2009 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | PYSEC-2026-4011 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | PYSEC-2026-4012 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | PYSEC-2026-4013 | moderate | transitive | pre-commit | filtered | dev dependency |
| virtualenv | PYSEC-2026-4014 | moderate | transitive | pre-commit | filtered | dev dependency |

### repo-node-express-boilerplate

[hagopj13/node-express-boilerplate](https://github.com/hagopj13/node-express-boilerplate/tree/179ae84efec61b14206d0305d941daed6c6d07f9) at `179ae84` (2023-08-12), audited 2026-11-04T20:56:59Z with npm 10.9.9.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| @babel/core | GHSA-4x5r-pxfx-6jf8 | low | transitive | jest | filtered | dev dependency |
| @babel/helpers | GHSA-968p-4wvh-cqc8 | moderate | transitive | jest | filtered | dev dependency |
| @babel/traverse | GHSA-67hx-6x53-jw92 | critical | transitive | jest | filtered | dev dependency |
| @sideway/formula | GHSA-c2jc-4fpr-4vhg | moderate | transitive | joi | action | - |
| @tootallnate/once | GHSA-vpq2-c234-7xj6 | low | transitive | jest, pm2 | review | - |
| ajv | GHSA-2g4f-4pwh-qvx6 | moderate | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier | filtered | dev dependency |
| ansi-regex | GHSA-93q8-gq69-wqmw | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, lint-staged, nodemon | filtered | dev dependency |
| async | GHSA-fwr7-v2mv-hh25 | high | transitive | pm2, winston | action | - |
| axios | GHSA-3g43-6gmg-66jw | high | transitive | pm2 | action | - |
| axios | GHSA-3p68-rc4w-qgx5 | high | transitive | pm2 | action | - |
| axios | GHSA-43fc-jf86-j433 | high | transitive | pm2 | action | - |
| axios | GHSA-5c9x-8gcm-mpgx | high | transitive | pm2 | action | - |
| axios | GHSA-62hf-57xw-28j9 | high | transitive | pm2 | action | - |
| axios | GHSA-6chq-wfr3-2hj9 | high | transitive | pm2 | action | - |
| axios | GHSA-7q8q-rj6j-mhjq | high | transitive | pm2 | action | - |
| axios | GHSA-898c-q2cr-xwhg | high | transitive | pm2 | action | - |
| axios | GHSA-fvcv-3m26-pcqx | high | transitive | pm2 | action | - |
| axios | GHSA-hfxv-24rg-xrqf | high | transitive | pm2 | action | - |
| axios | GHSA-j5f8-grm9-p9fc | high | transitive | pm2 | action | - |
| axios | GHSA-jr5f-v2jv-69x6 | high | transitive | pm2 | action | - |
| axios | GHSA-m7pr-hjqh-92cm | high | transitive | pm2 | action | - |
| axios | GHSA-mmx7-hfxf-jppx | high | transitive | pm2 | action | - |
| axios | GHSA-p92q-9vqr-4j8v | high | transitive | pm2 | action | - |
| axios | GHSA-pf86-5x62-jrwf | high | transitive | pm2 | action | - |
| axios | GHSA-pjwm-pj3p-43mv | high | transitive | pm2 | action | - |
| axios | GHSA-pmwg-cvhr-8vh7 | high | transitive | pm2 | action | - |
| axios | GHSA-vf2m-468p-8v99 | high | transitive | pm2 | action | - |
| axios | GHSA-w9j2-pvgh-6h63 | high | transitive | pm2 | action | - |
| axios | GHSA-wf5p-g6vw-rhxx | high | transitive | pm2 | action | - |
| axios | GHSA-xhjh-pmcv-23jw | high | transitive | pm2 | action | - |
| axios | GHSA-xx6v-rp6x-q39c | high | transitive | pm2 | action | - |
| body-parser | GHSA-27r3-jxmh-p828 | high | transitive | express, swagger-ui-express | action | - |
| body-parser | GHSA-qwcr-r2fm-qrc7 | high | transitive | express, swagger-ui-express | action | - |
| body-parser | GHSA-v422-hmwv-36x6 | high | transitive | express, swagger-ui-express | action | - |
| brace-expansion | GHSA-3jxr-9vmj-r5cp | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-6j4f-fj2g-mc7p | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-f886-m6hf-6m8v | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-mh99-v99m-4gvg | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-q2hr-2g5m-vwhr | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-qhr7-859c-m2p7 | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-rgw5-rvv9-x895 | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| brace-expansion | GHSA-v6h2-p8h4-qcjw | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| braces | GHSA-grv7-fg5c-xmjg | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| browserslist | GHSA-73wf-gq98-2v4g | high | transitive | jest | filtered | dev dependency |
| browserslist | GHSA-c83g-rgw3-j3cx | high | transitive | jest | filtered | dev dependency |
| compression | GHSA-vc2v-76pw-4v95 | high | direct | - | action | - |
| cookie | GHSA-pxg6-pf52-xh8x | low | transitive | express, swagger-ui-express | review | - |
| cookiejar | GHSA-h452-7996-h45h | moderate | transitive | supertest | filtered | dev dependency |
| cross-spawn | GHSA-3xgq-45jj-v275 | high | transitive | cross-env, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, lint-staged | action | - |
| decode-uri-component | GHSA-qr28-fpjm-wq7f | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| decode-uri-component | GHSA-vcc3-ghjq-m6fr | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| decode-uri-component | GHSA-w573-4hg7-7wgq | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| deepmerge | GHSA-gcqx-w48m-w2h4 | low | transitive | jest | filtered | dev dependency |
| degenerator | GHSA-9j49-mfvp-vmhm | high | transitive | pm2 | action | - |
| express | GHSA-qw6h-vgh9-j6wx | high | direct | swagger-ui-express | action | - |
| express | GHSA-rv95-896h-c2vc | high | direct | swagger-ui-express | action | - |
| flatted | GHSA-25h7-pfq9-p65f | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier | filtered | dev dependency |
| flatted | GHSA-rf6f-7fwh-wjgh | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier | filtered | dev dependency |
| follow-redirects | GHSA-cxjh-pqwp-8mfp | moderate | transitive | pm2 | action | - |
| follow-redirects | GHSA-jchw-25xp-jwwc | moderate | transitive | pm2 | action | - |
| follow-redirects | GHSA-r4q5-vmmm-2653 | moderate | transitive | pm2 | action | - |
| form-data | GHSA-fjxv-7rqg-78g4 | critical | transitive | coveralls, jest, supertest | filtered | dev dependency |
| form-data | GHSA-hmw2-7cc7-3qxx | critical | transitive | coveralls, jest, supertest | filtered | dev dependency |
| got | GHSA-pfrx-2q88-qq97 | moderate | transitive | nodemon | filtered | dev dependency |
| ip | GHSA-2p57-rm9w-gvfp | high | transitive | pm2 | action | - |
| ip | GHSA-78xj-cgh5-2h22 | high | transitive | pm2 | action | - |
| joi | GHSA-4528-x5fx-h6hg | high | direct | - | action | - |
| joi | GHSA-6h2x-m376-mqjq | high | direct | - | action | - |
| joi | GHSA-6w3j-5fw6-r9vr | high | direct | - | action | - |
| joi | GHSA-gg4h-3hg2-grpc | high | direct | - | action | - |
| joi | GHSA-q7cg-457f-vx79 | high | direct | - | action | - |
| joi | GHSA-wr44-6hxh-3jwq | high | direct | - | action | - |
| js-yaml | GHSA-2883-xcg3-v3hh | high | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, swagger-jsdoc | action | - |
| js-yaml | GHSA-52cp-r559-cp3m | high | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, swagger-jsdoc | action | - |
| js-yaml | GHSA-5p4m-2wfm-xmqj | high | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, swagger-jsdoc | action | - |
| js-yaml | GHSA-h67p-54hq-rp68 | high | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, swagger-jsdoc | action | - |
| js-yaml | GHSA-mh29-5h37-fv8m | high | transitive | coveralls, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, swagger-jsdoc | action | - |
| json-schema | GHSA-896r-f27r-55mw | critical | transitive | coveralls | filtered | dev dependency |
| json5 | GHSA-9c47-m6qq-7p4h | high | transitive | eslint-config-airbnb-base, eslint-plugin-import, jest | filtered | dev dependency |
| jsonwebtoken | GHSA-8cf7-32gw-wr33 | high | direct | passport-jwt | action | - |
| jsonwebtoken | GHSA-hjrf-2m68-5959 | high | direct | passport-jwt | action | - |
| jsonwebtoken | GHSA-qwph-4952-7xr6 | high | direct | passport-jwt | action | - |
| jws | GHSA-869p-cjfg-cm3x | high | transitive | jsonwebtoken, passport-jwt | action | - |
| lodash | GHSA-r5fr-rjxr-66jc | high | transitive | jest, pm2, winston | action | - |
| lodash | GHSA-xxjr-mmjv-4gpg | high | transitive | jest, pm2, winston | action | - |
| micromatch | GHSA-952p-6rrq-rcjv | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| minimatch | GHSA-23c5-xmqv-rm74 | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| minimatch | GHSA-3ppc-4f35-3m26 | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| minimatch | GHSA-7r86-cg39-jmmj | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| minimatch | GHSA-f8q6-p94x-37v3 | high | transitive | eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, nodemon, pm2, swagger-jsdoc | action | - |
| moment | GHSA-8hfj-j24r-96c4 | high | direct | pm2 | action | - |
| moment | GHSA-wc69-rhjr-hc9g | high | direct | pm2 | action | - |
| moment-timezone | GHSA-56x4-j7p9-fcf9 | moderate | transitive | pm2 | action | - |
| moment-timezone | GHSA-v78c-4p63-2j6c | moderate | transitive | pm2 | action | - |
| mongoose | GHSA-664h-wqgq-64gw | critical | direct | - | action | - |
| mongoose | GHSA-m7xq-9374-9rvx | critical | direct | - | action | - |
| mongoose | GHSA-vg7j-7cwx-8wgw | critical | direct | - | action | - |
| mongoose | GHSA-wpg9-53fq-2r8h | critical | direct | - | action | - |
| morgan | GHSA-4vj7-5mj6-jm8m | moderate | direct | - | action | - |
| morgan | GHSA-9f6g-j8ch-79g4 | moderate | direct | - | action | - |
| morgan | GHSA-jxfw-x594-9x9m | moderate | direct | - | action | - |
| nodemailer | GHSA-268h-hp4c-crq3 | high | direct | - | action | - |
| nodemailer | GHSA-2x7j-588g-ccc2 | high | direct | - | action | - |
| nodemailer | GHSA-39m8-27wv-hr27 | high | direct | - | action | - |
| nodemailer | GHSA-4ffr-jq9g-5ffx | high | direct | - | action | - |
| nodemailer | GHSA-4g23-2xm8-66gc | high | direct | - | action | - |
| nodemailer | GHSA-6vj9-mwq6-2f5v | high | direct | - | action | - |
| nodemailer | GHSA-85x2-q946-cp5h | high | direct | - | action | - |
| nodemailer | GHSA-8c8m-p3m8-cjg8 | high | direct | - | action | - |
| nodemailer | GHSA-8m3c-c648-2xjj | high | direct | - | action | - |
| nodemailer | GHSA-8vvx-rff5-p5rq | high | direct | - | action | - |
| nodemailer | GHSA-9h6g-pr28-7cqp | high | direct | - | action | - |
| nodemailer | GHSA-c7w3-x93f-qmm8 | high | direct | - | action | - |
| nodemailer | GHSA-g73g-hqqh-jr95 | high | direct | - | action | - |
| nodemailer | GHSA-m943-m63m-w62w | high | direct | - | action | - |
| nodemailer | GHSA-mm7p-fcc7-pg87 | high | direct | - | action | - |
| nodemailer | GHSA-p6gq-j5cr-w38f | high | direct | - | action | - |
| nodemailer | GHSA-r7g4-qg5f-qqm2 | high | direct | - | action | - |
| nodemailer | GHSA-rcmh-qjqh-p98v | high | direct | - | action | - |
| nodemailer | GHSA-v53p-9fqp-m79j | high | direct | - | action | - |
| nodemailer | GHSA-vvjj-xcjg-gr5g | high | direct | - | action | - |
| nodemailer | GHSA-wmmp-3585-3rmp | high | direct | - | action | - |
| nodemailer | GHSA-wqvq-jvpq-h66f | high | direct | - | action | - |
| on-headers | GHSA-76c9-3jph-rj3q | low | transitive | compression, morgan | review | - |
| pac-resolver | GHSA-9j49-mfvp-vmhm | high | transitive | pm2 | action | - |
| passport | GHSA-v923-w3x8-wh69 | moderate | direct | - | action | - |
| path-to-regexp | GHSA-37ch-88jc-xwx2 | high | transitive | express, swagger-ui-express | action | - |
| path-to-regexp | GHSA-9wv6-86v2-598j | high | transitive | express, swagger-ui-express | action | - |
| path-to-regexp | GHSA-rhx6-c78j-4q9w | high | transitive | express, swagger-ui-express | action | - |
| picomatch | GHSA-3v7f-55p6-f55p | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| picomatch | GHSA-c2c7-rcm5-vvqj | high | transitive | eslint-plugin-jest, jest, lint-staged, nodemon, pm2 | action | - |
| pm2 | GHSA-x5gf-qvw8-r2rm | high | direct | - | action | - |
| proxy-addr | GHSA-jqcg-44mw-7w3h | critical | transitive | express, swagger-ui-express | action | - |
| qs | GHSA-4mjr-xmp4-gh2g | high | transitive | coveralls, express, supertest, swagger-ui-express | action | - |
| qs | GHSA-6pq8-jhm2-2vcw | high | transitive | coveralls, express, supertest, swagger-ui-express | action | - |
| qs | GHSA-6rw7-vpxm-498p | high | transitive | coveralls, express, supertest, swagger-ui-express | action | - |
| qs | GHSA-hrpp-h998-j3pp | high | transitive | coveralls, express, supertest, swagger-ui-express | action | - |
| qs | GHSA-w7fw-mjwx-w883 | high | transitive | coveralls, express, supertest, swagger-ui-express | action | - |
| request | GHSA-p8p7-x288-28g6 | critical | transitive | coveralls | filtered | dev dependency |
| semver | GHSA-c2qf-rxjj-qqgw | high | transitive | cross-env, eslint, eslint-config-airbnb-base, eslint-config-prettier, eslint-plugin-import, eslint-plugin-jest, eslint-plugin-prettier, jest, jsonwebtoken, lint-staged, nodemon, passport-jwt, pm2, supertest | action | - |
| send | GHSA-m6fv-jmcg-4jfg | low | transitive | express, swagger-ui-express | review | - |
| serve-static | GHSA-cm22-4g7w-348p | low | transitive | express, swagger-ui-express | review | - |
| swagger-ui-dist | GHSA-6c9x-mj3g-h47x | moderate | transitive | swagger-ui-express | action | - |
| swagger-ui-dist | GHSA-qrmm-w75w-3wpx | moderate | transitive | swagger-ui-express | action | - |
| systeminformation | GHSA-3f7j-7jwc-fxfj | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-4vjg-vx72-qq4g | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-5vv4-hvf7-2h46 | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-5xpp-75jx-m839 | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-7648-jmwf-vw7j | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-9c88-49p5-5ggf | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-cvv5-9h9w-qp2m | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-gx6r-qc2v-3p3v | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-hvx9-hwr7-wjj9 | critical | transitive | pm2 | action | - |
| systeminformation | GHSA-wphj-fx3q-84ch | critical | transitive | pm2 | action | - |
| tough-cookie | GHSA-72xf-g2v4-qvf3 | moderate | transitive | coveralls, jest | filtered | dev dependency |
| uuid | GHSA-w5hq-g745-h8pq | moderate | transitive | coveralls, jest, pm2 | action | - |
| validator | GHSA-9965-vmph-33xx | high | direct | swagger-jsdoc | action | - |
| validator | GHSA-qgmg-gppg-76g5 | high | direct | swagger-jsdoc | action | - |
| validator | GHSA-vghf-hv5q-vc2g | high | direct | swagger-jsdoc | action | - |
| validator | GHSA-xx4c-jj58-r7x6 | high | direct | swagger-jsdoc | action | - |
| ws | GHSA-3h5v-q93c-6h6q | high | transitive | jest, pm2 | action | - |
| ws | GHSA-96hv-2xvq-fx4p | high | transitive | jest, pm2 | action | - |
| yaml | GHSA-48c2-rrv3-qjmp | moderate | transitive | lint-staged, swagger-jsdoc | action | - |

### repo-node-express-realworld

[gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app/tree/30b68e1e881462b2f4164ea09ab4c4f5699c7b0b) at `30b68e1` (2024-01-04), audited 2026-11-04T20:56:48Z with npm 10.9.9.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| @babel/core | GHSA-4x5r-pxfx-6jf8 | low | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| @babel/helpers | GHSA-968p-4wvh-cqc8 | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| @babel/plugin-transform-modules-systemjs | GHSA-fv7c-fp4j-7gwp | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node | filtered | dev dependency |
| @babel/runtime | GHSA-968p-4wvh-cqc8 | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| ajv | GHSA-2g4f-4pwh-qvx6 | moderate | transitive | @nx/eslint, @nx/eslint-plugin, @nx/node, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier | filtered | dev dependency |
| axios | GHSA-35jp-ww65-95wh | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-3g43-6gmg-66jw | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-3p68-rc4w-qgx5 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-3w6x-2g7m-8v23 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-42h9-826w-cgv3 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-43fc-jf86-j433 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-445q-vr5w-6q77 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-4hjh-wcwx-xvwj | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-5c9x-8gcm-mpgx | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-62hf-57xw-28j9 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-6chq-wfr3-2hj9 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-7q8q-rj6j-mhjq | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-898c-q2cr-xwhg | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-8hc4-vh64-cxmj | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-9fr6-4gfg-395g | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-fvcv-3m26-pcqx | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-hfxv-24rg-xrqf | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-j5f8-grm9-p9fc | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-j8rh-479h-cp32 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-jr5f-v2jv-69x6 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-m7pr-hjqh-92cm | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-mmx7-hfxf-jppx | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-p92q-9vqr-4j8v | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-pf86-5x62-jrwf | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-pmv8-rq9r-6j72 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-pmwg-cvhr-8vh7 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-q8qp-cvcw-x6jj | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-vf2m-468p-8v99 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-w9j2-pvgh-6h63 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-xhjh-pmcv-23jw | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| axios | GHSA-xx6v-rp6x-q39c | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | action | - |
| body-parser | GHSA-27r3-jxmh-p828 | high | direct | express | action | - |
| body-parser | GHSA-qwcr-r2fm-qrc7 | high | direct | express | action | - |
| body-parser | GHSA-v422-hmwv-36x6 | high | direct | express | action | - |
| brace-expansion | GHSA-3jxr-9vmj-r5cp | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-6j4f-fj2g-mc7p | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-f886-m6hf-6m8v | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-mh99-v99m-4gvg | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-q2hr-2g5m-vwhr | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-qhr7-859c-m2p7 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-rgw5-rvv9-x895 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| brace-expansion | GHSA-v6h2-p8h4-qcjw | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| braces | GHSA-grv7-fg5c-xmjg | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @types/jest, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, jest, jest-environment-node, jest-mock-extended, ts-jest | filtered | dev dependency |
| browserslist | GHSA-73wf-gq98-2v4g | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| browserslist | GHSA-c83g-rgw3-j3cx | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| cookie | GHSA-pxg6-pf52-xh8x | low | transitive | express | review | - |
| cross-spawn | GHSA-3xgq-45jj-v275 | high | transitive | @nx/eslint, @nx/eslint-plugin, @nx/node, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| deepmerge | GHSA-gcqx-w48m-w2h4 | low | transitive | @nx/jest, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |
| diff | GHSA-73rr-hh4g-fpgx | low | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest, ts-node | filtered | dev dependency |
| ejs | GHSA-ghr5-ch3p-vcr6 | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace | filtered | dev dependency |
| esbuild | GHSA-67mh-4wv8-2f99 | moderate | direct | @nx/esbuild | filtered | dev dependency |
| express | GHSA-qw6h-vgh9-j6wx | high | direct | - | action | - |
| express | GHSA-rv95-896h-c2vc | high | direct | - | action | - |
| flatted | GHSA-25h7-pfq9-p65f | high | transitive | @nx/eslint, @nx/eslint-plugin, @nx/node, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier | filtered | dev dependency |
| flatted | GHSA-rf6f-7fwh-wjgh | high | transitive | @nx/eslint, @nx/eslint-plugin, @nx/node, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier | filtered | dev dependency |
| follow-redirects | GHSA-cxjh-pqwp-8mfp | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, axios, nx | action | - |
| follow-redirects | GHSA-jchw-25xp-jwwc | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, axios, nx | action | - |
| follow-redirects | GHSA-r4q5-vmmm-2653 | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, axios, nx | action | - |
| form-data | GHSA-fjxv-7rqg-78g4 | critical | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, axios, nx | action | - |
| form-data | GHSA-hmw2-7cc7-3qxx | critical | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, axios, nx | action | - |
| js-yaml | GHSA-2883-xcg3-v3hh | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| js-yaml | GHSA-52cp-r559-cp3m | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| js-yaml | GHSA-5p4m-2wfm-xmqj | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| js-yaml | GHSA-h67p-54hq-rp68 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| js-yaml | GHSA-mh29-5h37-fv8m | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| jws | GHSA-869p-cjfg-cm3x | high | transitive | express-jwt, jsonwebtoken | action | - |
| micromatch | GHSA-952p-6rrq-rcjv | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @types/jest, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, jest, jest-environment-node, jest-mock-extended, ts-jest | filtered | dev dependency |
| minimatch | GHSA-23c5-xmqv-rm74 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| minimatch | GHSA-3ppc-4f35-3m26 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| minimatch | GHSA-7r86-cg39-jmmj | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, eslint, eslint-config-prettier, jest, jest-mock-extended, nx, ts-jest | filtered | dev dependency |
| nx | GHSA-g2r8-wvmj-jf5w | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace | filtered | dev dependency |
| nx | GHSA-hrvq-x7jp-36xv | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace | filtered | dev dependency |
| nx | GHSA-w2vw-w76x-qr89 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace | filtered | dev dependency |
| nx | GHSA-w3vv-58gj-gw77 | high | direct | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace | filtered | dev dependency |
| path-to-regexp | GHSA-37ch-88jc-xwx2 | high | transitive | express | action | - |
| path-to-regexp | GHSA-9wv6-86v2-598j | high | transitive | express | action | - |
| path-to-regexp | GHSA-rhx6-c78j-4q9w | high | transitive | express | action | - |
| picomatch | GHSA-3v7f-55p6-f55p | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @types/jest, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, jest, jest-environment-node, jest-mock-extended, ts-jest | filtered | dev dependency |
| picomatch | GHSA-c2c7-rcm5-vvqj | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @types/jest, @typescript-eslint/eslint-plugin, @typescript-eslint/parser, jest, jest-environment-node, jest-mock-extended, ts-jest | filtered | dev dependency |
| proxy-addr | GHSA-jqcg-44mw-7w3h | critical | transitive | express | action | - |
| qs | GHSA-4mjr-xmp4-gh2g | moderate | transitive | body-parser, express | action | - |
| qs | GHSA-6pq8-jhm2-2vcw | moderate | transitive | body-parser, express | action | - |
| qs | GHSA-6rw7-vpxm-498p | moderate | transitive | body-parser, express | action | - |
| qs | GHSA-w7fw-mjwx-w883 | moderate | transitive | body-parser, express | action | - |
| send | GHSA-m6fv-jmcg-4jfg | low | transitive | express | review | - |
| serve-static | GHSA-cm22-4g7w-348p | low | transitive | express | review | - |
| tmp | GHSA-52f5-9888-hmc6 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | filtered | dev dependency |
| tmp | GHSA-ph9p-34f9-6g65 | high | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, @nx/workspace, nx | filtered | dev dependency |
| uuid | GHSA-w5hq-g745-h8pq | moderate | transitive | @ngneat/falso | action | - |
| yaml | GHSA-48c2-rrv3-qjmp | moderate | transitive | @nx/esbuild, @nx/eslint, @nx/eslint-plugin, @nx/jest, @nx/js, @nx/node, jest, jest-mock-extended, ts-jest | filtered | dev dependency |

### repo-paperless-ngx

[paperless-ngx/paperless-ngx](https://github.com/paperless-ngx/paperless-ngx/tree/09d70ed7da7f56b9c197a57518fd363a1fddc3ff) at `09d70ed` (2026-11-04), audited 2026-11-04T21:29:34Z with pip-audit 2.10.1 from `uv.lock`.

| Package | Advisory | Severity | Type | Pulled in by | Verdict | Reason |
|---------|----------|----------|------|--------------|---------|--------|
| autobahn | CVE-2026-116579 | moderate | transitive | channels, channels-redis, daphne | action | - |
| nltk | PYSEC-2026-3740 | moderate | transitive | llama-index-core, llama-index-embeddings-huggingface, llama-index-embeddings-ollama, llama-index-embeddings-openai-like, llama-index-llms-ollama, llama-index-llms-openai-like | action | - |
| pyasn1 | CVE-2026-119194 | moderate | transitive | channels, channels-redis, daphne | action | - |
| pyasn1 | CVE-2026-119195 | moderate | transitive | channels, channels-redis, daphne | action | - |
| pyasn1 | CVE-2026-119196 | moderate | transitive | channels, channels-redis, daphne | action | - |
| pyasn1 | CVE-2026-119197 | moderate | transitive | channels, channels-redis, daphne | action | - |
| tornado | CVE-2026-115927 | moderate | transitive | flower | action | - |
| tornado | CVE-2026-116577 | moderate | transitive | flower | action | - |
| tornado | CVE-2026-116578 | moderate | transitive | flower | action | - |
| twisted | CVE-2026-106454 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-115774 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-115775 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-115776 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-115778 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-115877 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | CVE-2026-83813 | moderate | transitive | channels, channels-redis, daphne | action | - |
| twisted | GHSA-vpp8-g58w-m8mp | moderate | transitive | channels, channels-redis, daphne | action | - |

## Synthetic fixtures

Hand-written audit output with no lockfile. Without a lockfile depquiet cannot trace
transitive packages to the dependencies that pull them in, so it does not filter
them on reachability. Kept as parser regression tests, not as evidence.

| Scenario | Parser | Total | Action | Review | Filtered | Filter rate | Time |
|----------|--------|------:|-------:|-------:|---------:|------------:|-----:|
| npm-express-app | npm | 15 | 9 | 1 | 5 | **33%** | 2ms |
| pip-django-app | pip | 9 | 6 | 0 | 3 | **33%** | 1ms |
| trivy-node-container | trivy | 8 | 0 | 0 | 8 | **100%** | 1ms |
| grype-python-container | grype | 6 | 3 | 0 | 3 | **50%** | 1ms |

| Scenario | Unreachable | Dev-only | Low EPSS | Template |
|----------|------------:|---------:|---------:|---------:|
| npm-express-app | 5 | 4 | 0 | 0 |
| pip-django-app | 0 | 0 | 0 | 3 |
| trivy-node-container | 2 | 0 | 0 | 7 |
| grype-python-container | 0 | 0 | 0 | 3 |

*Generated by `benchmarks/run_benchmark.py`. Do not edit by hand.*
