"""Map Python distribution names to the module names they are imported as.

Advisories name the *distribution* (``PyYAML``, ``Pillow``, ``Django``); code
imports *modules* (``yaml``, ``PIL``, ``django``). Comparing the two
literally makes most real dependencies look unused, and an unused-looking
package is exactly what the reachability filter dismisses.

Sources, most precise first:

1. Installed metadata: ``top_level.txt`` / ``RECORD`` of every distribution in
   the project's virtualenv (``.venv``, ``venv``, ``env``) and in the
   environment depquiet itself runs in (common in CI, where depquiet is
   installed next to the project's dependencies).
2. A table of well-known mismatches.
3. Rules: case-insensitive, ``-``/``.`` -> ``_``, ``python-foo`` -> ``foo``,
   ``foo.bar`` -> ``foo`` (namespace packages).

Every source only *adds* candidates. More candidates can only make a package
look imported, so a wrong guess makes depquiet filter less, never more.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# PEP 503-normalized distribution name -> modules it provides.
KNOWN: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "ruamel-yaml": ("ruamel",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "opencv-contrib-python": ("cv2",),
    "opencv-contrib-python-headless": ("cv2",),
    "pyjwt": ("jwt",),
    "python-jose": ("jose",),
    "pyopenssl": ("OpenSSL",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pynacl": ("nacl",),
    "protobuf": ("google",),
    "grpcio": ("grpc",),
    "googleapis-common-protos": ("google",),
    "google-api-python-client": ("googleapiclient",),
    "google-auth": ("google",),
    "attrs": ("attr", "attrs"),
    "psycopg2-binary": ("psycopg2",),
    "psycopg-binary": ("psycopg",),
    "mysqlclient": ("MySQLdb",),
    "pymysql": ("pymysql",),
    "dnspython": ("dns",),
    "gitpython": ("git",),
    "python-ldap": ("ldap",),
    "pyzmq": ("zmq",),
    "pyserial": ("serial",),
    "pyusb": ("usb",),
    "websocket-client": ("websocket",),
    "python-socketio": ("socketio",),
    "python-engineio": ("engineio",),
    "python-multipart": ("multipart", "python_multipart"),
    "python-dotenv": ("dotenv",),
    "python-docx": ("docx",),
    "python-pptx": ("pptx",),
    "pdfminer-six": ("pdfminer",),
    "pypdf2": ("PyPDF2",),
    "djangorestframework": ("rest_framework",),
    "djangorestframework-simplejwt": ("rest_framework_simplejwt",),
    "django-cors-headers": ("corsheaders",),
    "django-environ": ("environ",),
    "django-filter": ("django_filters",),
    "django-redis": ("django_redis",),
    "msgpack-python": ("msgpack",),
    "faiss-cpu": ("faiss",),
    "faiss-gpu": ("faiss",),
    "setuptools": ("setuptools", "pkg_resources", "_distutils_hack"),
    "pywin32": ("win32api", "win32con", "pywintypes", "win32com"),
    "markdown": ("markdown",),
    "pyasn1-modules": ("pyasn1_modules",),
    "typing-extensions": ("typing_extensions",),
    "importlib-metadata": ("importlib_metadata",),
    "pygobject": ("gi",),
    "pycairo": ("cairo",),
    "python-magic": ("magic",),
    "python-slugify": ("slugify",),
    "python-json-logger": ("pythonjsonlogger",),
    "sentry-sdk": ("sentry_sdk",),
    "email-validator": ("email_validator",),
    "pyinstaller": ("PyInstaller",),
    "pysocks": ("socks", "sockshandler"),
    "jinja2": ("jinja2",),
    "markupsafe": ("markupsafe",),
    "tensorflow-cpu": ("tensorflow",),
    "tensorflow-gpu": ("tensorflow",),
    "torch": ("torch",),
    "py-cpuinfo": ("cpuinfo",),
    "argon2-cffi": ("argon2",),
    "pyhumps": ("humps",),
    "uvicorn": ("uvicorn",),
    "pydantic-settings": ("pydantic_settings",),
    "service-identity": ("service_identity",),
    "zope-interface": ("zope",),
    "backports-zoneinfo": ("backports",),
    "pyparsing": ("pyparsing",),
    "lxml": ("lxml",),
    "ujson": ("ujson",),
    "brotli": ("brotli",),
    "cffi": ("cffi", "_cffi_backend"),
    "pycparser": ("pycparser",),
}

_VENV_DIRS = (".venv", "venv", "env", ".env")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _own_name_candidates(dist: str) -> set[str]:
    """Module names derived from the whole distribution name."""
    norm = pep503(dist)
    out = {norm.replace("-", "_"), dist.replace("-", "_").replace(".", "_")}
    if norm.startswith("python-"):
        out.add(norm[len("python-") :].replace("-", "_"))
    if norm.startswith("py") and len(norm) > 4 and "-" not in norm:
        out.add(norm[2:])  # pyyaml -> yaml, pyjwt -> jwt (harmless extra guess)
    return {c.lower() for c in out if c}


def _rule_candidates(dist: str) -> set[str]:
    norm = pep503(dist)
    out = _own_name_candidates(dist)
    if "." in dist:
        out.add(dist.split(".", 1)[0])  # zope.interface -> zope
    parts = norm.split("-")
    # Namespace packages: llama-index-core -> llama_index, google-cloud-storage
    # -> google, ingredient-parser-nlp -> ingredient_parser.
    for i in range(1, len(parts)):
        out.add("_".join(parts[:i]))
    # Framework plugins installed by app label: django-allauth -> allauth,
    # flask-login -> flask_login is covered above, pytest-cov -> cov is not useful.
    for prefix in ("django-", "flask-", "sphinx-", "celery-"):
        if norm.startswith(prefix):
            out.add(norm[len(prefix) :].replace("-", "_"))
    return {c.lower() for c in out if c}


def _dist_info_modules(dist_info: Path) -> set[str]:
    """Top-level modules a single installed distribution provides."""
    top = dist_info / "top_level.txt"
    if top.is_file():
        try:
            return {x.strip() for x in top.read_text(errors="replace").split() if x.strip()}
        except OSError:
            return set()
    record = dist_info / "RECORD"
    mods: set[str] = set()
    if record.is_file():
        try:
            for line in record.read_text(errors="replace").splitlines():
                first = line.split(",", 1)[0].split("/", 1)[0]
                if (
                    not first
                    or first.endswith((".dist-info", ".data"))
                    or first in ("..", "__pycache__")
                ):
                    continue
                # ``mod.py``, ``_speedups.cpython-313-x86_64-linux-gnu.so``, ``x.pyd``
                is_file = "/" not in line.split(",", 1)[0]
                mods.add(first.split(".", 1)[0] if is_file else first)
        except OSError:
            pass
    return mods


def _dist_name(dist_info: Path) -> str:
    meta = dist_info / "METADATA"
    try:
        for line in meta.read_text(errors="replace").splitlines():
            if line.lower().startswith("name:"):
                return line.split(":", 1)[1].strip()
            if not line:
                break
    except OSError:
        pass
    return dist_info.name.split("-", 1)[0]


def _scan_site_packages(site: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    try:
        infos = [p for p in site.iterdir() if p.suffix == ".dist-info" and p.is_dir()]
    except OSError:
        return out
    for info in infos:
        mods = {m.lower() for m in _dist_info_modules(info)}
        if mods:
            out.setdefault(pep503(_dist_name(info)), set()).update(mods)
    return out


@lru_cache(maxsize=16)
def _project_environment(project: str) -> dict[str, frozenset[str]]:
    root = Path(project)
    merged: dict[str, set[str]] = {}
    for venv in _VENV_DIRS:
        lib = root / venv / "lib"
        sites = list(lib.glob("python3*/site-packages")) if lib.is_dir() else []
        sites += [root / venv / "Lib" / "site-packages"]  # Windows layout
        for site in sites:
            if site.is_dir():
                for dist, mods in _scan_site_packages(site).items():
                    merged.setdefault(dist, set()).update(mods)
    return {k: frozenset(v) for k, v in merged.items()}


@lru_cache(maxsize=1)
def _running_environment() -> dict[str, frozenset[str]]:
    from importlib.metadata import packages_distributions

    merged: dict[str, set[str]] = {}
    try:
        for module, dists in packages_distributions().items():
            for d in dists:
                merged.setdefault(pep503(d), set()).add(module.lower())
    except Exception:  # metadata of a broken install must not break a scan
        return {}
    return {k: frozenset(v) for k, v in merged.items()}


def _installed_modules(dist: str, project: Path | None) -> frozenset[str]:
    """Top-level modules of ``dist`` as actually installed, when it can be found."""
    norm = pep503(dist)
    found = _running_environment().get(norm, frozenset())
    if project is not None:
        found |= _project_environment(str(project.resolve())).get(norm, frozenset())
    return found


def import_candidates(dist: str, project: Path | None = None) -> set[str]:
    """Lower-cased module names that ``dist`` may be imported as.

    When the distribution is installed (in the project's virtualenv, or next
    to depquiet), its recorded top-level modules are the answer. Otherwise the
    name is all there is, and every plausible module name is a candidate:
    guessing too many keeps an alert, guessing too few would dismiss one.
    """
    known = {m.lower() for m in KNOWN.get(pep503(dist), ())}
    installed = _installed_modules(dist, project)
    if installed:
        return set(installed) | known | _own_name_candidates(dist)
    return _rule_candidates(dist) | known


def guessed_candidates(dist: str, project: Path | None = None) -> set[str]:
    """Candidates that are only a shared prefix of the name, not the name itself.

    ``django-auth-ldap`` may be imported as ``django``: true of a namespace
    package (``google-cloud-storage`` -> ``google``), false of a plugin. An
    import matching only such a guess keeps the alert, but it is not evidence
    of where this package is used.
    """
    if _installed_modules(dist, project):
        return set()
    norm = pep503(dist)
    confirmed = _own_name_candidates(dist) | {m.lower() for m in KNOWN.get(norm, ())}
    for prefix in ("django-", "flask-", "sphinx-", "celery-"):
        if norm.startswith(prefix):
            confirmed.add(norm[len(prefix) :].replace("-", "_"))
    return _rule_candidates(dist) - confirmed


# Libraries that import another distribution themselves, without the app ever
# naming it: when the parent is in use, so is the plugin. parent -> plugins
# (PEP 503 names).
IMPLICIT_PLUGINS: dict[str, tuple[str, ...]] = {
    "fastapi": ("python-multipart", "email-validator", "itsdangerous", "jinja2", "ujson", "orjson"),
    "starlette": ("python-multipart", "itsdangerous", "jinja2", "httpx"),
    "pydantic": ("email-validator",),
    "uvicorn": (
        "uvloop",
        "httptools",
        "websockets",
        "wsproto",
        "watchfiles",
        "python-dotenv",
        "pyyaml",
    ),
    "granian": ("uvloop", "watchfiles"),
    "gunicorn": ("gevent", "eventlet", "uvicorn", "setproctitle"),
    "sqlalchemy": (
        "psycopg2",
        "psycopg2-binary",
        "psycopg",
        "psycopg-binary",
        "asyncpg",
        "pymysql",
        "mysqlclient",
        "aiomysql",
        "aiosqlite",
        "oracledb",
        "pyodbc",
        "greenlet",
    ),
    "django": (
        "psycopg2",
        "psycopg2-binary",
        "psycopg",
        "psycopg-binary",
        "mysqlclient",
        "pymysql",
    ),
    "celery": ("redis", "librabbitmq", "kombu"),
    "kombu": ("redis", "librabbitmq"),
    "channels": ("daphne",),
    "requests": ("pysocks", "brotli", "chardet"),
    "httpx": ("h2", "brotli", "socksio"),
    "aiohttp": ("aiodns", "brotli"),
    "jinja2": ("markupsafe",),
    "pandas": ("openpyxl", "xlrd", "pyarrow", "sqlalchemy", "lxml"),
}
