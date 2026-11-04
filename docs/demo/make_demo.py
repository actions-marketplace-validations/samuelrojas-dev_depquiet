"""Render docs/demo/demo.gif and demo.mp4 from real command output.

Nothing in the animation is typed by hand: every line is captured from
running the commands on the benchmark project
(``benchmarks/fixtures/real-npm-express``):

1. ``npm audit``                                  (needs the npm registry)
2. ``npm audit --json | depquiet --stdin``        (offline)
3. ``depquiet explain GHSA-9wv6-86v2-598j``       (offline)

The only change is cosmetic: the three status emoji are drawn as plain
symbols, since the renderer may have no emoji font.

Requires: npm, ffmpeg, Python Playwright with Chromium.
Run:  python -I docs/demo/make_demo.py
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
FIXTURE = ROOT / "benchmarks" / "fixtures" / "real-npm-express"
ADVISORY = "GHSA-9wv6-86v2-598j"  # path-to-regexp, reached through express

COLS, ROWS = 100, 26
PROMPT = '<span class="p">~/app</span> <span class="d">$</span> '

# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


def _tty(cmd: str, cwd: Path) -> str:
    """Run ``cmd`` under a pseudo-terminal so tools emit their colors."""
    r = subprocess.run(
        ["script", "-qc", cmd, "/dev/null"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        env={
            **os.environ,
            "TERM": "xterm-256color",
            "COLUMNS": str(COLS),
            "PYTHONPATH": str(ROOT / "src"),
            "NO_COLOR": "",
            "FORCE_COLOR": "1",
        },
    )
    return r.stdout.replace("\r", "")


def capture(work: Path) -> dict[str, str]:
    shutil.copytree(FIXTURE / "project", work, dirs_exist_ok=True)
    audit = FIXTURE / "audit.json"
    py = sys.executable
    out = {
        "npm": _tty("npm audit --color=always", work),
        "depquiet": _tty(f"{py} -m depquiet --offline --stdin < {audit}", work),
    }
    scan = subprocess.run(
        [py, "-m", "depquiet", "--offline", "--stdin", "--json"],
        stdin=audit.open(),
        capture_output=True,
        text=True,
        cwd=work,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    ).stdout
    (work / "scan.json").write_text(scan)
    out["explain"] = _tty(f"{py} -m depquiet explain {ADVISORY} --from-json scan.json", work)
    return out


# ---------------------------------------------------------------------------
# ANSI -> HTML
# ---------------------------------------------------------------------------

_SGR = re.compile(r"\x1b\[([0-9;]*)m")
_COLORS = {
    "31": "r",
    "91": "r",
    "33": "y",
    "93": "y",
    "32": "g",
    "92": "g",
    "36": "c",
    "96": "c",
    "35": "m",
    "95": "m",
}
_EMOJI = {"✅": '<b class="g">✔</b>', "⚠️": '<b class="y">▲</b>', "🔴": '<b class="r">●</b>'}


def ansi_to_html(line: str) -> str:
    out: list[str] = []
    classes: set[str] = set()
    color = ""
    pos = 0
    for m in _SGR.finditer(line + "\x1b[0m"):
        text = line[pos : m.start()] if m.start() <= len(line) else line[pos:]
        if text:
            esc = html.escape(text)
            for k, v in _EMOJI.items():
                esc = esc.replace(k, v)
            cls = " ".join(sorted(classes | ({color} if color else set())))
            out.append(f'<span class="{cls}">{esc}</span>' if cls else esc)
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                classes.clear()
                color = ""
            elif code == "1":
                classes.add("bold")
            elif code == "2":
                classes.add("dim")
            elif code == "22":
                classes -= {"bold", "dim"}
            elif code == "39":
                color = ""
            elif code in _COLORS:
                color = _COLORS[code]
        pos = m.end()
    return "".join(out)


_OTHER_CSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-ln-z]")  # cursor moves, erase (not SGR "m")
_SPINNER = re.compile(r"[\u2800-\u28ff]")  # npm's braille progress spinner


def lines_of(text: str) -> list[str]:
    text = _SPINNER.sub("", _OTHER_CSI.sub("", text))
    lines = [ansi_to_html(x) for x in text.split("\n")]
    while lines and not _SGR.sub("", lines[0]).strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


# ---------------------------------------------------------------------------
# Storyboard
# ---------------------------------------------------------------------------


@dataclass
class Frame:
    lines: list[str]
    caption: str
    ms: int


class Screen:
    def __init__(self) -> None:
        self.buf: list[str] = []
        self.frames: list[Frame] = []
        self.caption = ""

    def show(self, ms: int, cursor: bool = False) -> None:
        view = self.buf[-ROWS:]
        if cursor and view:
            view = [*view[:-1], view[-1] + '<span class="cur">█</span>']
        self.frames.append(Frame(list(view), self.caption, ms))

    def type(self, cmd: str) -> None:
        self.buf.append(PROMPT)
        self.show(500, cursor=True)
        for i in range(1, len(cmd) + 1):
            self.buf[-1] = PROMPT + html.escape(cmd[:i])
            self.show(45 if cmd[i - 1] != " " else 70, cursor=True)
        self.show(350, cursor=True)

    def print(self, lines: list[str], per_frame: int, ms: int) -> None:
        for i in range(0, len(lines), per_frame):
            self.buf.extend(lines[i : i + per_frame])
            self.show(ms)

    def clear(self) -> None:
        self.buf = []


def storyboard(cap: dict[str, str]) -> list[Frame]:
    npm, dq, ex = lines_of(cap["npm"]), lines_of(cap["depquiet"]), lines_of(cap["explain"])
    s = Screen()

    s.caption = "npm audit on a real Express app"
    s.type("npm audit")
    s.print(npm, per_frame=6, ms=60)
    s.caption = "Which of these actually matter?"
    s.show(2600)

    # Second pause: the screen ends right after the first path-to-regexp entry.
    plain = [re.sub(r"<[^>]+>", "", x) for x in dq]
    ptr_end = next(i for i, x in enumerate(plain) if "path-to-regexp" in x) + 4

    s.clear()
    s.caption = "depquiet triages the same audit"
    s.buf.append("")
    s.type("npm audit --json | depquiet --stdin --offline")
    s.print(dq[: ROWS - 3], per_frame=2, ms=70)
    s.caption = "Filtered: dev tooling, or declared but never imported"
    s.show(3200)
    s.print(dq[ROWS - 3 : ptr_end], per_frame=2, ms=90)
    s.caption = "Kept: body-parser and path-to-regexp, reached through express"
    s.show(3400)
    s.print(dq[ptr_end:], per_frame=3, ms=70)
    s.caption = "Every alert says how it reaches your code"
    s.show(2400)

    s.clear()
    s.caption = "Ask why"
    s.buf.append("")
    s.type("npm audit --json | depquiet --stdin --offline --json > scan.json")
    s.type(f"depquiet explain {ADVISORY} --from-json scan.json")
    s.print(ex, per_frame=1, ms=90)
    s.caption = "pip install depquiet"
    s.show(4200)
    return s.frames


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

CSS = """
:root { --bg:#0d1117; --fg:#c9d1d9; }
* { box-sizing:border-box; margin:0; }
body { background:#010409; padding:24px; font-family:'DejaVu Sans Mono',monospace; }
#win { width:%(w)dpx; background:var(--bg); border-radius:10px; overflow:hidden;
       box-shadow:0 0 0 1px #30363d; }
#bar { height:30px; background:#161b22; display:flex; align-items:center; padding:0 12px; gap:7px; }
#bar i { width:12px; height:12px; border-radius:50%%; display:block; }
#term { padding:14px 16px; height:%(h)dpx; color:var(--fg); font-size:15px; line-height:21px;
        white-space:pre; overflow:hidden; }
#cap { height:44px; background:#161b22; color:#f0f6fc; font:600 17px system-ui,sans-serif;
       display:flex; align-items:center; justify-content:center; letter-spacing:.2px; }
.r{color:#ff7b72} .y{color:#e3b341} .g{color:#3fb950} .c{color:#79c0ff} .m{color:#d2a8ff}
.bold{font-weight:bold} .dim{opacity:.6} b{font-weight:normal}
.p{color:#79c0ff} .d{color:#8b949e} .cur{color:#c9d1d9}
"""


def render(frames: list[Frame], workdir: Path) -> None:
    from playwright.sync_api import sync_playwright

    width = COLS * 9 + 32
    height = ROWS * 21 + 28
    page_html = (
        f"<html><head><style>{CSS % {'w': width, 'h': height}}</style></head><body>"
        '<div id="win"><div id="bar"><i style="background:#ff5f56"></i>'
        '<i style="background:#ffbd2e"></i><i style="background:#27c93f"></i></div>'
        '<div id="term"></div><div id="cap"></div></div></body></html>'
    )
    shots = workdir / "frames"
    shots.mkdir()
    concat = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(
            viewport={"width": width + 48, "height": height + 150}, device_scale_factor=2
        )
        page.set_content(page_html)
        win = page.locator("#win")
        for i, f in enumerate(frames):
            page.evaluate(
                "([l, c]) => { document.getElementById('term').innerHTML = l.join('\\n');"
                " document.getElementById('cap').textContent = c; }",
                [f.lines, f.caption],
            )
            path = shots / f"{i:04d}.png"
            win.screenshot(path=str(path))
            concat += [f"file '{path}'", f"duration {f.ms / 1000:.3f}"]
        browser.close()
    concat.append(f"file '{shots / f'{len(frames) - 1:04d}.png'}'")
    (workdir / "frames.txt").write_text("\n".join(concat) + "\n")

    ff = [
        "ffmpeg",
        "-y",
        "-loglevel",
        "error",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(workdir / "frames.txt"),
    ]
    subprocess.run(
        [
            *ff,
            "-vf",
            "fps=30,format=yuv420p,scale=trunc(iw/2)*2:trunc(ih/2)*2",
            "-c:v",
            "libx264",
            "-crf",
            "20",
            "-movflags",
            "+faststart",
            str(OUT / "demo.mp4"),
        ],
        check=True,
    )
    subprocess.run(
        [
            *ff,
            "-vf",
            "fps=12,scale=960:-1:flags=lanczos,split[a][b];"
            "[a]palettegen=max_colors=64:stats_mode=diff[p];"
            "[b][p]paletteuse=dither=none:diff_mode=rectangle",
            str(OUT / "demo.gif"),
        ],
        check=True,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        cap = capture(work / "app")
        (OUT / "captured.json").write_text(json.dumps(cap, indent=2) + "\n")
        frames = storyboard(cap)
        render(frames, work)
    total = sum(f.ms for f in frames) / 1000
    print(f"{len(frames)} frames, {total:.1f}s -> {OUT / 'demo.gif'}, {OUT / 'demo.mp4'}")


if __name__ == "__main__":
    main()
