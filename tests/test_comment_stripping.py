"""Comment markers inside strings must not hide imports.

Before this, ``"assets/*"`` in a Rust function opened a block comment that
swallowed every later ``use`` up to the next ``*/``, and ``"issue #42"`` in
Ruby cut the rest of the line, ``require`` included. A missed import makes a
used package look unreachable, and its alerts would be filtered.
"""

from __future__ import annotations

import pytest

import depquiet.filters.reachability as R

CASES = [
    (
        R._rs_extract_imports,
        'fn a() { let p = "src/*"; }\nuse serde::Deserialize;\n/* x */\n',
        "serde",
    ),
    (R._rs_extract_imports, 'const U: &str = "https://x"; use reqwest::Client;\n', "reqwest"),
    (R._rs_extract_imports, "fn f<'a>(x: &'a str) {}\n/* c */ use tokio::fs;\n", "tokio"),
    (R._rs_extract_imports, 'let s = r#"a /* b"#;\nuse serde_json::Value;\n', "serde_json"),
    (
        R._go_extract_imports,
        'package main\nvar g = "a/*"\nimport "github.com/gin-gonic/gin"\n',
        "gin",
    ),
    (R._php_extract_uses, '<?php\n$g = "a/*";\nuse Monolog\\Logger;\n/* x */\n', "monolog"),
    (R._php_extract_uses, '<?php $c = "#fff"; use Monolog\\Logger;\n', "monolog"),
    (
        R._java_extract_imports,
        'class A { String g = "a/*"; }\nimport com.google.gson.Gson;\n',
        "gson",
    ),
    (
        R._dart_extract_imports,
        "var g = 'a/*';\nimport 'package:http/http.dart';\n/* x */\n",
        "http",
    ),
    (R._swift_extract_imports, 'let g = "a/*"\nimport Alamofire\n/* x */\n', "Alamofire"),
    (R._rb_extract_requires, 'puts "issue #42"; require "nokogiri"\n', "nokogiri"),
    (R._rb_extract_requires, 'log "user #{id}"\nrequire "json" # note\n', "json"),
]


@pytest.mark.parametrize(("extract", "source", "wanted"), CASES)
def test_marker_inside_a_string_does_not_hide_the_import(extract, source, wanted) -> None:
    assert any(wanted in name for name in extract(source))


@pytest.mark.parametrize(
    ("extract", "source"),
    [
        (R._rs_extract_imports, "// use fake::x;\n/* use fake::y; */\nuse a::b;\n"),
        (R._rb_extract_requires, '# require "fake"\n=begin\nrequire "fake"\n=end\nrequire "a"\n'),
        (R._php_extract_uses, "<?php\n// use Fake\\X;\n# use Fake\\Y;\nuse A\\B;\n"),
    ],
)
def test_real_comments_are_still_ignored(extract, source) -> None:
    assert not any("fake" in name.lower() for name in extract(source))


def test_unterminated_string_hides_at_most_its_own_line() -> None:
    assert "serde" in R._rs_extract_imports('let s = "oops /*\nuse serde::de;\n')


def test_always_flag_matches_package_names_like_package_managers() -> None:
    from depquiet.engine import _flag_key

    assert _flag_key("PyYAML") == _flag_key("pyyaml")
    assert _flag_key("Django") == _flag_key("django")
    assert _flag_key("ruamel.yaml") == _flag_key("ruamel-yaml")
