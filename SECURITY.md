# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in depquiet, please report it responsibly.

**Do NOT open a public issue.**

Instead, email **sarojas123@icloud.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a detailed response within 5 business days.

## Security Design Principles

depquiet is designed with security in mind:

- **No code execution**: depquiet never runs code from scanned projects. It only reads source files as text.
- **No network except EPSS**: the only outbound network call is to the public FIRST.org EPSS API (`api.first.org`). Use `--offline` to disable it entirely.
- **No secrets needed**: depquiet requires no API keys, tokens, or credentials for basic operation.
- **Conservative filtering**: depquiet never dismisses a vulnerability it isn't confident about. False negatives are treated as bugs.
- **Template safety**: community templates are declarative YAML — they cannot execute code or access the filesystem.

## Scope

depquiet's threat model covers:

- **Malicious templates**: templates loaded from untrusted sources could attempt to suppress real vulnerabilities. depquiet validates template structure and applies them narrowly (exact CVE + package match only).
- **Audit JSON injection**: piped audit JSON from untrusted sources is parsed with the standard library JSON parser. No `eval` or dynamic execution.
- **Path traversal**: project paths are resolved and validated before file operations.

## Dependencies

depquiet has **zero runtime dependencies** beyond the Python standard library. This is intentional — fewer dependencies means a smaller attack surface.
