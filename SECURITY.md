# Security policy

trigpoint handles GitHub credentials and untrusted repository content, so security
reports are taken seriously.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting on
`trigpoint-dev/trigpoint` (Security tab -> Report a vulnerability).

Useful details: affected version, a minimal reproduction, and the impact you expect
(token exposure, path escape, secret leakage, prompt injection, denial of service).

## Scope

In scope: token leakage (argv, URLs, `.git/config`, logs, exceptions), git argument or
ref injection, path traversal or symlink escape, secrets surviving redaction, parser
denial of service, cross-tenant cache leakage.

Out of scope: vulnerabilities in git, GitHub, or your own deployment configuration.

The threat model lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#11-security-model-threats-specific-to-llm--github--agents).
