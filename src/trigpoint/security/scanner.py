"""Secret scanner: finds credential-shaped spans in text.

Layered on purpose: precise provider patterns first (low false positives), then
generic assignment detection, then a conservative entropy fallback. Pure hex strings are
never flagged by entropy because git SHAs and checksums are everywhere in repos.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    rule: str
    start: int
    end: int


def shannon_entropy(value: str) -> float:
    """Bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


_PLACEHOLDER_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "secret",
        "changeme",
        "change_me",
        "example",
        "placeholder",
        "dummy",
        "sample",
        "redacted",
        "none",
        "null",
        "todo",
        "undefined",
    }
)
_PLACEHOLDER_PREFIX = re.compile(r"^(?:your[_\-.]|my[_\-.]|<|\$|\{|%|\[)", re.IGNORECASE)
_PLACEHOLDER_FILL = re.compile(r"^(?:x+|\*+|\.+|-+|_+|0+)$", re.IGNORECASE)


def is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered in _PLACEHOLDER_WORDS
        or bool(_PLACEHOLDER_PREFIX.match(lowered))
        or bool(_PLACEHOLDER_FILL.match(lowered))
        or "${" in lowered
        or "{{" in lowered
    )


Validator = Callable[["re.Match[str]"], bool]


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    group: str | int = 0
    validator: Validator | None = None


def _not_placeholder(group: str) -> Validator:
    return lambda m: not is_placeholder(m.group(group))


def _assignment_ok(m: re.Match[str]) -> bool:
    value = m.group("secret")
    if is_placeholder(value) or any(c in value for c in "()[]{}$<>"):
        return False
    # An unquoted bare identifier (`token = some_function`) is code, not a secret.
    return not (not m.group("quote") and re.fullmatch(r"[A-Za-z_][A-Za-z_.]*", value))


_KEYWORDS = (
    r"secret|password|passwd|pwd|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credentials?"
)

_RULES: tuple[_Rule, ...] = (
    _Rule(
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----"
            r"[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    # A BEGIN header with no END (truncated file): redact the header and what follows.
    _Rule(
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----(?:(?!-----END )[\s\S]){0,4096}"
        ),
    ),
    _Rule(
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    ),
    _Rule("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    _Rule("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    _Rule("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    _Rule("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    _Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _Rule("llm_api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}\b")),
    _Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ),
    _Rule(
        "bearer_token",
        re.compile(r"\bbearer\s+(?P<secret>[A-Za-z0-9._~+/\-]{20,}=*)", re.IGNORECASE),
        group="secret",
        validator=_not_placeholder("secret"),
    ),
    _Rule(
        "connection_string",
        re.compile(
            r"\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@'\"<>]+:(?P<secret>[^\s@/'\"<>]+)@",
            re.IGNORECASE,
        ),
        group="secret",
        validator=_not_placeholder("secret"),
    ),
    _Rule(
        "secret_assignment",
        re.compile(
            # Anchored to the start of a token: without the lookbehind the lazy prefix is
            # retried from every offset inside a long run, which is quadratic.
            rf"(?<![A-Za-z0-9_.\-])(?P<key>[A-Za-z0-9_.\-]*?(?:{_KEYWORDS})(?![A-Za-z])[A-Za-z0-9_.\-]*)"
            r"['\"]?\s*[:=]\s*(?P<quote>['\"]?)(?P<secret>[^\s'\",;#`]{8,})(?P=quote)",
            re.IGNORECASE,
        ),
        group="secret",
        validator=_assignment_ok,
    ),
)

# `=` is only allowed as trailing base64 padding, so `key=value` does not start at the key.
_ENTROPY_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9+_=\-])[A-Za-z0-9+_\-]{24,128}={0,2}(?![A-Za-z0-9+_=\-])"
)
_HEX_ONLY = re.compile(r"^[0-9a-fA-F\-]+$")  # also UUIDs
_LOWER_SNAKE = re.compile(r"^[a-z0-9_\-]+$")
_DIGEST_IN_TOKEN = re.compile(r"^(?:sha(?:1|224|256|384|512)|md5)-", re.IGNORECASE)
_DIGEST_BEFORE_TOKEN = re.compile(r"(?:sha(?:1|224|256|384|512)|md5|h1)[-:]$", re.IGNORECASE)
ENTROPY_THRESHOLD = 3.9


def _entropy_findings(text: str) -> list[Finding]:
    found: list[Finding] = []
    for m in _ENTROPY_CANDIDATE.finditer(text):
        token = m.group(0)
        if _HEX_ONLY.match(token):
            continue
        if not (any(c.isdigit() for c in token) and any(c.isalpha() for c in token)):
            continue
        if _DIGEST_IN_TOKEN.match(token) or _DIGEST_BEFORE_TOKEN.search(
            text[max(0, m.start() - 8) : m.start()]
        ):
            continue
        entropy = shannon_entropy(token)
        if entropy < ENTROPY_THRESHOLD:
            continue
        # Lowercase snake/kebab identifiers carry digits too; demand more entropy for them.
        if _LOWER_SNAKE.match(token) and entropy < ENTROPY_THRESHOLD + 0.4:
            continue
        found.append(Finding("high_entropy", m.start(), m.end()))
    return found


def _merge(findings: list[Finding]) -> list[Finding]:
    merged: list[Finding] = []
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if merged and f.start < merged[-1].end:
            last = merged[-1]
            # Keep the most specific rule name when a generic entropy hit overlaps one.
            rule = f.rule if last.rule == "high_entropy" else last.rule
            merged[-1] = Finding(rule, last.start, max(last.end, f.end))
        else:
            merged.append(f)
    return merged


def scan(text: str, *, entropy: bool = True) -> list[Finding]:
    """Return non-overlapping findings, ordered by position."""
    findings: list[Finding] = []
    for rule in _RULES:
        for m in rule.pattern.finditer(text):
            if rule.validator is not None and not rule.validator(m):
                continue
            start, end = m.span(rule.group)
            if end > start:
                findings.append(Finding(rule.name, start, end))
    if entropy:
        findings.extend(_entropy_findings(text))
    return _merge(findings)


def apply_redactions(text: str, findings: list[Finding]) -> str:
    """Replace each finding span with ``[REDACTED:<rule>]``. Findings must be non-overlapping."""
    out: list[str] = []
    cursor = 0
    for f in findings:
        out.append(text[cursor : f.start])
        out.append(f"[REDACTED:{f.rule}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)
