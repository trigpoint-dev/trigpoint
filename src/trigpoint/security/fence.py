"""Untrusted-content fencing and prompt-injection heuristics.

Repo text ends up inside LLM prompts, so it is an indirect prompt-injection channel.
Fencing does not make injection impossible; it makes provenance explicit, strips invisible
characters used to smuggle instructions, and surfaces suspicious phrases as warnings.
Integrators must still never grant write-capable tools on the strength of grounded text.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from html import escape

TAG = "untrusted_content"

# Invisible / direction-altering code points: zero-width, bidi controls ("Trojan Source"),
# BOM, soft hyphen, and the Unicode tag block used for "ASCII smuggling".
_HIDDEN_RANGES = (
    (0x200B, 0x200F),  # zero-width characters and LRM/RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x2064),  # word joiner and invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
    (0x00AD, 0x00AD),  # soft hyphen
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0xE0000, 0xE007F),  # tag block ("ASCII smuggling")
)
_HIDDEN = re.compile(
    "[" + "".join(f"{re.escape(chr(a))}-{re.escape(chr(b))}" for a, b in _HIDDEN_RANGES) + "]"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in (
        (
            "ignore_instructions",
            r"\b(?:ignore|disregard|forget|override)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|any)\b"
            r"[^\n]{0,30}\b(?:instructions?|prompts?|rules?|context)\b",
        ),
        ("role_reassignment", r"\byou are now\b|\bnew (?:system )?instructions?\s*:"),
        ("system_prompt_reference", r"\b(?:system prompt|developer message)\b"),
        ("chat_template_token", r"<\|(?:im_start|im_end|system|assistant|user)\|>|\[/?INST\]"),
        ("role_header", r"^\s*(?:#+\s*)?(?:system|assistant)\s*:\s*\S"),
        (
            "exfiltration",
            r"\b(?:send|post|upload|exfiltrate|leak)\b[^\n]{0,60}\b(?:to|at)\b[^\n]{0,20}https?://",
        ),
        ("conceal_from_user", r"\bdo not (?:tell|inform|mention|reveal)\b[^\n]{0,30}\buser\b"),
    )
)


@dataclass(frozen=True, slots=True)
class InjectionFlag:
    rule: str
    line: int
    excerpt: str


@dataclass(frozen=True, slots=True)
class FencedContent:
    text: str
    flags: list[InjectionFlag] = field(default_factory=list)
    stripped_chars: int = 0


def sanitize_text(text: str) -> tuple[str, int]:
    """Remove hidden and control characters. Returns (clean_text, removed_count)."""
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    cleaned, n_hidden = _HIDDEN.subn("", text)
    cleaned, n_control = _CONTROL.subn("", cleaned)
    return cleaned, n_hidden + n_control


def detect_injection(text: str, *, max_flags: int = 20) -> list[InjectionFlag]:
    flags: list[InjectionFlag] = []
    for lineno, line in enumerate(text.split("\n"), start=1):
        for rule, pattern in _INJECTION_PATTERNS:
            if pattern.search(line):
                flags.append(InjectionFlag(rule, lineno, line.strip()[:80]))
                if len(flags) >= max_flags:
                    return flags
    return flags


def fence_untrusted(text: str, *, source: str, sha: str | None = None) -> FencedContent:
    """Wrap repo-derived text in an explicit untrusted-content fence.

    Hidden characters are stripped (and counted), the closing tag cannot be forged from
    inside, and heuristic injection flags are returned for the caller to surface.
    """
    cleaned, stripped = sanitize_text(text)
    flags = detect_injection(cleaned)
    body = re.sub(rf"<(/?){TAG}", r"<\\\1" + TAG, cleaned, flags=re.IGNORECASE)
    attrs = f'source="{escape(source, quote=True)}"'
    if sha:
        attrs += f' sha="{escape(sha, quote=True)}"'
    attrs = attrs.replace("\n", " ")
    return FencedContent(f"<{TAG} {attrs}>\n{body}\n</{TAG}>", flags, stripped)
