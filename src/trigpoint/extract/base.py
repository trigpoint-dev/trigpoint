"""Shared extractor plumbing."""

from __future__ import annotations

import re

# Bump when any extractor's output changes; it is part of every cache key.
EXTRACTOR_VERSION = "1"

MAX_SYMBOLS_PER_FILE = 200
MAX_SIGNATURE_CHARS = 200
MAX_DOC_CHARS = 120

_WS = re.compile(r"\s+")


def clip(text: str, limit: int) -> str:
    """Collapse whitespace and cut to ``limit`` characters (ASCII ellipsis)."""
    text = _WS.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def first_line(doc: str | None, limit: int = MAX_DOC_CHARS) -> str:
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        if line.strip():
            return clip(line, limit)
    return ""
