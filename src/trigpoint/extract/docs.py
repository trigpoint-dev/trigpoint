"""README / prose extraction: a title and the first useful paragraph."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from trigpoint.domain import DocInfo, FileRecord
from trigpoint.extract.base import clip

MAX_SUMMARY_CHARS = 300
MIN_USEFUL_CHARS = 20

_BADGE = re.compile(r"!\[[^\]]*\]\([^)]*\)|\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML = re.compile(r"<[^>]+>")
_EMPHASIS = re.compile(r"(\*\*|__|\*|`)")
_HEADING = re.compile(r"^#{1,6}\s+(.*)$")
_SETEXT = re.compile(r"^(=+|-+)\s*$")


def is_readme(path: str) -> bool:
    return PurePosixPath(path).name.lower().split(".")[0] == "readme"


def summarize_markdown(text: str) -> DocInfo:
    """Return the first H1 and the first prose paragraph; empty fields if nothing usable."""
    title = ""
    lines = text.replace("\r\n", "\n").split("\n")
    in_fence = False
    para: list[str] = []
    prev = ""
    for raw in lines:
        line = raw.strip()
        if line.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _HEADING.match(line)
        if m:
            if not title and line.startswith("# "):
                title = clip(_EMPHASIS.sub("", _LINK.sub(r"\1", m.group(1))), 120)
            if para:
                break
            prev = ""
            continue
        if _SETEXT.match(line) and prev and not title and line.startswith("="):
            title = clip(prev, 120)
            prev = ""
            continue
        cleaned = _HTML.sub("", _BADGE.sub("", line)).strip()
        if not cleaned:
            if para:
                break
            prev = ""
            continue
        if cleaned.startswith(("|", ">", "- ", "* ", "+ ", "---", "[!")) or re.match(
            r"^\d+\.\s", cleaned
        ):
            if para:
                break
            prev = cleaned
            continue
        prev = cleaned
        para.append(_EMPHASIS.sub("", _LINK.sub(r"\1", cleaned)))
    summary = clip(" ".join(para), MAX_SUMMARY_CHARS)
    if len(summary) < MIN_USEFUL_CHARS:
        summary = ""
    return DocInfo(title=title, summary=summary)


def find_root_readme(files: tuple[FileRecord, ...]) -> str | None:
    candidates = sorted(f.path for f in files if "/" not in f.path and is_readme(f.path))
    return candidates[0] if candidates else None
