"""Build the file inventory: path, language, size, LOC, blob SHA and the three flags.

Inside a git work tree the file list comes from git (tracked + untracked-not-ignored), so
.gitignore is honoured and tracked blob SHAs come for free. Elsewhere we fall back to a
filesystem walk with default ignores. Symlinks are never followed or listed, and
secret-adjacent paths never even have their bytes opened.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from trigpoint.domain import FileRecord
from trigpoint.languages import (
    detect_language,
    is_generated_path,
    is_generated_text,
    is_test_path,
)
from trigpoint.security import Limits, PathPolicy

_DEFAULT_IGNORE_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        "dist",
        "build",
    }
)
_HEAD_BYTES = 8000


@dataclass(frozen=True, slots=True)
class WalkResult:
    files: tuple[FileRecord, ...]
    protected_skipped: int  # secret-adjacent or gitignored paths whose bytes were never read
    oversize: int  # files too large to read; listed with loc=0


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(  # noqa: S324 - git object id, not a security hash
        b"blob %d\x00" % len(data) + data
    ).hexdigest()


def _git(root: Path, args: list[str], timeout: float) -> bytes | None:
    try:
        proc = subprocess.run(  # noqa: S603
            ["git", "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def _list_with_git(root: Path, limits: Limits) -> dict[str, str] | None:
    """Return {relative_path: blob_sha or ''} or None if ``root`` is not a git work tree."""
    tracked = _git(root, ["ls-files", "-z", "-s", "--"], limits.git_timeout_s)
    if tracked is None:
        return None
    entries: dict[str, str] = {}
    for rec in tracked.split(b"\x00"):
        if not rec:
            continue
        meta, _, raw_path = rec.partition(b"\t")
        mode, sha, stage = meta.decode("ascii", "replace").split()[:3]
        if mode in ("120000", "160000") or stage != "0":  # symlink, submodule, conflict
            continue
        entries[raw_path.decode("utf-8", "surrogateescape")] = sha
    others = _git(root, ["ls-files", "-z", "-o", "--exclude-standard", "--"], limits.git_timeout_s)
    for raw_path in (others or b"").split(b"\x00"):
        if raw_path:
            entries.setdefault(raw_path.decode("utf-8", "surrogateescape"), "")
    return entries


def _list_with_fs(root: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _DEFAULT_IGNORE_DIRS)
        base = Path(dirpath)
        for fn in filenames:
            rel = (base / fn).relative_to(root).as_posix()
            entries[rel] = ""
    return entries


def _count_loc(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def _looks_minified(text: str, size: int) -> bool:
    lines = text.count("\n") + 1
    return size > 2000 and size / lines > 300


def walk(
    root: Path,
    *,
    policy: PathPolicy | None = None,
    limits: Limits | None = None,
) -> WalkResult:
    limits = limits or Limits()
    root = root.resolve(strict=True)
    policy = policy or PathPolicy.from_repo(root)
    listed = _list_with_git(root, limits)
    use_git = listed is not None
    if listed is None:
        listed = _list_with_fs(root)

    records: list[FileRecord] = []
    protected = oversize = 0
    total = 0
    for rel in sorted(listed):
        # Under git the file list already honours .gitignore; the policy still denies secrets.
        denied = policy.is_secret_path(rel) or (not use_git and policy.is_gitignored(rel))
        if denied:
            protected += 1
            continue
        path = root / rel
        try:
            st = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        limits.check_file_count(len(records) + 1)
        total += st.st_size
        limits.check_total_bytes(total)

        small = st.st_size <= limits.max_file_bytes
        try:
            with path.open("rb") as fh:
                data = fh.read(limits.max_file_bytes if small else _HEAD_BYTES)
        except OSError:
            continue
        head = data[:_HEAD_BYTES]
        is_binary = b"\x00" in head
        text = "" if is_binary else data.decode("utf-8", errors="replace")
        first_line = text.split("\n", 1)[0] if text else ""
        language = "binary" if is_binary else detect_language(rel, first_line)

        loc = 0
        if small and not is_binary:
            loc = _count_loc(text)
        elif not small:
            oversize += 1
        blob = listed[rel] or (git_blob_sha(data) if small else "")
        generated = (
            is_generated_path(rel)
            or is_generated_text(text[:1024])
            or (language in ("javascript", "css") and _looks_minified(text, st.st_size))
        )
        records.append(
            FileRecord(
                path=rel,
                language=language,
                size=st.st_size,
                loc=loc,
                blob_sha=blob,
                is_binary=is_binary,
                is_generated=generated,
                is_test=is_test_path(rel),
            )
        )
    return WalkResult(tuple(records), protected, oversize)
