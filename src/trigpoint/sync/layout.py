"""On-disk layout and per-project links.

    shared_root/{repo_key}/clone      one shallow clone per (repo, branch), shared by projects
    shared_root/{repo_key}/lock       persistent advisory lock file
    clone_root/{project_id}/{repo}    symlink (junction on Windows) -> the shared clone

Projects on the same repo share one clone; each gets its own stable path to it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from trigpoint.cache.keys import _check_name, check_key


@dataclass(frozen=True, slots=True)
class RepoPaths:
    repo_dir: Path

    @property
    def clone(self) -> Path:
        return self.repo_dir / "clone"

    @property
    def lock(self) -> Path:
        return self.repo_dir / "lock"


def repo_paths(shared_root: Path, repo_key: str) -> RepoPaths:
    return RepoPaths(shared_root / check_key(repo_key))


def project_link_path(clone_root: Path, project_id: str, repo_name: str) -> Path:
    return clone_root / check_key(project_id) / _check_name("repo", repo_name)


def _same_target(link: Path, target: Path) -> bool:
    try:
        return link.resolve(strict=True) == target.resolve(strict=True)
    except OSError:
        return False


def _remove_link(link: Path) -> None:
    try:
        link.unlink()
    except (PermissionError, IsADirectoryError, OSError):
        with contextlib.suppress(OSError):
            link.rmdir()  # Windows junctions


def link_project(link: Path, target: Path) -> Path:
    """Create or repair ``link`` -> ``target`` (idempotent)."""
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(link):
        if _same_target(link, target):
            return link
        if not link.is_symlink() and link.is_dir() and not _is_junction(link):
            raise FileExistsError(f"{link} exists and is a real directory, not a link")
        _remove_link(link)
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            raise
        # Symlinks need a privilege on Windows; a directory junction does not.
        subprocess.run(  # noqa: S603
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],  # noqa: S607
            check=True,
            capture_output=True,
        )
    return link


def _is_junction(path: Path) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None:
        return bool(is_junction(path))
    try:  # Python < 3.12
        return bool(path.is_dir() and os.path.realpath(path) != os.path.abspath(path))
    except OSError:
        return False


def remove_tree(path: Path) -> None:
    """Delete a directory tree, including read-only files (git object files are read-only,
    which makes a plain ``shutil.rmtree`` fail on Windows). Raises OSError if it cannot."""

    def make_writable_and_retry(func: Callable[[str], object], p: str, _exc: object) -> None:
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable_and_retry)
    else:
        shutil.rmtree(path, onerror=make_writable_and_retry)
