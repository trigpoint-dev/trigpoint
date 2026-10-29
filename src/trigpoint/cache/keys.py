"""Repository identity and cache-key rules.

Keys end up as file names on shared storage (EFS, Amazon S3 Files), so they are validated,
length-bounded (<= 255 bytes per path component, well under the 1024-byte S3 key limit),
and never contain separators or traversal sequences.
"""

from __future__ import annotations

import hashlib
import re

from trigpoint.domain import SCHEMA_VERSION
from trigpoint.errors import InvalidKeyError
from trigpoint.extract.base import EXTRACTOR_VERSION

_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_HOST = re.compile(r"^[A-Za-z0-9.-]{1,100}$")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SLUG_STRIP = re.compile(r"[^A-Za-z0-9._-]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _check_name(kind: str, value: str) -> str:
    if (
        not _NAME.match(value)
        or value in (".", "..")
        or value.startswith("-")
        or value.endswith(".lock")
    ):
        raise InvalidKeyError(f"invalid {kind}: {value!r}")
    return value


def _check_branch(branch: str) -> str:
    if (
        not branch
        or len(branch.encode("utf-8")) > 255
        or _CONTROL.search(branch)
        or branch.startswith(("-", "/"))
        or branch.endswith(("/", ".lock"))
        or ".." in branch
        or "//" in branch
    ):
        raise InvalidKeyError(f"invalid branch: {branch!r}")
    return branch


def repo_key(owner: str, repo: str, branch: str, *, host: str = "github.com") -> str:
    """Stable, readable, collision-free key for ``host/owner/repo@branch``.

    Raw ``{owner}_{repo}_{branch}`` collides (``a_b/c`` vs ``a/b_c``) and branch names
    contain ``/``, so the readable prefix is paired with a hash of the exact tuple.
    GitHub owner and repo names are case-insensitive; branches are not.
    """
    if not _HOST.match(host):
        raise InvalidKeyError(f"invalid host: {host!r}")
    owner = _check_name("owner", owner).lower()
    repo = _check_name("repo", repo).lower()
    branch = _check_branch(branch)
    digest = hashlib.sha256(
        "\x00".join((host.lower(), owner, repo, branch)).encode("utf-8")
    ).hexdigest()[:12]
    readable = _SLUG_STRIP.sub("-", f"{owner}_{repo}_{branch}").strip("-.")[:80] or "repo"
    return f"{readable}-{digest}"


def check_commit_sha(sha: str) -> str:
    if not _SHA.match(sha):
        raise InvalidKeyError(f"not a full commit SHA: {sha!r}")
    return sha


def check_key(key: str) -> str:
    if not _SAFE_KEY.match(key) or key in (".", "..") or ".." in key:
        raise InvalidKeyError(f"invalid cache key: {key!r}")
    return key


def repo_map_key(repo_key_: str, commit_sha: str) -> str:
    """(repo_key, git SHA, extractor version) -- plus schema version, which shapes the JSON."""
    check_key(repo_key_)
    return f"{repo_key_}.{check_commit_sha(commit_sha)}.e{EXTRACTOR_VERSION}-s{SCHEMA_VERSION}.json"


def describe_key(repo_key_: str, rendered_section: str) -> str:
    """(repo_key, sha256(rendered section)): shared across projects, repeat LLM calls are free."""
    check_key(repo_key_)
    digest = hashlib.sha256(rendered_section.encode("utf-8")).hexdigest()
    return f"{repo_key_}.{digest}.json"


def connection_key(project_id: str) -> str:
    return f"{check_key(project_id)}.md"
