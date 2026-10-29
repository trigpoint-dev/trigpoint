"""Path policy: which files may be read, and containment of every read inside the repo root.

Layer (a) of secrets handling: secret-adjacent files are never read at all.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath

import pathspec

from trigpoint.errors import LimitExceededError, PathEscapeError, SecretPathError
from trigpoint.security.limits import Limits

# gitignore-style. Order matters: the trailing negations re-allow documentation templates.
SECRET_PATH_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "*.ovpn",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    ".htpasswd",
    ".vault-token",
    "*.tfstate",
    "*.tfstate.*",
    "*.tfvars",
    "kubeconfig",
    ".aws/",
    ".ssh/",
    ".kube/",
    ".gnupg/",
    "**/.docker/config.json",
    "credentials",
    "credentials.json",
    "credentials.y*ml",
    "credentials.csv",
    "secrets.json",
    "secrets.y*ml",
    "secrets.toml",
    "secrets.env",
    "secrets.ini",
    "secrets.txt",
    "service-account*.json",
    "*.secret",
    "*.secrets",
    # templates that document configuration without holding it
    "!.env.example",
    "!.env.sample",
    "!.env.template",
    "!.env.dist",
    "!*.env.example",
)

_MAX_GITIGNORE_BYTES = 256 * 1024
BOM = chr(0xFEFF)


def sparse_checkout_patterns(extra_secret_patterns: Iterable[str] = ()) -> list[str]:
    """Sparse-checkout (non-cone) patterns that include everything except secret paths.

    Used so secret-adjacent files are never *materialized* in a clone. That matters most on
    Amazon S3 Files, where anything written to the mount is exported to a versioned bucket
    and deleting it afterwards does not remove the history.
    """
    deny = [*(p for p in SECRET_PATH_PATTERNS if not p.startswith("!")), *extra_secret_patterns]
    allow = [p[1:] for p in SECRET_PATH_PATTERNS if p.startswith("!")]
    return ["/*", *(f"!{p}" for p in deny), *allow]


def _normalize(rel: str) -> str:
    rel = rel.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return rel


class PathPolicy:
    """Decides whether a repo-relative path may be read."""

    def __init__(
        self,
        *,
        extra_secret_patterns: Iterable[str] = (),
        gitignore: str | None = None,
    ) -> None:
        # Extra patterns go before the built-in negations so a caller cannot accidentally
        # be overridden by them, but built-in secret patterns still apply.
        patterns = (*SECRET_PATH_PATTERNS, *extra_secret_patterns)
        self._secret = pathspec.PathSpec.from_lines("gitignore", patterns)
        self._gitignore = (
            pathspec.PathSpec.from_lines("gitignore", gitignore.splitlines()) if gitignore else None
        )

    @classmethod
    def from_repo(cls, root: Path, *, extra_secret_patterns: Iterable[str] = ()) -> PathPolicy:
        """Build a policy that also honours the repo's root ``.gitignore``."""
        text: str | None = None
        path = root / ".gitignore"
        try:
            if (
                path.is_file()
                and not path.is_symlink()
                and path.stat().st_size <= _MAX_GITIGNORE_BYTES
            ):
                text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = None
        return cls(extra_secret_patterns=extra_secret_patterns, gitignore=text)

    def is_secret_path(self, rel: str) -> bool:
        return bool(self._secret.match_file(_normalize(rel)))

    def is_gitignored(self, rel: str) -> bool:
        return self._gitignore is not None and bool(self._gitignore.match_file(_normalize(rel)))

    def should_skip(self, rel: str) -> bool:
        return self.is_secret_path(rel) or self.is_gitignored(rel)


def resolve_within(root: Path, rel: str | os.PathLike[str]) -> Path:
    """Resolve ``rel`` under ``root``; refuse anything that lands outside it.

    Symlinks are resolved, so a link pointing out of the tree is rejected.
    """
    rel_s = os.fspath(rel)
    if "\x00" in rel_s:
        raise PathEscapeError("NUL byte in path")
    if (
        PurePosixPath(rel_s).is_absolute()
        or PureWindowsPath(rel_s).is_absolute()
        or PureWindowsPath(rel_s).drive
        or rel_s.startswith(("/", "\\"))
    ):
        raise PathEscapeError(f"absolute path not allowed: {rel_s!r}")
    root_resolved = root.resolve(strict=True)
    candidate = (root_resolved / rel_s).resolve(strict=False)
    if not candidate.is_relative_to(root_resolved):
        raise PathEscapeError(f"path escapes root: {rel_s!r}")
    return candidate


def read_text_safely(
    root: Path,
    rel: str,
    *,
    policy: PathPolicy | None = None,
    limits: Limits | None = None,
) -> str:
    """Read a repo file as text with every guard applied.

    Raises SecretPathError, PathEscapeError, LimitExceededError. Only regular files are
    read (a FIFO or device would block or misbehave). Note: containment is checked before
    open, which is sound because the clone is held under our lock and not attacker-writable
    during a parse.
    """
    limits = limits or Limits()
    if policy is not None and policy.should_skip(rel):
        raise SecretPathError(f"refusing to read protected path: {rel}")
    path = resolve_within(root, rel)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise PathEscapeError(f"not a regular file: {rel}")
    limits.check_file_size(st.st_size, rel)
    with path.open("rb") as fh:
        data = fh.read(limits.max_file_bytes + 1)
    if len(data) > limits.max_file_bytes:
        raise LimitExceededError(f"{rel}: grew beyond max_file_bytes while reading")
    return data.decode("utf-8", errors="replace").removeprefix(BOM)
