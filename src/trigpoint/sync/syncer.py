"""Shared, hardened, cheap-to-refresh clones.

Flow for ``ensure(owner, repo, branch)``:

1. validate identifiers (strict regex, then ``git check-ref-format``);
2. ``git ls-remote`` the branch tip, which is one cheap round trip with no clone;
3. under a *shared* lock compare it with the local HEAD: equal -> **no-op**, no fetch;
4. otherwise take the *exclusive* lock, re-check (another worker may have just refreshed),
   then ``fetch --depth 1`` + ``checkout --force --detach`` + ``clean``.

The clone is built with ``git init`` + a fetch from an explicit URL, so no remote (and no
token, and not even the URL) is ever written to ``.git/config``. Secret-adjacent paths are
excluded with sparse-checkout *before* checkout, so they are never materialized.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from trigpoint.cache.keys import _check_branch, _check_name, repo_key
from trigpoint.errors import BranchNotFoundError, GitError, InvalidKeyError, LimitExceededError
from trigpoint.security import Limits, SecretStr, sparse_checkout_patterns
from trigpoint.sync.git import GitRunner
from trigpoint.sync.layout import link_project, project_link_path, remove_tree, repo_paths
from trigpoint.sync.locks import RepoLock

TokenProvider = Callable[[], "SecretStr | None"]
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


@dataclass(frozen=True, slots=True)
class SyncResult:
    repo_key: str
    path: Path  # the shared clone
    commit_sha: str
    changed: bool  # False for the cheap no-op path
    link: Path | None  # per-project path, if a project_id was given


def _host_of(base_url: str) -> str:
    return urlparse(base_url).hostname or "local"


class Syncer:
    def __init__(
        self,
        shared_root: str | Path,
        *,
        clone_root: str | Path | None = None,
        base_url: str = "https://github.com",
        token_provider: TokenProvider | None = None,
        limits: Limits | None = None,
        allow_insecure_file: bool = False,
        lock_timeout: float = 120.0,
        runner: GitRunner | None = None,
    ) -> None:
        self._shared = Path(shared_root)
        self._clone_root = Path(clone_root) if clone_root is not None else None
        self._limits = limits or Limits()
        self._token_provider = token_provider
        self._lock_timeout = lock_timeout
        self._runner = runner or GitRunner(
            base_url=base_url, limits=self._limits, allow_insecure_file=allow_insecure_file
        )
        self._base_url = self._runner.base_url

    # -- identity -----------------------------------
    def _identify(self, owner: str, repo: str, branch: str) -> str:
        _check_name("owner", owner)
        _check_name("repo", repo)
        _check_branch(branch)
        # Strict validation first; git's own ref-format check is the second opinion.
        self._runner.run(["check-ref-format", f"refs/heads/{branch}"])
        return repo_key(owner, repo, branch, host=_host_of(self._base_url))

    def _url(self, owner: str, repo: str) -> str:
        return f"{self._base_url}/{owner}/{repo}.git"

    def _token(self) -> SecretStr | None:
        return self._token_provider() if self._token_provider else None

    # -- remote / local state -----------------------------------
    def remote_sha(self, owner: str, repo: str, branch: str) -> str:
        ref = f"refs/heads/{branch}"
        out = self._runner.run(
            ["ls-remote", "--quiet", "--", self._url(owner, repo), ref], token=self._token()
        ).stdout
        for line in out.splitlines():
            sha, _, name = line.partition("\t")
            # ls-remote patterns match by suffix, so insist on the exact ref name.
            if name.strip() == ref and _SHA.match(sha):
                return sha
        raise BranchNotFoundError(f"branch {branch!r} not found on {owner}/{repo}")

    def _local_head(self, clone: Path) -> str | None:
        if not (clone / ".git").is_dir():
            return None
        res = self._runner.run(["rev-parse", "--verify", "-q", "HEAD"], cwd=clone, check=False)
        sha = res.stdout.strip()
        return sha if res.returncode == 0 and _SHA.match(sha) else None

    # -- refresh -----------------------------------
    def _refresh(self, clone: Path, owner: str, repo: str, branch: str) -> str:
        clone.mkdir(parents=True, exist_ok=True)
        git = self._runner
        if not (clone / ".git").is_dir():
            git.run(["init", "--quiet", "--template="], cwd=clone)  # no sample hooks
        # Sanitize before materialize: secret paths are excluded from the working tree.
        git.run(["config", "core.sparseCheckout", "true"], cwd=clone)
        git.run(["config", "core.sparseCheckoutCone", "false"], cwd=clone)
        info = clone / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "sparse-checkout").write_text(
            "\n".join(sparse_checkout_patterns()) + "\n", encoding="utf-8", newline="\n"
        )
        git.run(
            [
                "fetch",
                "--quiet",
                "--depth",
                "1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                self._url(owner, repo),
                f"refs/heads/{branch}",
            ],
            cwd=clone,
            token=self._token(),
        )
        sha = git.run(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], cwd=clone).stdout.strip()
        if not _SHA.match(sha):
            raise InvalidKeyError(f"unexpected commit id from git: {sha!r}")
        git.run(["checkout", "--quiet", "--force", "--detach", sha], cwd=clone)
        git.run(["clean", "--quiet", "-ffdx"], cwd=clone)
        self._enforce_caps(clone)
        return sha

    def _enforce_caps(self, clone: Path) -> None:
        """Layer (c): cap what a refresh may leave on disk. Offenders are wiped, not kept."""
        files = total = 0
        for dirpath, dirnames, filenames in os.walk(clone):
            if Path(dirpath) == clone and ".git" in dirnames:
                dirnames.remove(".git")
            for name in filenames:
                files += 1
                try:
                    total += os.lstat(os.path.join(dirpath, name)).st_size
                except OSError:
                    continue
                if files > self._limits.max_files or total > self._limits.max_total_bytes:
                    remove_tree(clone)
                    raise LimitExceededError(
                        f"clone exceeds limits (max_files={self._limits.max_files}, "
                        f"max_total_bytes={self._limits.max_total_bytes}); removed"
                    )

    # -- public API -----------------------------------
    def ensure(
        self, owner: str, repo: str, branch: str, *, project_id: str | None = None
    ) -> SyncResult:
        key = self._identify(owner, repo, branch)
        paths = repo_paths(self._shared, key)
        lock = RepoLock(paths.lock)
        target = self.remote_sha(owner, repo, branch)

        with lock.shared(self._lock_timeout):
            local = self._local_head(paths.clone)
        changed = False
        if local != target:
            with lock.exclusive(self._lock_timeout):
                local = self._local_head(paths.clone)  # another worker may have refreshed
                if local != target:
                    local = self._refresh(paths.clone, owner, repo, branch)
                    changed = True
        if local is None:  # cannot happen: refresh returns a SHA or raises
            raise GitError("clone has no HEAD after refresh")

        link: Path | None = None
        if project_id is not None:
            if self._clone_root is None:
                raise InvalidKeyError("project links require clone_root")
            link = link_project(project_link_path(self._clone_root, project_id, repo), paths.clone)
        return SyncResult(key, paths.clone, local, changed, link)

    @contextmanager
    def reading(self, owner: str, repo: str, branch: str) -> Iterator[Path]:
        """Hold the shared lock while a caller reads the clone, so a refresh cannot
        change files underneath a parse."""
        key = repo_key(owner, repo, branch, host=_host_of(self._base_url))
        paths = repo_paths(self._shared, key)
        with RepoLock(paths.lock).shared(self._lock_timeout):
            yield paths.clone
