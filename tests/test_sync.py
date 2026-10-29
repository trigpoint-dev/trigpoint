"""Sync tests run real git against a local bare repo; no network is involved."""

from __future__ import annotations

import base64
import subprocess
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import run_git
from trigpoint.api import build_repo_map
from trigpoint.errors import (
    BranchNotFoundError,
    GitError,
    InvalidKeyError,
    LimitExceededError,
    LockTimeoutError,
)
from trigpoint.security import Limits, SecretStr, sparse_checkout_patterns
from trigpoint.sync import GitRunner, RepoLock, Syncer
from trigpoint.sync.git import GitResult, auth_header_value

TOKEN = "ghs_" + "Qw3Er5Ty7Ui9Op1As2Df4Gh6Jk8Lz0Xc5Vb7"

MAIN_FILES = {
    "app.py": "def main():\n    return 1\n",
    "app/util.py": "def util():\n    return 2\n",
    "README.md": "# Shop\n\nA small service that sells things online.\n",
    # tracked secrets: they must never be materialized in the clone
    ".env": "API_KEY=abc\n",
    "app/.env": "NESTED=1\n",
    ".aws/credentials": "[default]\n",
    "keys/id_rsa": "private\n",
    ".env.example": "API_KEY=\n",
}


class Remote:
    """A local bare repo plus a working copy used to add commits to it."""

    def __init__(self, root: Path, owner: str = "acme", repo: str = "shop") -> None:
        self.base = root / "remotes"
        self.bare = self.base / owner / f"{repo}.git"
        self.work = root / "work"
        self.bare.mkdir(parents=True)
        self.work.mkdir()
        run_git(self.bare, "init", "--bare", "-q", "-b", "main")
        run_git(self.work, "init", "-q", "-b", "main")
        run_git(self.work, "remote", "add", "origin", str(self.bare))

    @property
    def url(self) -> str:
        return self.base.as_uri()

    def commit(
        self,
        files: dict[str, str] | None = None,
        *,
        delete: Sequence[str] = (),
        branch: str = "main",
    ) -> str:
        run_git(self.work, "checkout", "-q", "-B", branch)
        for rel, content in (files or {}).items():
            path = self.work / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode())
        for rel in delete:
            (self.work / rel).unlink()
        run_git(self.work, "add", "-A")
        run_git(self.work, "commit", "-q", "--allow-empty", "-m", "c")
        run_git(self.work, "push", "-q", "origin", f"HEAD:refs/heads/{branch}", "--force")
        return run_git(self.work, "rev-parse", "HEAD")


class SpyRunner(GitRunner):
    def __init__(self, **kw: Any) -> None:
        super().__init__(**kw)
        self.calls: list[list[str]] = []

    def run(self, args: Sequence[str], **kw: Any) -> GitResult:
        self.calls.append(list(args))
        return super().run(args, **kw)


@pytest.fixture
def remote(tmp_path: Path) -> Remote:
    r = Remote(tmp_path)
    r.commit(MAIN_FILES)
    return r


def make_syncer(tmp_path: Path, remote: Remote, **kw: Any) -> tuple[Syncer, SpyRunner]:
    limits = kw.pop("limits", Limits(git_timeout_s=60))
    runner = SpyRunner(base_url=remote.url, allow_insecure_file=True, limits=limits)
    syncer = Syncer(
        tmp_path / "shared",
        clone_root=tmp_path / "projects",
        limits=limits,
        runner=runner,
        lock_timeout=20,
        **kw,
    )
    return syncer, runner


# -- the core flow -------------------------------------------------------------------------
def test_first_sync_clones_shallow_and_never_materializes_secrets(
    tmp_path: Path, remote: Remote
) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    res = syncer.ensure("acme", "shop", "main")
    clone = res.path
    assert res.changed and res.commit_sha == run_git(remote.work, "rev-parse", "HEAD")
    assert (clone / "app.py").exists() and (clone / "app" / "util.py").exists()
    assert (clone / ".env.example").exists()  # documentation templates are allowed
    for secret in (".env", "app/.env", ".aws/credentials", "keys/id_rsa"):
        assert not (clone / secret).exists(), f"{secret} was materialized"
    assert run_git(clone, "rev-list", "--count", "HEAD") == "1"  # depth 1


def test_nothing_about_the_remote_is_persisted_in_git_config(
    tmp_path: Path, remote: Remote
) -> None:
    syncer, _ = make_syncer(tmp_path, remote, token_provider=lambda: SecretStr(TOKEN))
    res = syncer.ensure("acme", "shop", "main")
    config = (res.path / ".git" / "config").read_text()
    for needle in ("[remote", "url", "extraheader", TOKEN, remote.url, "x-access-token"):
        assert needle not in config, needle
    on_disk = b"".join(p.read_bytes() for p in (res.path / ".git").rglob("*") if p.is_file())
    assert TOKEN.encode() not in on_disk


def test_unchanged_remote_is_a_cheap_noop(tmp_path: Path, remote: Remote) -> None:
    syncer, runner = make_syncer(tmp_path, remote)
    first = syncer.ensure("acme", "shop", "main")
    runner.calls.clear()
    again = syncer.ensure("acme", "shop", "main")
    assert not again.changed and again.commit_sha == first.commit_sha
    verbs = {c[0] for c in runner.calls}
    assert "fetch" not in verbs and "checkout" not in verbs and "ls-remote" in verbs


def test_new_commits_update_the_working_tree(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    first = syncer.ensure("acme", "shop", "main")
    new_sha = remote.commit({"app/new.py": "x = 1\n"}, delete=["app/util.py"])
    second = syncer.ensure("acme", "shop", "main")
    assert second.changed and second.commit_sha == new_sha != first.commit_sha
    assert (second.path / "app" / "new.py").exists()
    assert not (second.path / "app" / "util.py").exists()  # deleted upstream, gone locally
    assert run_git(second.path, "rev-list", "--count", "HEAD") == "1"
    assert not (second.path / ".env").exists()


def test_local_edits_are_discarded_by_a_refresh(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    res = syncer.ensure("acme", "shop", "main")
    (res.path / "app.py").write_text("tampered")
    (res.path / "stray.txt").write_text("junk")
    remote.commit({"other.py": "y = 2\n"})
    syncer.ensure("acme", "shop", "main")
    assert (res.path / "app.py").read_text().startswith("def main")
    assert not (res.path / "stray.txt").exists()


def test_slashed_branch_gets_its_own_clone(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    feat_sha = remote.commit({"feature.py": "f = 1\n"}, branch="feature/x")
    main = syncer.ensure("acme", "shop", "main")
    feat = syncer.ensure("acme", "shop", "feature/x")
    assert main.path != feat.path and main.repo_key != feat.repo_key
    assert feat.commit_sha == feat_sha and (feat.path / "feature.py").exists()
    assert not (main.path / "feature.py").exists()


def test_missing_branch(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    with pytest.raises(BranchNotFoundError):
        syncer.ensure("acme", "shop", "nope")


@pytest.mark.parametrize("branch", ["--upload-pack=touch pwned", "-x", "a..b", "a//b", "a\nb"])
def test_hostile_branches_are_rejected_before_git_runs(
    tmp_path: Path, remote: Remote, branch: str
) -> None:
    syncer, runner = make_syncer(tmp_path, remote)
    with pytest.raises(InvalidKeyError):
        syncer.ensure("acme", "shop", branch)
    assert not any(c[0] in ("ls-remote", "fetch") for c in runner.calls)


@pytest.mark.parametrize("branch", ["a b", "a~1", "a^b", "a:b", "a?b", "a[b", "x.lock"])
def test_git_ref_format_is_the_second_line_of_defence(
    tmp_path: Path, remote: Remote, branch: str
) -> None:
    syncer, runner = make_syncer(tmp_path, remote)
    with pytest.raises((InvalidKeyError, GitError)):
        syncer.ensure("acme", "shop", branch)
    assert not any(c[0] in ("ls-remote", "fetch") for c in runner.calls)


def test_project_links_share_one_clone(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    a = syncer.ensure("acme", "shop", "main", project_id="proj-a")
    b = syncer.ensure("acme", "shop", "main", project_id="proj-b")
    again = syncer.ensure("acme", "shop", "main", project_id="proj-a")  # idempotent
    assert a.path == b.path
    assert a.link != b.link and a.link is not None and b.link is not None
    assert again.link == a.link
    for link in (a.link, b.link):
        assert link.name == "shop"
        assert link.resolve() == a.path.resolve()
        assert (link / "app.py").exists()


def test_clone_limits_wipe_the_clone(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote, limits=Limits(max_files=1, git_timeout_s=60))
    with pytest.raises(LimitExceededError):
        syncer.ensure("acme", "shop", "main")
    assert list((tmp_path / "shared").rglob("clone")) == []  # wiped, not left behind


def test_parsing_a_synced_clone_end_to_end(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    res = syncer.ensure("acme", "shop", "main")
    with syncer.reading("acme", "shop", "main") as clone:
        repo_map = build_repo_map(clone, name="shop", commit_sha=res.commit_sha)
    paths = {f.path for f in repo_map.files}
    assert {"app.py", "app/util.py", "README.md", ".env.example"} <= paths
    assert ".env" not in paths and "keys/id_rsa" not in paths
    assert repo_map.commit_sha == res.commit_sha


def test_concurrent_ensure_refreshes_exactly_once(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    results: list[bool] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            results.append(syncer.ensure("acme", "shop", "main").changed)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert sorted(results) == [False, False, False, True]


# -- token handling (unit) --------------------------------------------------------------------
def test_token_is_delivered_only_through_scoped_env_config() -> None:
    token = SecretStr(TOKEN)
    runner = GitRunner(base_url="https://github.com")
    env = runner.build_env(token)
    key = "http.https://github.com/.extraheader"
    pairs = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    header = pairs[key]
    assert base64.b64decode(header.rsplit(" ", 1)[1]).decode() == f"x-access-token:{TOKEN}"
    leaks = [k for k, v in env.items() if TOKEN in v and not k.startswith("GIT_CONFIG_VALUE_")]
    assert leaks == []
    assert not any(TOKEN in v for k, v in pairs.items() if k != key)
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"


def test_hardening_config_is_always_present() -> None:
    cfg = dict(GitRunner().config(None))
    assert not any("extraheader" in k for k in cfg)
    assert cfg["protocol.allow"] == "never" and cfg["protocol.https.allow"] == "always"
    assert cfg["credential.helper"] == "" and cfg["core.symlinks"] == "false"
    assert cfg["core.fsmonitor"] == "false" and cfg["submodule.recurse"] == "false"
    assert cfg["http.followRedirects"] == "initial" and cfg["fetch.fsckObjects"] == "true"
    assert "protocol.file.allow" not in cfg


def test_header_is_scoped_to_the_configured_host() -> None:
    token = SecretStr(TOKEN)
    ghes = dict(GitRunner(base_url="https://ghe.corp.example/").config(token))
    assert "http.https://ghe.corp.example/.extraheader" in ghes
    assert not any("github.com" in k for k in ghes)


def test_file_remotes_never_get_a_header_and_need_opt_in(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        GitRunner(base_url=tmp_path.as_uri())
    with pytest.raises(ValueError):
        GitRunner(base_url="http://github.com")
    cfg = dict(
        GitRunner(base_url=tmp_path.as_uri(), allow_insecure_file=True).config(SecretStr(TOKEN))
    )
    assert not any("extraheader" in k for k in cfg) and cfg["protocol.file.allow"] == "always"


def test_token_never_appears_in_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append((argv, kw["env"]))
        out = b"git version 2.47.1\n" if argv[1:] == ["--version"] else b""
        return subprocess.CompletedProcess(argv, 0, out, b"")

    monkeypatch.setattr("trigpoint.sync.git.subprocess.run", fake_run)
    token = SecretStr(TOKEN)
    GitRunner().run(
        ["ls-remote", "--", "https://github.com/o/r.git", "refs/heads/main"], token=token
    )
    real = [s for s in seen if s[0][1:] != ["--version"]]
    assert real and all(TOKEN not in " ".join(argv) for argv, _ in seen)
    assert auth_header_value(token) in real[0][1].values()  # env only, as a base64 header


def test_errors_are_redacted() -> None:
    token = SecretStr(TOKEN)
    header = auth_header_value(token)
    result = GitResult("", f"fatal: bad {header} and {TOKEN}", 128)
    err = GitRunner().error(["fetch"], result)
    assert TOKEN not in str(err) and header.rsplit(" ", 1)[1] not in str(err)
    assert err.returncode == 128


def test_a_failing_authenticated_call_does_not_leak_the_token() -> None:
    runner = GitRunner(base_url="https://127.0.0.1:9", limits=Limits(git_timeout_s=30))
    with pytest.raises(GitError) as exc:
        runner.run(["ls-remote", "--", "https://127.0.0.1:9/o/r.git"], token=SecretStr(TOKEN))
    assert TOKEN not in str(exc.value)


def test_sparse_patterns_exclude_secrets_and_keep_templates() -> None:
    patterns = sparse_checkout_patterns()
    assert patterns[0] == "/*" and "!.env" in patterns and "!*.pem" in patterns
    assert patterns.index("!.env.*") < patterns.index(".env.example")  # re-include comes last


# -- locks ---------------------------------------------------------------------------------------
def test_lock_semantics(tmp_path: Path) -> None:
    path = tmp_path / "x" / "lock"
    a, b = RepoLock(path), RepoLock(path)
    with a.shared(1), b.shared(1):
        pass  # readers do not block each other
    with a.exclusive(1):
        with pytest.raises(LockTimeoutError), b.shared(0.2):
            pass
        with pytest.raises(LockTimeoutError), b.exclusive(0.2):
            pass
    with a.shared(1), pytest.raises(LockTimeoutError), b.exclusive(0.2):
        pass
    with b.exclusive(1):  # released cleanly
        pass
    assert path.exists()  # persistent: never deleted, so no create/delete churn on shared storage


def test_reading_holds_a_shared_lock(tmp_path: Path, remote: Remote) -> None:
    syncer, _ = make_syncer(tmp_path, remote)
    res = syncer.ensure("acme", "shop", "main")
    other = RepoLock(res.path.parent / "lock")
    with (
        syncer.reading("acme", "shop", "main"),
        pytest.raises(LockTimeoutError),
        other.exclusive(0.2),
    ):
        pass
    with other.exclusive(1):
        pass
