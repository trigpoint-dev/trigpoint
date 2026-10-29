from __future__ import annotations

import os
from pathlib import Path

import pytest

from trigpoint.errors import LimitExceededError, PathEscapeError, SecretPathError
from trigpoint.security import Limits, PathPolicy, read_text_safely, resolve_within


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "app/.env",
        ".env.production",
        "deploy/server.pem",
        "keys/id_rsa",
        "keys/id_ed25519.pub",
        "infra/terraform.tfstate",
        "infra/prod.tfvars",
        ".aws/credentials",
        "home/.ssh/config",
        "config/credentials.json",
        "secrets.yaml",
        ".npmrc",
        "svc/service-account-prod.json",
        "sub\\dir\\.env",
    ],
)
def test_secret_paths_denied(path: str) -> None:
    assert PathPolicy().is_secret_path(path), path


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        ".env.sample",
        "src/secrets.py",
        "src/credentials_helper.py",
        "docs/secrets.md",
        "src/app.py",
        "README.md",
        "keyboard.py",
    ],
)
def test_ordinary_paths_allowed(path: str) -> None:
    assert not PathPolicy().is_secret_path(path), path


def test_gitignore_adds_skips(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("local_notes/\n*.dump\n")
    policy = PathPolicy.from_repo(tmp_path)
    assert policy.should_skip("local_notes/a.txt")
    assert policy.should_skip("db.dump")
    assert not policy.should_skip("src/app.py")


def test_gitignore_negation_cannot_unblock_a_secret(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("!.env\n")
    assert PathPolicy.from_repo(tmp_path).should_skip(".env")


def test_extra_patterns(tmp_path: Path) -> None:
    assert PathPolicy(extra_secret_patterns=["internal/**"]).is_secret_path("internal/x.py")


@pytest.mark.parametrize(
    "bad", ["../outside.txt", "a/../../outside.txt", "/etc/passwd", "C:\\x", "a\x00b"]
)
def test_resolve_within_rejects_escapes(tmp_path: Path, bad: str) -> None:
    with pytest.raises(PathEscapeError):
        resolve_within(tmp_path, bad)


def test_resolve_within_allows_inner(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.txt").write_text("x")
    assert resolve_within(tmp_path, "a/../a/f.txt") == (tmp_path / "a" / "f.txt").resolve()


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("nope")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform/user")
    with pytest.raises(PathEscapeError):
        read_text_safely(root, "link/secret.txt")


def test_read_text_safely_guards(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_bytes(b"print('hi')\n")  # bytes: no Windows newline translation
    (tmp_path / ".env").write_text("A=1")
    (tmp_path / "big.txt").write_text("x" * 100)
    policy = PathPolicy()
    assert read_text_safely(tmp_path, "ok.py", policy=policy) == "print('hi')\n"
    with pytest.raises(SecretPathError):
        read_text_safely(tmp_path, ".env", policy=policy)
    with pytest.raises(LimitExceededError):
        read_text_safely(tmp_path, "big.txt", limits=Limits(max_file_bytes=10))
    with pytest.raises(PathEscapeError):
        read_text_safely(tmp_path, ".")  # a directory is not a regular file


def test_limits_validation() -> None:
    with pytest.raises(ValueError):
        Limits(max_file_bytes=0)
    with pytest.raises(LimitExceededError):
        Limits(max_files=2).check_file_count(3)
