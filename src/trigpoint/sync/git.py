"""Hardened git runner. The only place trigpoint spawns git for sync.

Security properties (each has a test):

* the token travels **only** in the child's environment (``GIT_CONFIG_COUNT``/``KEY_n``/
  ``VALUE_n``), never in argv (visible in ``ps`` / ``/proc/*/cmdline``), the clone URL or
  ``.git/config``;
* the Authorization header is scoped to the configured git host
  (``http.<host>/.extraheader``), so a redirect to another host from a submodule, LFS or an
  HTTP redirect never receives it (and ``http.followRedirects=initial``);
* no shell, no prompts, no user/system git config, no credential helpers, no hooks, no
  fsmonitor, no submodule recursion, no LFS smudge, protocols limited to https (plus file
  only when explicitly enabled for tests), symlinks are not materialized;
* every call has a timeout, closed stdin and bounded captured output;
* error text is redacted, including the token and its base64 form.
"""

from __future__ import annotations

import base64
import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from trigpoint.errors import GitError, GitVersionError
from trigpoint.security import Limits, Redactor, SecretStr
from trigpoint.security.registry import default_registry

MIN_GIT = (2, 31)  # GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n
MAX_OUTPUT_BYTES = 5 * 1024 * 1024
MAX_STDERR_CHARS = 2000

_PASSTHROUGH_ENV = (
    "PATH",
    "SYSTEMROOT",
    "SystemRoot",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    # corporate proxies and private CAs, required in many enterprise networks
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "GIT_SSL_CAINFO",
    "CURL_CA_BUNDLE",
)

_HARDENING: tuple[tuple[str, str], ...] = (
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("core.hooksPath", os.devnull),
    ("core.fsmonitor", "false"),
    ("core.symlinks", "false"),  # a hostile symlink is written as a plain file instead
    ("credential.helper", ""),
    ("submodule.recurse", "false"),
    ("fetch.recurseSubmodules", "false"),
    ("http.followRedirects", "initial"),
    ("transfer.fsckObjects", "true"),
    ("fetch.fsckObjects", "true"),
    ("gc.auto", "0"),
    ("safe.directory", "*"),  # the clone is ours, possibly written by another pod's uid
    ("advice.detachedHead", "false"),
)


@dataclass(frozen=True, slots=True)
class GitResult:
    stdout: str
    stderr: str
    returncode: int


def auth_header_value(token: SecretStr) -> str:
    raw = f"x-access-token:{token.reveal()}".encode()
    return "Authorization: basic " + base64.b64encode(raw).decode("ascii")


class GitRunner:
    def __init__(
        self,
        *,
        base_url: str = "https://github.com",
        limits: Limits | None = None,
        allow_insecure_file: bool = False,
        git_executable: str = "git",
        redactor: Redactor | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in ("https", "file"):
            raise ValueError(f"base_url must be https (or file for tests): {base_url!r}")
        if parsed.scheme == "file" and not allow_insecure_file:
            raise ValueError("file:// remotes require allow_insecure_file=True (tests only)")
        self.base_url = base_url.rstrip("/")
        self._limits = limits or Limits()
        self._allow_file = allow_insecure_file
        self._git = git_executable
        self._redactor = redactor or Redactor()
        self._version_checked = False

    # -- configuration, built per call ------------------------------------------------------
    def config(self, token: SecretStr | None) -> list[tuple[str, str]]:
        cfg = list(_HARDENING)
        if self._allow_file:
            cfg.append(("protocol.file.allow", "always"))
        if token is not None and self.base_url.startswith("https://"):
            # Scoped to this host only; the trailing slash makes it a URL prefix match.
            cfg.append((f"http.{self.base_url}/.extraheader", auth_header_value(token)))
        return cfg

    def build_env(self, token: SecretStr | None = None) -> dict[str, str]:
        env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
        env.update(
            {
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_ASKPASS": "",
            }
        )
        cfg = self.config(token)
        env["GIT_CONFIG_COUNT"] = str(len(cfg))
        for i, (key, value) in enumerate(cfg):
            env[f"GIT_CONFIG_KEY_{i}"] = key
            env[f"GIT_CONFIG_VALUE_{i}"] = value
        return env

    # -- execution --------------------------------------------------------------------------
    def _check_version(self) -> None:
        if self._version_checked:
            return
        proc = self._spawn(["--version"], cwd=None, env=self.build_env(None))
        m = re.search(r"(\d+)\.(\d+)", proc.stdout)
        if not m or (int(m.group(1)), int(m.group(2))) < MIN_GIT:
            raise GitVersionError(
                f"git >= {MIN_GIT[0]}.{MIN_GIT[1]} is required, found: {proc.stdout.strip()!r}"
            )
        self._version_checked = True

    def _spawn(self, args: Sequence[str], *, cwd: Path | None, env: dict[str, str]) -> GitResult:
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, fixed executable
                [self._git, *args],
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self._limits.git_timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitError(f"git {args[0]} timed out after {self._limits.git_timeout_s}s") from exc
        except OSError as exc:
            raise GitError(f"could not execute git: {exc}") from exc
        return GitResult(
            stdout=proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
            stderr=proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", "replace"),
            returncode=proc.returncode,
        )

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        token: SecretStr | None = None,
        check: bool = True,
    ) -> GitResult:
        """Run ``git <args>``. The token (if any) is delivered via the environment only."""
        self._check_version()
        if token is not None:
            # Anything that echoes the token or its header gets scrubbed from errors/logs.
            default_registry.add(token.reveal())
            default_registry.add(auth_header_value(token))
            default_registry.add(auth_header_value(token).rsplit(" ", 1)[1])
        result = self._spawn(args, cwd=cwd, env=self.build_env(token))
        if check and result.returncode != 0:
            raise self.error(args, result)
        return result

    def error(self, args: Sequence[str], result: GitResult) -> GitError:
        stderr = self._redactor.redact(result.stderr.strip())[:MAX_STDERR_CHARS]
        return GitError(
            f"git {args[0] if args else ''} failed (exit {result.returncode})",
            returncode=result.returncode,
            stderr=stderr,
        )
