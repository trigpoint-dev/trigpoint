"""Installation access tokens: the short-lived credential git actually uses."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from trigpoint.auth.app_jwt import AppJwtSigner
from trigpoint.auth.client import GitHubClient
from trigpoint.cache.keys import _check_name
from trigpoint.errors import GitHubAPIError
from trigpoint.security import SecretStr

# Least privilege by default: clone and list. Pass {} to inherit everything the app has.
DEFAULT_PERMISSIONS: Mapping[str, str] = {"contents": "read", "metadata": "read"}
_MAX_CACHE = 256
_FALLBACK_LIFETIME = 3000.0  # GitHub tokens last an hour; used if expires_at is missing


@dataclass(frozen=True, slots=True)
class InstallationToken:
    token: SecretStr
    expires_at: float  # epoch seconds
    installation_id: int


_CacheKey = tuple[int, tuple[str, ...], tuple[tuple[str, str], ...]]


class InstallationTokenProvider:
    """Mints and caches installation tokens, one per (installation, repos, permissions).

    * tokens live in memory only and are refreshed ``refresh_skew`` seconds before expiry;
    * refresh is single-flight per key, so a burst of callers makes one API request;
    * the token is a ``SecretStr``: masked everywhere and scrubbed if it leaks into text.
    """

    def __init__(
        self,
        signer: AppJwtSigner,
        client: GitHubClient,
        *,
        default_permissions: Mapping[str, str] | None = None,
        refresh_skew: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._signer = signer
        self._client = client
        self._permissions = dict(
            DEFAULT_PERMISSIONS if default_permissions is None else default_permissions
        )
        self._skew = refresh_skew
        self._clock = clock
        self._cache: dict[_CacheKey, InstallationToken] = {}
        self._guard = threading.Lock()
        self._key_locks: dict[_CacheKey, threading.Lock] = {}

    def _fresh(self, tok: InstallationToken | None) -> bool:
        return tok is not None and tok.expires_at - self._clock() > self._skew

    def get(
        self,
        installation_id: int,
        *,
        repositories: Sequence[str] | None = None,
        permissions: Mapping[str, str] | None = None,
    ) -> InstallationToken:
        repos = tuple(sorted({_check_name("repo", r) for r in (repositories or ())}))
        perms = dict(self._permissions if permissions is None else permissions)
        key: _CacheKey = (int(installation_id), repos, tuple(sorted(perms.items())))
        with self._guard:
            cached = self._cache.get(key)
            if self._fresh(cached):
                assert cached is not None  # noqa: S101 - narrowing for the type checker
                return cached
            lock = self._key_locks.setdefault(key, threading.Lock())
        with lock:  # single flight: later callers find the first caller's token
            with self._guard:
                cached = self._cache.get(key)
            if self._fresh(cached):
                assert cached is not None  # noqa: S101
                return cached
            minted = self._mint(key[0], repos, perms)
            with self._guard:
                self._cache[key] = minted
                while len(self._cache) > _MAX_CACHE:
                    self._cache.pop(next(iter(self._cache)))
            return minted

    def invalidate(self, installation_id: int | None = None) -> None:
        with self._guard:
            for key in [k for k in self._cache if installation_id in (None, k[0])]:
                del self._cache[key]

    def _mint(
        self, installation_id: int, repos: tuple[str, ...], perms: Mapping[str, str]
    ) -> InstallationToken:
        body: dict[str, Any] = {}
        if repos:
            body["repositories"] = list(repos)
        if perms:
            body["permissions"] = dict(perms)
        resp = self._client.request(
            "POST",
            f"/app/installations/{int(installation_id)}/access_tokens",
            token=self._signer.token(),
            json=body or None,
        )
        data = resp.json()
        raw = data.get("token") if isinstance(data, dict) else None
        if not isinstance(raw, str) or not raw:
            raise GitHubAPIError("GitHub returned no installation token", status=resp.status_code)
        token = SecretStr(raw)  # registered for redaction as soon as it exists
        expires = self._clock() + _FALLBACK_LIFETIME
        stamp = data.get("expires_at")
        if isinstance(stamp, str):
            with contextlib.suppress(ValueError):  # keep the fallback lifetime
                expires = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
        return InstallationToken(token, expires, int(installation_id))
