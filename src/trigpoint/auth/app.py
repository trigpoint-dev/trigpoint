"""The one object most callers need: a GitHub App, any app, plus a git token provider."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from trigpoint.auth.app_jwt import AppJwtSigner
from trigpoint.auth.client import GitHubClient, GitHubEndpoints
from trigpoint.auth.discovery import Discovery
from trigpoint.auth.installation_token import InstallationTokenProvider
from trigpoint.security import SecretStr


class GitHubApp:
    """Authenticates as a GitHub App and hands out installation tokens.

    Bring any app: pass its id and private key. Several ``GitHubApp`` objects can live in
    one process (different apps, or the same app on github.com and a GHES instance); each
    keeps its own token cache.

        app = GitHubApp(app_id, private_key_pem)
        syncer = Syncer(shared, base_url=app.endpoints.git_base_url,
                        token_provider=app.token_provider(installation_id))
    """

    def __init__(
        self,
        app_id: str | int,
        private_key: str | SecretStr,
        *,
        endpoints: GitHubEndpoints | None = None,
        client: GitHubClient | None = None,
        default_permissions: Mapping[str, str] | None = None,
    ) -> None:
        self.endpoints = endpoints or GitHubEndpoints.github_com()
        self.signer = AppJwtSigner(app_id, private_key)
        self.client = client or GitHubClient(self.endpoints.api_base)
        self.tokens = InstallationTokenProvider(
            self.signer, self.client, default_permissions=default_permissions
        )
        self.discovery = Discovery(self.signer, self.client, self.tokens)

    @classmethod
    def from_env(
        cls, prefix: str = "TRIGPOINT_GITHUB_", env: Mapping[str, str] | None = None
    ) -> GitHubApp:
        """Build from ``<prefix>APP_ID`` and ``PRIVATE_KEY`` (or ``PRIVATE_KEY_PATH``).

        Optional ``<prefix>GHES_HOST`` selects a GitHub Enterprise Server instance.
        """
        e = os.environ if env is None else env
        app_id = e.get(f"{prefix}APP_ID")
        if not app_id:
            raise ValueError(f"{prefix}APP_ID is not set")
        if e.get(f"{prefix}PRIVATE_KEY"):
            key = e[f"{prefix}PRIVATE_KEY"]
        elif e.get(f"{prefix}PRIVATE_KEY_PATH"):
            key = Path(e[f"{prefix}PRIVATE_KEY_PATH"]).read_text(encoding="utf-8")
        else:
            raise ValueError(f"set {prefix}PRIVATE_KEY or {prefix}PRIVATE_KEY_PATH")
        host = e.get(f"{prefix}GHES_HOST")
        endpoints = GitHubEndpoints.enterprise_server(host) if host else None
        return cls(app_id, key, endpoints=endpoints)

    def token_provider(
        self, installation_id: int, *, repositories: Sequence[str] | None = None
    ) -> Callable[[], SecretStr]:
        """A zero-argument provider for ``Syncer(token_provider=...)``.

        Each call returns a currently valid token (minted or cached), optionally narrowed to
        specific repositories.
        """

        def provide() -> SecretStr:
            return self.tokens.get(installation_id, repositories=repositories).token

        return provide

    def close(self) -> None:
        self.client.close()
