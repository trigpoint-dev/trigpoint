"""Non-App credentials, for completeness: a fixed token or none at all."""

from __future__ import annotations

from collections.abc import Callable

from trigpoint.security import SecretStr


def static_token_provider(token: str | SecretStr | None) -> Callable[[], SecretStr | None]:
    """Provider for a fixed token (e.g. a fine-grained PAT) or ``None`` for public repos.

    GitHub Apps are the recommended credential: their tokens are short-lived and scoped.
    """
    secret = (
        None if token is None else (token if isinstance(token, SecretStr) else SecretStr(token))
    )
    return lambda: secret
