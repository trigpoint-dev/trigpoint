"""GitHub App JWT: the app proves who it is with a short-lived RS256 token."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError as exc:  # pragma: no cover
    raise ImportError("GitHub App support needs: pip install 'trigpoint[github]'") from exc

from trigpoint.security import SecretStr

MAX_LIFETIME = 600  # GitHub rejects JWTs valid for more than 10 minutes
CLOCK_DRIFT = 60  # backdate iat so a slightly fast local clock is not "issued in the future"


def normalize_pem(text: str) -> str:
    """Env vars often carry PEMs with literal ``\\n`` sequences; restore real newlines."""
    text = text.strip()
    if "\\n" in text and "\n" not in text:
        text = text.replace("\\n", "\n")
    return text


class AppJwtSigner:
    """Signs app JWTs. Works for any GitHub App: it only needs the app id and its key."""

    def __init__(
        self,
        app_id: str | int,
        private_key: str | SecretStr,
        *,
        lifetime: int = 540,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not 0 < lifetime <= MAX_LIFETIME - CLOCK_DRIFT:
            raise ValueError(f"lifetime must be 1..{MAX_LIFETIME - CLOCK_DRIFT} seconds")
        self.app_id = str(app_id).strip()
        if not self.app_id:
            raise ValueError("app_id is required")
        secret = private_key if isinstance(private_key, SecretStr) else SecretStr(private_key)
        try:
            key = serialization.load_pem_private_key(
                normalize_pem(secret.reveal()).encode(), password=None
            )
        except (ValueError, TypeError) as exc:
            # Never include key material in the message.
            raise ValueError("private_key is not a valid unencrypted PEM private key") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("GitHub Apps use RSA keys; got a different key type")
        self._key = key
        self._lifetime = lifetime
        self._clock = clock

    @classmethod
    def from_file(cls, app_id: str | int, path: str | Path, **kw: float) -> AppJwtSigner:
        return cls(app_id, Path(path).read_text(encoding="utf-8"), **kw)  # type: ignore[arg-type]

    def token(self) -> SecretStr:
        now = int(self._clock())
        claims = {"iat": now - CLOCK_DRIFT, "exp": now + self._lifetime, "iss": self.app_id}
        return SecretStr(jwt.encode(claims, self._key, algorithm="RS256"))

    def __repr__(self) -> str:
        return f"AppJwtSigner(app_id={self.app_id!r}, key=<redacted>)"
