"""The storage port. Adapters: local disk (also EFS / Amazon S3 Files mounts), S3 SDK later."""

from __future__ import annotations

from typing import Protocol

# Namespaces are the three chained layers.
NS_REPO_MAP = "repo-map"
NS_DESCRIBE = "describe"
NS_CONNECTION = "connection"


class CacheStore(Protocol):
    """Immutable-friendly byte store.

    Contract: ``put`` is atomic (readers never see partial data) and idempotent for equal
    bytes; ``get`` returns ``None`` on any miss (never raises for absence); a miss is always
    safe because every value can be recomputed.
    """

    def get(self, namespace: str, key: str) -> bytes | None: ...

    def put(self, namespace: str, key: str, data: bytes) -> None: ...
