"""Filesystem CacheStore.

Designed to also be correct on a shared network mount (EFS, Amazon S3 Files):

* values are written to a temp file in the target directory, then ``os.replace``d into
  place (atomic rename; **no hard links, no lock files**);
* paths are sharded ``tenant/namespace/ab/cd/key`` so no directory grows huge (the first
  access to an S3 Files directory imports metadata for every entry);
* there are no shared mutable files: every key is content-addressed or single-writer;
* a miss is just ``None`` (NFS close-to-open semantics can briefly hide a fresh write).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import tempfile
import time
from pathlib import Path

from trigpoint.cache.base import NS_CONNECTION, NS_DESCRIBE, NS_REPO_MAP
from trigpoint.cache.keys import check_key
from trigpoint.errors import InvalidKeyError, LimitExceededError

_TENANT = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_KNOWN_NAMESPACES = frozenset({NS_REPO_MAP, NS_DESCRIBE, NS_CONNECTION})
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_REPLACE_ATTEMPTS = 20


class LocalFsStore:
    """Cache under ``root/<tenant>/<namespace>/<shard>/<shard>/<key>``.

    ``tenant`` isolates installations: caches are not shared across tenants.
    """

    def __init__(
        self, root: str | Path, *, tenant: str = "default", max_bytes: int = DEFAULT_MAX_BYTES
    ) -> None:
        if not _TENANT.match(tenant) or tenant in (".", ".."):
            raise InvalidKeyError(f"invalid tenant: {tenant!r}")
        self._base = Path(root) / tenant
        self._max_bytes = max_bytes

    def _path(self, namespace: str, key: str) -> Path:
        if namespace not in _KNOWN_NAMESPACES:
            raise InvalidKeyError(f"unknown namespace: {namespace!r}")
        check_key(key)
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._base / namespace / h[:2] / h[2:4] / key

    def get(self, namespace: str, key: str) -> bytes | None:
        path = self._path(namespace, key)
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                with path.open("rb") as fh:
                    data = fh.read(self._max_bytes + 1)
            except (FileNotFoundError, NotADirectoryError):
                return None
            except PermissionError:
                # Windows: the file is mid-replace by a writer. Retry, then call it a miss.
                time.sleep(0.005 * (attempt + 1))
                continue
            if len(data) > self._max_bytes:
                return None  # oversized entries are treated as corrupt
            return data
        return None

    def put(self, namespace: str, key: str, data: bytes) -> None:
        if len(data) > self._max_bytes:
            raise LimitExceededError(f"cache value of {len(data)} bytes exceeds {self._max_bytes}")
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".part")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            self._publish(tmp, path, data)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)  # already renamed on success; cleanup on any failure

    @staticmethod
    def _publish(tmp: str, path: Path, data: bytes) -> None:
        """Atomic rename into place.

        On Windows ``os.replace`` fails with PermissionError while another handle has the
        destination open. Values are content-addressed, so if the destination already holds
        exactly these bytes the write is a success; otherwise retry briefly, then raise.
        """
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if _same_content(path, data):
                    return
                if attempt == _REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(0.005 * (attempt + 1))


def _same_content(path: Path, data: bytes) -> bool:
    try:
        return path.read_bytes() == data
    except OSError:
        return False
