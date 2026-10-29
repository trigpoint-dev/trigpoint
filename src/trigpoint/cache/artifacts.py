"""The three chained cache layers on top of a CacheStore.

* ``repo-map``   key (repo_key, git SHA, extractor+schema version): the whole walk+parse
                 result, shared by every project using that repo.
* ``describe``   key (repo_key, sha256(rendered section)): the LLM call, shared likewise.
* ``connection`` key project_id: the rendered ``connection.md``; pure output, never an input.

Anything that is free-form text is redacted again on the way in (defense in depth on top of
the redaction already applied when the RepoMap was built).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from trigpoint.cache import keys
from trigpoint.cache.base import NS_CONNECTION, NS_DESCRIBE, NS_REPO_MAP, CacheStore
from trigpoint.domain import RepoMap, repo_map_from_dict
from trigpoint.errors import InvalidKeyError, SchemaError
from trigpoint.security import Redactor


class ArtifactCache:
    def __init__(self, store: CacheStore, *, redactor: Redactor | None = None) -> None:
        self._store = store
        self._redactor = redactor or Redactor()

    # -- layer 1: repo-map ---------------------------------------------------------------
    def get_repo_map(self, repo_key: str, commit_sha: str) -> RepoMap | None:
        raw = self._store.get(NS_REPO_MAP, keys.repo_map_key(repo_key, commit_sha))
        if raw is None:
            return None
        try:
            return repo_map_from_dict(json.loads(raw))
        except (SchemaError, ValueError):  # stale schema or corrupt bytes: recompute
            return None

    def put_repo_map(self, repo_key: str, commit_sha: str, repo_map: RepoMap) -> None:
        # Already redacted by build_repo_map, which deliberately leaves identifiers intact;
        # re-scanning the JSON here could corrupt a path.
        payload = repo_map.to_json().encode("utf-8")
        self._store.put(NS_REPO_MAP, keys.repo_map_key(repo_key, commit_sha), payload)

    def get_or_build_repo_map(
        self, repo_key: str, commit_sha: str, build: Callable[[], RepoMap]
    ) -> tuple[RepoMap, bool]:
        """Return (repo_map, cache_hit). Builds and stores on a miss.

        An empty ``commit_sha`` (e.g. a non-git directory) cannot be keyed, so it is built
        and returned without caching.
        """
        if not commit_sha:
            return build(), False
        cached = self.get_repo_map(repo_key, commit_sha)
        if cached is not None:
            return cached, True
        built = build()
        self.put_repo_map(repo_key, commit_sha, built)
        return built, False

    # -- layer 2: describe -----------------------------------------------------------------
    def get_description(self, repo_key: str, rendered_section: str) -> str | None:
        raw = self._store.get(NS_DESCRIBE, keys.describe_key(repo_key, rendered_section))
        if raw is None:
            return None
        try:
            value = json.loads(raw)["text"]
        except (ValueError, KeyError, TypeError):
            return None
        return value if isinstance(value, str) else None

    def put_description(self, repo_key: str, rendered_section: str, text: str) -> None:
        payload = json.dumps({"text": self._redactor.redact(text)}).encode("utf-8")
        self._store.put(NS_DESCRIBE, keys.describe_key(repo_key, rendered_section), payload)

    # -- layer 3: connection.md ---------------------------------------------------------------
    def get_connection(self, project_id: str) -> str | None:
        raw = self._store.get(NS_CONNECTION, keys.connection_key(project_id))
        return raw.decode("utf-8", errors="replace") if raw is not None else None

    def put_connection(self, project_id: str, markdown: str) -> None:
        if not project_id:
            raise InvalidKeyError("project_id is required")
        data = self._redactor.redact(markdown).encode("utf-8")
        self._store.put(NS_CONNECTION, keys.connection_key(project_id), data)
