"""Adapter for any OpenAI-compatible ``/chat/completions`` endpoint (hosted or local)."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise ImportError("This adapter needs: pip install 'trigpoint[openai-compat]'") from exc

from trigpoint.errors import LLMError
from trigpoint.extract.base import clip
from trigpoint.security import Redactor, SecretStr

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
_RETRY_STATUSES = frozenset({408, 409, 429, 500, 502, 503, 504})
_MAX_RETRY_WAIT = 30.0


class OpenAICompatibleLLM:
    """Chat-completions client that works with most hosted and local model servers.

    ``base_url`` is the API root (e.g. ``https://api.openai.com/v1``, ``http://localhost:11434/v1``
    for Ollama). Plain ``http`` is accepted only for loopback hosts so a key is never sent in
    clear text over a network. Redirects are never followed.
    """

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | SecretStr | None = None,
        temperature: float | None = 0.0,
        max_tokens_param: str = "max_tokens",
        extra_body: Mapping[str, Any] | None = None,
        timeout: float = 60.0,
        max_retries: int = 2,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        redactor: Redactor | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK:
            raise ValueError("plain http is only allowed for localhost; use https")
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"invalid base_url: {base_url!r}")
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._key = (
            api_key if isinstance(api_key, SecretStr) or api_key is None else SecretStr(api_key)
        )
        self._temperature = temperature
        self._max_tokens_param = max_tokens_param  # newer OpenAI models want max_completion_tokens
        self._extra = dict(extra_body or {})
        self._retries = max_retries
        self._sleep = sleep
        self._redactor = redactor or Redactor()
        self._http = httpx.Client(
            transport=transport, timeout=timeout, follow_redirects=False, trust_env=True
        )

    def close(self) -> None:
        self._http.close()

    def complete(self, *, system: str, user: str, max_tokens: int) -> str:
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            self._max_tokens_param: max_tokens,
            **self._extra,
        }
        if self._temperature is not None:
            body["temperature"] = self._temperature
        headers = {"Content-Type": "application/json", "User-Agent": "trigpoint"}
        if self._key is not None:
            headers["Authorization"] = f"Bearer {self._key.reveal()}"

        resp: httpx.Response | None = None
        for attempt in range(self._retries + 1):
            last = attempt == self._retries
            try:
                resp = self._http.post(self._url, json=body, headers=headers)
            except httpx.TransportError as exc:
                if last:
                    raise LLMError(f"network error calling the LLM: {type(exc).__name__}") from exc
                self._sleep(min(0.5 * (2.0**attempt), _MAX_RETRY_WAIT))
                continue
            if resp.status_code in _RETRY_STATUSES and not last:
                self._sleep(self._retry_wait(resp, attempt))
                continue
            break
        assert resp is not None  # noqa: S101 - loop always assigns or raises
        if resp.status_code >= 300:
            raise LLMError(f"LLM request failed ({resp.status_code}): {self._error_text(resp)}")
        return self._extract(resp)

    # -- helpers -------------------------------------------------------------------------------
    @staticmethod
    def _retry_wait(resp: httpx.Response, attempt: int) -> float:
        try:
            return min(float(resp.headers["retry-after"]), _MAX_RETRY_WAIT)
        except (KeyError, ValueError):
            return min(0.5 * (2.0**attempt), _MAX_RETRY_WAIT)

    def _error_text(self, resp: httpx.Response) -> str:
        try:
            data = resp.json()
            err = data.get("error", data) if isinstance(data, dict) else {}
            text = str(err.get("message", "")) if isinstance(err, dict) else str(err)
        except ValueError:
            text = ""
        return clip(self._redactor.redact(text), 200) or "no message"

    @staticmethod
    def _extract(resp: httpx.Response) -> str:
        try:
            choice = resp.json()["choices"][0]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("unexpected response shape from the LLM endpoint") from exc
        if choice.get("finish_reason") == "content_filter":
            return ""  # the provider declined: no description
        content = (choice.get("message") or {}).get("content")
        if isinstance(content, list):  # some servers return typed parts
            content = "".join(
                p.get("text", "")
                for p in content
                if isinstance(p, dict) and p.get("type") == "text"
            )
        return content if isinstance(content, str) else ""
