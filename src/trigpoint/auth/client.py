"""Small GitHub REST client: pagination, rate limits, retries, and no redirect-following.

Security notes:

* ``follow_redirects`` is off, and pagination only follows ``Link`` URLs on the same origin
  as the API base, so the Authorization header can never be sent to another host;
* only ``https`` API bases are accepted;
* error text is redacted and never includes request headers.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise ImportError("GitHub App support needs: pip install 'trigpoint[github]'") from exc

from trigpoint.errors import AuthError, GitHubAPIError, NotFoundError, RateLimitError
from trigpoint.extract.base import clip
from trigpoint.security import Redactor, SecretStr

API_VERSION = "2022-11-28"
_PAGE_SIZE = 100
_MAX_PAGES = 200


@dataclass(frozen=True, slots=True)
class GitHubEndpoints:
    """Where a GitHub (or GitHub Enterprise Server) instance lives."""

    api_base: str
    git_base_url: str

    @classmethod
    def github_com(cls) -> GitHubEndpoints:
        return cls("https://api.github.com", "https://github.com")

    @classmethod
    def enterprise_server(cls, host: str) -> GitHubEndpoints:
        if not re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", host):
            raise ValueError(f"invalid GHES host: {host!r}")
        return cls(f"https://{host}/api/v3", f"https://{host}")


def _origin(url: str) -> tuple[str, str]:
    p = urlparse(url)
    return p.scheme, p.netloc.lower()


class GitHubClient:
    def __init__(
        self,
        api_base: str = "https://api.github.com",
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        max_wait: float = 60.0,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = "trigpoint",
        redactor: Redactor | None = None,
    ) -> None:
        if urlparse(api_base).scheme != "https":
            raise ValueError(f"api_base must be https: {api_base!r}")
        self.api_base = api_base.rstrip("/")
        self._origin = _origin(self.api_base)
        self._http = httpx.Client(
            transport=transport, timeout=timeout, follow_redirects=False, trust_env=True
        )
        self._max_retries = max_retries
        self._max_wait = max_wait
        self._clock = clock
        self._sleep = sleep
        self._ua = user_agent
        self._redactor = redactor or Redactor()

    def close(self) -> None:
        self._http.close()

    # -- requests ---------------------------------------------------------------------------
    def _headers(self, token: SecretStr) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token.reveal()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": self._ua,
        }

    def request(
        self,
        method: str,
        target: str,
        *,
        token: SecretStr,
        json: Any = None,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """``target`` is an API path (``/app``) or an absolute same-origin URL (from Link)."""
        if target.startswith("/"):
            url = self.api_base + target
        elif _origin(target) == self._origin:
            url = target
        else:
            raise GitHubAPIError("refusing to send credentials to a different origin")
        for attempt in range(self._max_retries + 1):
            last = attempt == self._max_retries
            try:
                resp = self._http.request(
                    method, url, headers=self._headers(token), json=json, params=params
                )
            except httpx.TransportError as exc:
                if last:
                    raise GitHubAPIError(
                        f"network error talking to GitHub: {type(exc).__name__}"
                    ) from exc
                self._sleep(min(0.5 * 2**attempt, self._max_wait))
                continue
            if resp.status_code >= 500 and not last:
                self._sleep(min(0.5 * 2**attempt, self._max_wait))
                continue
            wait = self._rate_limit_wait(resp)
            if wait is not None:
                if wait > self._max_wait or last:
                    raise RateLimitError(
                        f"GitHub rate limit; retry in {wait:.0f}s", retry_after=wait
                    )
                self._sleep(wait)
                continue
            return self._check(resp)
        raise GitHubAPIError("retries exhausted")  # pragma: no cover - loop always returns/raises

    def get_json(
        self, target: str, *, token: SecretStr, params: Mapping[str, Any] | None = None
    ) -> Any:
        return self.request("GET", target, token=token, params=params).json()

    def paginate(
        self,
        path: str,
        *,
        token: SecretStr,
        items_key: str | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every item across pages (``items_key`` for envelope responses)."""
        target: str | None = path
        query: dict[str, Any] | None = {"per_page": _PAGE_SIZE, **(params or {})}
        for _ in range(_MAX_PAGES):
            if target is None:
                return
            resp = self.request("GET", target, token=token, params=query)
            body = resp.json()
            items = body.get(items_key, []) if items_key else body
            yield from items
            nxt = resp.links.get("next")
            target, query = (nxt["url"] if nxt else None), None  # the Link URL carries its query
        raise GitHubAPIError(f"more than {_MAX_PAGES} pages; refusing to continue")

    # -- error mapping ---------------------------------------------------------------------------
    def _rate_limit_wait(self, resp: httpx.Response) -> float | None:
        if resp.status_code not in (403, 429):
            return None
        retry_after = resp.headers.get("retry-after")
        if retry_after:
            try:
                return max(float(retry_after), 0.0)
            except ValueError:
                return 60.0
        if resp.headers.get("x-ratelimit-remaining") == "0":
            try:
                reset = float(resp.headers.get("x-ratelimit-reset", "0"))
            except ValueError:
                return 60.0
            return max(reset - self._clock(), 0.0) + 1.0
        if "rate limit" in self._message(resp).lower():  # secondary limits, no headers
            return 60.0
        return None

    def _message(self, resp: httpx.Response) -> str:
        try:
            data = resp.json()
            text = str(data.get("message", "")) if isinstance(data, dict) else ""
        except ValueError:
            text = ""
        return clip(self._redactor.redact(text), 200)

    def _check(self, resp: httpx.Response) -> httpx.Response:
        code = resp.status_code
        if code < 300:
            return resp
        if code < 400:  # redirects are never followed: they could carry credentials elsewhere
            raise GitHubAPIError(f"unexpected redirect ({code}); not following", status=code)
        msg = self._message(resp) or "no message"
        if code == 401:
            raise AuthError(f"GitHub rejected the credentials (401): {msg}", status=code)
        if code == 403:
            raise AuthError(f"GitHub denied the request (403): {msg}", status=code)
        if code == 404:
            raise NotFoundError(
                f"not found, or not visible to this credential (404): {msg}", status=code
            )
        raise GitHubAPIError(f"GitHub API error {code}: {msg}", status=code)
