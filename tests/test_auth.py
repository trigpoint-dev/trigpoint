"""GitHub App auth tests against a fake GitHub served by httpx.MockTransport."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from trigpoint.auth import (
    AppJwtSigner,
    GitHubApp,
    GitHubClient,
    GitHubEndpoints,
    InstallationTokenProvider,
    static_token_provider,
)
from trigpoint.errors import (
    AuthError,
    GitHubAPIError,
    InvalidKeyError,
    NotFoundError,
    RateLimitError,
)
from trigpoint.security import SecretStr
from trigpoint.sync.git import GitRunner

APP_ID = "123456"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
PUBLIC = KEY.public_key()
API = "https://api.github.com"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGitHub:
    """Just enough of the GitHub API; verifies the app JWT like the real one would."""

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self.now = now
        self.requests: list[httpx.Request] = []
        self.minted = 0
        self.mint_bodies: list[dict[str, Any]] = []
        self.suspended: set[int] = set()
        self.mint_delay = 0.0
        self._lock = threading.Lock()

    def _auth(self, req: httpx.Request) -> str:
        value = req.headers.get("authorization", "")
        assert value.startswith("Bearer "), value
        return value.removeprefix("Bearer ")

    def __call__(self, req: httpx.Request) -> httpx.Response:
        with self._lock:
            self.requests.append(req)
        path = req.url.path
        if req.method == "POST" and path.endswith("/access_tokens"):
            claims = jwt.decode(
                self._auth(req), PUBLIC, algorithms=["RS256"], options={"verify_exp": False}
            )
            assert claims["iss"] == APP_ID
            time.sleep(self.mint_delay)
            with self._lock:
                self.minted += 1
                n = self.minted
                self.mint_bodies.append(json.loads(req.content or b"{}"))
            body = {"token": f"ghs_fake{n:03d}" + "x" * 30, "expires_at": iso(self.now() + 3600)}
            return httpx.Response(201, json=body)
        if path == "/app/installations":
            jwt.decode(self._auth(req), PUBLIC, algorithms=["RS256"])  # also checks exp
            if req.url.params.get("page") != "2":
                nxt = f'<{API}/app/installations?per_page=100&page=2>; rel="next"'
                return httpx.Response(
                    200, json=[self._inst(1, "acme", "Organization")], headers={"link": nxt}
                )
            extra = [self._inst(2, "Bob", "User")]
            extra.append({**self._inst(3, "gone", "User"), "suspended_at": "2026-01-01T00:00:00Z"})
            return httpx.Response(200, json=extra)
        if path.startswith("/repos/") and path.endswith("/installation"):  # JWT endpoint
            jwt.decode(self._auth(req), PUBLIC, algorithms=["RS256"])
            if path == "/repos/acme/shop/installation":
                return httpx.Response(200, json={"id": 1})
            return httpx.Response(404, json={"message": "Not Found"})
        assert self._auth(req).startswith("ghs_"), (
            "installation endpoints need an installation token"
        )
        if path == "/installation/repositories":
            repos = [self._repo("acme", "shop"), self._repo("acme", "api", private=False)]
            return httpx.Response(200, json={"total_count": 2, "repositories": repos})
        if path == "/repos/acme/shop":
            return httpx.Response(200, json={"default_branch": "trunk"})
        if path == "/repos/acme/shop/branches":
            branches = [
                {"name": "trunk", "commit": {"sha": "a" * 40}, "protected": True},
                {"name": "feature/x", "commit": {"sha": "b" * 40}, "protected": False},
            ]
            return httpx.Response(200, json=branches)
        return httpx.Response(404, json={"message": "Not Found"})

    @staticmethod
    def _inst(i: int, login: str, kind: str) -> dict[str, Any]:
        return {
            "id": i,
            "account": {"login": login, "type": kind},
            "repository_selection": "all",
            "suspended_at": None,
        }

    @staticmethod
    def _repo(owner: str, name: str, private: bool = True) -> dict[str, Any]:
        return {
            "name": name,
            "owner": {"login": owner},
            "default_branch": "trunk",
            "private": private,
            "archived": False,
            "fork": False,
        }


def make_client(handler: Callable[[httpx.Request], httpx.Response], **kw: Any) -> GitHubClient:
    return GitHubClient(API, transport=httpx.MockTransport(handler), sleep=lambda s: None, **kw)


@pytest.fixture
def gh() -> FakeGitHub:
    return FakeGitHub()


@pytest.fixture
def app(gh: FakeGitHub) -> GitHubApp:
    return GitHubApp(APP_ID, PEM, client=make_client(gh))


# -- JWT ---------------------------------------------------------------------------------
def test_jwt_claims_and_signature() -> None:
    now = 1_800_000_000
    token = AppJwtSigner(APP_ID, PEM, clock=lambda: now).token().reveal()
    claims = jwt.decode(
        token, PUBLIC, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False}
    )  # fixed fake clock
    assert claims["iss"] == APP_ID
    assert claims["iat"] == now - 60  # backdated for clock drift
    assert claims["exp"] - claims["iat"] <= 600  # GitHub's hard limit
    assert claims["exp"] > now
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


def test_jwt_accepts_numeric_ids_and_escaped_newline_pems() -> None:
    escaped = PEM.replace("\n", "\\n")
    signer = AppJwtSigner(98765, escaped)
    assert signer.app_id == "98765"
    jwt.decode(signer.token().reveal(), PUBLIC, algorithms=["RS256"])


def test_jwt_rejects_bad_keys_without_echoing_them() -> None:
    with pytest.raises(ValueError, match="valid unencrypted PEM") as exc:
        AppJwtSigner(APP_ID, "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----")
    assert "not-a-key" not in str(exc.value)
    ec_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(ValueError, match="RSA"):
        AppJwtSigner(APP_ID, ec_pem)
    with pytest.raises(ValueError):
        AppJwtSigner(APP_ID, PEM, lifetime=600)  # would exceed 10 minutes once backdated
    with pytest.raises(ValueError):
        AppJwtSigner("", PEM)


def test_signer_never_shows_the_key() -> None:
    signer = AppJwtSigner(APP_ID, PEM)
    assert "PRIVATE" not in repr(signer) and "PRIVATE" not in str(signer.token())


# -- installation tokens ------------------------------------------------------------------------
def test_token_is_minted_with_least_privilege_and_cached(app: GitHubApp, gh: FakeGitHub) -> None:
    first = app.tokens.get(7)
    second = app.tokens.get(7)
    assert first is second and gh.minted == 1
    assert gh.mint_bodies[0] == {"permissions": {"contents": "read", "metadata": "read"}}
    assert first.token.reveal().startswith("ghs_")


def test_tokens_are_scoped_per_repositories_and_permissions(app: GitHubApp, gh: FakeGitHub) -> None:
    a = app.tokens.get(7, repositories=["shop"])
    b = app.tokens.get(7, repositories=["shop", "api"])
    c = app.tokens.get(7, permissions={})
    d = app.tokens.get(7, repositories=["api", "shop"])  # order does not matter
    assert gh.minted == 3 and b is d
    assert len({a.token.reveal(), b.token.reveal(), c.token.reveal()}) == 3
    assert gh.mint_bodies[0]["repositories"] == ["shop"]
    assert gh.mint_bodies[1]["repositories"] == ["api", "shop"]
    assert "permissions" not in gh.mint_bodies[2]  # {} inherits what the app has


def test_hostile_repository_names_are_rejected(app: GitHubApp, gh: FakeGitHub) -> None:
    with pytest.raises(InvalidKeyError):
        app.tokens.get(7, repositories=["../evil"])
    assert gh.minted == 0


def test_tokens_refresh_before_they_expire() -> None:
    clock = [1_000_000.0]
    gh = FakeGitHub(now=lambda: clock[0])
    provider = InstallationTokenProvider(
        AppJwtSigner(APP_ID, PEM), make_client(gh), clock=lambda: clock[0], refresh_skew=300
    )
    t1 = provider.get(1)
    clock[0] += 3000  # 600s of life left: still fresh
    assert provider.get(1) is t1 and gh.minted == 1
    clock[0] += 400  # inside the 300s skew window: refresh
    t2 = provider.get(1)
    assert gh.minted == 2 and t2.token.reveal() != t1.token.reveal()
    provider.invalidate(1)
    provider.get(1)
    assert gh.minted == 3


def test_concurrent_callers_cause_a_single_mint(app: GitHubApp, gh: FakeGitHub) -> None:
    gh.mint_delay = 0.2
    got: list[str] = []
    threads = [
        threading.Thread(target=lambda: got.append(app.tokens.get(9).token.reveal()))
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert gh.minted == 1 and len(set(got)) == 1 and len(got) == 8


def test_minted_token_is_masked_and_registered_for_redaction(app: GitHubApp) -> None:
    from trigpoint.security import Redactor

    token = app.tokens.get(5).token
    raw = token.reveal()
    assert raw not in repr(token) and raw not in str(token) and raw not in repr(app.tokens.get(5))
    assert raw not in Redactor().redact(f"git said: {raw}")


# -- client ------------------------------------------------------------------------------------
def test_pagination_follows_same_origin_links(app: GitHubApp) -> None:
    ids = [i.id for i in app.discovery.list_installations(include_suspended=True)]
    assert ids == [1, 2, 3]


def test_pagination_never_follows_a_link_to_another_origin() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        evil = '<https://evil.example/steal>; rel="next"'
        return httpx.Response(200, json=[{"n": 1}], headers={"link": evil})

    client = make_client(handler)
    with pytest.raises(GitHubAPIError, match="different origin"):
        list(client.paginate("/things", token=SecretStr("tok-123456789")))


def test_redirects_are_not_followed() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    with pytest.raises(GitHubAPIError, match="redirect"):
        make_client(handler).get_json("/x", token=SecretStr("tok-123456789"))
    assert calls == [f"{API}/x"]


@pytest.mark.parametrize(
    ("status", "exc"),
    [(401, AuthError), (403, AuthError), (404, NotFoundError), (422, GitHubAPIError)],
)
def test_status_mapping(status: int, exc: type[Exception]) -> None:
    client = make_client(lambda r: httpx.Response(status, json={"message": "nope"}))
    with pytest.raises(exc):
        client.get_json("/x", token=SecretStr("tok-123456789"))


def test_error_messages_are_redacted_and_header_free() -> None:
    leaked = "ghp_" + "Ab1" * 12
    client = make_client(lambda r: httpx.Response(401, json={"message": f"bad token {leaked}"}))
    secret = SecretStr("tok-123456789-secret")
    with pytest.raises(AuthError) as err:
        client.get_json("/x", token=secret)
    assert leaked not in str(err.value) and "tok-123456789-secret" not in str(err.value)


def test_secondary_rate_limit_honours_retry_after() -> None:
    sleeps: list[float] = []
    responses = iter(
        [httpx.Response(429, headers={"retry-after": "2"}), httpx.Response(200, json={})]
    )
    client = GitHubClient(
        API, transport=httpx.MockTransport(lambda r: next(responses)), sleep=sleeps.append
    )
    client.get_json("/x", token=SecretStr("tok-123456789"))
    assert sleeps == [2.0]


def test_primary_rate_limit_waits_until_reset_but_not_forever() -> None:
    sleeps: list[float] = []
    headers = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1000005"}
    responses = iter(
        [
            httpx.Response(403, headers=headers, json={"message": "API rate limit exceeded"}),
            httpx.Response(200, json={}),
        ]
    )
    client = GitHubClient(
        API,
        transport=httpx.MockTransport(lambda r: next(responses)),
        sleep=sleeps.append,
        clock=lambda: 1_000_000.0,
    )
    client.get_json("/x", token=SecretStr("tok-123456789"))
    assert sleeps == [6.0]

    far = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(1_000_000 + 3600)}
    client2 = GitHubClient(
        API,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(403, headers=far, json={"message": "rate limit"})
        ),
        sleep=sleeps.append,
        clock=lambda: 1_000_000.0,
    )
    with pytest.raises(RateLimitError) as err:
        client2.get_json("/x", token=SecretStr("tok-123456789"))
    assert err.value.retry_after is not None and err.value.retry_after > 3000


def test_server_errors_are_retried_with_backoff_then_give_up() -> None:
    sleeps: list[float] = []
    responses = iter(
        [httpx.Response(502), httpx.Response(503), httpx.Response(200, json={"ok": 1})]
    )
    client = GitHubClient(
        API, transport=httpx.MockTransport(lambda r: next(responses)), sleep=sleeps.append
    )
    assert client.get_json("/x", token=SecretStr("tok-123456789")) == {"ok": 1}
    assert sleeps == [0.5, 1.0]
    always = GitHubClient(
        API,
        transport=httpx.MockTransport(lambda r: httpx.Response(500)),
        max_retries=2,
        sleep=lambda s: None,
    )
    with pytest.raises(GitHubAPIError, match="500"):
        always.get_json("/x", token=SecretStr("tok-123456789"))


def test_network_errors_become_github_errors() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = GitHubClient(
        API, transport=httpx.MockTransport(boom), max_retries=1, sleep=lambda s: None
    )
    with pytest.raises(GitHubAPIError, match="network error"):
        client.get_json("/x", token=SecretStr("tok-123456789"))


def test_only_https_api_bases() -> None:
    with pytest.raises(ValueError):
        GitHubClient("http://api.github.com")


# -- discovery ------------------------------------------------------------------------------------
def test_installations_hide_suspended_and_can_be_found_by_account(app: GitHubApp) -> None:
    names = [i.account for i in app.discovery.list_installations()]
    assert names == ["acme", "Bob"]
    found = app.discovery.find_installation("ACME")
    assert found is not None and found.id == 1 and found.account_type == "Organization"
    assert app.discovery.find_installation("nobody") is None


def test_repository_and_branch_pickers_use_an_installation_token(
    app: GitHubApp, gh: FakeGitHub
) -> None:
    repos = app.discovery.list_repositories(1)
    assert [r.full_name for r in repos] == ["acme/shop", "acme/api"]
    branches = app.discovery.list_branches(1, "acme", "shop")
    assert [(b.name, b.is_default, b.protected) for b in branches] == [
        ("trunk", True, True),
        ("feature/x", False, False),
    ]
    assert gh.minted == 1  # one token served both pickers


def test_installation_lookup_for_a_repo(app: GitHubApp) -> None:
    assert app.discovery.installation_for_repo("acme", "shop") == 1
    with pytest.raises(NotFoundError):
        app.discovery.installation_for_repo("acme", "missing")


def test_discovery_rejects_path_injection_before_any_request(
    app: GitHubApp, gh: FakeGitHub
) -> None:
    for owner, repo in [("../x", "r"), ("o", "r/../../admin"), ("o", "")]:
        with pytest.raises(InvalidKeyError):
            app.discovery.list_branches(1, owner, repo)
        with pytest.raises(InvalidKeyError):
            app.discovery.installation_for_repo(owner, repo)
    assert gh.requests == []


# -- the app facade: any app, many apps ------------------------------------------------------------
def test_from_env_accepts_inline_or_file_keys_and_ghes(tmp_path: Any) -> None:
    inline = GitHubApp.from_env(
        env={
            "TRIGPOINT_GITHUB_APP_ID": APP_ID,
            "TRIGPOINT_GITHUB_PRIVATE_KEY": PEM.replace("\n", "\\n"),
        }
    )
    assert inline.signer.app_id == APP_ID and inline.endpoints == GitHubEndpoints.github_com()
    key_file = tmp_path / "key.pem"
    key_file.write_text(PEM)
    ghes = GitHubApp.from_env(
        "X_",
        env={
            "X_APP_ID": "42",
            "X_PRIVATE_KEY_PATH": str(key_file),
            "X_GHES_HOST": "ghe.corp.example",
        },
    )
    assert ghes.endpoints.api_base == "https://ghe.corp.example/api/v3"
    assert ghes.endpoints.git_base_url == "https://ghe.corp.example"
    with pytest.raises(ValueError, match="APP_ID"):
        GitHubApp.from_env(env={})
    with pytest.raises(ValueError, match="PRIVATE_KEY"):
        GitHubApp.from_env(env={"TRIGPOINT_GITHUB_APP_ID": "1"})
    with pytest.raises(ValueError):
        GitHubEndpoints.enterprise_server("evil.example/path?x")


def test_two_apps_in_one_process_do_not_share_tokens() -> None:
    gh1, gh2 = FakeGitHub(), FakeGitHub()
    a = GitHubApp(APP_ID, PEM, client=make_client(gh1))
    b = GitHubApp(APP_ID, PEM, client=make_client(gh2))
    assert a.tokens.get(1).token.reveal() != "" and b.tokens.get(1).token.reveal() != ""
    assert (gh1.minted, gh2.minted) == (1, 1)


def test_token_provider_feeds_the_git_runner_with_a_host_scoped_header(app: GitHubApp) -> None:
    provide = app.token_provider(1, repositories=["shop"])
    token = provide()
    assert isinstance(token, SecretStr) and provide().reveal() == token.reveal()  # cached
    cfg = dict(GitRunner(base_url=app.endpoints.git_base_url).config(token))
    assert "http.https://github.com/.extraheader" in cfg
    assert token.reveal() not in "".join(cfg.keys())


def test_static_token_provider() -> None:
    assert static_token_provider(None)() is None
    assert static_token_provider("pat-123456789")().reveal() == "pat-123456789"  # type: ignore[union-attr]
