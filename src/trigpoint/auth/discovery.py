"""Discovery: which installations exist, which repos each can see, and their branches.

Works for any GitHub App. Nothing here is tied to a particular org or account; whatever the
app is installed on is what you get back.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from trigpoint.auth.app_jwt import AppJwtSigner
from trigpoint.auth.client import GitHubClient
from trigpoint.auth.installation_token import InstallationTokenProvider
from trigpoint.cache.keys import _check_name
from trigpoint.errors import GitHubAPIError


@dataclass(frozen=True, slots=True)
class Installation:
    id: int
    account: str  # org or user login
    account_type: str  # "Organization" | "User"
    repository_selection: str  # "all" | "selected"
    suspended: bool


@dataclass(frozen=True, slots=True)
class Repository:
    owner: str
    name: str
    default_branch: str
    private: bool
    archived: bool
    fork: bool

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True, slots=True)
class Branch:
    name: str
    sha: str
    protected: bool
    is_default: bool


def _installation(d: dict[str, Any]) -> Installation:
    account = d.get("account") or {}
    return Installation(
        id=int(d["id"]),
        account=str(account.get("login", "")),
        account_type=str(account.get("type", "")),
        repository_selection=str(d.get("repository_selection", "")),
        suspended=d.get("suspended_at") is not None,
    )


def _repository(d: dict[str, Any]) -> Repository:
    return Repository(
        owner=str(d["owner"]["login"]),
        name=str(d["name"]),
        default_branch=str(d.get("default_branch") or "main"),
        private=bool(d.get("private", False)),
        archived=bool(d.get("archived", False)),
        fork=bool(d.get("fork", False)),
    )


class Discovery:
    """Backs an installation picker, a repo picker and a branch picker."""

    def __init__(
        self, signer: AppJwtSigner, client: GitHubClient, tokens: InstallationTokenProvider
    ) -> None:
        self._signer = signer
        self._client = client
        self._tokens = tokens

    def list_installations(self, *, include_suspended: bool = False) -> list[Installation]:
        """Every installation of this app (authenticated as the app itself)."""
        found = [
            _installation(d)
            for d in self._client.paginate("/app/installations", token=self._signer.token())
        ]
        return [i for i in found if include_suspended or not i.suspended]

    def find_installation(self, account: str) -> Installation | None:
        """The installation on an org/user login (case-insensitive), if the app has one."""
        wanted = account.lower()
        return next((i for i in self.list_installations() if i.account.lower() == wanted), None)

    def installation_for_repo(self, owner: str, repo: str) -> int:
        """Installation id that covers ``owner/repo``. NotFoundError if the app can't see it."""
        o, r = quote(_check_name("owner", owner)), quote(_check_name("repo", repo))
        path = f"/repos/{o}/{r}/installation"
        data = self._client.get_json(path, token=self._signer.token())
        try:
            return int(data["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GitHubAPIError("unexpected installation response") from exc

    def list_repositories(self, installation_id: int) -> list[Repository]:
        token = self._tokens.get(installation_id).token
        return [
            _repository(d)
            for d in self._client.paginate(
                "/installation/repositories", token=token, items_key="repositories"
            )
        ]

    def list_branches(self, installation_id: int, owner: str, repo: str) -> list[Branch]:
        owner, repo = _check_name("owner", owner), _check_name("repo", repo)
        token = self._tokens.get(installation_id).token
        base = f"/repos/{quote(owner)}/{quote(repo)}"
        default = str(self._client.get_json(base, token=token).get("default_branch", ""))
        return [
            Branch(
                name=str(b["name"]),
                sha=str(b["commit"]["sha"]),
                protected=bool(b.get("protected", False)),
                is_default=b["name"] == default,
            )
            for b in self._client.paginate(f"{base}/branches", token=token)
        ]
