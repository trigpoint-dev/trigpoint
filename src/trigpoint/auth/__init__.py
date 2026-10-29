"""GitHub App authentication and discovery. Needs ``pip install 'trigpoint[github]'``."""

from trigpoint.auth.app import GitHubApp
from trigpoint.auth.app_jwt import AppJwtSigner
from trigpoint.auth.client import GitHubClient, GitHubEndpoints
from trigpoint.auth.discovery import Branch, Discovery, Installation, Repository
from trigpoint.auth.installation_token import InstallationToken, InstallationTokenProvider
from trigpoint.auth.static import static_token_provider

__all__ = [
    "AppJwtSigner",
    "Branch",
    "Discovery",
    "GitHubApp",
    "GitHubClient",
    "GitHubEndpoints",
    "Installation",
    "InstallationToken",
    "InstallationTokenProvider",
    "Repository",
    "static_token_provider",
]
