"""Exception hierarchy. Everything trigpoint raises deliberately derives from TrigpointError."""

from __future__ import annotations


class TrigpointError(Exception):
    """Base class for all trigpoint errors."""


class SecurityError(TrigpointError):
    """A security policy refused the operation."""


class PathEscapeError(SecurityError):
    """A path resolved outside its allowed root, or was malformed."""


class SecretPathError(SecurityError):
    """A path is secret-adjacent (or gitignored) and must not be read."""


class LimitExceededError(SecurityError):
    """A configured resource limit was exceeded."""


class SchemaError(TrigpointError):
    """A serialized document has an unsupported version or is malformed."""


class InvalidKeyError(TrigpointError, ValueError):
    """A cache key or repository identifier failed validation."""


class GitError(TrigpointError):
    """A git invocation failed. ``stderr`` is already redacted."""

    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(f"{message}: {stderr}" if stderr else message)
        self.returncode = returncode
        self.stderr = stderr


class GitVersionError(GitError):
    """The installed git is too old for the required hardening."""


class BranchNotFoundError(TrigpointError):
    """The requested branch does not exist on the remote."""


class LockTimeoutError(TrigpointError):
    """A repository lock could not be acquired in time."""


class GitHubAPIError(TrigpointError):
    """The GitHub API returned an error. ``message`` is already redacted."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthError(GitHubAPIError):
    """Bad, expired or insufficient credentials (HTTP 401 / non-rate-limit 403)."""


class NotFoundError(GitHubAPIError):
    """HTTP 404. GitHub also returns this for repos the credential cannot see."""


class RateLimitError(GitHubAPIError):
    """Rate limited and the required wait exceeds the configured maximum."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message, status=429)
        self.retry_after = retry_after


class LLMError(TrigpointError):
    """An LLM provider call failed. The message is already redacted."""
