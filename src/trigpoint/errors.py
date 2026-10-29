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
