"""Resource limits applied while reading and parsing untrusted repositories."""

from __future__ import annotations

from dataclasses import dataclass

from trigpoint.errors import LimitExceededError


@dataclass(frozen=True, slots=True)
class Limits:
    """Caps that bound the cost of processing a hostile or oversized repo."""

    max_file_bytes: int = 1_000_000
    max_files: int = 100_000
    max_total_bytes: int = 1024**3
    git_timeout_s: float = 300.0
    extractor_timeout_s: float = 10.0

    def __post_init__(self) -> None:
        for name in ("max_file_bytes", "max_files", "max_total_bytes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("git_timeout_s", "extractor_timeout_s"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def check_file_size(self, size: int, path: str) -> None:
        if size > self.max_file_bytes:
            raise LimitExceededError(
                f"{path}: {size} bytes exceeds max_file_bytes={self.max_file_bytes}"
            )

    def check_file_count(self, count: int) -> None:
        if count > self.max_files:
            raise LimitExceededError(f"{count} files exceeds max_files={self.max_files}")

    def check_total_bytes(self, total: int) -> None:
        if total > self.max_total_bytes:
            raise LimitExceededError(
                f"{total} bytes exceeds max_total_bytes={self.max_total_bytes}"
            )
