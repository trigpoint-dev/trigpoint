"""Redaction: registry scrub + pattern scan, for strings, structures and logs."""

from __future__ import annotations

import logging
from typing import Any

from trigpoint.security.registry import SecretRegistry, default_registry
from trigpoint.security.scanner import Finding, apply_redactions, scan

OVERSIZE_MARKER = "[REDACTED:oversize]"


class Redactor:
    """Applies the known-secret registry, then the pattern scanner.

    Fails closed: text longer than ``max_chars`` is replaced wholesale rather than being
    passed through unscanned.
    """

    def __init__(
        self,
        registry: SecretRegistry | None = None,
        *,
        entropy: bool = True,
        max_chars: int = 5_000_000,
    ) -> None:
        self._registry = registry if registry is not None else default_registry
        self._entropy = entropy
        self._max_chars = max_chars

    def redact_with_findings(self, text: str) -> tuple[str, list[Finding]]:
        if len(text) > self._max_chars:
            return OVERSIZE_MARKER, [Finding("oversize", 0, len(text))]
        text = self._registry.scrub(text)
        findings = scan(text, entropy=self._entropy)
        return apply_redactions(text, findings), findings

    def redact(self, text: str) -> str:
        return self.redact_with_findings(text)[0]

    def redact_obj(self, obj: Any) -> Any:
        """Redact every string in nested dict/list/tuple structures (keys included)."""
        if isinstance(obj, str):
            return self.redact(obj)
        if isinstance(obj, dict):
            return {self.redact_obj(k): self.redact_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact_obj(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.redact_obj(v) for v in obj)
        return obj


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs the message and any traceback.

    Attach it to *handlers* (a logger-level filter does not see child loggers' records).
    """

    def __init__(self, redactor: Redactor | None = None) -> None:
        super().__init__()
        self._redactor = redactor or Redactor()

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redactor.redact(record.getMessage())
        record.args = None
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self._redactor.redact(formatted)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = self._redactor.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = self._redactor.redact(record.stack_info)
        return True


def install_log_redaction(handler: logging.Handler, redactor: Redactor | None = None) -> None:
    """Attach a ``RedactingFilter`` to ``handler``."""
    handler.addFilter(RedactingFilter(redactor))
