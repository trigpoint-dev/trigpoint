"""Registry of exact secret values that must never appear in any output.

Pattern scanning catches secrets we can recognise; the registry catches the ones we
*know*, such as an installation token we just minted, whatever they look like.
"""

from __future__ import annotations

import threading
from collections import OrderedDict


class SecretRegistry:
    """Bounded, thread-safe set of known secret strings."""

    def __init__(self, max_entries: int = 1024, min_length: int = 8) -> None:
        self._max_entries = max_entries
        self._min_length = min_length
        self._values: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, value: str) -> None:
        # Very short values would shred ordinary text when scrubbed.
        if len(value) < self._min_length:
            return
        with self._lock:
            self._values.pop(value, None)
            self._values[value] = None
            while len(self._values) > self._max_entries:
                self._values.popitem(last=False)

    def scrub(self, text: str, marker: str = "[REDACTED:registered]") -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for value in values:
            if value in text:
                text = text.replace(value, marker)
        return text

    def clear(self) -> None:
        with self._lock:
            self._values.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)


default_registry = SecretRegistry()
