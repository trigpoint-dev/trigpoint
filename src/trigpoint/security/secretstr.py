"""A string wrapper that refuses to reveal itself by accident."""

from __future__ import annotations

import hmac
from typing import NoReturn

from trigpoint.security.registry import SecretRegistry, default_registry

_MASK = "**********"


class SecretStr:
    """Holds a secret. ``repr``/``str``/``format`` are masked; pickling is refused.

    The only way to read the value is ``reveal()``, so every use is greppable. On creation
    the value is added to a ``SecretRegistry`` so it is scrubbed if it leaks into text anyway.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str, *, registry: SecretRegistry | None = default_registry) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretStr requires a str")
        self._value = value
        if registry is not None:
            registry.add(value)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"SecretStr('{_MASK}')"

    def __str__(self) -> str:
        return _MASK

    def __format__(self, format_spec: str) -> str:
        return _MASK

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretStr):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = None  # type: ignore[assignment]

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretStr cannot be pickled")

    def __copy__(self) -> SecretStr:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> SecretStr:
        return self
