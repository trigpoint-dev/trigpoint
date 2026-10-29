from __future__ import annotations

import copy
import logging
import pickle

import pytest

from trigpoint.security import (
    RedactingFilter,
    Redactor,
    SecretRegistry,
    SecretStr,
)

TOKEN = "ghs_" + "Zx9" * 12


def test_secretstr_masks_everywhere() -> None:
    s = SecretStr(TOKEN, registry=None)
    assert TOKEN not in repr(s)
    assert TOKEN not in str(s)
    assert TOKEN not in f"{s}"
    assert TOKEN not in f"{s!r:>40}"
    assert s.reveal() == TOKEN


def test_secretstr_refuses_pickle_and_survives_copy() -> None:
    s = SecretStr(TOKEN, registry=None)
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert copy.deepcopy(s).reveal() == TOKEN


def test_secretstr_equality_and_unhashable() -> None:
    a, b = SecretStr("same-value-1", registry=None), SecretStr("same-value-1", registry=None)
    assert a == b
    assert a != SecretStr("other-value-2", registry=None)
    with pytest.raises(TypeError):
        hash(a)


def test_registry_scrubs_exact_values_even_if_unrecognisable() -> None:
    reg = SecretRegistry()
    SecretStr("plainlooking", registry=reg)
    out = Redactor(reg).redact("leaked plainlooking here")
    assert "plainlooking" not in out


def test_registry_ignores_short_values_and_is_bounded() -> None:
    reg = SecretRegistry(max_entries=2)
    reg.add("short")
    assert len(reg) == 0
    for v in ("value-aaaa", "value-bbbb", "value-cccc"):
        reg.add(v)
    assert len(reg) == 2
    assert reg.scrub("value-aaaa") == "value-aaaa"  # oldest was evicted
    assert "value-cccc" not in reg.scrub("value-cccc")


def test_redactor_fails_closed_on_oversize() -> None:
    assert Redactor(SecretRegistry(), max_chars=10).redact("x" * 11) == "[REDACTED:oversize]"


def test_redact_obj_walks_structures() -> None:
    r = Redactor(SecretRegistry())
    out = r.redact_obj({"a": ["token=" + "abcd1234efgh5678"], "n": 3})
    assert "abcd1234efgh5678" not in str(out)
    assert out["n"] == 3


def test_log_filter_scrubs_message_args_and_traceback() -> None:
    reg = SecretRegistry()
    SecretStr(TOKEN, registry=reg)
    logger = logging.getLogger("trigpoint.test.redact")
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    records: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = Capture()
    handler.addFilter(RedactingFilter(Redactor(reg)))
    logger.addHandler(handler)
    try:
        try:
            raise RuntimeError(f"boom {TOKEN}")
        except RuntimeError:
            logger.exception("failed with %s", TOKEN)
    finally:
        logger.removeHandler(handler)
    assert records
    assert TOKEN not in records[0]
