"""Scanner tests. Fake secrets are assembled at runtime so this file itself is not a
credential-shaped string that repo scanners would flag."""

from __future__ import annotations

import time

import pytest

from trigpoint.security import apply_redactions, scan

ALNUM = "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY"


def rules(text: str) -> list[str]:
    return [f.rule for f in scan(text)]


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("key = " + "AKIA" + "IOSFODNN7EXAMPLE", "aws_access_key_id"),
        ("t=" + "ghp_" + "a1" * 18, "github_token"),
        ("t=" + "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1", "github_token"),
        ("t=" + "xoxb-" + "1234567890-abcdefghij", "slack_token"),
        ("k=" + "sk_live_" + "abcdefghijklmnop1234", "stripe_key"),
        ("k=" + "AIza" + "SyA-1234567890abcdefghijklmnopqrstu", "google_api_key"),
        ("k=" + "sk-ant-" + "api03-" + "a1B2" * 10, "llm_api_key"),
        (
            "jwt="
            + "eyJhbGciOiJIUzI1NiJ9"
            + "."
            + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            + "."
            + "abcdefghijk",
            "jwt",
        ),
        ("Authorization: Bearer " + "abcdEFGH1234ijklMNOP5678", "bearer_token"),
    ],
)
def test_provider_patterns(text: str, rule: str) -> None:
    assert rule in rules(text)


def test_private_key_block_is_fully_redacted() -> None:
    begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
    end = "-----END " + "RSA PRIVATE KEY-----"
    text = f"before\n{begin}\nMIIEowIBAAKCAQEA\nabc123\n{end}\nafter"
    out = apply_redactions(text, scan(text))
    assert "MIIEow" not in out
    assert out.startswith("before\n[REDACTED:private_key_block]")
    assert out.endswith("\nafter")


def test_truncated_private_key_block_is_redacted() -> None:
    text = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    out = apply_redactions(text, scan(text))
    assert "MIIEvQ" not in out


def test_connection_string_redacts_only_the_password() -> None:
    text = "DATABASE_URL=postgres://app:" + "s3cretPw99" + "@db.internal:5432/main"
    out = apply_redactions(text, scan(text))
    assert "s3cretPw99" not in out
    assert "db.internal:5432/main" in out


@pytest.mark.parametrize(
    "text",
    [
        'password = "hunter2hunter2"',
        "api_key: 'abcd1234efgh5678'",
        '"client_secret": "zxcvbnm12345"',
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_secret_assignments(text: str) -> None:
    assert apply_redactions(text, scan(text)) != text


def test_high_entropy_token_flagged() -> None:
    assert "high_entropy" in rules(f"x {ALNUM} y")


@pytest.mark.parametrize(
    "text",
    [
        # git SHAs / checksums: pure hex is never flagged
        "commit " + "a" * 40,
        "sha256:" + "0123456789abcdef" * 4,
        "id 123e4567-e89b-12d3-a456-426614174000",
        # npm lockfile integrity
        "integrity sha512-" + "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo=",
        # identifiers and paths
        "def get_user_account_settings_by_identifier():",
        "src/trigpoint/security/scanner_module",
        "getUserAccountSettingsByIdentifierValue",
        # placeholders and code references
        "password = ${DB_PASSWORD}",
        'password = "<your-password>"',
        'token = os.environ["TOKEN"]',
        "password = some_function",
        'tokenizer = "bert-base-uncased"',
        "max_tokens = 4096",
        "postgres://user:password@localhost/db",
    ],
)
def test_no_false_positive(text: str) -> None:
    assert scan(text) == [], text


def test_overlapping_findings_are_merged() -> None:
    token = "ghp_" + "a1" * 18
    text = f'github_token = "{token}"'
    out = apply_redactions(text, scan(text))
    assert token not in out
    assert out.count("[REDACTED") == 1


def test_scan_is_linear_enough_on_adversarial_input() -> None:
    nasty = ("password" + "a" * 50 + "=") * 2000 + "-" * 100_000
    start = time.perf_counter()
    scan(nasty)
    assert time.perf_counter() - start < 5
