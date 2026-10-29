"""Security primitives: path policy, secret scanning/redaction, fencing, limits."""

from trigpoint.security.fence import (
    FencedContent,
    InjectionFlag,
    detect_injection,
    fence_untrusted,
    sanitize_text,
)
from trigpoint.security.limits import Limits
from trigpoint.security.paths import (
    SECRET_PATH_PATTERNS,
    PathPolicy,
    read_text_safely,
    resolve_within,
    sparse_checkout_patterns,
)
from trigpoint.security.redact import (
    RedactingFilter,
    Redactor,
    install_log_redaction,
    redact_dataclass,
)
from trigpoint.security.registry import SecretRegistry, default_registry
from trigpoint.security.scanner import Finding, apply_redactions, scan, shannon_entropy
from trigpoint.security.secretstr import SecretStr

__all__ = [
    "SECRET_PATH_PATTERNS",
    "FencedContent",
    "Finding",
    "InjectionFlag",
    "Limits",
    "PathPolicy",
    "RedactingFilter",
    "Redactor",
    "SecretRegistry",
    "SecretStr",
    "apply_redactions",
    "default_registry",
    "detect_injection",
    "fence_untrusted",
    "install_log_redaction",
    "read_text_safely",
    "redact_dataclass",
    "resolve_within",
    "sanitize_text",
    "scan",
    "sparse_checkout_patterns",
    "shannon_entropy",
]
