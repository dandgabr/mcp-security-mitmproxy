"""Security helpers for secret redaction (R4).

Prevents accidental exposure of credentials, authorization tokens, API keys,
session cookies and private key material when inspection/export tools return
data to agents. Anything the agent receives that may carry a secret passes
through here first.

Redaction is fail-closed: a header whose name merely *looks* sensitive is masked
rather than passed through, and a payload match replaces the whole value while
preserving the surrounding syntax (quotes included) so JSON/YAML stays parseable.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# A header is sensitive when its (lowercased) name contains any of these tokens.
# Substring matching is deliberate and fail-closed: "authorization", "cookie",
# "x-api-key", "x-custom-auth", "x-amz-security-token", "authentication", etc.
_SENSITIVE_HEADER_TOKENS: tuple[str, ...] = (
    "auth",
    "token",
    "key",
    "secret",
    "cookie",
    "credential",
    "password",
)

# Bearer / Basic schemes (Authorization and Proxy-Authorization).
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
_BASIC_PATTERN = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/]+=*")

# Bare JSON Web Tokens: three base64url segments, the first starting with "eyJ".
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# Cloud/provider API key shapes.
_AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_OPENAI_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b")

# key: value / key=value pairs whose key names a secret. The value is captured
# in full — including quoted values with spaces — so we never corrupt JSON.
_SECRET_KEY_NAMES = (
    r"authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|"
    r"access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|password|passwd|"
    r"secret|client[_-]?secret|private[_-]?key|auth[_-]?token|token"
)
_KEY_VALUE_SECRET_PATTERN = re.compile(
    r"(?i)(\"?(?:" + _SECRET_KEY_NAMES + r")\"?\s*[:=]\s*)"
    r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s&,;]+)"
)

# Header-style lines embedded in exported text (curl -H 'Authorization: ...',
# raw/httpie dumps). Rather than a fixed enumeration, the name is captured and
# checked with the same dynamic token heuristic as ``redact_headers`` — so
# ``Authentication``, ``X-Custom-Auth``, ``Proxy-*`` and any future custom
# sensitive header are covered without editing a list.
_HEADER_LINE_PATTERN = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*:\s*(\"[^\"]*\"|'[^']*'|[^'\"\\\r\n]+)"
)

# PEM blocks (private keys, encrypted keys, certificates). Masked whole: a
# private key in an exported flow is the highest-value secret on the wire.
_PEM_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    re.DOTALL,
)


def _is_sensitive_header(name: str) -> bool:
    lower = name.lower()
    return any(token in lower for token in _SENSITIVE_HEADER_TOKENS)


def _mask_value(value: str) -> str:
    """Replace a value with the mask, preserving surrounding quotes."""
    if value[:1] in ('"', "'") and value[-1:] == value[:1] and len(value) >= 2:
        return f"{value[0]}{REDACTED}{value[0]}"
    return REDACTED


def redact_headers(headers: list[list[str]] | tuple[Any, ...]) -> list[list[str]]:
    """Mask the value of every header whose name looks secret-bearing."""
    redacted: list[list[str]] = []
    for item in headers:
        if len(item) != 2:
            continue
        name, val = str(item[0]), str(item[1])
        redacted.append([name, REDACTED if _is_sensitive_header(name) else val])
    return redacted


def _redact_key_value(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_mask_value(match.group(2))}"


def _redact_header_line(match: re.Match[str]) -> str:
    name = match.group(1)
    if not _is_sensitive_header(name):
        return match.group(0)
    return f"{name}: {_mask_value(match.group(2))}"


def redact_text(text: str) -> str:
    """Redact tokens, passwords, JWTs, API keys and PEM blocks in a payload."""
    text = _PEM_PATTERN.sub(REDACTED, text)
    text = _BEARER_PATTERN.sub(f"Bearer {REDACTED}", text)
    text = _BASIC_PATTERN.sub(f"Basic {REDACTED}", text)
    text = _JWT_PATTERN.sub(REDACTED, text)
    text = _AWS_ACCESS_KEY_PATTERN.sub(REDACTED, text)
    text = _OPENAI_KEY_PATTERN.sub(REDACTED, text)
    text = _HEADER_LINE_PATTERN.sub(_redact_header_line, text)
    text = _KEY_VALUE_SECRET_PATTERN.sub(_redact_key_value, text)
    return text


__all__ = ["REDACTED", "redact_headers", "redact_text"]
