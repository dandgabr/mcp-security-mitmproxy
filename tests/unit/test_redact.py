"""Unit tests for secret redaction (R4, SEC-1/SEC-2)."""

from __future__ import annotations

import json

from mitmproxy.test import tflow

from mcp_security_mitmproxy.core.redact import REDACTED, redact_headers, redact_text
from mcp_security_mitmproxy.flows.manager import export_flow_offline
from mcp_security_mitmproxy.schemas.common import ExportFormat


def test_redact_headers_masks_sensitive_headers() -> None:
    headers = [
        ["Host", "example.com"],
        ["Authorization", "Bearer eyJhbGciOi..."],
        ["Proxy-Authorization", "Basic dXNlcjpwYXNz"],
        ["Cookie", "session=12345; auth=abcdef"],
        ["X-Api-Key", "secret-key-xyz"],
        ["Content-Type", "application/json"],
    ]
    redacted = redact_headers(headers)
    assert redacted[0] == ["Host", "example.com"]
    assert redacted[1] == ["Authorization", "[REDACTED]"]
    assert redacted[2] == ["Proxy-Authorization", "[REDACTED]"]
    assert redacted[3] == ["Cookie", "[REDACTED]"]
    assert redacted[4] == ["X-Api-Key", "[REDACTED]"]
    assert redacted[5] == ["Content-Type", "application/json"]


def test_redact_text_masks_bearer_and_secrets() -> None:
    raw = '{"access_token": "my-secret-token", "message": "Bearer abc.def.ghi"}'
    res = redact_text(raw)
    assert "my-secret-token" not in res
    assert "abc.def.ghi" not in res
    assert "[REDACTED]" in res


def test_redact_headers_masks_broad_sensitive_names() -> None:
    headers = [
        ["Host", "example.com"],
        ["Content-Type", "application/json"],
        ["X-Custom-Auth", "custom-value"],
        ["Authentication", "auth-value"],
        ["X-Amz-Security-Token", "amz-token-value"],
        ["X-Session-Key", "session-key-value"],
        ["Set-Cookie", "sid=abc"],
    ]
    redacted = dict(redact_headers(headers))
    assert redacted["Host"] == "example.com"
    assert redacted["Content-Type"] == "application/json"
    for name in (
        "X-Custom-Auth",
        "Authentication",
        "X-Amz-Security-Token",
        "X-Session-Key",
        "Set-Cookie",
    ):
        assert redacted[name] == REDACTED


def test_redact_text_masks_all_token_shapes() -> None:
    raw = "\n".join(
        [
            "Basic dXNlcjpwYXNz",
            "Bearer abc.def.ghi",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "AKIAIOSFODNN7EXAMPLE",
            "sk-abcdefghij1234567890",
        ]
    )
    redacted = redact_text(raw)
    assert "dXNlcjpwYXNz" not in redacted
    assert "abc.def.ghi" not in redacted
    assert "eyJhbGciOiJIUzI1NiJ9" not in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "sk-abcdefghij1234567890" not in redacted
    assert redacted.count(REDACTED) == 5


def test_redact_text_masks_embedded_header_lines() -> None:
    raw = "curl -H 'Authorization: x-secret-value' -H 'Cookie: session=abc123' http://example.com"
    redacted = redact_text(raw)
    assert "x-secret-value" not in redacted
    assert "session=abc123" not in redacted
    assert "Authorization: [REDACTED]" in redacted
    assert "Cookie: [REDACTED]" in redacted


def test_redact_text_preserves_json_validity() -> None:
    raw = '{"password": "p@ss word"}'
    redacted = redact_text(raw)
    assert "p@ss word" not in redacted
    assert json.loads(redacted) == {"password": REDACTED}


def test_redact_text_preserves_nested_json() -> None:
    raw = '{"api_key": "abc-123", "nested": {"access_token": "tok-xyz"}, "safe": "keep"}'
    redacted = redact_text(raw)
    assert json.loads(redacted) == {
        "api_key": REDACTED,
        "nested": {"access_token": REDACTED},
        "safe": "keep",
    }


def test_redact_text_masks_quoted_header_values() -> None:
    for raw in ("Authorization: 'opaque-token'", 'Authorization: "opaque-token"'):
        redacted = redact_text(raw)
        assert "opaque-token" not in redacted
        assert REDACTED in redacted


def test_redact_text_masks_json_authorization_and_cookie_keys() -> None:
    assert json.loads(redact_text('{"Authorization": "opaque-token"}')) == {
        "Authorization": REDACTED
    }
    assert json.loads(redact_text('{"Cookie": "sid=abc"}')) == {"Cookie": REDACTED}


def test_exported_flow_credentials_are_redacted() -> None:
    flow = tflow.tflow(resp=True)
    flow.request.headers["Authorization"] = "Bearer super-secret-token"
    flow.request.headers["Cookie"] = "session=abc123"
    flow.response.headers["Set-Cookie"] = "sid=xyz"

    for fmt in (ExportFormat.CURL, ExportFormat.HTTPIE, ExportFormat.RAW):
        exported = export_flow_offline(flow, fmt)
        assert "super-secret-token" in exported  # the raw export does carry the secret

        sanitized = redact_text(exported)
        assert "super-secret-token" not in sanitized
        assert "session=abc123" not in sanitized
        assert "sid=xyz" not in sanitized
        assert REDACTED in sanitized


def test_redact_text_masks_dynamic_sensitive_header_names() -> None:
    """The embedded-header rule uses the same token heuristic as redact_headers."""
    for line in (
        "Authentication: opaque",
        "X-Custom-Auth: opaque",
        "X-Goog-Api-Key: opaque",
        "X-Amz-Security-Token: opaque",
        "Proxy-Authorization: opaque",
    ):
        redacted = redact_text(line)
        assert "opaque" not in redacted, line
        assert REDACTED in redacted, line


def test_redact_text_keeps_non_sensitive_header_lines() -> None:
    text = "Content-Type: application/json"
    assert redact_text(text) == text


def test_redact_text_masks_pem_blocks() -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
        "-----END PRIVATE KEY-----"
    )
    redacted = redact_text(f"body:\n{pem}\ntrailer")
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" not in redacted
    assert "BEGIN PRIVATE KEY" not in redacted
    assert "trailer" in redacted
    assert REDACTED in redacted


def test_redact_text_masks_rsa_and_certificate_pem() -> None:
    for label in ("RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "CERTIFICATE"):
        pem = f"-----BEGIN {label}-----\nSECRETMATERIAL\n-----END {label}-----"
        redacted = redact_text(pem)
        assert "SECRETMATERIAL" not in redacted
        assert REDACTED in redacted
