"""Fase 4 rule engine — pure compilation of Pydantic specs into native options.

No I/O, no network, no ``mitmweb`` dependency: the functions here turn validated
contracts (:mod:`mcp_security_miproxy.schemas.rules` — note the package name
below) into the delimited strings mitmproxy stores in ``map_remote``,
``map_local``, ``modify_headers`` and ``modify_body``. Applying them over REST
is the tool layer's job.

Native grammar (``mitmproxy.utils.spec.parse_spec``)::

    [/flow-filter]/subject/replacement

The separator is the option's **first character** and the remainder is split in
two (no filter) or three (with filter). If the separator also occurs inside the
filter, subject or replacement, the spec is silently reinterpreted — so
:func:`select_delimiter` picks a character absent from *every* field.
"""

from __future__ import annotations

from typing import Any

from mitmproxy.utils.spec import parse_spec
from mitmproxy.utils.strutils import escaped_str_to_bytes

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.schemas.rules import (
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    ModifyBodyRuleSpec,
    ModifyHeaderRuleSpec,
    RuleEntry,
    RuleType,
)

# Ordered by preference: punctuation that rarely appears in URLs, regexes and
# flow-filter expressions. A full printable-ASCII sweep is the fallback.
_DELIMITER_CANDIDATES = "|!;,^%#@&~?$:*+=/"


def select_delimiter(*fields: str) -> str:
    """Return a single character absent from every field.

    Raises :class:`InvalidInputError` if even the full printable ASCII range
    collides (practically impossible, but fail-closed rather than emit a spec
    that mitmproxy would misparse).
    """
    for char in _DELIMITER_CANDIDATES:
        if all(char not in field for field in fields):
            return char
    for code in range(33, 127):
        char = chr(code)
        if all(char not in field for field in fields):
            return char
    raise InvalidInputError("no delimiter available: fields cover all printable ASCII")


def _join(filter_expression: str | None, subject: str, replacement: str) -> str:
    """Assemble one native spec string with a collision-free delimiter."""
    delimiter = select_delimiter(filter_expression or "", subject, replacement)
    if filter_expression:
        return f"{delimiter}{filter_expression}{delimiter}{subject}{delimiter}{replacement}"
    return f"{delimiter}{subject}{delimiter}{replacement}"


def _escape_backslashes(value: str) -> str:
    """Double every backslash so a literal value survives mitmproxy's decoding.

    ``modify_headers``/``modify_body`` run the replacement (and the body pattern
    as subject) through ``strutils.escaped_str_to_bytes`` — a C-escape decoder.
    Composing the spec with the user's literal text directly would reinterpret
    ``\\b`` as backspace, ``\\r\\n`` as CRLF, ``\\`` as a lone backslash, and so
    on. Escaping backslashes makes the round-trip lossless: the bytes mitmproxy
    finally sees are exactly the user's field.
    """
    return value.replace("\\", "\\\\")


def _wire_bytes(value: str) -> bytes:
    """Return the bytes mitmproxy will use after decoding ``value``.

    ``escaped_str_to_bytes`` is the exact function ``parse_modify_spec`` calls,
    so validating on this output guarantees semantic parity by construction.
    """
    try:
        return escaped_str_to_bytes(value)
    except ValueError as exc:
        raise InvalidInputError(f"invalid escape sequence: {exc}") from exc


def _reject_control_bytes(value: str, *, field: str) -> None:
    """Refuse a replacement whose decoded bytes contain CR, LF or a control char.

    On the header path this is the header-injection / response-splitting guard:
    ``safe\\r\\nX-Evil: pwned`` decodes to a real CRLF and would split the value
    into a forged second header. Rejecting on the decoded bytes means no escape
    spelling can slip a control character through. Horizontal tab (0x09) is
    permitted: RFC 9110 allows HTAB inside a field value and it is not a
    separator, so it cannot forge a header.
    """
    decoded = _wire_bytes(value)
    offending = sorted({byte for byte in decoded if (byte < 0x20 and byte != 0x09) or byte == 0x7F})
    if offending:
        raise InvalidInputError(
            f"{field} decodes to control characters ({', '.join(hex(b) for b in offending)}); "
            "header-injection / response-splitting is not permitted",
            detail={"field": field, "control_bytes": [hex(b) for b in offending]},
        )


def format_map_remote_spec(rule: MapRemoteRuleSpec) -> str:
    return _join(rule.filter_expression, rule.url_pattern, rule.replacement_url)


def format_map_local_spec(rule: MapLocalRuleSpec, canonical_path: str) -> str:
    """Compile a map_local rule using the already-allowlisted canonical path."""
    return _join(rule.filter_expression, rule.url_pattern, canonical_path)


def format_modify_headers_spec(rule: ModifyHeaderRuleSpec) -> str:
    """Compile a modify_headers rule.

    ``REMOVE`` is expressed as an empty replacement: mitmproxy pops matching
    headers and re-adds nothing when the replacement is empty. The value is
    validated on its decoded bytes (no CR/LF/control) and backslash-escaped so
    the literal value survives mitmproxy's C-escape decoding.
    """
    replacement = rule.header_value if rule.header_value is not None else ""
    if replacement:
        _reject_control_bytes(replacement, field="header_value")
    return _join(rule.filter_expression, rule.header_name, _escape_backslashes(replacement))


def format_modify_body_spec(rule: ModifyBodyRuleSpec) -> str:
    """Compile a modify_body rule, escaping backslashes for a lossless round-trip.

    The body replacement may legitimately contain backslashes/newlines, so it is
    escaped rather than rejected; the pattern keeps regex semantics (``\\b`` stays
    ``\\b``) because its backslashes are doubled before mitmproxy decodes them.
    """
    return _join(
        rule.filter_expression,
        _escape_backslashes(rule.pattern),
        _escape_backslashes(rule.replacement),
    )


RULE_OPTION_KEYS: tuple[RuleType, ...] = (
    RuleType.MAP_REMOTE,
    RuleType.MAP_LOCAL,
    RuleType.MODIFY_HEADERS,
    RuleType.MODIFY_BODY,
)
_OPTION_KEYS = RULE_OPTION_KEYS


def _option_value(options: dict[str, Any], rule_type: RuleType) -> list[str]:
    """Extract the ``value`` list of one option from a ``GET /options`` payload.

    ``dump_dicts`` returns ``{name: {"value": [...], "default": [...], ...}}``;
    an unexpected shape yields an empty list rather than a crash.
    """
    entry = options.get(rule_type.value)
    if not isinstance(entry, dict):
        return []
    value = entry.get("value")
    return [str(item) for item in value] if isinstance(value, list) else []


def parse_options(options: dict[str, Any]) -> list[RuleEntry]:
    """Project a ``GET /options`` payload into flat :class:`RuleEntry` rows.

    ``valid`` is ``False`` when the stored spec no longer parses — a rule that
    drifted (e.g. an operator edited it out of band) is surfaced, not hidden.
    """
    entries: list[RuleEntry] = []
    for rule_type in _OPTION_KEYS:
        for index, raw_spec in enumerate(_option_value(options, rule_type)):
            entries.append(
                RuleEntry(
                    rule_type=rule_type,
                    index=index,
                    raw_spec=raw_spec,
                    valid=_is_valid_spec(raw_spec),
                )
            )
    return entries


def _is_valid_spec(raw_spec: str) -> bool:
    try:
        parse_spec(raw_spec)
    except Exception:  # noqa: BLE001 - drift detection, any parse failure counts
        return False
    return True


__all__ = [
    "RULE_OPTION_KEYS",
    "format_map_local_spec",
    "format_map_remote_spec",
    "format_modify_body_spec",
    "format_modify_headers_spec",
    "parse_options",
    "select_delimiter",
]
