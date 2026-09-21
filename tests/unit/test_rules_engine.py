"""Unit tests for the Fase 4 rules engine (pure compilation, round-trip)."""

from __future__ import annotations

import pytest
from mitmproxy.utils.spec import parse_spec
from pydantic import ValidationError

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.rules.engine import (
    format_map_local_spec,
    format_map_remote_spec,
    format_modify_body_spec,
    format_modify_headers_spec,
    parse_options,
    select_delimiter,
)
from mcp_security_mitmproxy.schemas.rules import (
    HeaderOperation,
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    ModifyBodyRuleSpec,
    ModifyHeaderRuleSpec,
    RuleType,
)


def test_select_delimiter_picks_absent_char() -> None:
    assert select_delimiter("abc", "def") == "|"


def test_select_delimiter_skips_collisions() -> None:
    # '|' occurs in the fields, so the next candidate ('!') is chosen.
    assert select_delimiter("a|b", "c") == "!"
    assert select_delimiter("a|b!c", "d") == ";"


def test_select_delimiter_collision_in_replacement() -> None:
    delimiter = select_delimiter("subject", "re|placement")
    assert delimiter not in "subjectre|placement"


def test_format_map_remote_round_trip() -> None:
    rule = MapRemoteRuleSpec(
        url_pattern=r"^https://api\.example\.com/(.*)$",
        replacement_url=r"https://staging.internal/\1",
    )
    spec = format_map_remote_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == rule.url_pattern
    assert replacement == rule.replacement_url


def test_format_map_remote_with_filter_round_trip() -> None:
    rule = MapRemoteRuleSpec(
        filter_expression="~m POST",
        url_pattern=r"^https://api\.example\.com/",
        replacement_url="https://staging.internal/",
    )
    spec = format_map_remote_spec(rule)
    flow_filter, subject, replacement = parse_spec(spec)
    assert callable(flow_filter)
    assert subject == rule.url_pattern
    assert replacement == rule.replacement_url


def test_format_map_remote_delimiter_collision_is_avoided() -> None:
    rule = MapRemoteRuleSpec(
        url_pattern=r"https://api.example.com/a|b",
        replacement_url="https://b.internal/x|y",
    )
    spec = format_map_remote_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == rule.url_pattern
    assert replacement == rule.replacement_url


def test_format_map_local_round_trip_uses_canonical_path() -> None:
    rule = MapLocalRuleSpec(url_pattern=r"/api/v1/user", local_path="/srv/mocks/user.json")
    spec = format_map_local_spec(rule, "/srv/mocks/user.json")
    _, subject, replacement = parse_spec(spec)
    assert subject == rule.url_pattern
    assert replacement == "/srv/mocks/user.json"


def test_format_modify_headers_set_round_trip() -> None:
    rule = ModifyHeaderRuleSpec(header_name="X-Trace", header_value="abc", filter_expression="~s")
    spec = format_modify_headers_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == "X-Trace"
    assert replacement == "abc"


def test_format_modify_headers_remove_renders_empty_replacement() -> None:
    rule = ModifyHeaderRuleSpec(header_name="X-Secret", operation=HeaderOperation.REMOVE)
    spec = format_modify_headers_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == "X-Secret"
    assert replacement == ""


def test_format_modify_body_round_trip() -> None:
    """The escaped spec must decode back to the user's exact pattern/replacement."""
    from mitmproxy.utils.strutils import escaped_str_to_bytes

    rule = ModifyBodyRuleSpec(pattern=r'"role":\s*"user"', replacement='"role": "admin"')
    spec = format_modify_body_spec(rule)
    _, subject, replacement = parse_spec(spec)
    # mitmproxy decodes C-escapes; the engine doubles backslashes so the wire
    # value equals the user's field verbatim.
    assert escaped_str_to_bytes(subject).decode() == rule.pattern
    assert escaped_str_to_bytes(replacement).decode() == rule.replacement


def test_format_modify_body_empty_replacement_round_trip() -> None:
    rule = ModifyBodyRuleSpec(pattern=r"secret-token", replacement="")
    spec = format_modify_body_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == rule.pattern
    assert replacement == ""


@pytest.mark.parametrize(
    "value",
    [
        r"safe\r\nX-Evil: pwned",
        r"safe\x0d\x0aX-Evil: pwned",
        "safe\r\nX-Evil: pwned",  # raw CRLF is rejected at the schema
        r"a\bb",
        r"nul\x00byte",
    ],
)
def test_modify_headers_rejects_control_characters(value: str) -> None:
    """Any value decoding to a control byte is refused (header injection/R4)."""
    with pytest.raises((InvalidInputError, ValidationError)):
        rule = ModifyHeaderRuleSpec(header_name="X-Inject", header_value=value)
        format_modify_headers_spec(rule)


def test_modify_headers_legit_value_round_trips() -> None:
    from mitmproxy.addons.modifyheaders import parse_modify_spec

    rule = ModifyHeaderRuleSpec(header_name="X-Trace", header_value="by-mitm-e2e")
    spec = format_modify_headers_spec(rule)
    obj = parse_modify_spec(spec, False)
    assert obj.read_replacement() == b"by-mitm-e2e"
    # No forged second header.
    assert b"\r\n" not in obj.read_replacement()


def test_modify_body_pattern_keeps_regex_semantics() -> None:
    """Escaping must not destroy word boundaries or other regex escapes."""
    from mitmproxy.addons.modifyheaders import parse_modify_spec

    for pattern in (r"\bword\b", r"\d{3}", r"\w+\s"):
        rule = ModifyBodyRuleSpec(pattern=pattern, replacement="X")
        spec = format_modify_body_spec(rule)
        obj = parse_modify_spec(spec, True)
        assert obj.subject.decode() == pattern


def test_modify_body_backslash_and_newline_replacement_survives() -> None:
    from mitmproxy.addons.modifyheaders import parse_modify_spec

    rule = ModifyBodyRuleSpec(pattern="x", replacement="C:\\new\nline\\with\\backslashes")
    spec = format_modify_body_spec(rule)
    obj = parse_modify_spec(spec, True)
    assert obj.read_replacement().decode() == rule.replacement


def test_parse_options_projects_all_families() -> None:
    payload = {
        "map_remote": {"value": ["|a|b", "|c|d"]},
        "map_local": {"value": ["|e|/tmp/f"]},
        "modify_headers": {"value": []},
        "modify_body": {"value": ["|g|h"]},
    }
    rules = parse_options(payload)
    assert [(r.rule_type, r.index) for r in rules] == [
        (RuleType.MAP_REMOTE, 0),
        (RuleType.MAP_REMOTE, 1),
        (RuleType.MAP_LOCAL, 0),
        (RuleType.MODIFY_BODY, 0),
    ]
    assert all(r.valid for r in rules)


def test_parse_options_flags_invalid_spec_as_drift() -> None:
    # '|a|b' -> separator '|', 2 parts -> valid.
    assert parse_options({"map_remote": {"value": ["|a|b"]}})[0].valid is True
    # '|only-one-part' -> 1 part -> mitmproxy raises -> drift.
    assert parse_options({"map_remote": {"value": ["|only-one-part"]}})[0].valid is False
    # Empty string -> option[0] raises IndexError -> drift.
    assert parse_options({"map_remote": {"value": [""]}})[0].valid is False


def test_parse_options_missing_keys_yield_empty() -> None:
    assert parse_options({}) == []


def test_parse_options_ignores_unexpected_shape() -> None:
    assert parse_options({"map_remote": "not-a-dict"}) == []


@pytest.mark.parametrize(
    "rule",
    [
        MapRemoteRuleSpec(url_pattern=r"^https://x/", replacement_url="https://y/"),
        MapRemoteRuleSpec(
            filter_expression="~u /api & ~m POST",
            url_pattern=r"^https://x/",
            replacement_url="https://y/",
        ),
    ],
)
def test_map_remote_specs_never_reinterpret(rule: MapRemoteRuleSpec) -> None:
    spec = format_map_remote_spec(rule)
    _, subject, replacement = parse_spec(spec)
    assert subject == rule.url_pattern
    assert replacement == rule.replacement_url
