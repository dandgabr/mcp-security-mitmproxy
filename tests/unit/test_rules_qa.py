"""Fase 4 QA hardening — adversarial spec grammar and defence in depth.

Complements ``test_rules_engine.py`` / ``test_rules_tools.py`` with the cases the
risk analysis flagged as critical: delimiter exhaustion, round-trip preservation
under hostile field values, and the two independent guards that keep the four
native rule options out of the raw ``--set`` channel.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastmcp import Context
from mitmproxy.utils.spec import parse_spec
from pydantic import ValidationError

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import (
    SessionRegistry,
    _assert_no_reserved_options,
)
from mcp_security_mitmproxy.rules.engine import (
    RULE_OPTION_KEYS,
    format_map_remote_spec,
    select_delimiter,
)
from mcp_security_mitmproxy.schemas.common import ProxyMode, SessionStatus
from mcp_security_mitmproxy.schemas.mitmdump import MitmdumpStartInput
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, SessionState
from mcp_security_mitmproxy.schemas.rules import (
    HeaderOperation,
    MapLocalRuleSpec,
    MapRemoteRuleSpec,
    MitmClearRulesInput,
    MitmSetMapRemoteInput,
    ModifyBodyRuleSpec,
    ModifyHeaderRuleSpec,
    RuleType,
)
from mcp_security_mitmproxy.server import create_server

_ALL_DELIMITER_CANDIDATES = "|!;,^%#@&~?$:*+=/"
_ALL_PRINTABLE = "".join(chr(code) for code in range(33, 127))


# --------------------------------------------------------------------------- #
# Delimiter selection — equivalence partitions + boundary
# --------------------------------------------------------------------------- #


def test_delimiter_survives_every_candidate_being_present() -> None:
    """Worst case: all preferred candidates collide -> ASCII sweep must rescue."""
    delimiter = select_delimiter(_ALL_DELIMITER_CANDIDATES)
    assert delimiter not in _ALL_DELIMITER_CANDIDATES
    assert 33 <= ord(delimiter) < 127


def test_delimiter_exhaustion_fails_closed() -> None:
    """Fields covering all printable ASCII cannot be encoded -> INVALID_INPUT."""
    with pytest.raises(InvalidInputError):
        select_delimiter(_ALL_PRINTABLE, "")


def test_round_trip_survives_delimiter_chars_in_every_field() -> None:
    rule = MapRemoteRuleSpec(
        filter_expression="~u /a|b",
        url_pattern=rf"^https://x/{_ALL_DELIMITER_CANDIDATES}$",
        replacement_url=f"https://y/{_ALL_DELIMITER_CANDIDATES}",
    )
    _, subject, replacement = parse_spec(format_map_remote_spec(rule))
    assert subject == rule.url_pattern
    assert replacement == rule.replacement_url


@pytest.mark.parametrize(
    ("pattern", "replacement"),
    [
        ("a\nb", "c\nd"),
        ("héllo", "wörld"),
        ("a b", "  spaced  "),
        (r"^/api/(\d+)$", r"/v2/\1"),
        ("[", "x"),  # deliberately invalid regex, schema must refuse it
    ],
)
def test_map_remote_round_trip_preserves_fields(pattern: str, replacement: str) -> None:
    try:
        rule = MapRemoteRuleSpec(url_pattern=pattern, replacement_url=replacement)
    except ValidationError:
        assert pattern == "[", "only the invalid-regex case may be refused"
        return
    _, subject, replacement_out = parse_spec(format_map_remote_spec(rule))
    assert (subject, replacement_out) == (pattern, replacement)


# --------------------------------------------------------------------------- #
# Defence in depth: the raw --set channel must never reach rule options
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("option", [rt.value for rt in RULE_OPTION_KEYS])
def test_rules_cannot_be_injected_through_set_options(option: str) -> None:
    with pytest.raises(ValidationError):
        MitmdumpStartInput(
            mode=[ProxyModeSpec(mode=ProxyMode.REGULAR)],
            set_options={option: "|a|b"},
        )


@pytest.mark.parametrize("option", [rt.value for rt in RULE_OPTION_KEYS])
@pytest.mark.parametrize(
    "argv",
    [
        ["mitmdump", "--set", "{opt}=|a|b"],
        ["mitmdump", "--set={opt}=|a|b"],
    ],
)
def test_registry_guard_blocks_rule_options(argv: list[str], option: str) -> None:
    """Second, independent guard: even a schema bypass cannot spawn."""
    concrete = [element.format(opt=option) for element in argv]
    with pytest.raises(InvalidInputError):
        _assert_no_reserved_options(concrete)


def test_registry_guard_still_allows_benign_options() -> None:
    _assert_no_reserved_options(["mitmdump", "--set", "termlog_verbosity=warn"])
    _assert_no_reserved_options(["mitmdump", "--set=termlog_verbosity=warn"])


# --------------------------------------------------------------------------- #
# Schema boundaries for the rule contracts
# --------------------------------------------------------------------------- #


def test_map_local_requires_absolute_path() -> None:
    with pytest.raises(ValidationError):
        MapLocalRuleSpec(url_pattern="/x", local_path="mocks/user.json")


def test_header_value_file_syntax_is_refused() -> None:
    with pytest.raises(ValidationError):
        ModifyHeaderRuleSpec(header_name="X-K", header_value="@/etc/shadow")


def test_body_replacement_file_syntax_is_refused() -> None:
    with pytest.raises(ValidationError):
        ModifyBodyRuleSpec(pattern="a", replacement="@/etc/passwd")


def test_header_operation_invariants() -> None:
    with pytest.raises(ValidationError):
        ModifyHeaderRuleSpec(header_name="X-K", operation=HeaderOperation.SET)
    with pytest.raises(ValidationError):
        ModifyHeaderRuleSpec(header_name="X-K", operation=HeaderOperation.REMOVE, header_value="v")


def test_header_name_must_be_an_rfc9110_token() -> None:
    for bad in ("X K", "X:K", ""):
        with pytest.raises(ValidationError):
            ModifyHeaderRuleSpec(header_name=bad, header_value="v")


# --------------------------------------------------------------------------- #
# Tool contracts: clear must not touch other families (I1 / read-modify-write)
# --------------------------------------------------------------------------- #


def _rule_options_payload(**values: list[str]) -> dict[str, object]:
    families = [rt.value for rt in RULE_OPTION_KEYS]
    return {
        name: {"value": values.get(name, []), "default": [], "type": "sequence of str"}
        for name in families
    }


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    real_client = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(recording)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return captured


@pytest.fixture
def web_env(tmp_path: Path) -> tuple[object, LifespanContext, Context]:
    server = create_server()
    settings = Settings(session_root=tmp_path / "sessions")
    registry = SessionRegistry(settings)
    state = SessionState(
        session_id="web-1",
        executable="mitmweb",
        status=SessionStatus.RUNNING,
        web_host="127.0.0.1",
        web_port=8081,
    )
    registry._entries["web-1"] = MagicMock(
        state=state, leased_ports=[], web_token="tok", runner=MagicMock()
    )
    ctx = MagicMock(spec=Context)
    ctx.lifespan_context = LifespanContext(settings=settings, registry=registry)
    return server, ctx.lifespan_context, ctx


async def test_clear_one_family_leaves_the_others_untouched(web_env, monkeypatch) -> None:
    server, _lc, ctx = web_env
    payload = _rule_options_payload(
        map_remote=["|a|b"], map_local=["|c|/tmp/d"], modify_headers=["|X|v"], modify_body=["|p|r"]
    )
    captured = _install_transport(
        monkeypatch,
        lambda r: httpx.Response(200, json=payload) if r.method == "GET" else httpx.Response(200),
    )

    tool = await server.get_tool("mitm_clear_rules")
    res = await tool.fn(
        MitmClearRulesInput(session_id="web-1", rule_type=RuleType.MODIFY_HEADERS), ctx
    )

    assert res.ok is True
    assert res.cleared_count == 1
    put = [r for r in captured if r.method == "PUT"]
    assert len(put) == 1
    body = put[0].content.decode()
    assert "modify_headers" in body
    for untouched in ("map_remote", "map_local", "modify_body"):
        assert untouched not in body


async def test_set_rule_on_stopped_session_returns_domain_error(web_env, monkeypatch) -> None:
    """I1: a misused session must yield a domain code, never a raised exception."""
    server, lc, ctx = web_env
    stopped = SessionState(
        session_id="web-2",
        executable="mitmweb",
        status=SessionStatus.STOPPED,
        web_host="127.0.0.1",
        web_port=8081,
    )
    lc.registry._entries["web-2"] = MagicMock(
        state=stopped, leased_ports=[], web_token=None, runner=MagicMock()
    )
    _install_transport(monkeypatch, lambda _r: httpx.Response(200, json=_rule_options_payload()))

    tool = await server.get_tool("mitm_set_map_remote")
    res = await tool.fn(
        MitmSetMapRemoteInput(
            session_id="web-2",
            rule=MapRemoteRuleSpec(url_pattern="a", replacement_url="b"),
        ),
        ctx,
    )
    assert res.ok is False
    assert res.error is not None
    assert res.error.code.value == "SESSION_NOT_RUNNING"
