"""Fase 4 contracts — traffic-mutation rules (ADR-003, architecture 0003).

Pure Pydantic contracts only: no ``mitmproxy`` import, no I/O. The allowlist
check (R3) and the delimiter-aware option formatter live in ``rules/engine.py``
and ``core/paths.py``; this module defines *what an agent may ask for*, never
how it is applied.

Design notes that drive the field choices
-----------------------------------------
* ``modify_headers`` / ``modify_body`` in mitmproxy 12 are spec strings of the
  form ``[/flow-filter]/subject/replacement`` parsed by
  ``mitmproxy.utils.spec.parse_spec``. The *subject* of ``modify_headers`` is a
  literal header name; the subject of ``modify_body`` is a regex. Both are
  encoded by :func:`mcp_security_mitmproxy.rules.engine.format_*`, which picks a
  delimiter absent from every field.
* The native ``modify_headers`` addon always *pops* the matching header before
  re-adding it. There is no "append without replacing" primitive, so a true
  ``add`` operation is **not representable** through the option and is
  deliberately excluded from the contract (see ADR-003).
* ``local_path`` is validated against the allowlist by the tool layer. The
  schema only guarantees a non-empty, absolute, non-traversal-looking string so
  the failure is a clean ``PATH_NOT_ALLOWED`` and not a parse error.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator

from mcp_security_mitmproxy.schemas.common import ToolResult

# A header field-name is an RFC 9110 ``token``.
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


class RuleType(StrEnum):
    """The four native option families a rule can belong to."""

    MAP_REMOTE = "map_remote"
    MAP_LOCAL = "map_local"
    MODIFY_HEADERS = "modify_headers"
    MODIFY_BODY = "modify_body"


class HeaderOperation(StrEnum):
    """Operations the native ``modify_headers`` option can actually express.

    ``SET``    -> the option pops matching headers, then re-adds the value.
    ``REMOVE`` -> the option pops matching headers and adds nothing back.

    ``ADD`` (append a second value while keeping the original) is intentionally
    absent: the native addon has no such primitive. Accepting it would be a
    contract lie. A security audit that needs duplicated headers requires the
    embedded addon of ADR-003 §Option A, deferred out of Fase 4.
    """

    SET = "set"
    REMOVE = "remove"


def _validate_regex(value: str, field: str) -> str:
    """Reject a pattern mitmproxy would reject later, at the schema boundary."""
    try:
        re.compile(value)
    except re.error as exc:  # pragma: no cover - message asserted in tests
        raise ValueError(f"{field} is not a valid regular expression: {exc}") from exc
    return value


class MapRemoteRuleSpec(BaseModel):
    """``map_remote`` — rewrite a matching URL to another remote URL."""

    filter_expression: str | None = Field(
        default=None,
        description="Optional FlowFilter gating the rule (e.g. '~d api.example.com & ~m POST'). "
        "When omitted the rule applies to every request.",
    )
    url_pattern: str = Field(
        min_length=1,
        description="Regex matched against the full pretty URL; captured groups are usable "
        "as \\1..\\9 backreferences in replacement_url.",
    )
    replacement_url: str = Field(
        min_length=1,
        description="Replacement applied with re.sub (e.g. 'https://staging.internal\\1').",
    )

    @field_validator("url_pattern")
    @classmethod
    def _check_url_pattern(cls, value: str) -> str:
        return _validate_regex(value, "url_pattern")


class MapLocalRuleSpec(BaseModel):
    """``map_local`` — serve a mocked response from an allowlisted local path."""

    filter_expression: str | None = Field(
        default=None,
        description="Optional FlowFilter gating the rule.",
    )
    url_pattern: str = Field(
        min_length=1,
        description="Regex matched against the full pretty URL. An optional capture group "
        "selects the path suffix resolved under the local directory.",
    )
    local_path: str = Field(
        min_length=1,
        description="File or directory served as the mocked response. MUST pass "
        "core.paths.ensure_allowed against allowed_mock_roots before the option is set; "
        "the mitmproxy parser resolves it with strict=True, so it must already exist.",
    )

    @field_validator("url_pattern")
    @classmethod
    def _check_url_pattern(cls, value: str) -> str:
        return _validate_regex(value, "url_pattern")

    @model_validator(mode="after")
    def _check_absolute(self) -> MapLocalRuleSpec:
        if not self.local_path.startswith(("/", "~")):
            raise ValueError(
                "local_path must be absolute (or start with '~'); relative paths are ambiguous"
            )
        return self


class ModifyHeaderRuleSpec(BaseModel):
    """``modify_headers`` — set or remove a header on requests and/or responses.

    Direction is chosen through ``filter_expression``: ``~q`` limits the rule to
    request headers, ``~s`` to response headers, and no filter applies to both.
    """

    filter_expression: str | None = Field(
        default=None,
        description="FlowFilter selecting direction and scope (e.g. '~s' for responses only).",
    )
    header_name: str = Field(
        min_length=1,
        description="Literal HTTP header field-name (RFC 9110 token, not a regex).",
    )
    header_value: str | None = Field(
        default=None,
        description="Replacement value. Required for SET, forbidden for REMOVE.",
    )
    operation: HeaderOperation = HeaderOperation.SET

    @field_validator("header_name")
    @classmethod
    def _check_header_name(cls, value: str) -> str:
        if not _HEADER_NAME_RE.fullmatch(value):
            raise ValueError(f"header_name {value!r} is not a valid RFC 9110 token")
        return value

    @field_validator("header_value")
    @classmethod
    def _reject_file_syntax(cls, value: str | None) -> str | None:
        # mitmproxy treats a leading '@' in the replacement as a file path and
        # reads it from disk (host file disclosure). Only allowlisted paths may
        # be read, and the contract does not expose that channel here at all.
        if value is not None and value.startswith("@"):
            raise ValueError(
                "header_value must not start with '@': mitmproxy would read a local file"
            )
        # Cheap structural guard (stdlib only — schemas/ stays mitmproxy-free):
        # a raw CR/LF is header injection / response splitting. The engine
        # re-validates the *decoded* bytes, catching escaped spellings too.
        if value is not None and ("\r" in value or "\n" in value):
            raise ValueError("header_value must not contain raw CR/LF characters")
        return value

    @model_validator(mode="after")
    def _check_operation(self) -> ModifyHeaderRuleSpec:
        if self.operation is HeaderOperation.REMOVE and self.header_value is not None:
            raise ValueError("header_value must be omitted when operation=remove")
        if self.operation is HeaderOperation.SET and self.header_value is None:
            raise ValueError("header_value is required when operation=set")
        return self


class ModifyBodyRuleSpec(BaseModel):
    """``modify_body`` — regex substitution inside request/response payloads."""

    filter_expression: str | None = Field(
        default=None,
        description="FlowFilter selecting direction/type (e.g. '~q & ~t json').",
    )
    pattern: str = Field(
        min_length=1,
        description="Regex locating the payload fragment to replace (DOTALL is applied).",
    )
    replacement: str = Field(
        description="Replacement text. May be empty to delete the matched fragment.",
    )

    @field_validator("pattern")
    @classmethod
    def _check_pattern(cls, value: str) -> str:
        return _validate_regex(value, "pattern")

    @field_validator("replacement")
    @classmethod
    def _reject_file_syntax(cls, value: str) -> str:
        if value.startswith("@"):
            raise ValueError(
                "replacement must not start with '@': mitmproxy would read a local file"
            )
        return value


# --------------------------------------------------------------------------- #
# Tool I/O contracts
# --------------------------------------------------------------------------- #


class MitmSetMapRemoteInput(BaseModel):
    session_id: str
    rule: MapRemoteRuleSpec


class MitmSetMapRemoteOutput(ToolResult):
    rule_id: str | None = None
    rendered_spec: str | None = Field(
        default=None,
        description="The delimited option string actually sent to mitmproxy (audit trail).",
    )


class MitmSetMapLocalInput(BaseModel):
    session_id: str
    rule: MapLocalRuleSpec


class MitmSetMapLocalOutput(ToolResult):
    rule_id: str | None = None
    canonical_path: str | None = Field(
        default=None,
        description="Canonical, allowlist-validated path that was registered.",
    )
    rendered_spec: str | None = None


class MitmModifyHeadersInput(BaseModel):
    session_id: str
    rule: ModifyHeaderRuleSpec


class MitmModifyHeadersOutput(ToolResult):
    rule_id: str | None = None
    rendered_spec: str | None = None


class MitmModifyBodyInput(BaseModel):
    session_id: str
    rule: ModifyBodyRuleSpec


class MitmModifyBodyOutput(ToolResult):
    rule_id: str | None = None
    rendered_spec: str | None = None


class RuleEntry(BaseModel):
    """One active rule as read back from ``GET /options``."""

    rule_type: RuleType
    index: int = Field(ge=0, description="Position within its option list (order = precedence).")
    raw_spec: str = Field(description="Delimited option string as mitmproxy holds it.")
    valid: bool = Field(
        default=True,
        description="False when the stored spec no longer parses (drift detection).",
    )


class MitmListRulesInput(BaseModel):
    session_id: str


class MitmListRulesOutput(ToolResult):
    rules: list[RuleEntry] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class MitmClearRulesInput(BaseModel):
    session_id: str
    rule_type: RuleType | None = Field(
        default=None,
        description="Specific option family to clear. None clears all four (rule_type='all').",
    )


class MitmClearRulesOutput(ToolResult):
    cleared_count: int = 0
    remaining: dict[str, int] = Field(default_factory=dict)


__all__ = [
    "HeaderOperation",
    "MapLocalRuleSpec",
    "MapRemoteRuleSpec",
    "MitmClearRulesInput",
    "MitmClearRulesOutput",
    "MitmListRulesInput",
    "MitmListRulesOutput",
    "MitmModifyBodyInput",
    "MitmModifyBodyOutput",
    "MitmModifyHeadersInput",
    "MitmModifyHeadersOutput",
    "MitmSetMapLocalInput",
    "MitmSetMapLocalOutput",
    "MitmSetMapRemoteInput",
    "MitmSetMapRemoteOutput",
    "ModifyBodyRuleSpec",
    "ModifyHeaderRuleSpec",
    "RuleEntry",
    "RuleType",
]
