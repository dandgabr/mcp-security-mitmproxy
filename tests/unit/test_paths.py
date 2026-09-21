"""Unit tests for the R3 path allowlist."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_security_mitmproxy.core.errors import PathNotAllowedError
from mcp_security_mitmproxy.core.paths import ensure_allowed, ensure_allowed_many


def test_path_inside_root_is_allowed(allow_root: Path) -> None:
    target = allow_root / "dump.mitm"
    assert ensure_allowed(target, [allow_root]) == str(target.resolve())


def test_root_itself_is_allowed(allow_root: Path) -> None:
    assert ensure_allowed(allow_root, [allow_root]) == str(allow_root.resolve())


def test_path_outside_root_is_rejected(allow_root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere" / "dump.mitm"
    with pytest.raises(PathNotAllowedError):
        ensure_allowed(outside, [allow_root])


def test_empty_allowlist_denies_everything(allow_root: Path) -> None:
    with pytest.raises(PathNotAllowedError):
        ensure_allowed(allow_root / "dump.mitm", [])


def test_error_code_is_path_not_allowed(allow_root: Path, tmp_path: Path) -> None:
    from mcp_security_mitmproxy.schemas import ErrorCode

    with pytest.raises(PathNotAllowedError) as excinfo:
        ensure_allowed(tmp_path / "x.mitm", [allow_root])
    assert excinfo.value.code is ErrorCode.PATH_NOT_ALLOWED


def test_symlink_escape_is_rejected(allow_root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    escape = allow_root / "link"
    escape.symlink_to(outside)
    with pytest.raises(PathNotAllowedError):
        ensure_allowed(escape / "dump.mitm", [allow_root])


def test_ensure_allowed_many_preserves_order(allow_root: Path) -> None:
    paths = [allow_root / "a.mitm", allow_root / "b.mitm"]
    assert ensure_allowed_many(paths, [allow_root]) == [str(p.resolve()) for p in paths]


def test_ensure_allowed_many_rejects_first_invalid(allow_root: Path, tmp_path: Path) -> None:
    with pytest.raises(PathNotAllowedError):
        ensure_allowed_many([allow_root / "a.mitm", tmp_path / "bad.mitm"], [allow_root])
