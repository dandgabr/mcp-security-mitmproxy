"""Unit tests for offline flow manager operations."""

from __future__ import annotations

from pathlib import Path

import pytest
from mitmproxy import io as mio
from mitmproxy.test import tflow

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.flows.manager import (
    export_flow_offline,
    filter_flows,
    read_flows_from_dump,
)
from mcp_security_mitmproxy.schemas.common import ExportFormat


def test_export_flow_offline_formats() -> None:
    flow = tflow.tflow(resp=True)
    for fmt in [
        ExportFormat.CURL,
        ExportFormat.HTTPIE,
        ExportFormat.RAW,
        ExportFormat.RAW_REQUEST,
        ExportFormat.RAW_RESPONSE,
    ]:
        content = export_flow_offline(flow, fmt)
        assert isinstance(content, str)
        assert len(content) > 0


def test_filter_flows_matching() -> None:
    flow1 = tflow.tflow(resp=True)
    flow2 = tflow.tflow(resp=True)
    flow2.request.method = "POST"

    matched, count = filter_flows([flow1, flow2], "~m POST")
    assert count == 1
    assert len(matched) == 1
    assert matched[0].method == "POST"


def test_filter_flows_invalid_expression() -> None:
    with pytest.raises(InvalidInputError):
        filter_flows([], "~invalid(regex[[[")


def test_read_flows_from_dump(tmp_path: Path) -> None:
    dump_file = tmp_path / "test.mitm"
    with dump_file.open("wb") as f:
        w = mio.FlowWriter(f)
        w.add(tflow.tflow(resp=True))

    flows = read_flows_from_dump(dump_file)
    assert len(flows) == 1
    assert flows[0].response is not None
