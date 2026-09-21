"""Offline flow inspection, filtering and export via mitmproxy library (ADR-001, §3.3.8, §3.3.9).

Handles offline .mitm dump parsing, FlowFilter evaluation, and format exports
(curl, httpie, raw, raw_request, raw_response) directly in-process.
"""

from __future__ import annotations

import asyncio
import io as py_io
from pathlib import Path

from mitmproxy import flowfilter, master, options
from mitmproxy import io as mio
from mitmproxy.addons import export
from mitmproxy.http import HTTPFlow

from mcp_security_mitmproxy.core.errors import InvalidInputError
from mcp_security_mitmproxy.schemas.common import ExportFormat
from mcp_security_mitmproxy.schemas.mitmweb import FlowSummary


def read_flows_from_dump(dump_path: str | Path) -> list[HTTPFlow]:
    """Read flows from a .mitm file."""
    path = Path(dump_path)
    if not path.is_file():
        raise InvalidInputError(f"dump file {dump_path!r} not found or not a regular file")

    with path.open("rb") as f:
        return read_flows_from_bytes(f.read())


def read_flows_from_bytes(dump: bytes) -> list[HTTPFlow]:
    """Read flows from in-memory .mitm bytes (e.g. mitmweb ``/flows/dump``)."""
    flows: list[HTTPFlow] = []
    reader = mio.FlowReader(py_io.BytesIO(dump))
    for fl in reader.stream():
        flows.append(fl)  # type: ignore[arg-type]
    return flows


def find_flow_by_id(flows: list[HTTPFlow], flow_id: str) -> HTTPFlow:
    """Return the flow with ``flow_id`` or raise ``InvalidInputError``."""
    for flow in flows:
        if getattr(flow, "id", "") == flow_id:
            return flow
    raise InvalidInputError(f"flow {flow_id!r} not found in dump")


def filter_flows(
    flows: list[HTTPFlow],
    expression: str,
    *,
    limit: int = 100,
) -> tuple[list[FlowSummary], int]:
    """Evaluate a mitmproxy flowfilter expression over a list of flows."""
    try:
        matcher = flowfilter.parse(expression)
    except Exception as exc:
        raise InvalidInputError(f"invalid flowfilter expression {expression!r}: {exc}") from exc

    matched: list[FlowSummary] = []
    count = 0

    for f in flows:
        if matcher is None or matcher(f):
            count += 1
            if len(matched) < limit:
                req = getattr(f, "request", None)
                resp = getattr(f, "response", None)
                f_type = getattr(f, "type", "http")
                if f_type not in ("http", "tcp", "udp", "dns", "websocket"):
                    f_type = "http"

                time_start = getattr(f, "timestamp_start", None) or (
                    getattr(req, "timestamp_start", None) if req else None
                )
                time_end = (getattr(resp, "timestamp_end", None) if resp else None) or getattr(
                    f, "timestamp_end", None
                )
                duration = (time_end - time_start) if (time_start and time_end) else None

                matched.append(
                    FlowSummary(
                        flow_id=getattr(f, "id", ""),
                        type=f_type,
                        method=getattr(req, "method", None) if req else None,
                        scheme=getattr(req, "scheme", None) if req else None,
                        host=getattr(req, "host", "") if req else "",
                        port=getattr(req, "port", 80) if req else 80,
                        path=getattr(req, "path", None) if req else None,
                        status_code=getattr(resp, "status_code", None) if resp else None,
                        timestamp_start=time_start,
                        duration=duration,
                    )
                )

    return matched, count


def export_flow_offline(
    flow: HTTPFlow,
    format_name: ExportFormat,
    *,
    preserve_original_ip: bool = False,
) -> str:
    """Export a single flow using mitmproxy's export addon in-process."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()

    opts = options.Options()
    m = master.Master(opts, event_loop=loop)
    exp = export.Export()
    m.addons.add(exp)
    opts.export_preserve_original_ip = preserve_original_ip

    format_str = format_name.value
    try:
        content = exp.export_str(format_str, flow)
    except Exception as exc:
        raise InvalidInputError(f"failed to export flow as {format_str}: {exc}") from exc

    return content


__all__ = [
    "export_flow_offline",
    "filter_flows",
    "find_flow_by_id",
    "read_flows_from_bytes",
    "read_flows_from_dump",
]
