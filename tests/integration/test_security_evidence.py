"""Measured R1-R5 evidence — input for the Phase 5 security sign-off.

Each test produces evidence for one requirement with a **real** proxy running,
where only real network traffic can prove the requirement. The matching unit
checks (``test_paths.py``, ``test_redact.py``, ``test_modes.py``,
``test_server.py``) remain the first level; this one is the last.

* R1 — restricted bind: a default session listens on loopback only;
* R2 — credential isolation: the token stays out of the process cmdline and of
  the tool output, ``config.yaml`` is 0600, the session tree is 0700, and the
  private CA lands inside the session confdir;
* R3 — path allowlist against LFI: out-of-root, ``~/.ssh``, traversal and
  symlink are refused, with a live proxy proving the file is never served;
* R4 — redaction by default: real traffic carrying secrets comes back redacted,
  and the ``redact=False`` control shows the secrets (non-vacuity proof);
* R5 — no implicit escalation: no ``sudo``/``doas``/``pkexec`` in the real argv,
  and a malformed privileged mode fails explicitly.

Skipped when the mitmproxy executables are unavailable.
"""

from __future__ import annotations

import asyncio
import json
import socket
import stat
import time
from pathlib import Path

import httpx
import pytest

from mcp_security_mitmproxy.schemas.common import ProxyMode
from mcp_security_mitmproxy.schemas.mitmdump import MitmdumpStartInput
from mcp_security_mitmproxy.schemas.mitmweb import (
    MitmwebGetFlowDetailInput,
    MitmwebGetFlowsInput,
    MitmwebStartInput,
)
from mcp_security_mitmproxy.schemas.process import ProxyModeSpec, StopInput
from mcp_security_mitmproxy.schemas.rules import (
    MapLocalRuleSpec,
    MitmListRulesInput,
    MitmSetMapLocalInput,
)

from .conftest import free_port, mitmproxy_available, wait_for_port

pytestmark = mitmproxy_available

_PRIVILEGE_BINARIES = ("sudo", "doas", "pkexec", "su")


async def _call(server, name: str, params, ctx):
    tool = await server.get_tool(name)
    return await tool.fn(params, ctx)


async def _start_mitmweb(server, ctx, *, proxy_port: int, **overrides):
    params = {
        "mode": [ProxyModeSpec(mode=ProxyMode.REGULAR, listen_port=proxy_port)],
        "web_port": free_port(),
    }
    params.update(overrides)
    started = await _call(server, "mitmweb_start", MitmwebStartInput(**params), ctx)
    assert started.ok is True, started.error
    session = started.session
    for _ in range(200):
        if wait_for_port(session.listen_host, proxy_port, timeout=0.2) and wait_for_port(
            session.web_host, session.web_port, timeout=0.2
        ):
            return session
        await asyncio.sleep(0.1)
    pytest.fail("mitmweb session did not become ready")


def _non_loopback_ipv4() -> str | None:
    """This host's primary non-loopback IPv4, without emitting any packet."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1; UDP connect sends nothing
            address = sock.getsockname()[0]
        except OSError:  # pragma: no cover - no route
            return None
    return None if address.startswith("127.") else address


def _accepts_connection(host: str, port: int, *, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


async def _proxied(proxy_url: str, url: str, **kwargs) -> httpx.Response:
    async with httpx.AsyncClient(proxy=proxy_url, timeout=20) as client:
        return await client.get(url, **kwargs)


# --------------------------------------------------------------------------- #
# R1 — restrição de bind
# --------------------------------------------------------------------------- #


async def test_r1_default_session_listens_only_on_loopback(tools_env) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()
    session = await _start_mitmweb(server, ctx, proxy_port=proxy_port)
    try:
        assert session.web_host == "127.0.0.1"
        assert tools_env["settings"].binds_publicly is False
        assert _accepts_connection("127.0.0.1", session.web_port)

        public_ip = _non_loopback_ipv4()
        if public_ip is None:  # pragma: no cover - host without an external route
            pytest.skip("no non-loopback IPv4 to probe")
        assert not _accepts_connection(public_ip, session.web_port), (
            f"REST bridge also listening on {public_ip}:{session.web_port} (R1 violated)"
        )
    finally:
        await registry.shutdown_all(timeout=10.0)


# --------------------------------------------------------------------------- #
# R2 — isolamento de credenciais e material de CA
# --------------------------------------------------------------------------- #


async def test_r2_token_stays_off_argv_output_and_inside_the_session_tree(tools_env) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    settings = tools_env["settings"]
    token = "qa-r2-token-0123456789abcdef"
    proxy_port = free_port()

    session = await _start_mitmweb(server, ctx, proxy_port=proxy_port, web_password=token)
    try:
        session_id = session.session_id
        session_dir = settings.session_root / session_id

        # 1. The tool's output must not echo the credential.
        assert token not in session.model_dump_json()

        # 2. The registry keeps it server-side, and it is absent from the real
        #    spawned argv -- the same bytes `ps` would show.
        assert registry.get_web_token(session_id) == token
        assert all(token not in element for element in registry.get_runner(session_id).argv)
        assert session.pid is not None
        cmdline = Path(f"/proc/{session.pid}/cmdline").read_bytes().decode(errors="replace")
        assert token not in cmdline, "the web password leaked into the process cmdline"

        # 3. The secret travels through a 0600 config.yaml inside a 0700 tree.
        config = session_dir / "config.yaml"
        assert config.is_file()
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert token in config.read_text(encoding="utf-8")
        assert stat.S_IMODE(session_dir.stat().st_mode) == 0o700

        # 4. Isolated confdir keeps the CA private key inside the 0700 tree.
        ca_key = session_dir / "mitmproxy-ca.pem"
        deadline = time.time() + 20
        while time.time() < deadline and not ca_key.is_file():
            await asyncio.sleep(0.2)
        assert ca_key.is_file(), "the CA was not materialised inside the session confdir"
        assert stat.S_IMODE(ca_key.stat().st_mode) == 0o600
    finally:
        await registry.shutdown_all(timeout=10.0)


# --------------------------------------------------------------------------- #
# R3 — allowlist de paths contra LFI
# --------------------------------------------------------------------------- #


async def test_r3_lfi_is_refused_even_with_a_live_proxy(tools_env, tmp_path) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    mock_root = tools_env["mock_root"]
    proxy_port = free_port()

    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE-SECRET", encoding="utf-8")
    symlink = mock_root / "escape.txt"
    symlink.symlink_to(outside)

    session = await _start_mitmweb(server, ctx, proxy_port=proxy_port)
    sid = session.session_id
    try:
        probes = [
            "/etc/passwd",
            "~/.ssh/id_rsa",
            str(mock_root / ".." / "outside-secret.txt"),
            str(symlink),
        ]
        for path in probes:
            result = await _call(
                server,
                "mitm_set_map_local",
                MitmSetMapLocalInput(
                    session_id=sid,
                    rule=MapLocalRuleSpec(url_pattern="^http://lfi\\.test/", local_path=path),
                ),
                ctx,
            )
            assert result.ok is False, f"{path!r} was accepted by the allowlist"
            assert result.error is not None
            assert result.error.code.value == "PATH_NOT_ALLOWED"

        # Nothing was applied: the rule list is empty...
        listed = await _call(server, "mitm_list_rules", MitmListRulesInput(session_id=sid), ctx)
        assert listed.ok is True
        assert listed.counts.get("map_local", 0) == 0

        # ...and a live request cannot retrieve the file through the proxy.
        response = await _proxied(
            f"http://127.0.0.1:{proxy_port}", "http://lfi.test/passwd", headers={}
        )
        assert "root:" not in response.text
        assert "OUTSIDE-SECRET" not in response.text
    finally:
        await registry.shutdown_all(timeout=10.0)


# --------------------------------------------------------------------------- #
# R4 — redação por padrão no tráfego real
# --------------------------------------------------------------------------- #


async def test_r4_secrets_are_redacted_by_default_and_visible_only_on_request(
    tools_env, upstream_server
) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()
    session = await _start_mitmweb(server, ctx, proxy_port=proxy_port)
    sid = session.session_id
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    try:
        await _proxied(
            proxy_url,
            f"{upstream_server['origin']}/secret",
            headers={"Authorization": "Bearer qa-secret-token"},
        )

        flow_id = None
        for _ in range(50):
            flows = await _call(
                server, "mitmweb_get_flows", MitmwebGetFlowsInput(session_id=sid), ctx
            )
            if flows.ok and flows.flows:
                flow_id = flows.flows[0].flow_id
                break
            await asyncio.sleep(0.1)
        assert flow_id is not None, "the flow was never captured"

        redacted = await _call(
            server,
            "mitmweb_get_flow_detail",
            MitmwebGetFlowDetailInput(session_id=sid, flow_id=flow_id),
            ctx,
        )
        assert redacted.ok is True, redacted.error
        payload = json.dumps(redacted.detail)
        assert "qa-secret-token" not in payload, "R4: request credential leaked by default"
        assert "upstream-secret-token" not in payload, "R4: response body secret leaked by default"
        assert "upstream-cookie" not in payload, "R4: response cookie leaked by default"
        assert "[REDACTED]" in payload

        # Control: with redaction explicitly disabled the secrets do come back,
        # which proves the assertions above are not vacuous.
        raw = await _call(
            server,
            "mitmweb_get_flow_detail",
            MitmwebGetFlowDetailInput(session_id=sid, flow_id=flow_id, redact=False),
            ctx,
        )
        assert raw.ok is True, raw.error
        raw_payload = json.dumps(raw.detail)
        assert "qa-secret-token" in raw_payload
        assert "upstream-secret-token" in raw_payload
    finally:
        await registry.shutdown_all(timeout=10.0)


# --------------------------------------------------------------------------- #
# R5 — ausência de escalação implícita
# --------------------------------------------------------------------------- #


async def test_r5_privileged_mode_never_escalates_implicitly(tools_env) -> None:
    server, ctx = tools_env["server"], tools_env["ctx"]
    registry = tools_env["registry"]
    proxy_port = free_port()

    started = await _call(
        server,
        "mitmdump_start",
        MitmdumpStartInput(mode=[ProxyModeSpec(mode=ProxyMode.LOCAL, listen_port=proxy_port)]),
        ctx,
    )

    if started.ok:
        sid = started.session.session_id
        argv = registry.get_runner(sid).argv
        assert argv[0].endswith("mitmdump")
        assert "--mode" in argv and "local" in argv
        for binary in _PRIVILEGE_BINARIES:
            assert binary not in argv, f"implicit privilege escalation via {binary!r}"
        assert not any(element.startswith(("sudo", "doas", "pkexec")) for element in argv)
        await _call(server, "mitmdump_stop", StopInput(session_id=sid), ctx)
    else:
        assert started.error is not None
        assert started.error.code.value in {"INVALID_INPUT", "PROCESS_SPAWN_FAILED"}

    # The explicit-failure half of R5 is deterministic: a malformed privileged
    # mode is refused before any argv leaves the process.
    malformed = await _call(
        server,
        "mitmdump_start",
        MitmdumpStartInput(mode=[ProxyModeSpec(mode=ProxyMode.TUN, listen_port=proxy_port)]),
        ctx,
    )
    assert malformed.ok is False
    assert malformed.error is not None
    assert malformed.error.code.value == "INVALID_INPUT"

    await registry.shutdown_all(timeout=10.0)
    assert registry.active_count == 0


def test_r5_schemas_are_free_of_mitmproxy_imports() -> None:
    """The pure-contract invariant the security fixes must not break."""
    schemas_dir = Path(__file__).resolve().parents[2] / "src/mcp_security_mitmproxy/schemas"
    offenders = [
        path.name
        for path in schemas_dir.glob("*.py")
        if any(
            line.startswith(("import mitmproxy", "from mitmproxy"))
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    ]
    assert offenders == [], f"schemas/ must stay mitmproxy-free, found: {offenders}"
