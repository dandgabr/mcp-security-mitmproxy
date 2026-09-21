# Configuration

All runtime configuration lives in one `Settings` object (`src/mcp_security_mitmproxy/config.py`), resolved once at server startup through the FastMCP lifespan. Nothing is re-read at request time: restart the server process to apply changes.

## Environment variables

`Settings.from_env()` reads exactly two variables:

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `MCP_MITM_WEB_HOST` | `127.0.0.1` | Default bind address for the mitmweb REST/Web UI surface (R1). Any non-loopback value must be set deliberately. |
| `MCP_MITM_WEB_PORT` | `8081` | Default port for the same surface. |

Set them in the `env` block of your MCP client configuration (see [Getting Started](01-getting-started.md#register-the-server-with-an-mcp-client)). Tool-level parameters (`web_host`, `web_port` on `mitmweb_start`) override these defaults per session.

## Settings reference

| Field | Type | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `web_host` | string | `127.0.0.1` | REST/Web UI bind address (R1). `binds_publicly` is `true` for anything other than `127.0.0.1`, `::1`, `localhost`. |
| `web_port` | int | `8081` | 1–65535. |
| `allowed_dump_roots` | list[Path] | `[]` | Roots under which `.mitm` outputs and replay inputs are permitted (R3). |
| `allowed_script_roots` | list[Path] | `[]` | Roots under which addon scripts are permitted (R3). |
| `allowed_mock_roots` | list[Path] | `[]` | Roots under which `mitm_set_map_local` may read mock files. **Empty denies every `map_local` path** — secure by default. |
| `allowed_ca_roots` | list[Path] | `[]` | Roots under which CA material is permitted. |
| `shutdown_timeout_seconds` | float | `10.0` | Max wait per shutdown signal stage (0 < t ≤ 120). |
| `session_root` | Path | `<system tempdir>/mcp-security-mitmproxy` | Base for per-session directories `<root>/<session_id>/{dumps,ca,logs}`. Created `0700` (R2). |
| `log_capacity` | int | `500` | Stdout/stderr lines retained per child process (in-memory ring buffer), 1–100000. |

## Configuring the allowlists (the restriction knobs)

Every filesystem path an agent supplies — `save_path`, replay files, addon `scripts`, `map_local` mocks — must land under one of the corresponding roots, or the tool answers `PATH_NOT_ALLOWED`. The check resolves symlinks and compares canonical paths, so `../` traversal and symlink escape routes do not work.

**The shipped entrypoint has no environment variables for the roots, and they default to empty.** Empty means deny-everything. This is deliberate: a server started without an explicit allowlist must not accept agent paths. To enable path-based features, run a custom entrypoint that constructs `Settings` and starts the FastMCP app yourself:

```python
# custom_server.py — run with: uv run python custom_server.py
from pathlib import Path

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.server import create_server
from mcp_security_mitmproxy.core.lifecycle import app_lifespan
import mcp_security_mitmproxy.server as server_module

settings = Settings(
    allowed_dump_roots=[Path("/tmp/mcp-security-mitmproxy/runs")],
    allowed_script_roots=[Path("/home/user/addons")],
    allowed_mock_roots=[Path("/home/user/mocks")],
    session_root=Path("/tmp/mcp-security-mitmproxy"),
)
```

Because `app_lifespan` builds `Settings.from_env()`, the supported embedding pattern is to construct the server and wrap the lifespan with your own `Settings`:

```python
import contextlib
from collections.abc import AsyncIterator

from fastmcp import FastMCP

from mcp_security_mitmproxy.config import Settings
from mcp_security_mitmproxy.core.lifecycle import LifespanContext
from mcp_security_mitmproxy.core.session import SessionRegistry
from mcp_security_mitmproxy.tools import register_all_tools


@contextlib.asynccontextmanager
async def my_lifespan(server: FastMCP) -> AsyncIterator[LifespanContext]:
    settings = Settings(
        allowed_dump_roots=[Path("/tmp/mcp-security-mitmproxy/runs")],
        allowed_mock_roots=[Path("/home/user/mocks")],
    )
    registry = SessionRegistry(settings)
    try:
        yield LifespanContext(settings=settings, registry=registry)
    finally:
        await registry.shutdown_all(timeout=settings.shutdown_timeout_seconds)


app = FastMCP("mcp-security-mitmproxy", lifespan=my_lifespan)
register_all_tools(app)

if __name__ == "__main__":
    app.run()
```

Keep the `finally` shutdown — it is the guarantee that no proxy subprocess outlives the server.

### Choosing roots

* One directory per purpose, dedicated to this server. Never point roots at `$HOME`, project directories or system paths.
* Make roots *narrower* than the writes they allow: `allowed_dump_roots` receives files the child process writes (`-w`), so give it a scratch directory you can wipe.
* `allowed_mock_roots` is a *read* surface: mitmproxy serves the file contents to whatever client matches the rule. Only place files there that are safe to disclose to proxy clients.
* Addon scripts under `allowed_script_roots` execute as Python inside the mitmproxy child process. Treat that directory with source-code discipline: it is a code-execution surface, not a data directory.

## Session directories and isolation

Each session gets its own tree under `session_root`, created `0700`:

```text
<session_root>/<session_id>/
├── dumps/        # scratch for session-scoped dumps
├── ca/           # per-session CA material; the agent never sees private keys (R2)
├── logs/         # session log scratch
└── config.yaml   # 0600 — secret-bearing options, e.g. web_password
```

The child process is spawned with `--set confdir=<session dir>` inserted ahead of the caller's argv, and its working directory is the session directory. Two consequences:

1. mitmproxy picks up `config.yaml` *after* applying `confdir`, so secret options reach the child without ever appearing on the command line (invisible in `/proc/<pid>/cmdline`).
2. A caller-supplied `--set confdir=...` is rejected — it would shadow the isolation directory.

Cleanup: `mitmdump_stop` / `mitmweb_stop` terminate the process and release ports but **keep** the directory (dumps may still be needed). The directory is deleted when the session is removed or when the server shuts down. See [Secrets Handling](05-secrets-handling.md#what-stays-on-disk) for the implications.

## Ports

`SessionRegistry.start` probe-binds every requested port (proxy ports against `listen_host`, the web port against `web_host`) before spawning. A port already leased by another session, or occupied by anything else, fails with `PORT_IN_USE` before a child exists. Pick a different port; there is no auto-relocation, so session contracts stay predictable.

## Process logging

Each child's stdout/stderr streams into an in-memory ring buffer capped at `log_capacity` lines (default 500). Logs live only in memory of the MCP server process; they are not written to disk and are not currently exposed as a tool.
