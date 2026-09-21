# Getting Started

This tutorial takes you from a clean checkout to a working capture session driven through MCP: install the server, register it with an MCP client, start a proxy session, read traffic, mutate it with a rule, and shut everything down cleanly.

## Prerequisites

* Python **3.13 or newer**
* [uv](https://docs.astral.sh/uv/) for dependency and environment management
* mitmproxy binaries on `PATH` — installing the package brings in the mitmproxy library, and `uv run` exposes the `mitmdump`/`mitmweb` entry points from the same virtual environment

## Install

```bash
git clone https://github.com/dandgabr/mcp-security-mitmproxy.git
cd mcp-security-mitmproxy
uv sync
```

## Run the server

```bash
uv run mcp-security-mitmproxy
```

Equivalent module form:

```bash
uv run python -m mcp_security_mitmproxy
```

The server speaks MCP over **stdio**. It is a child process of your MCP client; it does not open a port for MCP itself. Proxy ports are only opened when a session starts.

## Register the server with an MCP client

All clients below spawn the server as a child process over stdio. The `env` blocks are optional — `MCP_MITM_WEB_HOST` / `MCP_MITM_WEB_PORT` default to `127.0.0.1` / `8081`; set them only to change those defaults. Always use an absolute path.

### IDE and desktop clients

#### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mcp-security-mitmproxy",
        "run", "mcp-security-mitmproxy"
      ],
      "env": {
        "MCP_MITM_WEB_HOST": "127.0.0.1",
        "MCP_MITM_WEB_PORT": "8081"
      }
    }
  }
}
```

#### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mcp-security-mitmproxy",
        "run", "mcp-security-mitmproxy"
      ]
    }
  }
}
```

#### Zed (`~/.config/zed/settings.json`)

```json
{
  "context_servers": {
    "mitmproxy": {
      "command": {
        "path": "uv",
        "args": [
          "--directory", "/absolute/path/to/mcp-security-mitmproxy",
          "run", "mcp-security-mitmproxy"
        ]
      }
    }
  }
}
```

### Terminal agents

#### Codex (`~/.codex/config.toml`)

Codex reads MCP servers from the `mcp_servers` table of its TOML config. Merge into the existing file — do not replace it:

```toml
[mcp_servers.mitmproxy]
command = "uv"
args = ["--directory", "/absolute/path/to/mcp-security-mitmproxy", "run", "mcp-security-mitmproxy"]

[mcp_servers.mitmproxy.env]
MCP_MITM_WEB_HOST = "127.0.0.1"
MCP_MITM_WEB_PORT = "8081"
```

Or register through the CLI (the `--` separates Codex flags from the server command):

```bash
codex mcp add mitmproxy \
  --env MCP_MITM_WEB_HOST=127.0.0.1 --env MCP_MITM_WEB_PORT=8081 \
  -- uv --directory /absolute/path/to/mcp-security-mitmproxy run mcp-security-mitmproxy
```

Verify with `codex mcp list`.

#### OpenCode (`opencode.json`)

OpenCode uses a project-level `.opencode/opencode.json` or the global `~/.config/opencode/opencode.json`. Note that `command` is a **single array**, not a command-plus-args pair:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mitmproxy": {
      "type": "local",
      "command": [
        "uv", "--directory", "/absolute/path/to/mcp-security-mitmproxy",
        "run", "mcp-security-mitmproxy"
      ],
      "environment": {
        "MCP_MITM_WEB_HOST": "127.0.0.1",
        "MCP_MITM_WEB_PORT": "8081"
      },
      "enabled": true
    }
  }
}
```

Restart OpenCode (or start a new session) after editing; the 18 tools appear in the tool list.

#### Antigravity (`~/.gemini/config/mcp_config.json`)

Antigravity loads MCP servers from the global `mcp_config.json` (all sessions) or from a plugin's own `mcp_config.json`. Merge the entry into the existing `mcpServers` map:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mcp-security-mitmproxy",
        "run", "mcp-security-mitmproxy"
      ],
      "env": {
        "MCP_MITM_WEB_HOST": "127.0.0.1",
        "MCP_MITM_WEB_PORT": "8081"
      }
    }
  }
}
```

Inspect the connection in the UI under **Additional Options (…) → MCP Servers**; discovered tools are injected into the agent's toolset automatically.

#### CommandCode (`~/.commandcode/mcp.json`)

CommandCode keeps its MCP registry in `~/.commandcode/mcp.json` (user scope) with an explicit `transport` field:

```json
{
  "mcpServers": {
    "mitmproxy": {
      "transport": "stdio",
      "enabled": true,
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/mcp-security-mitmproxy",
        "run", "mcp-security-mitmproxy"
      ],
      "env": {
        "MCP_MITM_WEB_HOST": "127.0.0.1",
        "MCP_MITM_WEB_PORT": "8081"
      }
    }
  }
}
```

Or register through the CLI (`-s user` writes the global registry; drop it for project scope):

```bash
commandcode mcp add mitmproxy -s user \
  -e MCP_MITM_WEB_HOST=127.0.0.1 -e MCP_MITM_WEB_PORT=8081 \
  -- uv --directory /absolute/path/to/mcp-security-mitmproxy run mcp-security-mitmproxy
```

Verify with `commandcode mcp list`; manage live connections with `/mcp` inside a session.

Restart the client after saving. It spawns the server and the 18 tools appear in the tool list.

## First session

The typical cycle is: start a `mitmweb` session, send traffic through its proxy port, list flows, inspect one flow, optionally add a mutation rule, then stop the session.

### 1. Start a mitmweb session

Call `mitmweb_start` with one proxy mode:

```json
{
  "mode": [{ "mode": "regular", "listen_port": 8888 }],
  "web_port": 8081
}
```

On success the tool returns a `session` object with a `session_id` (UUID), the process `pid`, and a `web_url` (`http://127.0.0.1:8081/`). The web UI token is generated internally and is never echoed back. Keep the `session_id`; every other tool takes it.

Point any HTTP client at the proxy to generate traffic:

```bash
curl -x http://127.0.0.1:8888 https://httpbin.org/get
```

### 2. List captured flows

```json
{ "session_id": "<session_id>", "limit": 20 }
```

`mitmweb_get_flows` returns `FlowSummary` rows: `flow_id`, `type` (`http`, `tcp`, `udp`, `dns`, `websocket`), method, host, path, status code, timestamp and duration.

### 3. Inspect one flow

```json
{ "session_id": "<session_id>", "flow_id": "<flow_id>" }
```

`mitmweb_get_flow_detail` returns headers, payloads and (for WebSocket flows) messages. Headers whose names look secret-bearing and body content that matches token patterns are replaced with `[REDACTED]` before the tool answers — redaction is on by default (see [Secrets Handling](05-secrets-handling.md)).

### 4. Apply a traffic rule

Rules run on `mitmweb` sessions only (they are applied over the mitmweb REST bridge; a headless `mitmdump` session has no such endpoint). Example redirect:

```json
{
  "session_id": "<session_id>",
  "rule": {
    "url_pattern": "^https://api\\.example\\.com/v1/(.*)$",
    "replacement_url": "https://staging.internal/v1/\\1"
  }
}
```

`mitm_set_map_remote` returns a `rule_id` such as `map_remote:0` and the exact `rendered_spec` sent to mitmproxy — keep it as your audit trail. `mitm_list_rules` reads back every active rule; `mitm_clear_rules` resets one family or all four.

### 5. Stop the session

```json
{ "session_id": "<session_id>" }
```

Shutdown escalates through `SIGINT` → `SIGTERM` → `SIGKILL`, so the child never survives as an orphan. Stopping the MCP server itself tears down every remaining session through the lifespan hook — no zombie process and no bound port outlives the server.

## Common first-run errors

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `PATH_NOT_ALLOWED: no allowlist roots configured` | You passed `save_path`, `scripts` or a `map_local` path, but the corresponding allowlist is empty (the default). | Configure allowlist roots — see [Configuration](03-configuration.md). |
| `PORT_IN_USE` | The chosen proxy or web port is taken. | Pick another `listen_port` / `web_port`. |
| `INVALID_INPUT: modes require elevated privileges` | You requested `local` or `tun` mode. | These modes are refused outright; run mitmproxy outside this server if you need them. |
| `--set <option> is reserved` | `set_options` tried to override an isolation-critical option. | Drop the option; the protected channels are the dedicated rules tools. |

## Where to go next

* [Tools Reference](02-tools-reference.md) — full contracts for all 18 tools.
* [Configuration](03-configuration.md) — environment variables, session directories, allowlists.
* [Security Model](04-security-model.md) — why the restrictions exist and how each is enforced.
