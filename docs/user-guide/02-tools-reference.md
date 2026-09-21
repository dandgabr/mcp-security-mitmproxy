# Tools Reference

Complete reference for the 18 MCP tools exposed by `mcp-security-mitmproxy`. All tools return the same envelope: `ok: true` plus result fields, or `ok: false` with an `error` object (`code`, `message`, optional `detail`). No tool ever raises to the MCP client.

```
mitmdump controls   mitmdump_start · mitmdump_stop · mitmdump_replay
mitmweb controls    mitmweb_start · mitmweb_stop · mitmweb_get_flows · mitmweb_get_flow_detail
core / offline      session_list · session_status · mitm_execute_command · mitm_export_flow · mitm_filter_flows
rules (mutation)    mitm_set_map_remote · mitm_set_map_local · mitm_modify_headers · mitm_modify_body · mitm_list_rules · mitm_clear_rules
```

## Shared types

### `ProxyModeSpec`

One `--mode` argument for a mitmproxy executable.

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `mode` | `regular` \| `local` \| `wireguard` \| `reverse` \| `transparent` \| `tun` \| `upstream` \| `socks5` \| `dns` | required | Proxy mode. |
| `upstream_url` | string \| null | `null` | **Required** for `reverse` and `upstream`; rejected on every other mode. |
| `protocol` | `tcp` \| `udp` \| `dns` \| `http3` \| `quic` \| `tls` \| `dtls` | `null` | Scheme override for `reverse:`. |
| `listen_port` | int 1–65535 \| null | `null` | Proxy listen port. Only the first spec that declares one is emitted. |
| `intercept` | list[string] \| null | `[]` for `local` | `local:` intercept spec (`process`, `!process`, `pid`). Empty = everything. |
| `wireguard_key_path` | string \| null | `null` | **Required** for `wireguard`. |
| `interface_name` | string \| null | `null` | **Required** for `tun`. |

`local` and `tun` are refused by every start/replay tool (see [Security Model](04-security-model.md), R5).

### `SessionState`

Returned by every start tool and by `session_status`.

| Field | Description |
| :--- | :--- |
| `session_id` | UUID used by all other tools. |
| `executable` | `mitmdump` or `mitmweb`. |
| `status` | `starting` · `running` · `stopping` · `stopped` · `failed`. |
| `modes` | The `ProxyModeSpec` list the session was started with. |
| `listen_host`, `listen_ports` | Proxy bind address and leased ports (includes the web port on mitmweb sessions). |
| `web_host`, `web_port` | Set only on mitmweb sessions. |
| `pid` | Child process id. |
| `save_path` | Canonical dump path, when `-w` was requested. |
| `created_at`, `exit_code` | Set once available. |

### `FlowSummary`

| Field | Description |
| :--- | :--- |
| `flow_id` | mitmproxy flow id (use with `mitmweb_get_flow_detail`, `mitm_export_flow`). |
| `type` | `http` · `tcp` · `udp` · `dns` · `websocket`. |
| `method`, `scheme`, `host`, `port`, `path` | Request line data (null for non-HTTP flows). |
| `status_code` | Response status, when a response exists. |
| `timestamp_start`, `duration` | Capture time and observed latency in seconds. |

### `FlowDetailLevel` (mitmdump `--flow-detail`)

`none` (0) · `uri` (1) · `short` (2, default) · `verbose` (3) · `full` (4). The MCP contract uses these names; the server translates to the integer mitmproxy's CLI requires.

### `ToolError` codes

`INVALID_INPUT` · `SESSION_NOT_FOUND` · `SESSION_NOT_RUNNING` · `PORT_IN_USE` · `PROCESS_SPAWN_FAILED` · `PATH_NOT_ALLOWED` · `COMMAND_NOT_ALLOWED` · `UPSTREAM_UNREACHABLE` · `TIMEOUT` · `INTERNAL_ERROR`. Resolution guidance per code lives in [Security Model](04-security-model.md#handling-restriction-errors).

---

## mitmdump controls

### `mitmdump_start`

Starts a headless capture session. Use it when an agent only needs traffic recorded or replayed, with no interactive inspection.

**Input**

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `mode` | `ProxyModeSpec[]` | required | At least one. |
| `listen_host` | string | `127.0.0.1` | Proxy bind address. |
| `save_path` | string \| null | `null` | Output `.mitm` file. Validated against `allowed_dump_roots`. |
| `flow_detail` | `FlowDetailLevel` | `short` | Mapped to mitmproxy's int 0–4. |
| `filter_expression` | string \| null | `null` | FlowFilter, e.g. `~d example.com & ~m POST`. |
| `scripts` | string[] | `[]` | Addon scripts. Each validated against `allowed_script_roots`. |
| `set_options` | map[string, any] | `{}` | Raw mitmproxy options. Reserved keys are rejected (see below). |

**Output**: `session: SessionState`.

**Errors**: `PATH_NOT_ALLOWED`, `INVALID_INPUT` (reserved option, privileged mode, no mode), `PORT_IN_USE`, `PROCESS_SPAWN_FAILED`.

Example:

```json
{
  "mode": [{ "mode": "regular", "listen_port": 8888 }],
  "save_path": "/tmp/mcp-security-mitmproxy/run1/mitm-out.mitm",
  "filter_expression": "~d api.example.com",
  "set_options": { "stream_large_bodies": "1m" }
}
```

### `mitmdump_stop` / `mitmweb_stop`

Identical contract; both stop any managed session.

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `session_id` | string | required | UUID from the start tool. |
| `timeout_seconds` | float | `10.0` | Max wait per signal stage, 0 < t ≤ 120. |
| `force` | bool | `false` | Send `SIGKILL` after the timeout when `true`. Without it, a stubborn process yields `TIMEOUT`. |

Stopping runs `SIGINT` → `SIGTERM` → (`SIGKILL` if `force`), clears the port leases and marks the session `stopped` (or `failed` on a non-zero exit). **Note:** `stop` does not delete the session directory on disk; dump files remain until the session is removed or the server shuts down (see [Secrets Handling](05-secrets-handling.md#what-stays-on-disk)).

### `mitmdump_replay`

Replays stored `.mitm` files through a fresh mitmdump session: client replay (`--client-replay`, `-C`) re-sends recorded requests; server replay (`--server-replay`, `-S`) answers incoming requests with recorded responses.

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `mode` | `ProxyModeSpec[]` | required | At least one. |
| `client_replay` | string[] | `[]` | `.mitm` paths; each validated against `allowed_dump_roots`. |
| `server_replay` | string[] | `[]` | Same validation. |
| `replay_kill_extra` | bool | `true` | Sets `replay_kill_extra=true` (kill non-replay traffic). |
| `save_path` | string \| null | `null` | Validated against `allowed_dump_roots`. |

At least one of `client_replay` / `server_replay` is required, otherwise `INVALID_INPUT`.

---

## mitmweb controls

### `mitmweb_start`

Starts an interactive session: proxy plus web UI plus the REST bridge that every inspection and rules tool uses.

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `mode` | `ProxyModeSpec[]` | required | At least one. |
| `listen_host` | string | `127.0.0.1` | Proxy bind address. |
| `web_host` | string | `127.0.0.1` | REST/Web UI bind. Non-loopback values are an explicit opt-in (R1). |
| `web_port` | int | `8081` | REST/Web UI port. |
| `web_open_browser` | bool | `false` | Passed to mitmproxy's `web_open_browser`. |
| `web_password` | string \| null | `null` | REST/Web UI token. When omitted the server generates `secrets.token_hex(16)`. **Never echoed in any output.** |
| `save_path` | string \| null | `null` | Validated against `allowed_dump_roots`. |
| `scripts` | string[] | `[]` | Each validated against `allowed_script_roots`. |

**Output**: `session: SessionState` and `web_url` (`http://<web_host>:<web_port>/`). Ports are probed before spawn — proxy ports against `listen_host`, the web port against `web_host` — so a stolen lease fails with `PORT_IN_USE` instead of a confusing child crash.

### `mitmweb_get_flows`

Lists captured flows. With a `filter_expression` the filter is evaluated server-side by mitmweb (via `/flows/dump`), so `total` counts the matched set, not the whole session; pagination slices afterwards.

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `session_id` | string | required | Must be a **running** session. |
| `filter_expression` | string \| null | `null` | FlowFilter, e.g. `~u /api/ & ~c 200`. |
| `limit` | int | `50` | 1–500. |
| `offset` | int | `0` | ≥ 0. |
| `include_body` | bool | `false` | Reserved. Flow summaries never carry bodies in this version. |

**Output**: `flows: FlowSummary[]`, `total: int`.

### `mitmweb_get_flow_detail`

Fetches one flow's headers, payload and messages. This is the tool agents use to *read* traffic.

| Field | Type | Default | Constraints |
| :--- | :--- | :--- | :--- |
| `session_id` | string | required | Running mitmweb session. |
| `flow_id` | string | required | From `mitmweb_get_flows`. |
| `parts` | `request`[] \| `response`[] \| `messages`[] | `["request","response"]` | Which parts to fetch. `messages` covers WebSocket/TCP frames. |
| `content_view` | string \| null | `null` | mitmproxy content view (`json`, `grpc`, `protobuf`, …). `null` = `auto`. |
| `redact` | bool | `true` | When `true`, sensitive header values and payload matches are masked before the tool answers (R4). |

**Output**: `detail` — `flow_id` plus one entry per requested part; each request/response part includes a `content_view` block (`text`, `view_name`, `description`) when the view resolves.

---

## Core, sessions and offline operations

### `session_list`

No input. Returns `sessions: SessionState[]` — every session the server knows, running or not. Use it to recover after a client reconnects without restarting the server.

### `session_status`

`session_id` (required) → `session: SessionState`. Unknown ids give `SESSION_NOT_FOUND`.

### `mitm_execute_command`

Executes one allowlisted mitmproxy command on a running mitmweb session through `/commands/<command>`.

| Field | Type | Notes |
| :--- | :--- | :--- |
| `session_id` | string | Running mitmweb session. |
| `command` | string | Must be exactly one of: `view.clear`, `view.properties.set`, `flow.kill`, `flow.resume`, `flow.mark`, `flow.comment`, `replay.client`, `replay.server`. Anything else → `COMMAND_NOT_ALLOWED` (the error `detail` lists the allowed set). |
| `arguments` | string[] | `[]` | Positional arguments, e.g. `["<flow_id>"]` for `flow.kill`. |

**Output**: `result` — the command's return value from mitmweb.

### `mitm_export_flow`

Exports one flow as a replayable command line or raw bytes. Three sources, in order of precedence:

1. `flow_path` — offline export from a `.mitm` file (validated against `allowed_dump_roots`).
2. `session_id` with a `save_path` — reads that dump file.
3. `session_id` without a `save_path` — downloads the live dump from the mitmweb bridge.

| Field | Type | Default | Notes |
| :--- | :--- | :--- | :--- |
| `flow_id` | string | required | Matched inside the dump; missing ids → `INVALID_INPUT`. |
| `format` | `curl` \| `httpie` \| `raw` \| `raw_request` \| `raw_response` | required | |
| `session_id` | string \| null | `null` | Required when `flow_path` is absent. |
| `flow_path` | string \| null | `null` | Allowlisted `.mitm` path. |
| `preserve_original_ip` | bool | `false` | Keeps the original destination IP in Host-style exports. |

**Output**: `content`, `format`. The content always passes through the text redaction engine before it is returned — there is no opt-out (R4).

### `mitm_filter_flows`

Evaluates a FlowFilter expression offline (`.mitm` file or session dump) instead of through the live view.

| Field | Type | Default | Notes |
| :--- | :--- | :--- | :--- |
| `expression` | string | required | e.g. `~m POST & ~b login`, `~websocket`, `~u ~api/`. Invalid syntax → `INVALID_INPUT`. |
| `session_id` | string \| null | `null` | Live session (uses `save_path` or the live dump endpoint). |
| `flow_path` | string \| null | `null` | Allowlisted `.mitm` path. |
| `limit` | int | `100` | 1–1000. |

**Output**: `matched: FlowSummary[]`, `count` (all matches, before the limit). One of `session_id` / `flow_path` is required.

Useful operators: `~u` URL regex · `~m` method · `~d` domain · `~c` status code · `~b` body regex · `~h` header · `~q` request-only · `~s` response-only · `~websocket`, `~tcp`, `~udp` · `&`, `|`, `!` combinators.

---

## Rules (codeless traffic mutation)

All six tools operate on **running mitmweb sessions** only; they read and write mitmproxy options through the REST bridge (`GET`/`PUT /options`). Every mutation is a read-modify-write of the whole option list — mitmproxy replaces list options wholesale, it never appends. Each set tool returns:

* `rule_id` — `<option>:<index>` (e.g. `modify_headers:2`), usable as a stable handle while the list is unchanged;
* `rendered_spec` — the exact delimited string sent to mitmproxy (audit trail).

### `mitm_set_map_remote`

Rewrites matching request URLs to another remote URL.

```json
{
  "session_id": "<id>",
  "rule": {
    "filter_expression": "~d api.example.com",
    "url_pattern": "^https://api\\.example\\.com/v1/(.*)$",
    "replacement_url": "https://staging.internal/v1/\\1"
  }
}
```

`url_pattern` must compile as a Python regex (validated at the schema); capture groups are available as `\1`–`\9` in `replacement_url`. `filter_expression` is optional; without it the rule matches everything.

### `mitm_set_map_local`

Serves a mocked response from a local file or directory. The strictest tool in the catalog:

* `local_path` must be **absolute** (or `~`-prefixed) — relative paths are rejected at the schema;
* the canonical path (symlinks resolved) must fall under a configured `allowed_mock_roots` root, **before** the spec is compiled — an empty allowlist denies every path (`PATH_NOT_ALLOWED`);
* the target must already exist, because mitmproxy's native parser resolves it with `strict=True`.

```json
{
  "session_id": "<id>",
  "rule": {
    "url_pattern": "^https://cdn.example.com/app\\.js$",
    "local_path": "/home/user/mocks/app.js"
  }
}
```

**Output** additionally includes `canonical_path` — the exact path that was registered.

### `mitm_modify_headers`

Sets or removes one HTTP header. Direction is chosen through the filter: `~q` requests, `~s` responses, no filter = both.

| Rule field | Constraints |
| :--- | :--- |
| `header_name` | Literal RFC 9110 token (`Content-Type`), **not** a regex. |
| `operation` | `set` (default) — replace the header; `remove` — delete it (`header_value` must be omitted; with `set` it is required). |
| `header_value` | Must not start with `@` (mitmproxy would read a local file), must not contain raw CR/LF, and must not decode to control bytes after mitmproxy's escape decoding — the header-injection guard. Backslashes are escaped for a lossless round trip. |

Note: the native mitmproxy option always *replaces* matching headers. There is no "append second value" primitive, so no `add` operation exists in the contract.

```json
{
  "session_id": "<id>",
  "rule": {
    "filter_expression": "~u /api/",
    "header_name": "X-Debug-Flag",
    "header_value": "1",
    "operation": "set"
  }
}
```

### `mitm_modify_body`

Regex substitution inside request/response payloads (DOTALL semantics).

| Rule field | Constraints |
| :--- | :--- |
| `pattern` | Python regex locating the fragment; must compile at the schema. |
| `replacement` | Literal replacement text; may be empty (deletes the match); must not start with `@`; backslash-escaped for lossless transport. |

```json
{
  "session_id": "<id>",
  "rule": {
    "filter_expression": "~q & ~u /login",
    "pattern": "\"password\":\"[^\"]*\"",
    "replacement": "\"password\":\"test\""
  }
}
```

### `mitm_list_rules`

`session_id` → `rules: RuleEntry[]` and `counts` per family. Each `RuleEntry` carries `rule_type`, `index` (position in its option list — order is precedence), the raw `raw_spec` string, and `valid`. A `valid: false` entry means the stored spec no longer parses (out-of-band drift) and is surfaced rather than hidden.

### `mitm_clear_rules`

| Field | Behavior |
| :--- | :--- |
| `rule_type` absent | Clears all four families. |
| `rule_type` = `map_remote` \| `map_local` \| `modify_headers` \| `modify_body` | Clears only that family. |

**Output**: `cleared_count` and `remaining` (counts re-read from mitmweb after the write, so the result reflects reality, not intent).

---

## Error envelope example

Every failure looks like this — the agent can branch on `code` without parsing prose:

```json
{
  "ok": false,
  "error": {
    "code": "PATH_NOT_ALLOWED",
    "message": "path /etc/passwd is outside the configured allowlist",
    "detail": { "path": "/etc/passwd", "roots": ["/tmp/mocks"] }
  }
}
```

Unexpected internal failures collapse to `INTERNAL_ERROR` with only the exception class name in `message` — exception arguments are never forwarded, because they can carry secrets.
