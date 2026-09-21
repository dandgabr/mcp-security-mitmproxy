# Secrets Handling

The server inspects traffic that carries credentials: tokens, cookies, API keys, session material. Two questions drive this document: *what does the agent see?* and *where do secrets live at runtime?* The answers differ — redaction governs tool outputs, filesystem permissions govern everything else.

## What the agent sees: the redaction engine

`core/redact.py` implements two functions, both fail-closed: content that merely *looks* sensitive is masked rather than passed through.

### `redact_headers(headers)` — header-level masking

A header value is replaced with `[REDACTED]` when its name contains any of these tokens (case-insensitive substring match):

```
auth · token · key · secret · cookie · credential · password
```

That covers `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Custom-Auth`, `X-Goog-Api-Key`, `X-Amz-Security-Token`, `Authentication`, and anything future-shaped — without maintaining a list. `mitmweb_get_flow_detail` applies it to request and response headers whenever `redact: true` (the default).

### `redact_text(text)` — payload-level masking

Applied to exported content (`mitm_export_flow`, always) and to content views and WebSocket/TCP messages in flow detail. One pass, seven pattern families:

| Pattern family | Example matched | Replacement |
| :--- | :--- | :--- |
| PEM blocks (DOTALL, whole block) | `-----BEGIN PRIVATE KEY-----…` | `[REDACTED]` |
| Bearer scheme | `Bearer eyJhbGciOi…` | `Bearer [REDACTED]` |
| Basic scheme | `Basic dXNlcjpwYXNz…` | `Basic [REDACTED]` |
| Bare JWTs (three base64url segments) | `eyJhbGciOi….…` | `[REDACTED]` |
| AWS access key ids | `AKIA…` / `ASIA…` (16 chars) | `[REDACTED]` |
| OpenAI-style keys | `sk-…` | `[REDACTED]` |
| Header-style lines and `key: value` / `key=value` pairs whose key names a secret (`authorization`, `cookie`, `access_token`, `refresh_token`, `api_key`, `password`, `secret`, `client_secret`, `private_key`, …) | `"api_key": "abc123"` | key preserved, value → `[REDACTED]` |

Two details matter for downstream parsing:

* Quoting is preserved (`"api_key": "[REDACTED]"`), so JSON/YAML structures survive redaction.
* Header-line detection uses the same dynamic token heuristic as `redact_headers`, so `curl -H 'X-Custom-Auth: …'` in an export is masked too.

### Where redaction applies — and where it does not

| Surface | Redaction |
| :--- | :--- |
| `mitmweb_get_flow_detail` | On by default (`redact: true`); headers and text content masked. You can pass `redact: false` — an explicit, per-call decision. |
| `mitm_export_flow` | Always. No opt-out exists in the contract. |
| `mitmweb_get_flows`, `mitm_filter_flows` | Summaries only: no bodies, no headers — nothing to redact. |
| mitmproxy's **web UI** (`web_url`) | Not routed through this server's engine. Anyone with browser access to the UI sees raw traffic. |
| `.mitm` dump files | Raw. See below. |

**Rule of thumb:** keep `redact: true` (i.e., do nothing). Pass `redact: false` only when you specifically need the raw bytes, on a session whose traffic you already consider compromised.

## Where secrets live at runtime

### The web token

* **Generation:** `secrets.token_hex(16)` (128 bits) when `mitmweb_start` receives no `web_password`.
* **Delivery:** written to `<session_dir>/config.yaml` (`0600`) and picked up by mitmproxy through `confdir`. It never appears in argv, so `/proc/<pid>/cmdline` never exposes it.
* **Storage:** in the server process memory, keyed by session. Not echoed in `mitmweb_start` output. Not written to any log.
* **Rotation:** stop the session and start a new one — there is no in-place rotation. A supplied `web_password` is your responsibility as the caller; prefer letting the server generate it.

### Session directories

```
<session_root>/<session_id>/   # 0700
├── dumps/  ├── ca/  └── logs/
└── config.yaml                  # 0600 — holds web_password
```

`ca/` holds the per-session Certificate Authority. mitmproxy generates it there; the private key never crosses a tool boundary. Directory permissions are re-asserted with `chmod` after creation.

### What stays on disk

Redaction applies to *tool outputs*. It does not apply to files:

* A `save_path` dump (`-w`) is a full-fidelity recording: raw headers, raw bodies, every credential that crossed the proxy.
* The session directory — including `config.yaml` and `ca/` — survives `mitmdump_stop`/`mitmweb_stop`. It is deleted when the session is removed or when the MCP server process shuts down (the lifespan teardown runs `shutdown_all`, which cleans every remaining tree).

Operator discipline:

1. Point `allowed_dump_roots` at a dedicated directory on a filesystem you treat as sensitive (encrypted at rest if the traffic matters).
2. Delete dumps when the work is done; stopping a session is not cleanup.
3. The default `session_root` is under the system temp directory. On multi-user machines, check that tmp-cleaning policies match your retention expectations — and prefer an explicit `session_root` under your own home.

### Process logs

Each child's stdout/stderr is captured into an in-memory ring buffer (500 lines by default). mitmproxy logs can echo request lines, never bodies; still, the buffer lives in the server process only, is never written to disk, and is not exposed as a tool.

### Error messages

`to_tool_result` converts unexpected exceptions into `INTERNAL_ERROR` with only the exception class name — exception *arguments* are dropped, because library errors frequently embed the data being processed (URLs, headers, payloads). Domain errors (`PATH_NOT_ALLOWED`, etc.) carry only paths and option names you already supplied.

## Practical checklist

- [ ] `redact` left at `true` for all inspection calls (default).
- [ ] Allowlist roots point at dedicated, permission-restricted directories — not `$HOME`, not the repo.
- [ ] `web_host` on loopback; the web UI is a raw-traffic surface outside the redaction engine.
- [ ] Dumps deleted after use; session directories treated as sensitive until server shutdown.
- [ ] `web_password` supplied by you only when integrating with an external auth setup; otherwise let the server generate it.
- [ ] `redact: false` calls (when unavoidable) never piped into persistent notes, tickets or logs.
