# ADR-003: Codeless Traffic Manipulation, Dynamic Rules, and LFI Prevention

* **Status**: ACCEPTED (validated and implemented in Phase 4)
* **Decision Makers**: Software Architect, Backend Developer, Security Architect, Product Owner
* **Date**: 2026-09-21
* **Phase**: Phase 4 — Codeless Traffic Manipulation & Addon System

## Context and Problem Statement

AI agents operating `mcp-security-mitmproxy` require active network traffic intervention capabilities (route redirection, local response mocking, header injection/removal, and mutation of request/response bodies).

This intervention must take place in real time during live sessions without requiring the agent to author complex Python scripts or restart proxy processes for each new test scenario.

Three architectural and security constraints governed this decision:

1. **Critical Risk of Local File Inclusion (LFI - R3)**: Mitmproxy's native `map_local` addon reads host files and serves them as HTTP responses. If an agent supplies an arbitrary path (such as `/etc/shadow`, `/proc/kcore`, or private SSH keys), the proxy becomes an exfiltration conduit for confidential host assets.
2. **File Exfiltration via the `@` Syntax**: The `modify_headers` and `modify_body` addons support the `@path` prefix to read replacement contents from local files.
3. **Syntax Delimiter Ambiguity**: Native mitmproxy rules use arbitrary delimiters in the format `[/filter]/pattern/replacement`. If the regular expression pattern or URL contains unescaped slashes or the chosen delimiter, the rule breaks silently or behaves unpredictably.

## Decision Drivers

* **D1 — LFI and Path Traversal Prevention (R3)**: No file outside authorized roots (`allowed_dump_roots` / `allowed_mock_roots`) may be served by `map_local` or accessed via header/body file expansions.
* **D2 — Dynamic Runtime Mutation**: Ability to inject and clear rules without stopping the proxy or invalidating the active `session_id`.
* **D3 — Reuse of Native mitmproxy Addons**: Leverage established, tested implementations of `mapremote`, `maplocal`, `modifyheaders`, and `modifybody` rather than reinventing network interception logic.
* **D4 — Strictly Typed Contracts**: AI agents interact with unambiguous Pydantic models (`MapRemoteRuleSpec`, `MapLocalRuleSpec`, etc.), never with raw, manually concatenated spec strings.

## Considered Options

### Option A — Proprietary Python Rules Addon
Implement a custom addon (`rules_engine.py`) intercepting mitmproxy's `request` and `response` hooks, evaluating rules stored in memory or SQLite.
* *Pros*: Granular telemetry counters per rule.
* *Cons*: Heavy engineering overhead; duplicates existing `map_local`/`map_remote` logic; introduces concurrency risks and Python execution overhead on every network frame.

### Option B — Static Configuration via CLI (`--set`)
Accept rules exclusively upon proxy startup (`mitmdump_start` and `mitmweb_start`).
* *Pros*: Simple implementation.
* *Cons*: Inflexible. Agents cannot introduce a mock or alter a header mid-session without restarting capture.

### Option C — Hybrid Integration via Native Addons and Dynamic REST Updates (Chosen)
Utilize native mitmproxy addons (`mapremote`, `maplocal`, `modifyheaders`, `modifybody`). For active `mitmweb` sessions, `MitmwebClient` updates options via **`PUT /options`**. For `mitmdump`, initial rules pass via `--set`. All local filesystem paths must be validated by `ensure_allowed()`.

> **Factual Note (verified against mitmproxy 12.2.3):** The options mutation endpoint is **`PUT /options`** (`mitmproxy/tools/web/app.py`, `class Options.put`); no `POST /options` endpoint exists. Furthermore, updating a `Sequence[str]` option **replaces the entire collection** rather than appending. Every mutation requires a read-modify-write workflow (`GET /options` → mutate list → `PUT /options`).

## Decision Outcome

Adopt **Option C**:

1. **Expose Dedicated MCP Tools**:
   - `mitm_set_map_remote(session_id, rule)`
   - `mitm_set_map_local(session_id, rule)`
   - `mitm_modify_headers(session_id, rule)`
   - `mitm_modify_body(session_id, rule)`
   - `mitm_list_rules(session_id)`
   - `mitm_clear_rules(session_id, rule_type)`

2. **LFI Shielding (R3)**:
   - Every invocation of `mitm_set_map_local` resolves symlinks and validates the target path against the configured allowlist via [`core/paths.py:ensure_allowed()`](file:///home/daniel/Code/mcp-security-mitmproxy/src/mcp_security_mitmproxy/core/paths.py).
   - Any path outside the allowlist is rejected immediately with `PATH_NOT_ALLOWED`.

3. **Block Unvalidated `@` Syntax**:
   - In `mitm_modify_headers` and `mitm_modify_body`, values beginning with `@` are rejected at the schema boundary, preventing arbitrary local file reads through header/body replacements.

4. **Safe Delimiter Compilation (`rules/engine.py`)**:
   - An internal compiler selects an unused delimiter (`|`, `#`, `!`, `;`) that does not collide with characters in the regex patterns, replacement URLs, or filters.
   - Native spec syntax is `[/flow-filter]/subject/replacement` (`mitmproxy/utils/spec.py:parse_spec`): the separator is the **first character**, followed by 2 parts (without filter) or 3 parts (with filter). A 3-part string without an explicit filter intent is parsed as a flow filter—making deterministic compilation mandatory.

5. **Reserved Options in Raw `set_options` Channel**:
   - `RESERVED_SET_OPTIONS` was expanded from `{confdir, scripts}` to include `map_local`, `map_remote`, `modify_headers`, `modify_body`, `save_stream_file`, and `hardump`.
   - Contract invariant: **agents cannot set these options through raw `--set` flags**. Only `rules/engine.py` generates them, with canonical paths pre-validated by `ensure_allowed()`.
   - `map_remote` is reserved for contract consistency: all routing rules must be compiled by the engine.
   - `save_stream_file` and `hardump` are reserved to prevent arbitrary filesystem write operations (`save.py` expands `strftime` wildcards; `savehar.py` writes HAR files to arbitrary paths).

## Consequences

### Positive
* AI agents configure API mocks and header manipulations dynamically with immediate feedback.
* Zero LFI vulnerability surface; file-based mocking is strictly confined to safe directory allowlists.
* Maintains full compatibility with mitmproxy 12 internal architecture.

### Negative and Mitigations
* Large rule sets could produce overlapping match rules (e.g. multiple mocks matching the same path prefix).
  * *Mitigation*: `mitm_list_rules` and `mitm_clear_rules` allow agents to inspect and flush rule collections at any point.
