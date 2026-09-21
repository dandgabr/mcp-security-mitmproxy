# ADR-002: Secret Redaction Strategy and In-Process Flow Management

* **Status**: ACCEPTED
* **Decision Makers**: Software Architect, Backend Developer, Security Architect, Product Owner
* **Date**: 2026-09-21
* **Phase**: Phase 3 — MCP Tools, REST Client, Secret Redaction, and Offline Flows

## Context and Problem Statement

When AI agents inspect captured network traffic, HTTP request/response bodies and headers frequently carry authentication credentials, session tokens, API keys, and passwords. Returning these secrets as plaintext into an LLM context window violates the principle of least privilege and security requirement **R4** ("configurable secret redaction before returning payloads to the model").

Additionally, agents must analyze and export flows captured during prior sessions stored in local `.mitm` dump files, or inspect flows in active sessions without relying exclusively on a long-lived `mitmweb` instance.

Two fundamental architectural problems required a technical decision in Phase 3:

1. **Where and how to apply secret redaction (R4):** Destructive redaction inside the proxy engine would alter the live traffic transmitted to target servers; conversely, non-destructive redaction in the MCP layer must operate deterministically before JSON-RPC serialization.
2. **How to inspect, filter, and export flows offline:** Spawning an ephemeral `mitmdump` or `mitmweb` subprocess solely to inspect a `.mitm` file introduces latency, port allocation collisions, and unnecessary lifecycle overhead.

## Decision Drivers

* **D1 — Credential Leakage Protection (R4)**: No `Bearer` tokens, API keys, session cookies, or sensitive credential pairs must leak into AI agent context windows by default (`redact=True`).
* **D2 — Non-Interference with In-Flight Traffic**: The proxy engine must forward pristine payloads to target servers; sanitization occurs strictly at the observability boundary exposed to the MCP client.
* **D3 — Efficient and Isolated Offline Flow Operations**: Reading `.mitm` dumps, evaluating `FlowFilter` expressions, and exporting to external formats (`curl`, `httpie`, `raw`, `raw_request`, `raw_response`) must execute in-process without network sockets or subprocess overhead.
* **D4 — Mitmproxy 12 Compatibility**: Rely on native APIs (`mitmproxy.io.FlowReader`, `mitmproxy.flowfilter`, and the `mitmproxy.addons.export.Export` addon).

## Considered Options

### Secret Redaction Strategy

* **Option A — Python Addon in mitmproxy**: Intercept `response` and overwrite headers/bodies directly within the proxy engine.
  * *Rejected*: Corrupts real network payloads under test, breaking authenticated API workflows.
* **Option B — Heuristic Sanitization in a Dedicated Layer (`core/redact.py`)**: `MitmwebClient` and flow serializers apply masking to structured copies before encapsulating results into the `ToolResult` envelope.
  * *Chosen*: Preserves original traffic in transit while ensuring payloads served to AI models are sanitized by default.

### Offline Operations Strategy

* **Option C — Ephemeral Subprocess `mitmdump -r <dump> -C <flow>`**: Invoke the CLI for each offline query.
  * *Rejected*: High process spawn overhead, fragile stdout parsing, and risk of leaked zombie processes under rapid queries.
* **Option D — In-Process Engine (`flows/manager.py`)**: Instantiate an ephemeral in-memory `mitmproxy.master.Master` attached to the current event loop for the `Export` addon, paired directly with `FlowReader` and `FlowFilter`.
  * *Chosen*: Sub-10ms latency, zero socket allocation, and strict typing via native `HTTPFlow` objects.

## Decision Outcome

1. Implement [`core/redact.py`](file:///home/daniel/Code/mcp-security-mitmproxy/src/mcp_security_mitmproxy/core/redact.py) providing:
   - `redact_headers`: Masks known sensitive headers (`authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `x-auth-token`, `private-token`, `token`, `access_token`) and any header name containing `token`.
   - `redact_text`: Uses regular expressions to replace `Bearer <token>` strings and sensitive JSON key-value pairs (`"access_token": "..."`, `"password": "..."`, etc.) with `"[REDACTED]"`.
2. Integrate redaction directly into `MitmwebClient.get_flow_detail` in [`web_client/client.py`](file:///home/daniel/Code/mcp-security-mitmproxy/src/mcp_security_mitmproxy/web_client/client.py) with the parameter `redact: bool = True`.
3. Implement [`flows/manager.py`](file:///home/daniel/Code/mcp-security-mitmproxy/src/mcp_security_mitmproxy/flows/manager.py) containing:
   - `read_flows_from_dump(dump_path)`: Streams flows via `mio.FlowReader(f.stream())`.
   - `filter_flows(flows, expression, limit)`: Compiles and evaluates mitmproxy expressions via `flowfilter.parse(expression)`, mapping results to `FlowSummary`.
   - `export_flow_offline(flow, format_name, preserve_original_ip)`: Executes mitmproxy's `export.Export` addon using an in-memory `master.Master` instance.
4. Restrict command execution in `tools/core_tools.py` through `ALLOWED_COMMANDS` (R3):
   - `view.clear`, `view.properties.set`, `flow.kill`, `flow.resume`, `flow.mark`, `flow.comment`, `replay.client`, `replay.server`. Any other command triggers `COMMAND_NOT_ALLOWED`.

## Consequences

### Positive

* **Safe by Default**: Agents receive sanitized payloads unless explicitly requested otherwise, preventing accidental credential exposure in logs and LLM contexts.
* **High Performance for Offline Dumps**: Reading and exporting captured flows requires no port allocation and completes synchronously with minimal overhead.
* **Privilege Isolation**: Commands executed via `mitm_execute_command` are bounded by an explicit allowlist, preventing arbitrary shell execution or unsafe internal mitmproxy calls.

### Negative and Mitigations

* **Heuristic Regex Coverage**: Regular expressions may fail on non-standard, custom-encoded token formats. *Mitigation*: The sensitive header list covers standard authentication patterns, and Phase 4 adds granular rule selectors.
* **Memory Footprint on Massive Dumps**: `read_flows_from_dump` buffers flows into memory. *Mitigation*: The `limit` parameter caps serialized results, and input files are streamed through `FlowReader`.
