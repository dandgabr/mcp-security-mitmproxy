# ADR-001: Technology Stack and Subprocess Execution Architecture

* **Status**: ACCEPTED (validated and implemented across Phases 1, 2, and 3)
* **Deciders**: Software Architect, Backend Developer, Product Owner, Security Architect
* **Date**: 2026-09-21
* **Phase**: Phase 1 — Technical Architecture, MCP Contracts, and Scaffolding (Confirmed in Phase 3)

## Context and Problem Statement

The `mcp-security-mitmproxy` project exposes the capabilities of the mitmproxy ecosystem (`mitmdump`, `mitmweb`, and `mitmproxy`) to AI agents through the Model Context Protocol. Phase 1 requires selecting the technology stack, directory layout, tool schemas, and baseline ADR.

Three concrete constraints drive this decision:

1. **Python version is driven by dependency constraints, not preference.** `mitmproxy` 12.2.3 declares `requires_python >=3.12` and targets CPython 3.12, 3.13, and 3.14. Running on Python 3.11 is impossible with mitmproxy 12+.
2. **AI agents must re-observe traffic before acting.** A proxy running inside an opaque subprocess returns no state to the agent. The system requires an authenticated, structured inspection channel between network capture and the model.
3. **Subprocess lifecycle is the primary operational risk.** Leaked ports, zombie processes, and orphaned CA certificates outlive the MCP server if teardown is not deterministic.

## Decision Drivers

* **D1 — Dependency Compatibility**: The stack must install cleanly on supported CPython runtimes without dependency resolution conflicts.
* **D2 — Agent Observability**: Structured inspection of flows, bodies, and headers without human intervention in a terminal UI or web browser.
* **D3 — Deterministic Teardown**: Zero leaked ports or orphaned child processes after MCP server shutdown.
* **D4 — Security Surface Minimization**: The proxy handles credentials and CA keys; the architecture must minimize secrets handled directly by the agent.
* **D5 — Stable Contracts**: Tool schemas must evolve without breaking connected MCP clients.

## Options Considered

### MCP Framework

* **Option A — Low-level official `mcp` SDK**: Provides complete protocol control but requires manual JSON Schema generation and request handler wiring.
* **Option B — `fastmcp` (v4.0.5)**: Provides `@mcp.tool` and `@mcp.resource` decorators, automatic schema generation from type hints and Pydantic models, and `lifespan` context management for shared state.
* **Option C — Custom JSON-RPC Implementation**: Discarded immediately; high maintenance overhead without tangible benefits.

### Coupling Strategy with mitmproxy

* **Option D — Pure Subprocess (CLI) Wrapper**: Spawns `mitmdump`, `mitmweb`, or `mitmproxy` and parses stdout. Discarded due to brittle output parsing.
* **Option E — Pure In-Process Library (`DumpMaster`/`WebMaster`)**: Imports `mitmproxy`, runs the master inside the same asyncio event loop, and registers custom addons. Discarded due to event loop conflicts and crash propagation.
* **Option F — Hybrid Architecture**: Managed subprocess for traffic interception + `mitmweb` REST API for structured flow inspection; in-process library usage restricted to offline flow transformation.

## Decision Outcome

Adopt **FastMCP 4.x over `mcp` 2.x**, using a **hybrid architecture (Option F)** on **Python 3.13+**.

**Selected Stack:**

| Component | Version | Role | Source (Verified 2026-09-21) |
| :--- | :--- | :--- | :--- |
| Python | `>=3.13` | Runtime | CPython 3.13+ environment |
| mitmproxy | `>=12.2,<13` | Proxy engine and flow management | PyPI 12.2.3 |
| fastmcp | `>=4.0.5,<5` | MCP server, schema generation, lifespan | PyPI 4.0.5 |
| mcp | `>=2.2.0,<3` | Protocol SDK (transitive and explicit) | PyPI 2.2.0 |
| pydantic | `>=2.13,<3` | Input/output schemas and validation | PyPI 2.13.5 |
| httpx | `>=0.27` | REST bridge client for `mitmweb` | PyPI |
| pytest / pytest-asyncio / pytest-cov | `>=9 / >=1 / >=7` | Automated test suite | PyPI pytest 9.1.1 |
| ruff | `>=0.16` | Linting and code formatting | PyPI 0.16.8 |
| hatchling | `>=1.32` | Build backend | PyPI 1.32.4 |

**Flow Inspection Mechanism:** `mitmweb` runs as a managed child process and serves as the primary structured inspection interface via REST (`GET /flows`, `/flows/{id}`, `/flows/{id}/request/content.data`, `/flows/dump`). Executable tools act as thin wrappers over CLI options, while offline flow operations (filtering, replay, export) use mitmproxy in-process libraries when no active proxy is needed.

> Version note: `mitmproxy` 12 **does not support native HAR export**. `mitmproxy/addons/export.py` registers only `curl`, `httpie`, `raw`, `raw_request`, and `raw_response`. Flow exports use these formats or standard `.mitm` binary dumps.

### Positive Consequences

* **Typed, Automated Schemas (D5)**: Contracts derive directly from Pydantic models, preventing documentation drift.
* **Single Structured Inspection Channel (D2)**: Eliminates brittle stdout parsing and gives agents typed access to request/response bodies, headers, and metadata.
* **Centralized Lifecycle via Lifespan (D3)**: Single point of process registration and deterministic port cleanup on shutdown.
* **Fault Isolation**: A proxy process failure does not crash the MCP server; runners detect exit codes and release resources cleanly.

### Trade-offs and Mitigations

* **Dual Flow Sources**: Subprocesses (`mitmweb`) and in-process readers could produce divergent serializations. *Mitigation*: Centralized `FlowSummary` schema in `schemas/` tested by contract.
* **Subprocess Latency**: Process startup incurs minor latency. *Mitigation*: Single long-lived session per task workflow, reusable across commands.
* **REST Surface Exposure**: `mitmweb` binds to `web_host`/`web_port`. Restricting binding to `127.0.0.1` by default is mandatory.

## Security Requirements (R1 to R5)

* **R1**: `web_host` defaults to `127.0.0.1`; binding to `0.0.0.0` requires explicit parameters and triggers audit logging.
* **R2**: Agents never receive the CA private key or raw web tokens; dump files and CA data are stored in restricted-permission directories (`0700`).
* **R3**: Dump and addon script paths pass through path allowlist checks, preventing arbitrary file read/write.
* **R4**: Request and response bodies can contain sensitive credentials; inspection endpoints apply configurable redaction before returning data to LLM models.
* **R5**: Modes requiring elevated kernel permissions (such as eBPF `local` mode or `tun`) must fail explicitly if permissions are missing, never attempting silent privilege escalation.
