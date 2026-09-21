# ADR-004: Integrated Validation, Security Compliance (R1-R5), E2E Live Testing, and Packaging

* **Status**: ACCEPTED (validated in Phase 5)
* **Decision Makers**: Software Architect, Backend Developer, Security Architect, QA Developer, Product Owner
* **Date**: 2026-09-21
* **Phase**: Phase 5 — Integrated Validation, Stress Testing, Packaging, and Delivery

## Context and Problem Statement

With Phases 1 through 4 complete, `mcp-security-mitmproxy` reached 18 MCP tools, integrated three executables (`mitmdump`, `mitmweb`, `mitmproxy`), dynamic option management, and a codeless traffic mutation engine.

Phase 5 finalizes the development lifecycle by addressing four core operational challenges:

1. **E2E Validation with Live Network Traffic**: Unit mocks alone cannot prove proxy interoperability against real mitmproxy subprocesses listening on live TCP sockets.
2. **CSRF Handshake Resilience for REST Mutation**: `mitmweb` relies on Tornado with CSRF protection enabled via the `_mitmproxy_xsrf` cookie. Mutations sent to `PUT /options` fail with HTTP 403 unless the REST client performs an upfront token handshake.
3. **Integrated Audit of Safeguards R1 through R5**: Ensure absolute mitigation of parameter injection (`--set`), Local File Inclusion (LFI in `map_local`), credential exposure via command lines (`/proc/<pid>/cmdline`), and token leakage in exports.
4. **Standardized Packaging**: Ensure the final package is self-contained and easily installed by any standard MCP host (Claude Desktop, Cursor, Zed, Antigravity).

## Decision Drivers

* **D1 — Operational Fidelity with Zero Regressions**: Validate behavior using live `mitmweb` subprocesses serving real HTTP requests forwarded through the proxy.
* **D2 — Safe by Default Posture (R1-R5)**: Zero secrets in command-line arguments, loopback-restricted binds, and strict allowlists for filesystem paths.
* **D3 — Deterministic Teardown**: No orphaned listening ports or zombie processes remaining after session closure or server shutdown.
* **D4 — Clean Distribution**: Standard package build via `uv build` producing wheels and source distributions free of circular dependencies or missing binaries.

## Decision Outcome

### 1. Integrated Test Suite Validation (202 Passing Tests)
The automated test suite reached **202 passing tests** (0 failures), grouped into three distinct layers:
- **Unit Tests**: Static validation of Pydantic contracts, canonical serialization, and delimiter round-trip integrity (`rules/engine.py`).
- **Adversarial & Boundary Tests (QA)**: Collision characters, edge delimiters, and failure tolerance (`test_rules_qa.py`).
- **Live Integration Tests (`test_rules_integration.py`)**: Spawns live `mitmweb` processes on ephemeral ports, sends real HTTP requests through `httpx.AsyncClient(proxy=...)`, and verifies payload mocking via `map_local`.

### 2. CSRF Handshake Implementation in `MitmwebClient`
To allow mutation tools (`mitm_set_map_remote`, `mitm_set_map_local`, etc.) to update options dynamically via `PUT /options`, `MitmwebClient` implements automated bootstrapping:
- Any write request inspects the session CSRF token (`_mitmproxy_xsrf`) and injects the corresponding `X-XSRFToken` header, bypassing Tornado's 403 guard transparently.

### 3. Security Compliance Matrix (R1 through R5)

| Requirement | Threat Mitigated | Verified Implementation |
| :--- | :--- | :--- |
| **R1 — Restricted Bind** | Exposure of web interface or REST bridge on untrusted networks. | Default set to `127.0.0.1`. Public binds (`0.0.0.0`) require explicit schema inputs and trigger the `binds_publicly` audit property. |
| **R2 — CA & Credential Isolation** | Credential leakage via `/proc/<pid>/cmdline` and exposure of private keys. | The web authentication password is generated dynamically via `secrets.token_hex(16)` and stored in `config.yaml` with strict `0600` permissions inside an isolated session directory (`confdir` with `0700` permissions), keeping secrets out of subprocess command lines. |
| **R3 — Strict Allowlists & LFI Shielding** | Arbitrary filesystem access and argument injection. | (1) `ensure_allowed` validates paths against `allowed_dump_roots`, `allowed_script_roots`, and `allowed_mock_roots`.<br/>(2) Commands restricted to `ALLOWED_COMMANDS`.<br/>(3) Blocked `@` prefix in headers/body replacements.<br/>(4) Expanded `RESERVED_SET_OPTIONS` blocking overrides for `confdir`, `scripts`, `map_local`, `map_remote`, `modify_headers`, `modify_body`, `save_stream_file`, and `hardump`. |
| **R4 — Non-Destructive Secret Redaction** | Credential leakage in LLM context windows. | `core/redact.py` masks sensitive headers (`Authorization`, `Cookie`, `X-API-Key`) and payloads (Bearer tokens, passwords, keys) by default (`redact=True`) in flow views and cURL/HTTPie/raw exports. |
| **R5 — Zero Implicit Privilege Escalation** | Execution of privileged operations without operator consent. | Modes requiring advanced Linux network privileges (`local` eBPF, `tun`) fail immediately if system prerequisites are not pre-configured. |

### 4. Distribution and Packaging via `uv build`
The project uses the `hatchling>=1.32` build backend in `pyproject.toml`:
- Produces clean artifacts: `dist/mcp_security_mitmproxy-0.1.0-py3-none-any.whl` and `dist/mcp_security_mitmproxy-0.1.0.tar.gz`.
- Exposes the command-line entry point `mcp-security-mitmproxy`, executable directly via `uv run` or installed into Python virtual environments.

## Consequences

### Positive
* **Production Readiness**: All 18 MCP tools operate reliably under live subprocess conditions.
* **Contained Attack Surface**: The proxy functions as an offensive and defensive security testing tool without exposing the hosting environment.
* **Autonomous Agent Ergonomics**: MCP hosts can orchestrate capture, inspection, and mutation workflows without custom scripts or manual interventions.

### Negative and Mitigations
* **Host Environment Constraints**: Advanced modes such as WireGuard and local eBPF interception depend on host kernel features and system binaries.
  * *Mitigation*: Emits clear, diagnostic error messages detailing missing host prerequisites.
