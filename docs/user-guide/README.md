# User Guide

Practical documentation for running and operating `mcp-security-mitmproxy`: an MCP server that exposes `mitmdump` and `mitmweb` to AI agents as managed subprocesses, with allowlists, secret redaction and deterministic process teardown.

## Contents

| Document | Type | What it covers |
| :--- | :--- | :--- |
| [Getting Started](01-getting-started.md) | Tutorial | Install, launch the server, wire an MCP client, run a first capture session end to end. |
| [Tools Reference](02-tools-reference.md) | Reference | All 18 MCP tools: inputs, outputs, defaults, constraints, errors, invocation examples. |
| [Configuration](03-configuration.md) | Reference + How-To | Every `Settings` field, environment variables, and how to configure the filesystem allowlists that gate dumps, scripts and mock files. |
| [Security Model](04-security-model.md) | Explanation | The five security requirements (R1–R5), where each is enforced, the reserved-option system, and how to respond to every restriction error code. |
| [Secrets Handling](05-secrets-handling.md) | How-To + Explanation | What the redaction engine masks, where secrets live at runtime, what stays on disk, and operator guidance for keeping credentials out of agent outputs. |

## Reading order

Start with **Getting Started** if the server is not running yet. Use **Tools Reference** as the daily lookup while writing agent prompts or client code. Read **Configuration** before enabling any path-based feature (`save_path`, addon `scripts`, `map_local`), because all of them are denied until you configure allowlist roots. **Security Model** and **Secrets Handling** explain the boundaries and what to do when a tool answers `PATH_NOT_ALLOWED`, `COMMAND_NOT_ALLOWED` or returns `[REDACTED]`.
