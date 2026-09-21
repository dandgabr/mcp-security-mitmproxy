"""Entrypoint: ``python -m mcp_security_mitmproxy``."""

from __future__ import annotations


def main() -> None:
    from mcp_security_mitmproxy.server import run

    run()


if __name__ == "__main__":
    main()
