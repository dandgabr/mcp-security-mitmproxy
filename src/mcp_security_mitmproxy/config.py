"""Runtime settings.

Boundary note (architecture §2): ``config.py`` is a leaf module — it imports
only pydantic and the standard library so it can be evaluated without the
proxy stack. Environment loading is intentionally dependency-free for Fase 1;
if richer layering is needed later it can migrate to ``pydantic-settings``
without touching call sites.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8081
DEFAULT_LOG_CAPACITY = 500


def _default_session_root() -> Path:
    """Per-user, non-shared base for session temp dirs (R2)."""
    return Path(tempfile.gettempdir()) / "mcp-security-mitmproxy"


class Settings(BaseModel):
    """Immutable-ish server configuration resolved at process start."""

    web_host: str = Field(
        default=DEFAULT_WEB_HOST,
        description="R1: REST/WS bind address. Non-loopback values must be explicit.",
    )
    web_port: int = Field(default=DEFAULT_WEB_PORT, ge=1, le=65535)
    allowed_dump_roots: list[Path] = Field(
        default_factory=list,
        description="R3: roots under which dump/.mitm outputs are permitted.",
    )
    allowed_script_roots: list[Path] = Field(
        default_factory=list,
        description="R3: roots under which addon scripts are permitted.",
    )
    allowed_mock_roots: list[Path] = Field(
        default_factory=list,
        description=(
            "R3/Fase 4: roots under which map_local may read a mock file or directory. "
            "Empty denies every map_local path (secure by default)."
        ),
    )
    allowed_ca_roots: list[Path] = Field(
        default_factory=list,
        description="R3: roots under which CA material is permitted.",
    )
    shutdown_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    session_root: Path = Field(
        default_factory=_default_session_root,
        description=(
            "Base directory for per-session temp dirs (<root>/<id>/dumps and <root>/<id>/ca). "
            "Created with 0700 permissions (R2)."
        ),
    )
    log_capacity: int = Field(
        default=DEFAULT_LOG_CAPACITY,
        ge=1,
        le=100_000,
        description="Number of stdout/stderr lines retained per process (ring buffer).",
    )

    @property
    def binds_publicly(self) -> bool:
        """True when the REST surface is bound to a non-loopback address (R1)."""
        return self.web_host not in {"127.0.0.1", "::1", "localhost"}

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        kwargs: dict[str, object] = {}
        if "MCP_MITM_WEB_HOST" in source:
            kwargs["web_host"] = source["MCP_MITM_WEB_HOST"]
        if "MCP_MITM_WEB_PORT" in source:
            kwargs["web_port"] = int(source["MCP_MITM_WEB_PORT"])
        return cls(**kwargs)
