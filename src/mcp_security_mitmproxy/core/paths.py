"""R3 — path allowlist.

Every filesystem path supplied by an agent (dump output, addon script, CA
material) passes through :func:`ensure_allowed` before it reaches a subprocess
argv. The check resolves symlinks and compares canonical parents against the
configured roots, preventing directory-traversal and arbitrary file writes.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from mcp_security_mitmproxy.core.errors import PathNotAllowedError


def _canonical(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def ensure_allowed(path: str | Path, roots: Iterable[str | Path]) -> str:
    """Return the canonical path if it lands under one of ``roots``.

    An empty ``roots`` collection denies everything: secure by default, since a
    server started without an explicit allowlist must not accept agent paths.
    """
    target = _canonical(path)
    allowed_roots = [_canonical(root) for root in roots]
    if not allowed_roots:
        raise PathNotAllowedError(
            f"path {target} rejected: no allowlist roots configured",
            detail={"path": str(target)},
        )
    for root in allowed_roots:
        if target == root or root in target.parents:
            return str(target)
    raise PathNotAllowedError(
        f"path {target} is outside the configured allowlist",
        detail={"path": str(target), "roots": [str(r) for r in allowed_roots]},
    )


def ensure_allowed_many(paths: Iterable[str | Path], roots: Iterable[str | Path]) -> list[str]:
    """Validate a collection, returning canonical paths in input order."""
    return [ensure_allowed(path, roots) for path in paths]


__all__ = ["ensure_allowed", "ensure_allowed_many"]
