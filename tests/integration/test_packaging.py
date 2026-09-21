"""Distribution packaging — Phase 5 acceptance criterion.

Builds with ``uv build`` and validates the artifacts under ``dist/``: the wheel
carries the full package (including ``rules/``) plus the console script, the
sdist carries sources/tests/docs, and the wheel **installs and imports** outside
the ``src/`` tree.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DIST = REPO_ROOT / "dist"

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not available")

_EXPECTED_MODULES = (
    "mcp_security_mitmproxy/__init__.py",
    "mcp_security_mitmproxy/__main__.py",
    "mcp_security_mitmproxy/rules/engine.py",
    "mcp_security_mitmproxy/schemas/rules.py",
    "mcp_security_mitmproxy/tools/rules.py",
    "mcp_security_mitmproxy/web_client/client.py",
)


@pytest.fixture(scope="module")
def artifacts() -> dict[str, Path]:
    """Build once per module and return the produced wheel and sdist."""
    result = subprocess.run(
        ["uv", "build"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert result.returncode == 0, f"uv build failed:\n{result.stdout}\n{result.stderr}"

    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    assert wheels, f"uv build produced no wheel in {DIST}"
    assert sdists, f"uv build produced no sdist in {DIST}"
    return {"wheel": wheels[-1], "sdist": sdists[-1]}


def test_build_produces_non_empty_artifacts(artifacts: dict[str, Path]) -> None:
    for kind, path in artifacts.items():
        assert path.is_file(), f"{kind} missing"
        assert path.stat().st_size > 0, f"{kind} is empty"


def test_wheel_carries_the_package_and_the_console_script(artifacts: dict[str, Path]) -> None:
    with zipfile.ZipFile(artifacts["wheel"]) as archive:
        names = archive.namelist()
        for module in _EXPECTED_MODULES:
            assert module in names, f"{module} missing from the wheel"

        entry_points = next((n for n in names if n.endswith("entry_points.txt")), None)
        assert entry_points is not None, "wheel has no entry_points.txt"
        text = archive.read(entry_points).decode()
        assert "mcp-security-mitmproxy" in text
        assert "mcp_security_mitmproxy.__main__:main" in text

        metadata = next((n for n in names if n.endswith("METADATA")), None)
        assert metadata is not None, "wheel has no METADATA"
        meta = archive.read(metadata).decode()
        assert "Name: mcp-security-mitmproxy" in meta
        assert "Requires-Python:" in meta


def test_sdist_carries_sources_tests_and_docs(artifacts: dict[str, Path]) -> None:
    with tarfile.open(artifacts["sdist"], "r:gz") as archive:
        names = archive.getnames()

    assert any(name.endswith("src/mcp_security_mitmproxy/rules/engine.py") for name in names)
    assert any(name.endswith("tests/integration/test_concurrency_lifecycle.py") for name in names)
    assert any(
        name.endswith("docs/adr/0004-validacao-integrada-e-entrega-final.md") for name in names
    )
    assert any(name.endswith("pyproject.toml") for name in names)


def test_wheel_imports_from_the_artifact_not_from_src(
    artifacts: dict[str, Path], tmp_path: Path
) -> None:
    """Install-free smoke test: import the extracted wheel, prove it wins sys.path."""
    extracted = tmp_path / "wheel"
    with zipfile.ZipFile(artifacts["wheel"]) as archive:
        archive.extractall(extracted)

    script = (
        "import json, mcp_security_mitmproxy as pkg,"
        " mcp_security_mitmproxy.rules.engine as engine,"
        " mcp_security_mitmproxy.schemas.rules as rules;"
        "print(json.dumps({'pkg': pkg.__file__, 'engine': engine.__file__,"
        " 'rules': rules.__file__, 'version': getattr(pkg, '__version__', None)}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "PYTHONPATH": str(extracted)},
    )
    assert result.returncode == 0, f"import from wheel failed:\n{result.stderr}"

    info = json.loads(result.stdout)
    for key in ("pkg", "engine", "rules"):
        assert str(extracted) in info[key], f"{key} was imported from {info[key]}, not the wheel"
    assert str(REPO_ROOT / "src") not in info["pkg"]
    if info["version"] is not None:
        assert isinstance(info["version"], str)
