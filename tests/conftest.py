"""Shared fixtures and the licensed-IDA gate.

A test marked ``@pytest.mark.requires_ida`` needs a licensed local IDA
installation and a C compiler. An ordinary contributor run skips such a test
with the exact missing prerequisite as the reason; a run with
``VULFI_REQUIRE_LIVE=1`` turns that skip into a failure, so CI (and any run that
claims live coverage) can never quietly report a clean suite that never touched
IDA.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path

import pytest

#: Set to ``1`` to fail instead of skip when a live prerequisite is missing.
REQUIRE_LIVE_ENV = "VULFI_REQUIRE_LIVE"

#: Operator-configured root of the managed workspace, isolated per test.
DATA_DIR_ENV = "VULFI_MCP_DATA_DIR"

FIXTURES = Path(__file__).parent / "fixtures"

#: Exactly the flags the plan pins, so a call site keeps its own arguments.
CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_ida: needs a licensed local IDA installation; skipped without"
        f" one unless {REQUIRE_LIVE_ENV}=1 is set",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("requires_ida") is None:
        return
    reason = _missing_ida_prerequisite()
    if reason is not None:
        missing_prerequisite(reason)


def missing_prerequisite(reason: str) -> None:
    """Skip, or fail when the run promised live coverage."""
    if os.environ.get(REQUIRE_LIVE_ENV) == "1":
        pytest.fail(f"{REQUIRE_LIVE_ENV}=1 but {reason}", pytrace=False)
    pytest.skip(reason)


@lru_cache(maxsize=1)
def _missing_ida_prerequisite() -> str | None:
    """Return why live IDA cannot run here, or ``None`` when it can."""
    for module in ("idapro", "ida_nexus", "ida_domain"):
        if find_spec(module) is None:
            return f"the {module} package is not installed"
    install_dir = _ida_install_dir()
    if install_dir is None:
        return (
            "no IDA installation is configured; set IDADIR or"
            " Paths/ida-install-dir in ~/.idapro/ida-config.json"
        )
    if not install_dir.is_dir():
        return f"the configured IDA installation is missing: {install_dir}"
    return None


def _ida_install_dir() -> Path | None:
    configured = os.environ.get("IDADIR")
    if configured:
        return Path(configured).expanduser()
    config = Path("~/.idapro/ida-config.json").expanduser()
    try:
        paths = json.loads(config.read_text(encoding="utf-8")).get("Paths", {})
    except (OSError, ValueError, AttributeError):
        return None
    directory = paths.get("ida-install-dir") if isinstance(paths, dict) else None
    return Path(directory).expanduser() if isinstance(directory, str) else None


@pytest.fixture
def managed_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the managed workspace at ``tmp_path`` for the duration of a test."""
    data_dir = tmp_path / "vulfi-data"
    monkeypatch.setenv(DATA_DIR_ENV, str(data_dir))
    return data_dir


@pytest.fixture
def compiled_calls(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_calls.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / "vulfi_calls"
    command = [
        str(compiler),
        *CC_FLAGS,
        "-o",
        str(binary),
        str(FIXTURES / "vulfi_calls.c"),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_calls.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary
