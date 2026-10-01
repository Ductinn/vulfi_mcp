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
import socket
import subprocess
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from functools import lru_cache
from importlib.util import find_spec
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import pytest
from ida_nexus import WorkerStartError, probe_database_state

from vulfi_mcp.ida_adapter import ManagedDatabaseError, findings_ida
from vulfi_mcp.ida_runtime import TRIAGE_STATUSES

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
    config.addinivalue_line(
        "markers",
        "requires_ghidra: needs a running GhidraMCP headless server and its"
        f" bridge; skipped without one unless {REQUIRE_LIVE_ENV}=1 is set",
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    # This hook only fires from a conftest or a plugin, which is why both live
    # gates live here rather than beside the tests they guard: a
    # ``pytest_runtest_setup`` defined in a test module is simply never called,
    # and the gate it holds never runs.
    for marker, probe in (
        ("requires_ida", _missing_ida_prerequisite),
        ("requires_ghidra", _missing_ghidra_prerequisite),
    ):
        if item.get_closest_marker(marker) is None:
            continue
        reason = probe()
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


#: Where the GhidraMCP bridge executable is, when the operator did not say.
GHIDRA_BRIDGE_ENV: Final = "VULFI_GHIDRA_BRIDGE"
DEFAULT_GHIDRA_BRIDGE: Final = "/tmp/vulfi-ghidra/bridge-venv/bin/bridge-mcp-ghidra"

#: Where the GhidraMCP headless server listens, when the operator did not say.
GHIDRA_URL_ENV: Final = "VULFI_GHIDRA_MCP_URL"
DEFAULT_GHIDRA_URL: Final = "http://127.0.0.1:8192"

#: How to start that server, named in the skip reason so a missing
#: prerequisite is actionable rather than merely reported.
GHIDRA_START_HINT: Final = (
    "start it with /tmp/vulfi-ghidra/bin/start-headless.sh (see"
    " .superpowers/sdd/2026-09-29-vulfi-mcp-fallback/task-2-report.md)"
)


def ghidra_bridge() -> str:
    return os.environ.get(GHIDRA_BRIDGE_ENV) or DEFAULT_GHIDRA_BRIDGE


def ghidra_url() -> str:
    return os.environ.get(GHIDRA_URL_ENV) or DEFAULT_GHIDRA_URL


def _missing_ghidra_prerequisite() -> str | None:
    """Return why the live Ghidra provider cannot run here, or ``None``.

    Not cached, unlike the IDA probe: an installation either is or is not
    there, but a server is a process that can go away between two tests, and a
    cached "it was up once" is how a dead provider turns into four failures
    instead of one honest skip.
    """
    if shutil.which("gcc") is None:
        return "gcc is not installed, so vulfi_fallback.c cannot be built"
    bridge = Path(ghidra_bridge())
    if not bridge.is_file() or not os.access(bridge, os.X_OK):
        return (
            f"the GhidraMCP bridge is not at {bridge}; set"
            f" {GHIDRA_BRIDGE_ENV} to the executable built by"
            " `uv pip install <ghidra-mcp checkout>`"
        )
    split = urlsplit(ghidra_url())
    host, port = split.hostname or "127.0.0.1", split.port or 80
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except OSError as refused:
        return (
            f"no GhidraMCP headless server is listening on {host}:{port}"
            f" ({refused}); {GHIDRA_START_HINT}"
        )
    return None


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


# --------------------------------------------------------------------------
# The vendor's bad-pack defect, and the contract this project keeps around it
# --------------------------------------------------------------------------

#: IDA 9.4.260714 sometimes packs a database it then refuses to reopen — an
#: open Hex-Rays defect ("Inaccurate 'database is empty' error (9.4)"),
#: measured on this build at roughly one packed database in fifty and recorded
#: in `.superpowers/sdd/2026-09-29-vulfi-ida-core/task-3-report.md`. Nothing
#: this adapter controls moves that rate, so the durability a save can promise
#: is not "it survived" but **"never silently corrupt, and always tell the
#: caller"**: the bytes each save replaces are kept, a failed reopen rolls back
#: to them exactly once, and the caller is told what that cost.
#:
#: A live test that saves a managed database and opens it again therefore has
#: two correct outcomes, and asserting only the first is what made this suite
#: flake. **Do not "fix" a test that uses this by deleting the tolerance** —
#: that reintroduces a failure roughly two runs in three. Tighten it only when
#: the vendor defect is fixed, or when this server verifies each pack at save
#: time (ruled out for this milestone: one extra IDA process per mutating
#: operation, permanently, for a defect that is the vendor's to fix).
_ROLLED_BACK = "the save before this one left a database it cannot read"
_UNRECOVERABLE = "built again from its source"


def names_the_rollback(error: BaseException) -> bool:
    """Whether ``error`` is this server reporting the vendor's bad pack."""
    return isinstance(error, ManagedDatabaseError) and (
        _ROLLED_BACK in str(error) or _UNRECOVERABLE in str(error)
    )


@contextmanager
def _durable_or_reported() -> Iterator[list[str]]:
    """Hold a body to "the state is intact, or the loss was reported".

    Append each managed database the body produces to the yielded list. If the
    body completes, every assertion in it stood and nothing was tolerated. If
    it raises the rollback error instead, that outcome is accepted — but only
    after checking the thing the rollback must never produce: a record that
    answers, and answers something half-written. A rolled-back database is an
    *earlier* consistent generation, never an inconsistent one.

    Any other error, including a ``WorkerStartError`` with no rollback behind
    it, propagates untouched. This tolerates one named vendor defect, not
    failure in general.
    """
    produced: list[str] = []
    try:
        yield produced
    except BaseException as reported:
        if not names_the_rollback(reported):
            raise
        for database in produced:
            _assert_record_is_consistent(database)


def _assert_record_is_consistent(database: str) -> None:
    """Every row the rolled-back database still answers with is whole."""
    if probe_database_state(database)["state"] != "packed":
        # `_restore_pre_save` said the workspace has to be rebuilt, and left
        # nothing claiming to be readable. That is the loud outcome, not a
        # silent one.
        return
    try:
        page = findings_ida(database, 0, 200)
    except ManagedDatabaseError as again:
        assert names_the_rollback(again), f"{database}: {again!r}"
        return
    except WorkerStartError:
        # Not readable at all is not "silently wrong": nothing answered. The
        # rollback consumed the spare, so a second bad pack has none left.
        return
    for row in page["findings"]:
        assert row["status"] in TRIAGE_STATUSES, row
        if row["status"] == "Not Checked":
            assert row["rationale"] == "", row
            assert row["triage_revision"] == 0, row
        else:
            assert row["rationale"].strip(), row
            assert row["triage_revision"] >= 1, row


@pytest.fixture
def durable_or_reported() -> Callable[[], AbstractContextManager[list[str]]]:
    """The bad-pack tolerance, as a fixture so no test has to import it."""
    return _durable_or_reported
