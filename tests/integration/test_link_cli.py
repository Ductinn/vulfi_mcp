"""The local ``vulfi-mcp link`` command, against a real paired fixture.

Linking is not an MCP tool. The command shows both assessments before it
asks which one is canonical, and an unknown status fails before anything
is stored.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conftest import (
    CC_FLAGS,
    FIXTURES,
    ghidra_bridge,
    ghidra_url,
    missing_prerequisite,
)
from vulfi_mcp.catalog import get_catalog
from vulfi_mcp.ida_adapter import ensure_managed_idb, findings_ida, scan_ida, triage_ida
from vulfi_mcp.prepare import scan_target
from vulfi_mcp.rules import Rule, load_stock_rules
from vulfi_mcp.server import vulfi_triage

pytestmark = [pytest.mark.requires_ida, pytest.mark.requires_ghidra]

PROVIDER_LOCK = Path(tempfile.gettempdir()) / "vulfi-ghidra-{}-{}.lock".format(
    urlsplit(ghidra_url()).hostname or "127.0.0.1",
    urlsplit(ghidra_url()).port or 80,
)
LOCK_TIMEOUT = 300.0

COPY_RULE: Rule = {
    "name": "Unchecked Copy",
    "function_names": ["strcpy", "wcscpy"],
    "wrappers": False,
    "mark_if": {
        "High": "not param[1].is_constant()",
        "Medium": "False",
        "Low": "False",
    },
}


@pytest.fixture(autouse=True)
def provider_lock() -> Iterator[None]:
    PROVIDER_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(PROVIDER_LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        import fcntl

        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    pytest.fail(f"GhidraMCP lock held too long: {PROVIDER_LOCK}")
                time.sleep(0.5)
        yield
    finally:
        import fcntl

        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)


@pytest.fixture
def ghidra_config(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    config = tmp_path / "providers.toml"
    config.write_text(
        "\n".join(
            (
                "[ghidra]",
                'transport = "stdio"',
                f'command = "{ghidra_bridge()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "bridge.err"}"',
                "",
                "[ghidra.env]",
                'PATH = "/usr/bin:/bin"',
                f'HOME = "{tmp_path / "bridge-home"}"',
                f'GHIDRA_MCP_URL = "{ghidra_url()}"',
                'GHIDRA_MCP_LOG_LEVEL = "WARNING"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{managed_data_dir}"',
                f'remote = "{managed_data_dir}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "bridge-home").mkdir(exist_ok=True)
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


def _compile(tmp_path: Path) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / "calls"
    completed = subprocess.run(
        [compiler, *CC_FLAGS, "-o", str(binary), str(FIXTURES / "vulfi_calls.c")],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return binary


def _command() -> str:
    candidate = Path(sys.executable).parent / "vulfi-mcp"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which("vulfi-mcp")
    if found:
        return found
    pytest.skip("vulfi-mcp is not installed in this environment")
    return ""


def test_cli_shows_both_assessments_before_choosing_and_rejects_unknown_status(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """Both existing assessments are on screen before the canonical source is chosen.

    The production change that must fail this test is asking for a source
    before either assessment is shown, or storing a status the vocabulary
    does not have.
    """
    binary = _compile(tmp_path)
    managed = ensure_managed_idb(str(binary))
    ida = scan_ida(managed, (COPY_RULE,), "default", path=str(binary))
    external = scan_target(str(binary), (COPY_RULE,), "default", backend="ghidra")
    ida_row = ida["findings"][0]
    external_row = next(row for row in external["findings"] if row["backend"] == "ghidra")
    triage_ida(managed, ida_row["id"], "Suspicious", "ida saw a variable source")
    vulfi_triage(
        str(binary),
        external_row["id"],
        "False Positive",
        "external saw a checked length",
    )

    unknown = subprocess.run(
        [
            _command(),
            "link",
            "--path",
            str(binary),
            "--ida-id",
            ida_row["id"],
            "--external-id",
            external_row["id"],
            "--binary",
            str(binary),
            "--source",
            "ida",
            "--status",
            "Maybe",
            "--rationale",
            "not a status",
        ],
        check=False,
        capture_output=True,
        text=True,
        input="ida\n",
    )
    assert unknown.returncode != 0
    assert "Maybe" in unknown.stderr or "status" in unknown.stderr.lower()
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        stored = catalog._connection.execute("SELECT count(*) FROM links").fetchone()
    finally:
        catalog.close()
    assert stored[0] == 0

    reviewed = subprocess.run(
        [
            _command(),
            "link",
            "--path",
            str(binary),
            "--ida-id",
            ida_row["id"],
            "--external-id",
            external_row["id"],
            "--binary",
            str(binary),
            "--source",
            "ida",
            "--status",
            "Vulnerable",
            "--rationale",
            "the ida assessment is the one that stands",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        input="ida\n",
    )
    dialogue = reviewed.stderr
    prompt_at = dialogue.find("Type 'ida'")
    assert prompt_at != -1, dialogue
    before = dialogue[:prompt_at]
    assert "Suspicious" in before and "False Positive" in before
    assert ida_row["id"] in before and external_row["id"] in before
    lowered = before.lower()
    # The operator chooses after seeing the mapping, not after a later check.
    assert "image base" in lowered, before
    assert "rva" in lowered, before
    assert "bytes" in lowered, before
    assert "xref" in lowered, before
    assert __import__("re").search(r"bytes\s+[0-9a-f]{8,}", lowered), before

    refused = subprocess.run(
        [
            _command(),
            "link",
            "--path",
            str(binary),
            "--ida-id",
            ida_row["id"],
            "--external-id",
            "not-a-stored-finding",
            "--binary",
            str(binary),
            "--source",
            "ida",
            "--status",
            "Vulnerable",
            "--rationale",
            "this pair was never proved",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        input="ida\n",
    )
    refused_text = refused.stderr + refused.stdout
    assert refused.returncode != 0
    assert "Type '" not in refused_text, refused_text
    assert "nothing was linked" in refused_text.lower() or "no external" in refused_text.lower()
    assert reviewed.returncode == 0, reviewed.stderr
    result = json.loads(reviewed.stdout)
    assert result["confirmed"] is True
    assert result["link_revision"] == 1
    assert result["sync_state"] == "synchronized"
    assert result["chosen_source"] == "ida"
    assert result["status"] == "Vulnerable"

    reopened = get_catalog(str(binary))
    assert reopened is not None
    try:
        held = reopened.link(str(result["link_id"]))
    finally:
        reopened.close()
    assert held is not None
    assert held["link_revision"] == 1
    assert held["sync_state"] == "synchronized"
    page = findings_ida(managed, 0, 200, path=str(binary))
    mirrored = next(row for row in page["findings"] if row["id"] == ida_row["id"])
    assert mirrored["link_id"] == result["link_id"]
    assert mirrored["link_revision"] == 1
    assert mirrored["status"] == "Vulnerable"

    tools = {
        name
        for name in dir(__import__("vulfi_mcp.server", fromlist=["server"]))
        if name.startswith("vulfi_")
    }
    assert "vulfi_link" not in tools
