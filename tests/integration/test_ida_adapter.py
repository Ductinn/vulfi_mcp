"""Live IDA coverage of the managed workspace and the single Nexus lease.

These tests open real databases through the public ``ida_nexus`` API. They are
gated by the ``requires_ida`` marker in ``tests/conftest.py``.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
from ida_nexus import DatabaseBusyError, DatabaseHandle, RemoteError

from vulfi_mcp.ida_adapter import ensure_managed_idb, invoke_ida

pytestmark = pytest.mark.requires_ida

SUMMARY = "database_summary"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _managed_databases(root: Path) -> set[Path]:
    return set(root.rglob("*.i64")) if root.exists() else set()


def test_managed_copy_opens_saves_reopens(
    compiled_calls: Path, managed_data_dir: Path, tmp_path: Path
) -> None:
    source_digest = _digest(compiled_calls)

    managed = Path(ensure_managed_idb(str(compiled_calls)))

    assert managed.is_file()
    assert managed.suffix == ".i64"
    assert managed_data_dir in managed.parents
    # The source binary is read-only: no IDB is created beside it.
    assert list(compiled_calls.parent.glob("*.i64")) == []
    assert _digest(compiled_calls) == source_digest

    summary = invoke_ida(str(managed), SUMMARY, {"name_limit": 500})

    assert summary["mutated"] is False
    assert summary["idb_path"] == str(managed)
    assert summary["function_count"] > 0
    assert {
        "copy_from_argument",
        "copy_from_environment",
        "copy_constant",
        "copy_wrapper",
        "main",
    } <= set(summary["function_names"])

    # The same input resolves to the same managed IDB, and the saved analysis
    # survives the close: a second lease reopens it and sees the same database.
    assert ensure_managed_idb(str(compiled_calls)) == str(managed)
    reopened = invoke_ida(str(managed), SUMMARY, {"name_limit": 500})
    assert reopened["function_count"] == summary["function_count"]
    assert reopened["function_names"] == summary["function_names"]

    # A saved, unlocked IDB supplied by the user is cloned, never opened in place.
    user_idb = tmp_path / "user_supplied.i64"
    shutil.copy2(managed, user_idb)
    user_digest = _digest(user_idb)

    clone = Path(ensure_managed_idb(str(user_idb)))

    assert clone.is_file()
    assert clone != user_idb
    assert managed_data_dir in clone.parents
    assert _digest(user_idb) == user_digest
    cloned = invoke_ida(str(clone), SUMMARY, {"name_limit": 500})
    assert cloned["function_names"] == summary["function_names"]


def test_busy_source_idb_is_not_copied(
    compiled_calls: Path, managed_data_dir: Path, tmp_path: Path
) -> None:
    managed = Path(ensure_managed_idb(str(compiled_calls)))
    locked_idb = tmp_path / "locked.i64"
    shutil.copy2(managed, locked_idb)
    before = _managed_databases(managed_data_dir)

    holder = DatabaseHandle.open(str(locked_idb))
    try:
        with pytest.raises(DatabaseBusyError):
            ensure_managed_idb(str(locked_idb))
    finally:
        holder.close(wait_for_database=True)

    assert _managed_databases(managed_data_dir) == before


def test_unknown_operation_is_rejected(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    managed = ensure_managed_idb(str(compiled_calls))

    with pytest.raises(RemoteError) as failure:
        invoke_ida(managed, "no_such_operation", {})

    assert "no_such_operation" in str(failure.value)


def test_invoke_refuses_to_open_a_binary(compiled_calls: Path) -> None:
    # Opening a binary through a lease would analyze it in place, beside a file
    # this server must never write to.
    with pytest.raises(ValueError):
        invoke_ida(str(compiled_calls), SUMMARY, {})

    assert list(compiled_calls.parent.glob("*.i64")) == []
