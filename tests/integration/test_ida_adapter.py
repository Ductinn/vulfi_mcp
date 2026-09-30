"""Live IDA coverage of the managed workspace and the single Nexus lease.

These tests open real databases through the public ``ida_nexus`` API. They are
gated by the ``requires_ida`` marker in ``tests/conftest.py``.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

import pytest
from ida_nexus import (
    DatabaseBusyError,
    DatabaseHandle,
    NexusConnectionError,
    RemoteError,
    find_database_owner,
    probe_database_state,
)

from vulfi_mcp.ida_adapter import (
    RELEASE_TIMEOUT,
    ManagedDatabaseError,
    _publish,
    ensure_managed_idb,
    invoke_ida,
)

pytestmark = pytest.mark.requires_ida

SUMMARY = "database_summary"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _managed_databases(root: Path) -> set[Path]:
    return set(root.rglob("*.i64")) if root.exists() else set()


def _beside(source: Path) -> list[str]:
    """Everything in the source's directory except the source itself."""
    return sorted(item.name for item in source.parent.iterdir() if item != source)


def test_managed_copy_opens_saves_reopens(
    compiled_calls: Path, managed_data_dir: Path, tmp_path: Path
) -> None:
    source_digest = _digest(compiled_calls)

    managed = Path(ensure_managed_idb(str(compiled_calls)))

    assert managed.is_file()
    assert managed.suffix == ".i64"
    assert managed_data_dir in managed.parents
    # The source binary is read-only: IDA leaves nothing at all beside it, not
    # even the unpacked components that only become a `.i64` when saved.
    assert _beside(compiled_calls) == [managed_data_dir.name]
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

    assert _beside(compiled_calls) == []


def test_a_live_database_is_never_published(
    compiled_calls: Path, managed_data_dir: Path, tmp_path: Path
) -> None:
    # A `.i64` exists on disk while its database is live, and the lease close
    # only waits when Nexus reported a pending shutdown, so publishing must be
    # gated on the observed state instead of on the file being there.
    staged = Path(ensure_managed_idb(str(compiled_calls)))
    target = tmp_path / "published.i64"

    holder = DatabaseHandle.open(str(staged))
    try:
        with pytest.raises(ManagedDatabaseError) as failure:
            _publish(staged, target)
    finally:
        holder.close(wait_for_database=True)

    assert "in_use" in str(failure.value)
    assert not target.exists()
    assert staged.is_file()


def test_a_shared_database_is_not_waited_on(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    # A lease that attached to somebody else's live instance must not wait for
    # that instance to die: the wait could only end when the other session
    # does, and would then discard an operation that already completed.
    managed = ensure_managed_idb(str(compiled_calls))

    holder = DatabaseHandle.open(managed)
    try:
        started = time.monotonic()
        result = invoke_ida(managed, SUMMARY, {"name_limit": 5})
        elapsed = time.monotonic() - started
    finally:
        holder.close(wait_for_database=True)

    assert result["function_count"] > 0
    assert elapsed < RELEASE_TIMEOUT


def test_a_read_only_operation_leaves_the_database_alone(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    # A worker saves its database on close by default, so every lease used to
    # rewrite the packed .i64 even when nothing was mutated. Those repeated
    # rewrites are what eventually left a managed database unopenable.
    managed = Path(ensure_managed_idb(str(compiled_calls)))
    before = _digest(managed)

    first = invoke_ida(str(managed), SUMMARY, {"name_limit": 5})
    second = invoke_ida(str(managed), SUMMARY, {"name_limit": 5})

    assert first["function_count"] == second["function_count"]
    assert _digest(managed) == before


def test_a_failed_shutdown_still_closes_the_lease(
    compiled_calls: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The discarding shutdown is a fallible RPC (transport error, its own
    # timeout, a dead worker, a 409 from a sibling). If it could skip the
    # close, the lease would never be released and its worker would hold the
    # managed .i64 for the rest of this process's life, wedging every later
    # open of that database. The error is injected at the handle boundary
    # because what is under test is this module's ordering, not IDA.
    managed = Path(ensure_managed_idb(str(compiled_calls)))

    def boom(self: DatabaseHandle, *, save: bool = True) -> None:
        raise NexusConnectionError("injected shutdown failure")

    monkeypatch.setattr(DatabaseHandle, "shutdown_database", boom)
    with pytest.raises(NexusConnectionError):
        invoke_ida(str(managed), SUMMARY, {"name_limit": 5})
    monkeypatch.undo()

    # The lease skips its release wait when the shutdown failed, so this test
    # does the waiting instead: the registry entry is gone and the worker has
    # repacked the database it held, which is what "closed" has to mean here.
    deadline = time.monotonic() + RELEASE_TIMEOUT
    while find_database_owner(str(managed)) is not None:
        assert time.monotonic() < deadline, "the lease outlived the failed shutdown"
        time.sleep(0.05)
    while probe_database_state(managed)["state"] != "packed":
        assert time.monotonic() < deadline, "the worker never released the database"
        time.sleep(0.05)

    # The two entry points the wedged worker used to break: the release gate
    # ensure_managed_idb applies to a supplied IDB, and a later lease.
    clone = ensure_managed_idb(str(managed))
    assert Path(clone).is_file()
    assert invoke_ida(str(managed), SUMMARY, {"name_limit": 5})["function_count"] > 0
