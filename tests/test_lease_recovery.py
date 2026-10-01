"""The lease's rescue protocol, at the seam where IDA would be.

Every fact here is a decision this module makes *before* any worker runs:
whether an open failure says anything about the bytes on disk, whether the
target may be overwritten at all, and whether a successful open proved those
bytes readable. None of that needs a database, and none of it can be observed
reliably through one — the defect it exists for fires about once in fifty
packs. So the worker is a scripted stand-in and the assertions are about files
on disk and errors raised.

The live end-to-end counterparts, on a real damaged IDA 9.4 database, are in
``tests/integration/test_ida_adapter.py``.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from ida_nexus import DatabaseOpenOptions, WorkerStartError

from vulfi_mcp import ida_adapter
from vulfi_mcp.ida_adapter import ManagedDatabaseError, _lease, _pre_save

GOOD = b"the bytes the previous save replaced" * 4
SAVED = b"the bytes the last save wrote" * 4

#: The three unrelated conditions Nexus reports as one ``WorkerStartError``.
#: Only a launcher exit whose log tail names *this* database is about the file.
READINESS_TIMEOUT = "timed out waiting for idalib worker 4242: still opening"
WRONG_IDB = "worker 4242 opened /elsewhere/other.i64, expected /here/managed.i64"
LAUNCHER_DIED = (
    "idalib worker launcher 4242 exited with status 1\n\n"
    "[ida-nexus] ida: could not check out a licence"
)


def _bad_pack(target: Path) -> str:
    """What the vendor defect leaves behind: rc 4, "Database is empty"."""
    return (
        "idalib worker launcher 4242 exited with status 1\n\n"
        "[ida-nexus] Hex-Rays Decompiler v9.4.0.260714\n"
        f"[ida-nexus] Failed to open database {os.path.realpath(target)}"
    )


def _kernel_abort(target: Path) -> str:
    """IDA's own abort on a database it parsed far enough to reject.

    Measured, not assumed: this is what a managed `.i64` with a zeroed page
    produces on IDA 9.4.260714, and it is what the live tests in
    ``tests/integration/test_ida_adapter.py`` actually raise.
    """
    return (
        "idalib worker launcher 4242 exited with status 1\n\n"
        "Attempting to load the first available model...\n"
        f"FATAL ERROR: The database {os.path.realpath(target)} is corrupted"
    )


@dataclass
class _Instance:
    record_id: str = "worker-1"
    managed: bool = True
    idb_path: str = ""
    pid: int = 4242


@dataclass
class _Handle:
    instance: _Instance
    shutdowns: int = 0
    closes: int = 0

    def shutdown_database(self, save: bool) -> None:
        self.shutdowns += 1

    def close(self, wait_for_database: bool) -> None:
        self.closes += 1


@dataclass
class _Seam:
    """Everything ``_lease`` asks the world, scripted."""

    target: Path
    owner: str | None = None
    record_id: str = "worker-1"
    managed: bool = True
    state: str = "packed"
    error: str | None = None
    opens: list[BaseException | None] = field(default_factory=list)
    attempts: list[str] = field(default_factory=list)

    def open(self, path: str, *, options: Any = None) -> _Handle:
        self.attempts.append(path)
        outcome = self.opens.pop(0) if self.opens else None
        if isinstance(outcome, BaseException):
            raise outcome
        return _Handle(_Instance(self.record_id, self.managed, path))

    def options(self) -> DatabaseOpenOptions:
        return DatabaseOpenOptions(worker_cwd=str(self.target.parent))


@pytest.fixture
def seam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Seam:
    target = tmp_path / "managed.i64"
    target.write_bytes(SAVED)
    scripted = _Seam(target=target)

    class _FakeHandle:
        @staticmethod
        def open(path: str, *, options: Any = None) -> _Handle:
            return scripted.open(path, options=options)

    def owner(path: str, *, output_database: Any = None) -> Any:
        return None if scripted.owner is None else _Instance(scripted.owner)

    def probe(path: Any) -> dict[str, Any]:
        return {"state": scripted.state, "error": scripted.error, "dirty": False}

    monkeypatch.setattr(ida_adapter, "DatabaseHandle", _FakeHandle)
    monkeypatch.setattr(ida_adapter.ida_nexus, "find_database_owner", owner)
    monkeypatch.setattr(ida_adapter.ida_nexus, "probe_database_state", probe)
    monkeypatch.setattr(ida_adapter, "_await_released", lambda instance: None)
    return scripted


def _with_spare(seam: _Seam) -> Path:
    spare = _pre_save(seam.target)
    spare.write_bytes(GOOD)
    return spare


# --------------------------------------------------------------------------
# The spare is dropped only by a lease that actually loaded the file
# --------------------------------------------------------------------------


def test_a_lease_that_attached_to_a_live_instance_keeps_the_spare(
    seam: _Seam,
) -> None:
    # Nexus returns an already-live instance before it touches the filesystem,
    # so attaching to a GUI session's or a sibling's worker proves nothing
    # about the packed bytes. Dropping the spare there would throw away the
    # only copy of the last database IDA demonstrably loaded.
    seam.owner = "gui-session"
    seam.record_id = "gui-session"
    spare = _with_spare(seam)

    with _lease(seam.target, seam.options(), rescue=True) as handle:
        assert handle.instance.record_id == "gui-session"

    assert spare.read_bytes() == GOOD


def test_a_lease_that_spawned_the_worker_drops_the_spare(seam: _Seam) -> None:
    # The other half of the same gate: our own worker did read the file, so
    # the previous generation has nothing left to rescue.
    seam.owner = None
    seam.record_id = "worker-1"
    spare = _with_spare(seam)

    with _lease(seam.target, seam.options(), rescue=True):
        pass

    assert not spare.exists()
    assert seam.target.read_bytes() == SAVED


# --------------------------------------------------------------------------
# Only a refused open of these very bytes may roll back
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [READINESS_TIMEOUT, WRONG_IDB, LAUNCHER_DIED],
    ids=["readiness-timeout", "wrong-idb", "launcher-died"],
)
def test_a_start_failure_that_is_not_about_the_file_never_rolls_back(
    seam: _Seam, message: str
) -> None:
    # Each of these leaves a perfectly readable database. Restoring over it
    # would destroy the save it carries and report a cause that is not true.
    # The readiness timeout is the sharpest: its worker is often still
    # starting, and clearing the unpacked components would unlink the .id0 it
    # is in the middle of creating.
    spare = _with_spare(seam)
    component = seam.target.with_suffix(".id0")
    component.write_bytes(b"a worker is writing this")
    seam.opens = [WorkerStartError(message)]

    with pytest.raises(WorkerStartError) as refused:
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert str(refused.value) == message
    assert seam.target.read_bytes() == SAVED
    assert spare.read_bytes() == GOOD
    assert component.read_bytes() == b"a worker is writing this"
    assert seam.attempts == [str(seam.target)]


@pytest.mark.parametrize(
    "refusal", [_bad_pack, _kernel_abort], ids=["rc4-empty", "kernel-abort"]
)
def test_a_refused_open_of_this_database_rolls_back_once_and_reports(
    seam: _Seam, refusal: Callable[[Path], str]
) -> None:
    # Either way idalib named this file and would not load it: the vendor
    # defect's rc 4, and IDA's own abort on a database it parsed far enough to
    # reject. The live tests raise the second; production raised the first.
    spare = _with_spare(seam)
    component = seam.target.with_suffix(".id0")
    component.write_bytes(b"left behind by the failed open")
    seam.opens = [WorkerStartError(refusal(seam.target))]

    with pytest.raises(ManagedDatabaseError) as rolled_back:
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert "put back" in str(rolled_back.value)
    assert seam.target.read_bytes() == GOOD
    assert not spare.exists()
    assert not component.exists()
    # Once. The damaged bytes are never reopened, and the restored copy is
    # opened exactly one more time.
    assert seam.attempts == [str(seam.target), str(seam.target)]


def test_a_refused_open_naming_another_database_never_rolls_back(
    seam: _Seam,
) -> None:
    # A launcher log can carry a failed open of a database this lease is not
    # opening at all. Matching the marker alone would roll back on it.
    spare = _with_spare(seam)
    seam.opens = [
        WorkerStartError(
            "idalib worker launcher 4242 exited with status 1\n\n"
            "[ida-nexus] Failed to open database /somewhere/else/other.i64\n"
            "FATAL ERROR: The database /somewhere/else/other.i64 is corrupted"
        )
    ]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED
    assert spare.read_bytes() == GOOD


# --------------------------------------------------------------------------
# A state that could not be determined is a refusal
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        "database is on a network filesystem where file locks are not reliable",
        "could not inspect .id0",
        "the .id0 B-tree header is truncated",
    ],
    ids=["network-filesystem", "unreadable-header", "truncated-header"],
)
def test_a_state_that_could_not_be_determined_refuses_the_rollback(
    seam: _Seam, error: str
) -> None:
    # `probe_database_state` answers `in_use` only when it took and read the
    # advisory lock. On any of these it answers `unknown` with `error` set,
    # and another live session is exactly what cannot be excluded — so the
    # rollback would unlink that session's components and overwrite its file.
    spare = _with_spare(seam)
    component = seam.target.with_suffix(".id0")
    component.write_bytes(b"another session is using this")
    seam.state = "unknown"
    seam.error = error
    seam.opens = [WorkerStartError(_bad_pack(seam.target))]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED
    assert spare.read_bytes() == GOOD
    assert component.read_bytes() == b"another session is using this"


def test_a_database_another_session_holds_refuses_the_rollback(
    seam: _Seam,
) -> None:
    spare = _with_spare(seam)
    seam.state = "in_use"
    seam.opens = [WorkerStartError(_bad_pack(seam.target))]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED
    assert spare.read_bytes() == GOOD


# --------------------------------------------------------------------------
# The spare protocol belongs to the session lease and to no other
# --------------------------------------------------------------------------


def test_a_lease_without_rescue_leaves_files_beside_its_target_alone(
    seam: _Seam,
) -> None:
    # `_analyze_binary` leases the operator's source binary and `_clone_idb`
    # leases a staging copy. Neither target can have a spare this module
    # wrote, so a `<target>.pre-save` beside one is a file of the operator's
    # whose contents this module cannot know.
    theirs = _pre_save(seam.target)
    theirs.write_bytes(b"not ours to delete")

    with _lease(seam.target, seam.options()):
        pass

    assert theirs.read_bytes() == b"not ours to delete"
    assert seam.target.read_bytes() == SAVED


def test_a_lease_without_rescue_never_overwrites_its_target(seam: _Seam) -> None:
    # The same scoping, on the failing path: `os.replace(spare, target)` here
    # would overwrite the operator's input binary with a file of theirs.
    theirs = _pre_save(seam.target)
    theirs.write_bytes(b"not ours to restore")
    seam.opens = [WorkerStartError(_bad_pack(seam.target))]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options()):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED
    assert theirs.read_bytes() == b"not ours to restore"
    assert seam.attempts == [str(seam.target)]


def test_a_spare_that_cannot_be_opened_either_is_reported_as_unusable(
    seam: _Seam,
) -> None:
    # The recovery is tried once and then gives up loudly, rather than
    # answering from a database nothing has ever opened.
    _with_spare(seam)
    seam.opens = [
        WorkerStartError(_bad_pack(seam.target)),
        WorkerStartError(_bad_pack(seam.target)),
    ]

    with pytest.raises(ManagedDatabaseError) as unusable:
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert "built again from its source" in str(unusable.value)
    assert len(seam.attempts) == 2


# --------------------------------------------------------------------------
# A damaged database with no spare is discarded, not met again forever
# --------------------------------------------------------------------------


def test_a_refused_open_with_no_spare_discards_the_managed_database(
    seam: _Seam,
) -> None:
    # The staging save behind `ensure_managed_idb` is the one write with no
    # rescue copy, and `_publish` cannot tell a database the vendor defect
    # damaged there from a good one: `probe_database_state` calls both
    # `packed`. Nothing can recover those bytes, so leaving them in place made
    # the workspace permanently dead and every later open an opaque
    # `WorkerStartError`.
    component = seam.target.with_suffix(".id0")
    component.write_bytes(b"left by the interrupted open")
    seam.opens = [WorkerStartError(_bad_pack(seam.target))]

    with pytest.raises(ManagedDatabaseError) as discarded:
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert "discarded" in str(discarded.value)
    assert "built again from its source" in str(discarded.value)
    assert not seam.target.exists()
    assert not component.exists()
    # One discard and no retry: rebuilding is the next ensure_managed_idb's.
    assert seam.attempts == [str(seam.target)]


@pytest.mark.parametrize(
    "message",
    [READINESS_TIMEOUT, WRONG_IDB, LAUNCHER_DIED],
    ids=["readiness-timeout", "wrong-idb", "launcher-died"],
)
def test_a_start_failure_that_is_not_about_the_file_discards_nothing(
    seam: _Seam, message: str
) -> None:
    # The same distinction the rollback is gated on: none of these says the
    # bytes are bad, and a lease-invariant regression looks exactly like one of
    # them. Discarding here would delete a readable database and hide it.
    seam.opens = [WorkerStartError(message)]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED


@pytest.mark.parametrize(
    ("owner", "state", "error"),
    [
        ("gui-session", "packed", None),
        (None, "in_use", None),
        (None, "unknown", "the .id0 header is truncated"),
    ],
    ids=["owned", "in-use", "undetermined"],
)
def test_a_database_another_session_may_hold_is_never_discarded(
    seam: _Seam, owner: str | None, state: str, error: str | None
) -> None:
    # Deleting a file another session has open destroys that session's work,
    # so the discard is gated exactly like the restore it replaces.
    seam.owner = owner
    seam.state = state
    seam.error = error
    seam.opens = [WorkerStartError(_bad_pack(seam.target))]

    with pytest.raises(WorkerStartError):
        with _lease(seam.target, seam.options(), rescue=True):
            pytest.fail("the lease body must never run")

    assert seam.target.read_bytes() == SAVED
