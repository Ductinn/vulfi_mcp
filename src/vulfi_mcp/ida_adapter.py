"""Managed IDA workspaces and the single Nexus lease each operation uses.

Two responsibilities, and nothing else:

``ensure_managed_idb``
    Turn a binary or a user's saved IDB into an IDB this server may mutate.
    The source binary is never written to, and a user IDB is copied rather
    than opened, so VulFi triage state can never land in a file the user also
    has open in the GUI. Managed databases live under
    ``$VULFI_MCP_DATA_DIR`` (or ``$XDG_DATA_HOME/vulfi-mcp``), never in this
    repository, never beside the source, and never beside the user's IDB.

``invoke_ida``
    Open exactly one lease, run exactly one worker operation through
    :func:`vulfi_mcp.ida_runtime.run`, save only when that operation reports a
    mutation, and release the lease whatever happens.

Only the public ``ida_nexus`` API is used: no private manager, no GUI API, and
no MCP ``instance_id``. Everything crossing the worker boundary is JSON-native,
because the remote module is bound with ``codec="json"``.
"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

import ida_nexus
from ida_nexus import (
    DatabaseBusyError,
    DatabaseHandle,
    DatabaseInstance,
    DatabaseOpenOptions,
)
from ida_nexus.database_state import unpacked_database_paths

from vulfi_mcp import ida_runtime

__all__ = [
    "DATA_DIR_ENV",
    "ManagedDatabaseError",
    "data_dir",
    "ensure_managed_idb",
    "invoke_ida",
]

#: Operator configuration for the managed workspace root. Plan 2 reads the same
#: variable for its catalog, so it is resolved here and nowhere else.
DATA_DIR_ENV: Final = "VULFI_MCP_DATA_DIR"

#: Suffixes that mean "this path is already a database, not a binary".
IDB_SUFFIXES: Final = (".i64", ".idb")

#: Seconds one worker operation may run before the lease gives up on it.
WORKER_TIMEOUT: Final = 600.0

#: Seconds to wait for IDA to repack a database once its lease closed.
RELEASE_TIMEOUT: Final = 120.0

#: File states of a supplied IDB that make copying it unsafe.
_UNSAFE_STATES: Final = {
    "in_use": "it is open in another IDA session",
    "unpacked": "it is unpacked, so unsaved work would be lost",
    "crashed": "it was left behind by a crashed IDA session",
    "missing": "it does not exist",
    "unknown": "its state could not be determined",
}

_RUNTIME_SOURCE: Final = Path(ida_runtime.__file__).resolve()
_STAGING: Final = ".staging-"
#: Longest directory-name prefix kept from a target's file name.
_MAX_STEM: Final = 48


class ManagedDatabaseError(RuntimeError):
    """The managed workspace could not produce, or keep, a usable IDB."""


def data_dir() -> Path:
    """Root directory for everything this server owns on disk.

    Resolved once, here: a relative or symlinked configuration would otherwise
    make every managed path depend on the process working directory, and would
    hand callers a spelling of the file that differs from the one IDA reports.
    """
    configured = os.environ.get(DATA_DIR_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    base = Path(os.environ.get("XDG_DATA_HOME") or "~/.local/share").expanduser()
    return (base / "vulfi-mcp").resolve()


def ensure_managed_idb(path: str) -> str:
    """Return the managed IDB for ``path``, analyzing or cloning it if needed.

    ``path`` is either a binary, which is analyzed into a fresh managed
    database, or a saved ``.i64``/``.idb``, which is copied and opened only as
    that copy. A supplied IDB that is open, unpacked, dirty, crashed, or owned
    by a live instance raises :class:`ida_nexus.DatabaseBusyError` and is left
    untouched.

    The result is deterministic: the same file at the same path always resolves
    to the same managed database, and a database that is already there is
    reused instead of being analyzed again.
    """
    source = _canonical_source(path)
    is_database = source.suffix.lower() in IDB_SUFFIXES
    if is_database:
        # Checked before a byte of it is read: a live IDB's bytes are not its
        # saved bytes, so hashing one would key the workspace on a moving file.
        _require_released(source)
    workspace = _workspace(source)
    managed = workspace / _managed_name(source)
    reusable = _reusable(managed)
    if reusable is not None:
        return reusable
    if is_database:
        return _clone_idb(source, managed, workspace)
    return _analyze_binary(source, managed, workspace)


def invoke_ida(
    idb_path: str, operation: str, payload: dict[str, object]
) -> dict[str, object]:
    """Run one worker operation against one managed IDB, under one lease.

    The payload and the result are JSON-normalized, the IDB is saved only when
    the operation reports ``mutated``, and a save that does not report success
    raises instead of returning a result that looks durable.
    """
    database = Path(idb_path).expanduser()
    if database.suffix.lower() not in IDB_SUFFIXES:
        # Opening a binary here would analyze it in place, next to a file this
        # server must never write to.
        raise ValueError(f"invoke_ida needs an IDA database, got {database}")
    if not database.is_file():
        raise FileNotFoundError(f"no such IDA database: {database}")
    if not isinstance(operation, str) or not operation:
        raise ValueError("operation must be a non-empty string")
    request = _json_value(payload if payload is not None else {}, "payload")
    if not isinstance(request, dict):
        raise TypeError(f"payload must be a JSON object, got {type(payload).__name__}")

    options = DatabaseOpenOptions(worker_cwd=str(database.parent))
    with _lease(database, options) as handle:
        result = _worker_run()(handle, operation, request)
        normalized = _json_value(result, f"{operation} result")
        if not isinstance(normalized, dict):
            raise ManagedDatabaseError(
                f"{operation} returned {type(result).__name__}, expected a JSON object"
            )
        if normalized.get("mutated"):
            _require_saved(handle.save_database(), database)
    return normalized


# --------------------------------------------------------------------------
# Managed workspace layout
# --------------------------------------------------------------------------


def _canonical_source(path: str) -> Path:
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"no such binary or IDA database: {source}")
    return source


def _workspace(source: Path) -> Path:
    """Deterministic per-target directory: same file, same path, same folder."""
    identity = hashlib.sha256()
    identity.update(str(source).encode("utf-8", "surrogateescape"))
    identity.update(b"\0")
    identity.update(_content_digest(source).encode("ascii"))
    return data_dir() / "databases" / f"{_stem(source)}-{identity.hexdigest()[:16]}"


def _managed_name(source: Path) -> str:
    """Keep an existing database's format; analyze a binary into a 64-bit IDB."""
    suffix = source.suffix.lower()
    return _stem(source) + (suffix if suffix in IDB_SUFFIXES else ".i64")


def _stem(source: Path) -> str:
    kept = "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in source.stem
    )
    return kept[:_MAX_STEM] or "database"


def _content_digest(source: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _reusable(managed: Path) -> str | None:
    """Return the managed database when it is usable, else clear the leftovers."""
    if not managed.exists():
        return None
    state = ida_nexus.probe_database_state(managed)["state"]
    if state in ("packed", "in_use"):
        return str(managed)
    _discard(managed)
    return None


def _discard(database: Path) -> None:
    for stale in (database, *unpacked_database_paths(database)):
        with suppress(FileNotFoundError, IsADirectoryError):
            stale.unlink()


def _staging(workspace: Path) -> Path:
    """A private scratch directory: a half-finished IDB never gets the real name.

    One per call, so two processes preparing the same target cannot overwrite
    each other's work in progress; the finished database is published with a
    single atomic rename.
    """
    workspace.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=_STAGING, dir=workspace))


# --------------------------------------------------------------------------
# Producing a managed database
# --------------------------------------------------------------------------


def _analyze_binary(source: Path, managed: Path, workspace: Path) -> str:
    """Analyze a read-only binary into the managed workspace."""
    staging = _staging(workspace)
    try:
        options = DatabaseOpenOptions(
            output_database=str(staging / managed.name),
            worker_cwd=str(staging),
        )
        with _lease(source, options) as handle:
            handle.wait_autoanalysis()
            produced = Path(handle.instance.idb_path)
            _require_saved(handle.save_database(), produced)
        return _publish(produced, managed)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _clone_idb(source: Path, managed: Path, workspace: Path) -> str:
    """Copy a saved, unlocked IDB into the workspace and open only the copy.

    Only the packed file is copied. ``_require_released`` already established
    that no component files exist beside it, and the one way they could appear
    afterwards is another session opening the source: copying that session's
    live components would stage a database that probes as crashed.
    """
    staging = _staging(workspace)
    try:
        copy = staging / managed.name
        shutil.copy2(source, copy)
        with _lease(copy, DatabaseOpenOptions(worker_cwd=str(staging))) as handle:
            produced = Path(handle.instance.idb_path)
            _require_saved(handle.save_database(), produced)
        return _publish(produced, managed)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _publish(produced: Path, managed: Path) -> str:
    """Move a released database from staging onto its deterministic name.

    A ``.i64`` exists on disk while its database is live, so the file being
    there proves nothing. ``DatabaseHandle.close(wait_for_database=True)`` only
    waits when its lease-release call reported a pending shutdown, and that call
    can time out; publishing then would rename and delete files a worker is
    still writing, and the half-written result would be reused forever. The
    probe is the invariant: only a ``packed`` database is finished.
    """
    if not produced.is_file():
        raise ManagedDatabaseError(f"IDA did not leave a database at {produced}")
    state = ida_nexus.probe_database_state(produced)["state"]
    if state != "packed":
        raise ManagedDatabaseError(
            f"refusing to publish {produced}: IDA has not released it"
            f" (state: {state})"
        )
    _discard(managed)
    os.replace(produced, managed)
    return str(managed)


def _require_released(source: Path) -> None:
    """Refuse to copy an IDB that another session owns or has not saved."""
    state = ida_nexus.probe_database_state(source)
    name = state["state"]
    if name in _UNSAFE_STATES:
        raise DatabaseBusyError(
            f"refusing to copy {source}: {_UNSAFE_STATES[name]} (state: {name})"
        )
    if state["dirty"]:
        raise DatabaseBusyError(
            f"refusing to copy {source}: it holds unsaved changes (state: {name})"
        )
    owner = ida_nexus.find_database_owner(source)
    if owner is not None:
        raise DatabaseBusyError(
            f"refusing to copy {source}: it is owned by {owner.backend}"
            f" process {owner.pid}"
        )


def _require_saved(result: Any, database: Path) -> None:
    if not (isinstance(result, dict) and result.get("saved")):
        raise ManagedDatabaseError(f"IDA reported no save for {database}: {result!r}")


# --------------------------------------------------------------------------
# One lease, one worker entry point
# --------------------------------------------------------------------------


@contextmanager
def _lease(target: Path, options: DatabaseOpenOptions) -> Iterator[DatabaseHandle]:
    """Hold exactly one Nexus lease, release it, and see it released.

    An IDB is unpacked while a worker holds it, and the worker keeps the packed
    file open until it exits, so a caller that returns earlier would hand out a
    path whose bytes are still moving. ``close(wait_for_database=True)`` is
    asked for that wait but only performs it when its ``/release_lease`` call
    reported ``shutdown_pending``, and that call is a two-second best effort
    that reports ``False`` on any timeout or transport error. The observed
    release is therefore the authority, not the close.

    A failure while closing is only reported when the work itself succeeded, so
    it can never mask the real error.
    """
    handle = DatabaseHandle.open(str(target), options=options)
    instance = handle.instance
    failed = False
    try:
        yield handle
    except BaseException:
        failed = True
        raise
    finally:
        try:
            handle.close(wait_for_database=True)
            if not failed:
                _await_released(instance)
        except Exception:
            if not failed:
                raise


def _await_released(instance: DatabaseInstance) -> None:
    """Wait for the worker to let go of its database and finish repacking it."""
    database = Path(instance.idb_path)
    if not ida_nexus.wait_database_released(instance, timeout=RELEASE_TIMEOUT):
        raise ManagedDatabaseError(
            f"{database} was still held {RELEASE_TIMEOUT:g}s after its lease closed"
        )
    deadline = time.monotonic() + RELEASE_TIMEOUT
    while True:
        state = ida_nexus.probe_database_state(database)["state"]
        if state == "packed":
            return
        if time.monotonic() >= deadline:
            raise ManagedDatabaseError(
                f"{database} is still {state} {RELEASE_TIMEOUT:g}s after its lease"
                " closed; IDA never repacked it"
            )
        time.sleep(0.05)


@lru_cache(maxsize=1)
def _worker_run() -> Any:
    """Bind the worker's single entry point to its source module, once."""
    module = ida_nexus.RemoteModule(str(_RUNTIME_SOURCE), codec="json")

    def run(operation: str, payload: dict[str, object]) -> dict[str, object]: ...

    return module.function(run, timeout=WORKER_TIMEOUT)


def _json_value(value: object, label: str) -> Any:
    """Return ``value`` as JSON-native data, or say exactly what cannot cross."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{label}: JSON cannot carry {value!r}")
        return value
    if isinstance(value, (list, tuple)):
        return [
            _json_value(item, f"{label}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(
                    f"{label}: JSON object keys must be strings,"
                    f" got {type(key).__name__}"
                )
            normalized[key] = _json_value(item, f"{label}.{key}")
        return normalized
    raise TypeError(
        f"{label}: {type(value).__name__} cannot cross the JSON worker boundary"
    )
