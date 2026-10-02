"""Managed IDA workspaces and the single Nexus lease each operation uses.

Three responsibilities, and nothing else:

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

``scan_ida``
    Ask the worker for one scan's evidence and evaluate the rules over it
    here, on the host, so :mod:`vulfi_mcp.ida_runtime`'s restricted
    interpreter and its budgets never run inside IDA. Facts cross the
    boundary; rule objects do not.

Only the public ``ida_nexus`` API is used: no private manager, no GUI API, and
no MCP ``instance_id``. Everything crossing the worker boundary is JSON-native,
because the remote module is bound with ``codec="json"``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import tempfile
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, NamedTuple

import ida_nexus
from ida_nexus import (
    DatabaseBusyError,
    DatabaseHandle,
    DatabaseInstance,
    DatabaseOpenOptions,
    NexusError,
    WorkerStartError,
)
from ida_nexus.database_state import unpacked_database_paths

from vulfi_mcp import ida_runtime
from vulfi_mcp.contracts import (
    Backend,
    Finding,
    FindingsPage,
    RuleCoverage,
    ScanResult,
    TriageResult,
)
from vulfi_mcp.ida_runtime import (
    TRIAGE_STATUSES,
    ExpressionError,
    FunctionCall,
    Param,
    RuleContext,
    UnavailableEvidenceError,
    evaluate_rule,
    utc_now,
    validate_page,
    validate_rationale,
    validate_scope,
    validate_status,
)
from vulfi_mcp.rules import canonical_rule_digest

if TYPE_CHECKING:  # pragma: no cover - annotations only.
    from vulfi_mcp.rules import Rule

__all__ = [
    "DATA_DIR_ENV",
    "NO_DATABASE_REASON",
    "ManagedDatabaseError",
    "data_dir",
    "ensure_managed_idb",
    "existing_managed_idb",
    "findings_ida",
    "invoke_ida",
    "mirror_linked_ida",
    "scan_ida",
    "triage_ida",
    "unscanned_findings_page",
]

#: Operator configuration for the managed workspace root. Plan 2 reads the same
#: variable for its catalog, so it is resolved here and nowhere else.
DATA_DIR_ENV: Final = "VULFI_MCP_DATA_DIR"

#: Suffixes that mean "this path is already a database, not a binary".
IDB_SUFFIXES: Final = (".i64", ".idb")

#: Seconds one worker operation may run before the lease gives up on it.
WORKER_TIMEOUT: Final = 600.0

#: Seconds to wait for a worker to exit and leave its database packed.
RELEASE_TIMEOUT: Final = 120.0

#: Process table, when this platform has one; the fallback is ``os.kill``.
_PROC: Final = Path("/proc")

#: "Several live instances answer for this target", so this lease owns none.
_AMBIGUOUS: Final = object()

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

#: Name suffix of the copy a mutating save keeps of the bytes it replaces.
#: IDA 9.4 occasionally packs a database it can no longer open — ``rc 4``,
#: ``Database is empty``, while the file still probes ``packed`` — so the last
#: known-good bytes stay beside it until an open proves the new ones readable.
_PRE_SAVE: Final = ".pre-save"
#: Where that copy is written before it is put in place, so a copy interrupted
#: half way never becomes the copy a recovery trusts.
_PARTIAL: Final = ".partial"

#: ``ida_nexus`` raises one ``WorkerStartError`` for three unrelated failures:
#: a readiness timeout, a worker that opened a different IDB than asked for,
#: and a launcher process that exited non-zero — licence trouble, a missing
#: shared library, an OOM kill, a transient fork failure. Only the last, and
#: only when the worker log tail it carries shows idalib refusing this very
#: file, says anything about the bytes on disk. Everything else leaves a
#: perfectly readable database that must not be rolled back over.
_LAUNCHER_EXIT: Final = "idalib worker launcher "
_EXITED_WITH: Final = " exited with status "
#: The two lines idalib leaves when it named a database and refused to load
#: it, each as the text before and after the path. The first is
#: ``ida_domain.database._open_new_database`` re-raising a non-zero
#: ``idapro.open_database``, which is the ``rc 4`` / "Database is empty" shape
#: the vendor defect produces; the second is IDA's own kernel abort on a
#: database it parsed far enough to reject. Both name the file, and a line
#: that names a different file is about a different file.
_REFUSALS: Final = (
    ("Failed to open database ", ""),
    ("FATAL ERROR: The database ", " is corrupted"),
)

#: The backend tag every row this adapter produces carries. The worker names
#: itself the same way, and refuses a row that claims anything else.
BACKEND: Final[Backend] = "ida"

#: Address space of a finding in a single-image database.
ADDRESS_SPACE: Final = "image"

#: Findings one scan result carries back; ``scope_total`` counts them all.
MAX_SCAN_FINDINGS: Final = 100

#: Rows one stored page carries when a caller does not say.
DEFAULT_PAGE_LIMIT: Final = 100

#: This milestone stores no reviewer-created links, so no pair is out of step.
SYNC_STATE: Final = "unlinked"

#: Facts that cross as JSON arrays but reach the evaluator as tuples.
_SEQUENCE_FACTS: Final = frozenset(
    {"calls_before", "calls_after", "return_check_values", "reachable_from_names"}
)
_PARAM_FACTS: Final = frozenset(Param.__dataclass_fields__)
_CALL_FACTS: Final = frozenset(FunctionCall.__dataclass_fields__)

#: Said once per scan: Plan 3's external catalog is not part of this milestone.
_CATALOG_WARNING: Final = (
    "target_total covers this managed IDB only; the external finding catalog"
    " is not part of this IDA-only milestone"
)

#: Why the other store reports ``available: false``. An absent store is
#: unavailable, never an empty one, so no reader can mistake it for zero rows.
_CATALOG_REASON: Final = (
    "the external finding catalog arrives with Plan 3; this milestone stores"
    " IDA findings in the managed IDB only"
)

#: Why the IDA store reports ``available: false`` for a target nothing has
#: scanned. A read may not analyze a binary into existence, so this is what
#: "there is no store" looks like — never an empty one.
NO_DATABASE_REASON: Final = (
    "this target has no managed IDA database yet, and only vulfi_scan creates"
    " one: there is no store to answer from, which is not the same as a target"
    " with no findings"
)


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



def _is_managed_database(source: Path) -> bool:
    """Whether ``source`` is already a database this server keeps."""
    try:
        source.resolve().relative_to((data_dir() / "databases").resolve())
    except ValueError:
        return False
    return source.is_file() and source.suffix.lower() in IDB_SUFFIXES


def existing_managed_idb(path: str) -> str | None:
    """The managed IDB for ``path``, or ``None`` when there is not one yet.

    The same deterministic resolution :func:`ensure_managed_idb` performs, and
    nothing else: no analysis, no clone, no staging directory, no deletion. A
    read answers from the database a scan already made, so it asks this and
    reports its store unavailable when the answer is ``None`` — creating a
    database to page rows out of would turn a read into minutes of analysis
    and permanent on-disk state, and would answer "no findings" where the
    truth is "nothing has scanned this target".
    """
    source = _canonical_source(path)
    if source.suffix.lower() in IDB_SUFFIXES and _is_managed_database(source):
        # The caller named the managed database itself. Looking for a copy of
        # that copy would miss the store this file already is.
        return str(source)
    if source.suffix.lower() in IDB_SUFFIXES:
        # Same gate as `ensure_managed_idb`, for the same reason: a live IDB's
        # bytes are not its saved bytes, so the workspace key would be read
        # off a moving file.
        _require_released(source)
    managed = _workspace(source) / _managed_name(source)
    return str(managed) if managed.is_file() else None


def invoke_ida(
    idb_path: str, operation: str, payload: dict[str, object]
) -> dict[str, object]:
    """Run one worker operation against one managed IDB, under one lease.

    The payload and the result are JSON-normalized, the IDB is saved only when
    the operation reports ``mutated``, and a save that does not report success
    raises instead of returning a result that looks durable.
    """
    with _session(idb_path) as worker:
        return worker.run(operation, payload)


def scan_ida(
    idb_path: str,
    rules: tuple[Rule, ...],
    scope: str,
    *,
    path: str | None = None,
    decompiler: str = "auto",
    limits: dict[str, int] | None = None,
) -> ScanResult:
    """Evaluate ``rules`` over one managed IDB's call sites, and store the rows.

    The worker extracts JSON-native evidence; every ``mark_if`` branch is
    evaluated here, by the same restricted interpreter the rule template
    describes, so rule evaluation never runs inside IDA. A rule whose facts
    IDA could not establish is reported ``unsupported`` and a rule whose
    expression failed is reported ``failed``; neither becomes a clean
    negative, and ``Info`` is reserved for a call site whose argument list IDA
    verified as empty.

    The evaluated rows are then committed to the managed IDB's own record, and
    the rows this returns are the stored ones: a rescan of this scope carries
    an earlier assessment forward by exact finding ID, a ``complete`` scan
    retires a row whose call site is gone, and a ``partial`` one keeps it and
    marks it stale instead. Evaluation happens on the host between the two
    worker calls, but both run under one lease, the record's whole
    read/modify/write happens inside the second of them, and one save at the
    end of the lease commits whatever either of them changed.

    ``decompiler="disabled"`` runs the same disassembly-only extraction IDA
    falls back to when Hex-Rays is absent. ``limits`` may only tighten
    :data:`vulfi_mcp.ida_runtime.SCAN_LIMITS`.

    The scan is the one read path that may write to the analysis itself: it
    applies a pinned VulFi prototype with ``SetType`` to a rule-named function
    IDA has no type for, in the managed database only, and reports each
    application under ``scope_health["ida"]["applied_prototypes"]``.
    """
    if not rules:
        raise ValueError("scan_ida needs at least one rule")
    scope = validate_scope(scope)
    payload: dict[str, object] = {
        "rules": [
            {
                "index": index,
                "function_names": list(rule["function_names"]),
                "wrappers": rule["wrappers"],
            }
            for index, rule in enumerate(rules)
        ],
        "prototypes": _prototypes(),
        "decompiler": decompiler,
    }
    if limits:
        payload["limits"] = dict(limits)
    with _session(idb_path) as worker:
        raw = worker.run("scan", payload)
        evaluation = _evaluate(raw, rules, scope)
        stored = worker.run("store_scan", _store_payload(rules, scope, evaluation))
    result = _scan_result(raw, scope, idb_path, path, evaluation, stored)
    if path:
        # The save already landed. A member this scan retired must pause now,
        # not on the next findings page.
        from vulfi_mcp.server import pause_linked_members

        pause_linked_members(path)
    return result


def findings_ida(
    idb_path: str,
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
    *,
    path: str | None = None,
) -> FindingsPage:
    """Page the rows this managed IDB already stores, without rescanning.

    The window is checked before any database is opened, so an out-of-range
    page costs nothing and can never create an IDB just to refuse a read. The
    page spans every scope of the IDA backend in one total order: address
    space, then location, then finding ID.
    """
    offset, limit = validate_page(offset, limit)
    stored = invoke_ida(idb_path, "findings_page", {"offset": offset, "limit": limit})
    return {
        "path": path or idb_path,
        "idb_path": idb_path,
        "offset": offset,
        "limit": limit,
        "findings": _findings(stored),
        "page_total": int(stored.get("page_total") or 0),
        "target_total": int(stored.get("target_total") or 0),
        # Plan 3's catalog is the other store, and it is not here yet.
        "target_total_complete": False,
        "stale_total": int(stored.get("stale_total") or 0),
        "status_counts": _status_counts(stored),
        "store_health": _store_health(stored),
        "sync_state": SYNC_STATE,
        "warnings": [_CATALOG_WARNING],
    }


def unscanned_findings_page(
    path: str, offset: int = 0, limit: int = DEFAULT_PAGE_LIMIT
) -> FindingsPage:
    """The honest page for a target no scan has ever produced a database for.

    Zero rows, and both stores reported unavailable with a reason: the IDA one
    because this target has no managed database, the catalog one because it
    arrives with Plan 3. ``target_total_complete`` is false, so no caller can
    read this as "this target has no findings". No database is opened, and
    none is created.
    """
    offset, limit = validate_page(offset, limit)
    return {
        "path": path,
        # There is no managed database to name, and naming one that does not
        # exist would read as a database this call just made.
        "idb_path": "",
        "offset": offset,
        "limit": limit,
        "findings": [],
        "page_total": 0,
        "target_total": 0,
        "target_total_complete": False,
        "stale_total": 0,
        "status_counts": {},
        "store_health": _unavailable_store_health(NO_DATABASE_REASON),
        "sync_state": SYNC_STATE,
        "warnings": [NO_DATABASE_REASON, _CATALOG_WARNING],
    }


def triage_ida(
    idb_path: str,
    finding_id: str,
    status: str,
    rationale: str,
    *,
    path: str | None = None,
) -> TriageResult:
    """Assess one stored finding, by its exact ID.

    The status and the rationale are checked here, before a database is
    opened, and so is the ID being a non-empty string. Its shape is not:
    composing and parsing a finding ID is the record's own business, and an
    ID the record does not hold is refused there whatever it looks like.
    Either way a refused update writes nothing: the record keeps its bytes
    and ``triage_revision`` its value.
    """
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding_id must be a non-empty string")
    status = validate_status(status)
    rationale = validate_rationale(rationale)
    stored = invoke_ida(
        idb_path,
        "triage",
        {"finding_id": finding_id, "status": status, "rationale": rationale},
    )
    finding = stored.get("finding")
    if not isinstance(finding, dict):
        raise ManagedDatabaseError(
            f"triage stored {finding_id!r} but returned no finding"
        )
    return {
        "path": path or idb_path,
        "idb_path": idb_path,
        "finding": finding,
        "triage_revision": int(stored.get("triage_revision") or 0),
        "target_total": int(stored.get("target_total") or 0),
        # Plan 3's catalog is the other store; an absent store is unavailable,
        # never zero, so this total is explicitly incomplete.
        "target_total_complete": False,
        "status_counts": _status_counts(stored),
        "store_health": _store_health(stored),
        "sync_state": SYNC_STATE,
        "warnings": [_CATALOG_WARNING],
    }


def call_site_proof_ida(idb_path: str, address: int | str) -> dict[str, object]:
    """The open database's image base, bytes, and xrefs at one address."""
    return invoke_ida(idb_path, "call_site_proof", {"address": address})


def mirror_linked_ida(
    idb_path: str,
    finding_id: str,
    event_id: str,
    expected_revision: int,
    decision: dict[str, object],
) -> dict[str, object]:
    """Compare one finding's revision, mirror the linked decision, and save.

    One worker operation does the compare and the write. The lease saves only
    when that operation mutated the record, so a replay that finds the
    intended revision already present does not save again. A save that fails
    is reported as not applied: it is never a synchronized mirror.
    """
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding_id must be a non-empty string")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("event_id must be a non-empty string")
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise ValueError(
            f"expected_revision must be an integer, got {expected_revision!r}"
        )
    if not isinstance(decision, dict):
        raise ValueError("decision must be an object")
    try:
        mirrored = invoke_ida(
            idb_path,
            "mirror_linked",
            {
                "finding_id": finding_id,
                "event_id": event_id,
                "expected_revision": expected_revision,
                "decision": decision,
            },
        )
    except ManagedDatabaseError as failed:
        return {
            "mutated": False,
            "applied": False,
            "already": False,
            "conflict": False,
            "saved": False,
            "reason": str(failed),
        }
    mirrored["saved"] = bool(mirrored.get("applied") or mirrored.get("already"))
    return mirrored



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
    _unlink(
        database,
        *unpacked_database_paths(database),
        *_pre_save_paths(database),
    )


def _discard_unpacked(database: Path) -> None:
    """Drop the components an interrupted open left beside a packed database.

    A worker that dies in ``open_database`` still leaves the ``.id0`` and its
    siblings behind, and a packed ``.i64`` next to them is a crashed database
    that the next open refuses outright.
    """
    _unlink(*unpacked_database_paths(database))


def _unlink(*paths: Path) -> None:
    for stale in paths:
        with suppress(FileNotFoundError, IsADirectoryError):
            stale.unlink()


def _pre_save(database: Path) -> Path:
    """Where the bytes a mutating save replaces are kept, beside the database."""
    return database.with_name(database.name + _PRE_SAVE)


def _pre_save_paths(database: Path) -> tuple[Path, ...]:
    spare = _pre_save(database)
    return (spare, spare.with_name(spare.name + _PARTIAL))


def _keep_pre_save(database: Path) -> None:
    """Copy ``database`` aside so a save that damages it can be undone.

    Written under a scratch name and renamed into place: a copy interrupted
    half way must never become the copy a recovery puts back.
    """
    spare, partial = _pre_save_paths(database)
    shutil.copy2(database, partial)
    os.replace(partial, spare)


def _drop_pre_save(database: Path) -> None:
    """Forget the spare copy: the bytes on disk have just been opened."""
    _unlink(*_pre_save_paths(database))


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

    This lease is deliberately not a ``rescue`` lease — a staging copy has no
    spare of its own, and the only thing this module could put back is a file
    it never wrote. But the bytes being opened are the *source's* bytes, so
    the one failure that is about them is the vendor's bad pack, and leaving
    it as a bare ``WorkerStartError`` breaks this module's one promise: the
    caller is always told. ``.i64``s this server saved reach this path
    routinely (``ensure_managed_idb`` on a managed database, and the
    "operator-supplied IDB" the design is built around is normally one), and
    a run of the suite caught exactly that — ``_clone_idb`` opening a
    byte-identical copy of a database ``probe_database_state`` had just
    called ``packed`` and idalib refused with "Failed to open database".
    Nothing is written to ``source`` either way; only the error changes, from
    an opaque launcher exit into this server naming the defect.
    """
    staging = _staging(workspace)
    try:
        copy = staging / managed.name
        shutil.copy2(source, copy)
        try:
            with _lease(copy, DatabaseOpenOptions(worker_cwd=str(staging))) as handle:
                produced = Path(handle.instance.idb_path)
                _require_saved(handle.save_database(), produced)
        except WorkerStartError as damaged:
            if not _refused_these_bytes(damaged, copy):
                raise
            raise ManagedDatabaseError(
                f"IDA could not open the copy it made of {source}: those"
                " bytes are a database IDA 9.4 packed and can no longer load."
                f" Nothing was written to {source}, and no managed database"
                " was produced from it — it has to be built again from its"
                " source binary."
            ) from damaged
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


def _save_session(handle: DatabaseHandle, database: Path) -> None:
    """Commit what a live lease changed, keeping the bytes it overwrites.

    Every write this module makes to a database that is already published
    goes through here, so the spare copy exists for all of them and for
    nothing else. The two staging saves behind ``ensure_managed_idb`` need no
    spare: they write a private file that only reaches its managed name once
    ``_publish`` has seen IDA release it.
    """
    _keep_pre_save(database)
    _require_saved(handle.save_database(), database)


# --------------------------------------------------------------------------
# One lease, one worker entry point
# --------------------------------------------------------------------------


class _Worker:
    """One open managed database, and the operations run against it.

    A scan evaluates its rules on the host, between two worker operations, so
    it needs both of them to see the same open database: a second lease would
    reopen the IDB, and could find it owned by somebody else by then. Holding
    one lease keeps the evidence and the record it is stored in consistent.

    What the session mutated reaches disk through :meth:`save`, once, after
    its last operation. Saving per operation would pack and rewrite the whole
    database twice for one scan — a prototyping scan mutates the analysis and
    the record that follows it mutates the netnode — and the second write
    contains everything the first one did, so the first is pure I/O
    proportional to the size of the IDB.
    """

    def __init__(self, handle: DatabaseHandle, database: Path) -> None:
        self._handle = handle
        self._database = database
        self._unsaved = False

    def run(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        """Run one operation, and note a mutation for this session to save."""
        if not isinstance(operation, str) or not operation:
            raise ValueError("operation must be a non-empty string")
        request = _json_value(payload if payload is not None else {}, "payload")
        if not isinstance(request, dict):
            raise TypeError(
                f"payload must be a JSON object, got {type(payload).__name__}"
            )
        result = _worker_run()(self._handle, operation, request)
        normalized = _json_value(result, f"{operation} result")
        if not isinstance(normalized, dict):
            raise ManagedDatabaseError(
                f"{operation} returned {type(result).__name__}, expected a JSON object"
            )
        if normalized.get("mutated"):
            self._unsaved = True
        return normalized

    def save(self) -> None:
        """Commit what this session mutated, while the lease still holds it.

        A netnode write that is not saved is not durable, and IDA offers no
        transaction: a failed save is reported, never swallowed. Deferring the
        write does not weaken that — the save runs inside the lease, before
        the database is closed, and its failure reaches the caller instead of
        a result that looks durable.

        IDA reporting a successful save is not proof that it wrote a database
        it can read back, so the bytes this save replaces are kept beside it
        until an open proves the new ones good.
        """
        if not self._unsaved:
            return
        self._unsaved = False
        _save_session(self._handle, self._database)


@contextmanager
def _session(idb_path: str) -> Iterator[_Worker]:
    """Open one managed IDB under one lease, for one or more operations.

    The session saves once, when its body has finished and the lease still
    holds the database. A body that raised saves nothing, and nothing it
    changed reaches disk either: the operation it failed in never returned a
    result claiming durability, and a lease this process owns ends with a
    discarding shutdown whether or not the body raised.

    This is the only lease that asks for the rescue copy. It is the only one
    whose target is a published managed database, so it is the only one whose
    target can ever have a spare worth consulting: the other two lease a
    source binary and a staging copy, beside neither of which this module
    writes anything.
    """
    database = Path(idb_path).expanduser()
    if database.suffix.lower() not in IDB_SUFFIXES:
        # Opening a binary here would analyze it in place, next to a file this
        # server must never write to.
        raise ValueError(f"this operation needs an IDA database, got {database}")
    if not database.is_file():
        raise FileNotFoundError(f"no such IDA database: {database}")
    options = DatabaseOpenOptions(worker_cwd=str(database.parent))
    with _lease(database, options, rescue=True) as handle:
        worker = _Worker(handle, database)
        yield worker
        worker.save()


@contextmanager
def _lease(
    target: Path,
    options: DatabaseOpenOptions,
    *,
    rescue: bool = False,
) -> Iterator[DatabaseHandle]:
    """Hold exactly one Nexus lease and shut our own worker down behind us.

    A worker closes its database with ``save=True`` by default, so *every*
    close rewrote the packed ``.i64``, even for a read-only operation that
    changed nothing an agent asked for. That rewrite is the exposure behind the
    managed databases that turned permanently unopenable after a few dozen
    leases (``idapro.open_database`` then answers ``rc 4`` while
    ``probe_database_state`` still calls the file ``packed``). Durability here
    comes from one place only — the explicit ``save_database()`` the mutating
    operation already did, and whose failure is reported — so a lease we own
    ends with an explicit discarding shutdown and the file is left alone.

    The close is then asked to wait for that shutdown, but only performs the
    wait when its ``/release_lease`` call reported ``shutdown_pending``, and
    that call is a two-second best effort reporting ``False`` on any timeout or
    transport error. The observed release is therefore the authority.

    Both are only ours to do when this lease spawned the worker: Nexus attaches
    to any live instance that already owns the target instead of spawning one,
    and that instance belongs to a GUI session or a sibling lease. Shutting it
    down would end somebody else's session, and waiting on its lifetime lock
    would stall until that session ended and then fail an operation that has
    already completed.

    The discarding shutdown is a fallible RPC — a transport error, its own
    five-second timeout, a worker that died, or a 409 from a sibling — so it is
    nested in its own ``try``: the close is the one step that must happen
    whatever else does, because ``DatabaseHandle`` has no finalizer and a lease
    left open keeps the worker process alive on the managed ``.i64`` for the
    rest of this process's life, wedging every later open of that database.

    All of it runs whether or not the body raised. Releasing the last lease of
    a managed worker marks a shutdown that still saves (Nexus clears that flag
    only for an explicit discarding shutdown), so a lease that skipped its own
    teardown after a failure had the worker write the very mutation the failed
    operation never confirmed — and the next lease opened while that worker was
    still writing. A failed operation must leave the database exactly as it
    found it, and the next one must not race the process that held it.

    What differs on a failing path is only whose error is reported: the body's,
    always. A teardown that then fails travels with it as a note instead of
    replacing it or vanishing.

    One open failure is recoverable rather than fatal, but only one shape of
    it, and only for a ``rescue`` lease. IDA 9.4 sometimes packs a database it
    then refuses to load (``rc 4``, ``Database is empty``, while
    ``probe_database_state`` still calls the file ``packed``), so every save
    :func:`_session` makes leaves the previous bytes in a spare copy. When an
    open fails *with that signature* on a database nobody owns and that copy
    is there, it is put back and the open is tried once more. Whether or not
    that second open works, the caller is told: a rolled-back database is
    missing whatever the last save changed, and answering from it as if
    nothing had happened would contradict the durability the operation before
    this one was given.

    When there is no spare at all — the staging save that first produced the
    database is the one write with no earlier generation to keep — the bytes
    are unrecoverable and the managed database is discarded instead, so the
    next ``ensure_managed_idb`` builds it again from the source rather than
    meeting the same dead file forever. The caller is told that too.

    Every other ``WorkerStartError`` travels untouched. A readiness timeout, a
    worker that opened the wrong IDB, a launcher that died of a licence or a
    missing library — none of them says the file is bad, and rolling back on
    one would destroy a readable database, report a cause that is not true,
    and (for the timeout, whose worker is often still starting) unlink the
    ``.id0`` that worker is in the middle of creating.

    Dropping the spare is gated the same way for the same reason. Nexus
    returns an already-live instance before it touches the filesystem, so a
    lease that attached to a GUI session's or a sibling's worker never read
    the packed file and proves nothing about it; only ``ours`` means "this
    lease spawned the worker, so idalib loaded these bytes".
    """
    prior = _prior_owner(target, options.output_database)
    recovered = False
    try:
        handle = DatabaseHandle.open(str(target), options=options)
    except WorkerStartError as damaged:
        if not rescue or not _refused_these_bytes(damaged, target):
            raise
        handle = _recover_unreadable(target, options, damaged)
        recovered = True
    instance = handle.instance
    # Not "nobody owned it before": the instance this lease actually got. A
    # stale owner seen a moment ago must not disown a worker we then spawned.
    ours = (
        instance.managed
        and prior is not _AMBIGUOUS
        and prior != instance.record_id
    )
    if rescue and ours and not recovered:
        # Our own worker loaded these bytes, so the copy taken before they
        # were written has nothing left to rescue. An attached instance read
        # nothing: its answer is valid even when the path does not exist.
        _drop_pre_save(target)
    failure: BaseException | None = None
    try:
        if recovered:
            # Raised inside the lease so the restored database is released the
            # same way any other lease releases one.
            raise ManagedDatabaseError(
                f"IDA could not open {target}: the save before this one left a"
                " database it cannot read. The copy taken before that save has"
                " been put back and opens, so this workspace works again, but"
                " whatever that save changed is gone from it."
            )
        yield handle
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            try:
                if ours:
                    handle.shutdown_database(save=False)
            finally:
                handle.close(wait_for_database=True)
            if ours:
                _await_released(instance)
        except Exception as teardown:
            if failure is None:
                raise
            failure.add_note(f"while ending the lease on {target}: {teardown!r}")


def _prior_owner(target: Path, output_database: str | Path | None) -> object:
    """The record id of a live instance already owning ``target``, if any."""
    try:
        owner = ida_nexus.find_database_owner(
            str(target), output_database=output_database
        )
    except NexusError:
        # Several live candidates: this lease cannot claim what it will get.
        return _AMBIGUOUS
    return owner.record_id if owner is not None else None


def _refused_these_bytes(damaged: WorkerStartError, target: Path) -> bool:
    """Whether this start failure is idalib refusing to load ``target`` itself.

    ``WorkerStartError`` is Nexus's single "the worker never became ready", and
    two of the three conditions behind it say nothing at all about the file: a
    readiness timeout, and a worker that opened some other IDB. The third, a
    launcher exiting non-zero, covers everything from a licence failure to an
    OOM kill; only the worker log tail it carries distinguishes them, and only
    a line naming *this* database as one idalib refused means the bytes are
    the problem.

    The path is compared against the resolved target because that is what the
    worker opened (``args.input.expanduser().resolve(strict=True)``). Anything
    that does not match exactly is not recognised, and an unrecognised failure
    never overwrites a file.
    """
    first, _, tail = str(damaged).partition("\n")
    if not (first.startswith(_LAUNCHER_EXIT) and _EXITED_WITH in first):
        return False
    named = {str(target), os.path.realpath(target)}
    for line in tail.splitlines():
        for head, end in _REFUSALS:
            if head not in line:
                continue
            said = line.partition(head)[2].strip()
            if end:
                if not said.endswith(end):
                    continue
                said = said[: -len(end)].strip()
            if said in named:
                return True
    return False


def _recover_unreadable(
    target: Path,
    options: DatabaseOpenOptions,
    damaged: WorkerStartError,
) -> DatabaseHandle:
    """Put the copy taken before the last save back, and open that instead.

    Only for a database no live instance owns and no unregistered session
    holds: overwriting or deleting a file another session has open would
    destroy that session's work.

    ``probe_database_state`` reports ``in_use`` only when it took and read the
    advisory ``.id0`` lock. It reports ``unknown`` with ``error`` set when the
    database is on a network filesystem where locks are not reliable, when the
    ``.id0`` header cannot be inspected, and when that header is truncated or
    unsigned — exactly the cases where another live session cannot be excluded.
    Those are refusals too, for the same reason ``_require_released`` refuses
    every unsafe state rather than the one it can name.

    With no spare there is nothing to put back, and that case is real: the
    staging save behind ``ensure_managed_idb`` is the one write this module
    makes with no rescue copy, because it writes a private file that has no
    earlier generation to keep. A database the vendor defect damaged *there*
    passes ``_publish``'s gate — ``probe_database_state`` calls a corrupt file
    ``packed`` — and then refuses every later open, permanently. Nothing can
    recover those bytes, so the managed database is discarded instead: the
    caller is told, and the next ``ensure_managed_idb`` analyzes the source
    again rather than meeting the same dead file forever. One discard, no
    retry here; the rebuild belongs to the next call.
    """
    if _prior_owner(target, None) is not None:
        raise damaged
    state = ida_nexus.probe_database_state(target)
    if state["state"] == "in_use" or state["error"] is not None:
        raise damaged
    spare = _pre_save(target)
    if not spare.is_file():
        _discard(target)
        raise ManagedDatabaseError(
            f"IDA could not read back {target}, and the save that produced it"
            " kept no copy to restore: the managed database has been discarded"
            " and has to be built again from its source binary, which the next"
            " scan of that target does"
        ) from damaged
    _discard_unpacked(target)
    os.replace(spare, target)
    try:
        return DatabaseHandle.open(str(target), options=options)
    except WorkerStartError as dead:
        raise ManagedDatabaseError(
            f"IDA could not open {target}, and neither can the copy taken"
            " before its last save; nothing in this workspace is usable and it"
            " has to be built again from its source"
        ) from dead


def _await_released(instance: DatabaseInstance) -> None:
    """Wait for our worker to exit and leave a finished database behind.

    Three separate facts, in this order, and none of them implies the next:
    the instance released its registry lifetime lock; the worker process is
    gone; the database is packed. The process matters because IDA rewrites the
    packed ``.i64`` as it shuts down and deregisters before it exits, so a lease
    that returned on the registry signal alone handed the next open a file the
    previous worker was still writing — which corrupts it beyond repair while
    ``probe_database_state`` still calls it ``packed``.

    A worker that never goes fails loudly rather than hanging. Anything the
    operation saved was confirmed durable by ``_require_saved`` before this
    wait started, and the error says so, because the database on disk is not
    what failed here.
    """
    database = Path(instance.idb_path)
    deadline = time.monotonic() + RELEASE_TIMEOUT
    if not ida_nexus.wait_database_released(instance, timeout=RELEASE_TIMEOUT):
        raise ManagedDatabaseError(
            f"{database} was still held {RELEASE_TIMEOUT:g}s after its lease"
            " closed; anything this operation saved is already on disk"
        )
    while not _worker_exited(instance.pid):
        if time.monotonic() >= deadline:
            raise ManagedDatabaseError(
                f"IDA worker {instance.pid} for {database} was still running"
                f" {RELEASE_TIMEOUT:g}s after its lease closed; anything this"
                " operation saved is already on disk"
            )
        time.sleep(0.02)
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


def _worker_exited(pid: int) -> bool:
    """Whether an IDA worker process is gone.

    A worker spawned by Nexus is a child of this process, so once it exits it
    stays visible as a zombie until :mod:`subprocess` reaps it; that counts as
    gone, because a zombie holds no files open.
    """
    if _PROC.is_dir():
        try:
            stat = (_PROC / str(pid) / "stat").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return True
        return stat.rpartition(") ")[2][:1] == "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


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


# --------------------------------------------------------------------------
# Rule evaluation over extracted evidence
# --------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _prototypes() -> dict[str, str]:
    """The pinned VulFi prototype table shipped with this package."""
    payload = (
        resources.files(__package__)
        .joinpath("data/prototypes.json")
        .read_text("utf-8")
    )
    table = json.loads(payload)
    if not isinstance(table, dict):
        raise ManagedDatabaseError("data/prototypes.json is not a JSON object")
    return table


class _Evaluation(NamedTuple):
    """What the host made of one scan's evidence, before it was stored."""

    scan_id: str
    scanned_at: str
    findings: list[Finding]
    coverage: list[RuleCoverage]
    complete: bool
    tally: dict[str, int]
    warnings: list[str]


def _evaluate(
    raw: dict[str, Any], rules: tuple[Rule, ...], scope: str
) -> _Evaluation:
    """Evaluate every rule over the evidence one scan brought back."""
    scan_id = uuid.uuid4().hex
    records = {
        record["rule_index"]: record
        for record in raw.get("rules", [])
        if isinstance(record, dict)
    }
    mode = raw.get("analysis_mode")
    binary_sha256 = raw.get("input_sha256")
    findings: list[Finding] = []
    coverage: list[RuleCoverage] = []
    tally = {
        "sites": 0,
        "evaluated": 0,
        "unsupported": 0,
        "failed": 0,
        "skipped": 0,
    }
    complete = not raw.get("bounded")

    for index, rule in enumerate(rules):
        record = records.get(index)
        if record is None:
            complete = False
            coverage.append(
                _coverage(index, "failed", "the scan returned no result for this rule")
            )
            continue
        rows, state, reason, site_counts = _rule_outcome(
            rule,
            index,
            record,
            scope=scope,
            digest=canonical_rule_digest(rule),
            mode=mode,
            scan_id=scan_id,
            binary_sha256=binary_sha256,
        )
        findings.extend(rows)
        coverage.append(_coverage(index, state, reason))
        for key, value in site_counts.items():
            tally[key] += value
        if state != "evaluated":
            complete = False

    # Only what the scan itself observed is recorded; the catalog note below
    # is about this response, not about anything this database now holds.
    warnings = [str(warning) for warning in raw.get("warnings") or []]
    return _Evaluation(
        scan_id=scan_id,
        scanned_at=utc_now(),
        findings=findings,
        coverage=coverage,
        complete=complete,
        tally=tally,
        warnings=warnings,
    )


def _store_payload(
    rules: tuple[Rule, ...],
    scope: str,
    evaluation: _Evaluation,
) -> dict[str, object]:
    """The scan, as the record's own operation wants to receive it."""
    return {
        "scope": scope,
        "rules": [dict(rule) for rule in rules],
        "scan_id": evaluation.scan_id,
        "scanned_at": evaluation.scanned_at,
        "coverage": "complete" if evaluation.complete else "partial",
        "rule_coverage": list(evaluation.coverage),
        "warnings": list(evaluation.warnings),
        "findings": list(evaluation.findings),
        "offset": 0,
        "limit": MAX_SCAN_FINDINGS,
    }


def _scan_result(
    raw: dict[str, Any],
    scope: str,
    idb_path: str,
    path: str | None,
    evaluation: _Evaluation,
    stored: dict[str, Any],
) -> ScanResult:
    """Turn one scan's evidence and its committed record into the contract.

    Every count here comes from the store, not from the evaluation: after a
    partial scan the scope also holds the rows this scan did not see, and a
    result that reported only the observed ones would quietly under-report a
    scope it had just widened.
    """
    mode = raw.get("analysis_mode")
    return {
        "path": path or idb_path,
        "idb_path": raw.get("idb_path") or idb_path,
        "binary_sha256": raw.get("input_sha256"),
        "analysis_id": None,
        "preparation_revision": None,
        "backend": BACKEND,
        "scope": scope,
        "scan_id": evaluation.scan_id,
        "scanned_at": evaluation.scanned_at,
        "coverage": "complete" if evaluation.complete else "partial",
        "rule_coverage": evaluation.coverage,
        "findings": _findings(stored),
        "scope_total": int(stored.get("scope_total") or 0),
        "target_total": int(stored.get("target_total") or 0),
        # Plan 3's catalog is the other store; an absent store is unavailable,
        # never zero, so this total is explicitly incomplete.
        "target_total_complete": False,
        "status_counts": _status_counts(stored),
        "scope_health": {
            BACKEND: {
                "analysis_mode": mode,
                "decompiler_available": raw.get("decompiler_available"),
                "decompiler_requested": raw.get("decompiler_requested"),
                "function_count": raw.get("function_count"),
                "code_function_count": raw.get("code_function_count"),
                "call_sites": evaluation.tally["sites"],
                "evaluated_sites": evaluation.tally["evaluated"],
                "unsupported_sites": evaluation.tally["unsupported"],
                "failed_sites": evaluation.tally["failed"],
                # Wrapper sites the wrapped call ruled out, as upstream
                # does: discovered and returned, deliberately unevaluated.
                "skipped_wrapper_sites": evaluation.tally["skipped"],
                "bounded": bool(raw.get("bounded")),
                "applied_prototypes": raw.get("applied_prototypes") or [],
                "observed_findings": len(evaluation.findings),
                "stale_findings": int(stored.get("scope_stale") or 0),
            }
        },
        "store_health": _store_health(stored),
        "sync_state": SYNC_STATE,
        "warnings": [*evaluation.warnings, _CATALOG_WARNING],
    }


def _findings(stored: dict[str, Any]) -> list[Finding]:
    rows = stored.get("findings")
    if not isinstance(rows, list):
        raise ManagedDatabaseError(
            f"the stored record returned {type(rows).__name__}, expected findings"
        )
    return [row for row in rows if isinstance(row, dict)]


def _status_counts(stored: dict[str, Any]) -> dict[str, dict[str, int]]:
    counts = stored.get("status_counts")
    if not isinstance(counts, dict):
        raise ManagedDatabaseError("the stored record returned no status counts")
    return {
        name: {status: int(table.get(status, 0)) for status in TRIAGE_STATUSES}
        for name, table in counts.items()
        if isinstance(table, dict)
    }


def _store_health(stored: dict[str, Any]) -> dict[str, object]:
    """Which stores answered, and what the one that did has in it."""
    return {
        BACKEND: {
            "available": True,
            "netnode": ida_runtime.NETNODE_NAME,
            "schema_version": stored.get("schema_version"),
            "managed_idb_id": stored.get("managed_idb_id"),
            "record_present": bool(stored.get("record_present")),
            "record_digest": stored.get("record_digest"),
            "record_bytes": stored.get("record_bytes"),
            "stale_total": stored.get("stale_total"),
            "scopes": stored.get("scopes") or [],
        },
        "catalog": {"available": False, "reason": _CATALOG_REASON},
    }


def _unavailable_store_health(reason: str) -> dict[str, object]:
    """Neither store answered, and each says why.

    The IDA entry carries no counts at all. A store that is not there has no
    rows, no digest and no scopes, and publishing zeroes for them is the one
    shape this contract exists to rule out.
    """
    return {
        BACKEND: {
            "available": False,
            "reason": reason,
            "netnode": ida_runtime.NETNODE_NAME,
        },
        "catalog": {"available": False, "reason": _CATALOG_REASON},
    }


def _coverage(
    index: int,
    state: Literal["evaluated", "unsupported", "failed"],
    reason: str | None,
) -> RuleCoverage:
    return {
        "rule_index": index,
        "backend": BACKEND,
        "state": state,
        "reason": reason,
    }


def _rule_outcome(
    rule: Rule,
    index: int,
    record: dict[str, Any],
    *,
    scope: str,
    digest: str,
    mode: object,
    scan_id: str,
    binary_sha256: str | None,
) -> tuple[
    list[Finding],
    Literal["evaluated", "unsupported", "failed"],
    str | None,
    dict[str, int],
]:
    """Evaluate one rule over the sites the worker found for it."""
    findings: list[Finding] = []
    occurrences: dict[str, int] = {}
    unsupported: list[str] = []
    failed: list[str] = []
    evaluated = 0
    skipped = 0
    skip = 0
    for site in record.get("sites", []):
        if skip:
            skip -= 1
            skipped += 1
            continue
        priority, problem, outcome = _site_priority(rule, site)
        if outcome == "unsupported":
            unsupported.append(problem or "a fact this rule needs is unavailable")
        elif outcome == "failed":
            failed.append(problem or "the expression could not be evaluated")
        else:
            evaluated += 1
        if site.get("gate"):
            # Upstream never reports the wrapped call itself: it only decides
            # whether the wrappers are worth looking at. A site we could not
            # evaluate keeps them in scope rather than dropping them.
            if outcome == "evaluated" and priority is None:
                skip = int(site.get("wrapped_count") or 0)
            continue
        if priority is None:
            continue
        address = site["address"]
        occurrence = occurrences.get(address, 0)
        occurrences[address] = occurrence + 1
        findings.append(
            _finding(
                rule,
                index,
                site,
                priority=priority,
                occurrence=occurrence,
                scope=scope,
                digest=digest,
                mode=mode,
                scan_id=scan_id,
                binary_sha256=binary_sha256,
                kind=record.get("kind"),
            )
        )

    considered = evaluated + len(unsupported) + len(failed)
    problems: list[str] = []
    if failed:
        problems.append(f"{len(failed)} of {considered} call sites failed: {failed[0]}")
    if unsupported:
        problems.append(
            f"{len(unsupported)} of {considered} call sites lack the facts this"
            f" rule needs: {unsupported[0]}"
        )
    problems.extend(str(note) for note in record.get("notes") or [])
    if failed:
        state: Literal["evaluated", "unsupported", "failed"] = "failed"
    elif problems or record.get("truncated"):
        state = "unsupported"
    else:
        state = "evaluated"
    reason = "; ".join(problems) if problems else None
    if state != "evaluated" and reason is None:
        reason = "the scan was bounded before it saw every call site"
    counts = {
        "sites": considered,
        "evaluated": evaluated,
        "unsupported": len(unsupported),
        "failed": len(failed),
        "skipped": skipped,
    }
    return findings, state, reason, counts


def _site_priority(
    rule: Rule, site: dict[str, Any]
) -> tuple[str | None, str | None, str]:
    """This site's priority, or why it could not be decided."""
    params = site.get("params")
    if params is None:
        return None, site.get("params_reason"), "unsupported"
    if not params:
        # A verified empty argument list, which is upstream's `Info`.
        return "Info", None, "evaluated"
    context = RuleContext(
        params=tuple(_param(fact) for fact in params),
        call=_function_call(site.get("call") or {}),
    )
    try:
        return evaluate_rule(rule, context), None, "evaluated"
    except UnavailableEvidenceError as error:
        return None, str(error), "unsupported"
    except ExpressionError as error:
        return None, str(error), "failed"


def _param(fact: dict[str, Any]) -> Param:
    return Param(**_established(fact, _PARAM_FACTS))


def _function_call(fact: dict[str, Any]) -> FunctionCall:
    return FunctionCall(**_established(fact, _CALL_FACTS))


def _established(fact: dict[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    """Keep only the facts the backend supplied; the rest stay UNAVAILABLE."""
    return {
        key: tuple(value) if key in _SEQUENCE_FACTS else value
        for key, value in fact.items()
        if key in allowed
    }


def _finding(
    rule: Rule,
    index: int,
    site: dict[str, Any],
    *,
    priority: str,
    occurrence: int,
    scope: str,
    digest: str,
    mode: object,
    scan_id: str,
    binary_sha256: str | None,
    kind: object,
) -> Finding:
    address = site["address"]
    branch = priority if priority in ida_runtime.PRIORITIES else None
    return {
        "id": (
            f"{BACKEND}:{scope}:{index}:{digest}"
            f":{ADDRESS_SPACE}:{address}:{occurrence}"
        ),
        "backend": BACKEND,
        "source": scope,
        "binary_sha256": binary_sha256,
        "rule_index": index,
        "rule_digest": digest,
        "rule_name": rule["name"],
        "function_name": site["function_name"],
        "found_in": site["found_in"],
        "address_space": ADDRESS_SPACE,
        "address": address,
        "relative_address": site.get("relative_address"),
        "occurrence": occurrence,
        "priority": priority,
        "status": "Not Checked",
        "rationale": "",
        "assessed_at": None,
        "triage_revision": 0,
        "link_id": None,
        "link_revision": None,
        "last_seen_scan_id": scan_id,
        "stale": False,
        "evidence": {
            "matched_branch": branch,
            "expression": rule["mark_if"][branch] if branch else None,
            "analysis_mode": mode,
            "rule_kind": kind,
            "matched_name": site.get("matched_name"),
            "display_name": site.get("display_name"),
            "wrapper_of": site.get("wrapper_of"),
            "argument_count": site.get("argument_count"),
            "expected_argument_count": site.get("expected_argument_count"),
            "params": site.get("params"),
            "call": site.get("call"),
        },
    }
