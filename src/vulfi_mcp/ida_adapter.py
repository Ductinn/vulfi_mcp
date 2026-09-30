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
    "ManagedDatabaseError",
    "data_dir",
    "ensure_managed_idb",
    "findings_ida",
    "invoke_ida",
    "scan_ida",
    "triage_ida",
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
    worker calls, but both run under one lease and the record's whole
    read/modify/write happens inside the second of them.

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
    return _scan_result(raw, scope, idb_path, path, evaluation, stored)


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


def triage_ida(
    idb_path: str,
    finding_id: str,
    status: str,
    rationale: str,
    *,
    path: str | None = None,
) -> TriageResult:
    """Assess one stored finding, by its exact ID.

    The status, the rationale and the ID's shape are checked here, before a
    database is opened; the ID itself can only be checked against the record,
    and an unknown one is refused there. Either way a refused update writes
    nothing: the record keeps its bytes and ``triage_revision`` its value.
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
        "status_counts": _status_counts(stored),
        "store_health": _store_health(stored),
        "sync_state": SYNC_STATE,
        "warnings": [_CATALOG_WARNING],
    }


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


class _Worker:
    """One open managed database, and the operations run against it.

    A scan evaluates its rules on the host, between two worker operations, so
    it needs both of them to see the same open database: a second lease would
    reopen the IDB, and could find it owned by somebody else by then. Holding
    one lease keeps the evidence and the record it is stored in consistent.
    """

    def __init__(self, handle: DatabaseHandle, database: Path) -> None:
        self._handle = handle
        self._database = database

    def run(self, operation: str, payload: dict[str, object]) -> dict[str, object]:
        """Run one operation, and save the database when it reports a mutation."""
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
            # A netnode write that is not saved is not durable, and IDA offers
            # no transaction: a failed save is reported, never swallowed.
            _require_saved(self._handle.save_database(), self._database)
        return normalized


@contextmanager
def _session(idb_path: str) -> Iterator[_Worker]:
    """Open one managed IDB under one lease, for one or more operations."""
    database = Path(idb_path).expanduser()
    if database.suffix.lower() not in IDB_SUFFIXES:
        # Opening a binary here would analyze it in place, next to a file this
        # server must never write to.
        raise ValueError(f"this operation needs an IDA database, got {database}")
    if not database.is_file():
        raise FileNotFoundError(f"no such IDA database: {database}")
    options = DatabaseOpenOptions(worker_cwd=str(database.parent))
    with _lease(database, options) as handle:
        yield _Worker(handle, database)


@contextmanager
def _lease(target: Path, options: DatabaseOpenOptions) -> Iterator[DatabaseHandle]:
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

    A failure while closing is only reported when the work itself succeeded, so
    it can never mask the real error.
    """
    prior = _prior_owner(target, options.output_database)
    handle = DatabaseHandle.open(str(target), options=options)
    instance = handle.instance
    # Not "nobody owned it before": the instance this lease actually got. A
    # stale owner seen a moment ago must not disown a worker we then spawned.
    ours = (
        instance.managed
        and prior is not _AMBIGUOUS
        and prior != instance.record_id
    )
    failed = False
    try:
        yield handle
    except BaseException:
        failed = True
        raise
    finally:
        try:
            if not failed and ours:
                handle.shutdown_database(save=False)
            handle.close(wait_for_database=True)
            if not failed and ours:
                _await_released(instance)
        except Exception:
            if not failed:
                raise


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
