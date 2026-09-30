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
from datetime import UTC, datetime
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal

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
from vulfi_mcp.contracts import Backend, Finding, RuleCoverage, ScanResult
from vulfi_mcp.ida_runtime import (
    ExpressionError,
    FunctionCall,
    Param,
    RuleContext,
    UnavailableEvidenceError,
    evaluate_rule,
)
from vulfi_mcp.rules import canonical_rule_digest

if TYPE_CHECKING:  # pragma: no cover - annotations only.
    from vulfi_mcp.rules import Rule

__all__ = [
    "DATA_DIR_ENV",
    "ManagedDatabaseError",
    "data_dir",
    "ensure_managed_idb",
    "invoke_ida",
    "scan_ida",
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

#: The backend tag every row this adapter produces carries.
BACKEND: Final[Backend] = "ida"

#: Address space of a finding in a single-image database.
ADDRESS_SPACE: Final = "image"

#: Findings one scan result carries back; ``scope_total`` counts them all.
MAX_SCAN_FINDINGS: Final = 100

#: Triage states a scope reports counts for, in the order they are shown.
TRIAGE_STATUSES: Final = (
    "Not Checked",
    "False Positive",
    "Suspicious",
    "Vulnerable",
)

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


def scan_ida(
    idb_path: str,
    rules: tuple[Rule, ...],
    scope: str,
    *,
    path: str | None = None,
    decompiler: str = "auto",
    limits: dict[str, int] | None = None,
) -> ScanResult:
    """Evaluate ``rules`` over every call site one managed IDB can show.

    The worker extracts JSON-native evidence; every ``mark_if`` branch is
    evaluated here, by the same restricted interpreter the rule template
    describes, so rule evaluation never runs inside IDA. A rule whose facts
    IDA could not establish is reported ``unsupported`` and a rule whose
    expression failed is reported ``failed``; neither becomes a clean
    negative, and ``Info`` is reserved for a call site whose argument list IDA
    verified as empty.

    ``decompiler="disabled"`` runs the same disassembly-only extraction IDA
    falls back to when Hex-Rays is absent. ``limits`` may only tighten
    :data:`vulfi_mcp.ida_runtime.SCAN_LIMITS`.

    The scan is the one read path that may write: it applies a pinned VulFi
    prototype with ``SetType`` to a rule-named function IDA has no type for,
    in the managed database only, and reports each application under
    ``scope_health["ida"]["applied_prototypes"]``.
    """
    if not rules:
        raise ValueError("scan_ida needs at least one rule")
    if not isinstance(scope, str) or not scope:
        raise ValueError("scope must be a non-empty string")
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
    return _scan_result(
        invoke_ida(idb_path, "scan", payload), rules, scope, idb_path, path
    )


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
    """Hold exactly one Nexus lease, release it, and see our own worker go.

    An IDB is unpacked while a worker holds it, and the worker keeps the packed
    file open until it exits, so a caller that returns earlier would hand out a
    path whose bytes are still moving. ``close(wait_for_database=True)`` is
    asked for that wait but only performs it when its ``/release_lease`` call
    reported ``shutdown_pending``, and that call is a two-second best effort
    that reports ``False`` on any timeout or transport error. The observed
    release is therefore the authority, not the close.

    That wait is only ours to make when this lease spawned the worker. Nexus
    attaches to any live instance that already owns the target instead of
    spawning one, and such an instance's lifetime lock belongs to whoever owns
    it — a GUI session or a sibling lease. Waiting on that lock would stall
    until somebody else's session ends and then fail an operation that already
    completed, and possibly already saved, which is why a database somebody
    else already owns is left on Nexus's own semantics.

    A failure while closing is only reported when the work itself succeeded, so
    it can never mask the real error.
    """
    alone = _opens_alone(target, options.output_database)
    handle = DatabaseHandle.open(str(target), options=options)
    instance = handle.instance
    ours = alone and instance.managed
    failed = False
    try:
        yield handle
    except BaseException:
        failed = True
        raise
    finally:
        try:
            handle.close(wait_for_database=True)
            if not failed and ours:
                _await_released(instance)
        except Exception:
            if not failed:
                raise


def _opens_alone(target: Path, output_database: str | Path | None) -> bool:
    """Whether opening ``target`` spawns a worker instead of attaching to one."""
    try:
        owner = ida_nexus.find_database_owner(
            str(target), output_database=output_database
        )
    except NexusError:
        # Several live candidates: somebody else is running, so this lease is
        # not the one that will own the worker either way.
        return False
    return owner is None


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


def _scan_result(
    raw: dict[str, Any],
    rules: tuple[Rule, ...],
    scope: str,
    idb_path: str,
    path: str | None,
) -> ScanResult:
    """Turn one worker result plus the rules into the public scan contract."""
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
    tally = {"sites": 0, "evaluated": 0, "unsupported": 0, "failed": 0}
    complete = not raw.get("bounded")

    for index, rule in enumerate(rules):
        record = records.get(index)
        if record is None:
            complete = False
            coverage.append(
                _coverage(index, "failed", "the scan returned no result for this rule")
            )
            continue
        rows, state, reason, counts = _rule_outcome(
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
        for key, value in counts.items():
            tally[key] += value
        if state != "evaluated":
            complete = False

    counts = dict.fromkeys(TRIAGE_STATUSES, 0)
    for finding in findings:
        counts[finding["status"]] += 1
    warnings = [str(warning) for warning in raw.get("warnings") or []]
    warnings.append(_CATALOG_WARNING)
    return {
        "path": path or idb_path,
        "idb_path": raw.get("idb_path") or idb_path,
        "binary_sha256": binary_sha256,
        "analysis_id": None,
        "preparation_revision": None,
        "backend": BACKEND,
        "scope": scope,
        "scan_id": scan_id,
        "scanned_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "coverage": "complete" if complete else "partial",
        "rule_coverage": coverage,
        "findings": findings[:MAX_SCAN_FINDINGS],
        "scope_total": len(findings),
        "target_total": len(findings),
        # Plan 3's catalog is the other store; an absent store is unavailable,
        # never zero, so this total is explicitly incomplete.
        "target_total_complete": False,
        "status_counts": {BACKEND: counts, "aggregate": dict(counts)},
        "scope_health": {
            BACKEND: {
                "analysis_mode": mode,
                "decompiler_available": raw.get("decompiler_available"),
                "decompiler_requested": raw.get("decompiler_requested"),
                "function_count": raw.get("function_count"),
                "code_function_count": raw.get("code_function_count"),
                "call_sites": tally["sites"],
                "evaluated_sites": tally["evaluated"],
                "unsupported_sites": tally["unsupported"],
                "failed_sites": tally["failed"],
                "bounded": bool(raw.get("bounded")),
                "applied_prototypes": raw.get("applied_prototypes") or [],
            }
        },
        "warnings": warnings,
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
    skip = 0
    for site in record.get("sites", []):
        if skip:
            skip -= 1
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
