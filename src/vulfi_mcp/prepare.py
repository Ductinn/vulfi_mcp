"""Preparation passes over a managed IDA analysis, and the revisions they make.

Before a scan can say anything trustworthy about a target, the analysis it
reads has to contain the functions, the strings, the object layouts and the
pointer tables that are really there. This module is the host side of that
work: it checks a request, hands it to the one worker operation that does
it, records what came back, and answers the two public tools that expose it.

Three things are deliberately *not* here.

**No second IDA path.** Every byte this module causes to be written reaches
disk through :func:`vulfi_mcp.ida_adapter.invoke_ida`, which is the one lease
that keeps a rescue copy of the bytes a save replaces and reports a failed
save as a failure. There is no save route in this file.

**No duplicated vocabulary.** The pass names, the ceilings and the rules for
tightening them live in :mod:`vulfi_mcp.ida_runtime`, next to the code that
spends them, and are validated here by calling that module's validators and
re-raising what they say. A caller gets the refusal before a database is
opened, and gets exactly one wording for it.

**No analysis this module invented.** Everything in a result is the worker's
own report of what it read out of the database, or the catalog's own report
of what it stored: candidates carry the bytes or the instructions they were
recovered from, and a pass that was cut short names the addresses it never
reached.

Four rules shape the orchestration on top of that.

**Only two entry points may create a managed database.** ``vulfi_scan`` and
``vulfi_prepare``. :func:`preparation_page` is a read: it resolves the
managed database with
:func:`vulfi_mcp.ida_adapter.existing_managed_idb` and reports an
*unavailable* store when there is not one, because creating a database to
page candidates out of would turn a read into minutes of analysis and would
answer "nothing was found" where the truth is "nothing has prepared this".

**A revision is reused only when all four of its premises still hold.**
Source identity, managed artifact, backend capability fingerprint and the
requested pass coverage. Anything less re-runs preparation; a weaker result
is never substituted for the one that was asked for.

**The database carries a summary, the catalog carries the evidence.** The
managed record holds the analysis id, the artifact revision, one coverage
word per pass and the catalog key — bounded, and nothing else. It is written
after the run that earned it has been saved, through the same lease that
saves, so a revision the caller was told about is one the database really
holds.

**An unavailable backend is said out loud.** ``ghidra`` and ``r2`` are named
in the design and implemented in Plan 3. Here they are refused by name. No
fallback to IDA is reported, because no fallback happens.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Final

from vulfi_mcp.catalog import (
    CATALOG_UNAVAILABLE_REASON,
    Catalog,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.contracts import Candidate, PreparationPage, PreparationResult
from vulfi_mcp.ida_adapter import (
    BACKEND,
    IDB_SUFFIXES,
    ensure_managed_idb,
    existing_managed_idb,
    invoke_ida,
)
from vulfi_mcp.ida_runtime import (
    MAX_PREPARE_WARNINGS,
    PREPARE_LIMITS,
    PREPARE_PASSES,
    OperationError,
    validate_analysis_id,
    validate_page,
    validate_prepare_limits,
    validate_prepare_passes,
)

__all__ = [
    "BACKENDS",
    "CATALOG_UNAVAILABLE_REASON",
    "IMPLEMENTED_BACKENDS",
    "LIMITS",
    "NOTHING_PREPARED_REASON",
    "NO_MANAGED_DATABASE_REASON",
    "PASSES",
    "PreparationError",
    "ensure_prepared",
    "prepare_target",
    "preparation_page",
    "resolve_backend",
    "run_ida_passes",
]

#: The passes this build runs, in the order dependencies require. ``strings``
#: recovers raw mapped bytes on its own, but the buffers that exist only in
#: instructions need ``functions`` to have run first, and a request that
#: leaves ``functions`` out is told which stage that cost it. ``structures``
#: and ``pointer_tables`` read the analysis as they find it, and run last
#: because a function the first pass recovers is one whose operands and
#: whose entry they can then see.
PASSES: Final[tuple[str, ...]] = PREPARE_PASSES

#: The ceilings one run may spend. A request may lower any of these and
#: cannot raise one.
LIMITS: Final[dict[str, int]] = dict(PREPARE_LIMITS)

#: Every backend selector the design names.
BACKENDS: Final[tuple[str, ...]] = ("auto", "ida", "ghidra", "r2")

#: The ones this build can honour. ``auto`` resolves to IDA because IDA is
#: the only backend here; Plan 3 is what gives ``auto`` something to choose
#: between.
IMPLEMENTED_BACKENDS: Final[tuple[str, ...]] = ("auto", "ida")

#: The worker operations this module sends.
_RUN: Final = "prepare"
_SUMMARY: Final = "preparation_summary"
_RECORD: Final = "record_preparation"

#: Candidates one result carries inline. The count is always exact and
#: ``vulfi_preparation`` pages the rest; a run may produce two thousand
#: candidates and no MCP result should carry two thousand evidence blobs.
INLINE_CANDIDATES: Final = 100

#: Applied candidate ids one result carries inline, for the same reason.
INLINE_APPLIED: Final = 100

#: Exactly the fields :class:`vulfi_mcp.contracts.Candidate` publishes, in
#: the order it declares them.
_CANDIDATE_FIELDS: Final[tuple[str, ...]] = (
    "candidate_id",
    "kind",
    "backend",
    "address_space",
    "address",
    "evidence",
    "confidence",
    "state",
    "reason",
)

#: Why a read reports no store when the target has no managed database.
#: Deliberately not phrased as "no candidates": nothing has been prepared,
#: which a caller must not render as a prepared target that found nothing.
NO_MANAGED_DATABASE_REASON: Final = (
    "this target has no managed IDA database yet, and only vulfi_scan and"
    " vulfi_prepare create one: there is no prepared analysis to page, which"
    " is not the same as a preparation that recovered nothing"
)

#: Why a read reports no store when the database and the catalog are both
#: there and no preparation of this target is recorded in either.
NOTHING_PREPARED_REASON: Final = (
    "this target has a managed IDA database but no preparation has been"
    " recorded for it: call vulfi_prepare, or vulfi_scan, which prepares"
    " before it scans. No candidate store answered, which is not the same as"
    " a preparation that recovered nothing"
)


class PreparationError(ValueError):
    """A preparation request was refused before any database was opened."""


# --------------------------------------------------------------------------
# One run against one managed database
# --------------------------------------------------------------------------


def run_ida_passes(
    idb_path: str,
    passes: tuple[str, ...] = PASSES,
    limits: dict[str, int] | None = None,
) -> dict[str, object]:
    """Run ``passes`` over one managed IDB and return what they recovered.

    ``idb_path`` must already be a managed database —
    :func:`vulfi_mcp.ida_adapter.ensure_managed_idb` produces one, and the
    operator's own binary or supplied IDB is never opened here. ``passes`` is
    reordered into dependency order and de-duplicated; a name this build does
    not run is refused rather than quietly replaced with one that it does.
    ``limits`` may only tighten :data:`LIMITS`.

    The returned dictionary is the worker's, with these keys:

    ``passes``
        One :class:`vulfi_mcp.contracts.PassResult` per pass that ran, each
        carrying its per-range coverage. A range the run stopped inside names
        what is left of it in ``unvisited``; a range it never started names
        all of itself. ``coverage`` is ``complete`` only when every range is.
    ``candidates``
        Every :class:`vulfi_mcp.contracts.Candidate` the run produced, with
        the bytes or the instructions it rests on. ``state`` is ``applied``
        only for the ones the managed database now carries.
    ``applied_ids``, ``artifact_revision``
        What changed, and the revision of the managed artifact that now
        describes it. The revision moves only when something was applied, in
        the same write that carries the change.
    ``skipped_prerequisites``
        One entry per stage that did not run because the pass it depends on
        was not requested. A subset never reports a coverage it did not
        produce.
    ``warnings``, ``bounded``
        Everything the run wants said out loud, and whether any budget ran
        out at all.
    ``capabilities``, ``capability_fingerprint``, ``preparation``
        What this backend could do for this database, the digest of it that
        decides whether a later request may reuse this revision, and the
        bounded summary the managed record carries.
    ``idb_path``, ``requested_idb_path``, ``input_file``, ``input_sha256``,
    ``image_base``, ``processor``, ``managed_idb_id``
        Which database answered and what it was built from. ``idb_path`` is
        the one IDA reports it has open and ``requested_idb_path`` is the one
        this call named, so a mismatch is visible rather than papered over.

    Raises :class:`PreparationError` for a request that is wrong on its face,
    before anything is opened, and lets
    :class:`vulfi_mcp.ida_adapter.ManagedDatabaseError`,
    :class:`FileNotFoundError` and :class:`ValueError` from the lease through
    unchanged: a database that cannot be opened or saved is not a
    preparation that found nothing.
    """
    payload = _request(passes, limits)
    result = invoke_ida(idb_path, _RUN, payload)
    return _checked(result, idb_path)


def _request(
    passes: tuple[str, ...], limits: dict[str, int] | None
) -> dict[str, object]:
    """One validated payload, or exactly what is wrong with the request."""
    try:
        chosen = validate_prepare_passes(passes)
        bounds = validate_prepare_limits({} if limits is None else limits)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused
    return {"passes": list(chosen), "limits": bounds}


def _checked(result: dict[str, object], idb_path: str) -> dict[str, object]:
    """The worker's report, with the database it describes named in it.

    The worker reports the path IDA has open, which is the same file; this
    adds the path the caller asked about so a result can be matched to a
    request without comparing two spellings of one database.
    """
    reported = result.get("backend")
    if reported != BACKEND:
        raise PreparationError(
            f"the IDA worker reported backend {reported!r}, not {BACKEND!r}"
        )
    for key in ("passes", "candidates"):
        if not isinstance(result.get(key), list):
            raise PreparationError(
                f"the IDA worker returned no {key} list: {result.get(key)!r}"
            )
    result["requested_idb_path"] = idb_path
    return result


# --------------------------------------------------------------------------
# The public operations
# --------------------------------------------------------------------------


def prepare_target(
    path: str, backend: str = "auto", passes: list[str] | None = None
) -> PreparationResult:
    """Prepare ``path`` for scanning, or reuse the revision that already did.

    ``passes=None`` runs all four in dependency order; a nonempty subset runs
    only those and reports the stages their missing prerequisites cost. An
    empty list, a pass this build does not run and a backend it does not have
    are all refused here, before a managed database or a catalog file can
    exist because of them.

    A recorded revision is reused — nothing runs, nothing is applied and the
    artifact revision does not move — only when the target's source identity,
    the managed artifact, the backend capability fingerprint and the recorded
    pass coverage all still match this request. The result says so in
    ``reused``.
    """
    resolved = resolve_backend(backend)
    requested_backend = str(backend)
    requested = _requested_passes(passes)
    reused = _reuse(path, requested_backend, resolved, requested)
    if reused is not None:
        return reused
    # Only now may a database exist: no malformed request above this line can
    # be the reason one was created.
    idb_path = ensure_managed_idb(path)
    result = run_ida_passes(idb_path, requested)
    return _record(path, idb_path, requested_backend, resolved, requested, result)


def preparation_page(
    path: str,
    analysis_id: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> PreparationPage:
    """One window of a recorded preparation, without re-running anything.

    ``0 <= offset`` and ``1 <= limit <= 200``, enforced before the workspace
    is consulted. Nothing here analyzes, creates or writes: a target with no
    managed database, a missing catalog and a database nothing has prepared
    are each reported as an unavailable store with the reason, never as an
    empty page.
    """
    offset, limit = validate_page(offset, limit)
    wanted = None if analysis_id is None else _analysis_argument(analysis_id)
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        return _unavailable(path, None, None, NO_MANAGED_DATABASE_REASON, offset, limit)
    summary = _summary(idb_path)
    stored = summary["preparation"]
    revision = _revision(stored)
    managed_idb_id = _text(summary.get("managed_idb_id"))
    if managed_idb_id is None and Path(path).suffix.lower() in IDB_SUFFIXES:
        # A database target is keyed on the identity its managed record
        # mints, and this record has never been written: there is nothing to
        # look the target up by, which is "nothing has prepared this", not an
        # error about an argument the caller never supplied.
        return _unavailable(
            path, idb_path, revision, NOTHING_PREPARED_REASON, offset, limit
        )
    catalog = get_catalog(path, managed_idb_id)
    if catalog is None:
        return _unavailable(
            path, idb_path, revision, CATALOG_UNAVAILABLE_REASON, offset, limit
        )
    with catalog:
        chosen = wanted or _recorded_id(stored) or catalog.latest_analysis()
        if chosen is None:
            return _unavailable(
                path, idb_path, revision, NOTHING_PREPARED_REASON, offset, limit
            )
        # An analysis id this target does not hold raises UnknownAnalysisError:
        # a caller naming a revision that is not there asked a question with
        # no answer, which is not the same as a revision that is empty.
        page = catalog.page_candidates(chosen, offset, limit)
        recorded = catalog.pass_results(chosen)
        return {
            "path": path,
            "idb_path": idb_path,
            "backend": BACKEND,
            "available": True,
            "reason": None,
            "analysis_id": chosen,
            "target_key": catalog.target_key,
            "source_sha256": catalog.source_sha256,
            "managed_idb_id": catalog.managed_idb_id,
            "source_association": catalog.source_association,
            "preparation_revision": revision,
            "offset": page["offset"],
            "limit": page["limit"],
            "total": page["total"],
            "loaded": page["loaded"],
            "candidates": _candidates(page["candidates"]),
            "passes": recorded,
            "warnings": _warnings(_pass_warnings(recorded)),
        }


def ensure_prepared(
    path: str, backend: str = "auto", analysis_id: str | None = None
) -> PreparationResult:
    """The preparation revision a scan will read, preparing one if need be.

    With no ``analysis_id`` this is :func:`prepare_target` over all four
    passes, which reuses a matching revision and otherwise makes one. With an
    ``analysis_id`` it reuses that exact revision or refuses: silently
    preparing a different one under a name the caller supplied would report a
    revision nobody asked for, and silently ignoring the name would scan an
    analysis the caller did not choose.
    """
    resolved = resolve_backend(backend)
    requested_backend = str(backend)
    if analysis_id is None:
        return prepare_target(path, backend=backend, passes=None)
    wanted = _analysis_argument(analysis_id)
    reused = _reuse(path, requested_backend, resolved, _requested_passes(None))
    if reused is not None and reused["analysis_id"] == wanted:
        return reused
    held = "nothing matching this request has been prepared for this target"
    if reused is not None:
        held = f"the reusable revision recorded here is {reused['analysis_id']!r}"
    raise PreparationError(
        f"analysis_id={analysis_id!r} names no reusable preparation revision"
        f" of this target: {held}. A revision is reusable only for the same"
        " source identity, the same managed artifact, the same backend"
        " capability fingerprint and the requested pass coverage. Omit"
        " analysis_id to prepare the target, or call vulfi_prepare first."
        " Nothing was analyzed, nothing was created and nothing was scanned."
    )


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------


def resolve_backend(backend: object) -> str:
    """The backend that will really run, or a refusal naming what will not.

    One wording, used by every tool that takes a ``backend`` selector, so a
    caller never has to learn two ways of being told the same thing.
    """
    if backend in IMPLEMENTED_BACKENDS:
        return BACKEND
    if backend in BACKENDS:
        raise PreparationError(
            f"backend={backend!r} is unavailable in this build: the {backend}"
            " provider arrives with Plan 3, so no pass ran, nothing was"
            " prepared, nothing was scanned and nothing was stored. This is a"
            " missing capability, not an empty result, and nothing fell back"
            f" to IDA — a result produced by IDA is not a {backend} result."
            " Pass 'ida' or 'auto' to use the backend this build does have."
        )
    raise PreparationError(
        f"backend={backend!r} is not a backend this design names; the"
        f" selectors are {', '.join(BACKENDS)}"
    )


def _requested_passes(passes: object) -> tuple[str, ...]:
    try:
        return validate_prepare_passes(passes)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused


def _analysis_argument(analysis_id: object) -> str:
    try:
        return validate_analysis_id(analysis_id)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused


# --------------------------------------------------------------------------
# Reuse
# --------------------------------------------------------------------------


def _summary(idb_path: str) -> dict[str, Any]:
    """The managed record's preparation summary, read without writing."""
    summary = invoke_ida(idb_path, _SUMMARY, {})
    if summary.get("backend") != BACKEND:
        raise PreparationError(
            f"the IDA worker reported backend {summary.get('backend')!r},"
            f" not {BACKEND!r}"
        )
    stored = summary.get("preparation")
    if not isinstance(stored, dict):
        raise PreparationError(
            f"the managed record carries no preparation summary: {stored!r}"
        )
    return summary


def _revision(stored: dict[str, Any]) -> int:
    revision = stored.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        return 0
    return revision


def _recorded_id(stored: dict[str, Any]) -> str | None:
    recorded = stored.get("analysis_id")
    return recorded if isinstance(recorded, str) and recorded else None


def _reuse(
    path: str, requested_backend: str, resolved: str, requested: tuple[str, ...]
) -> PreparationResult | None:
    """The recorded revision this request may reuse, or ``None``.

    Every ``None`` below is a premise that no longer holds, and each one
    means the passes run again. There is deliberately no "close enough": a
    revision made by a different backend, against a different artifact, by an
    IDA with different capabilities, or covering fewer passes than were asked
    for is not this request's answer, and reusing it would report a coverage
    that revision never produced.

    Nothing here creates anything. ``existing_managed_idb`` and
    ``get_catalog`` are both read-only, so a reuse check on a target nothing
    has touched leaves the workspace exactly as it found it.
    """
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        return None
    summary = _summary(idb_path)
    stored = summary["preparation"]
    recorded = _recorded_id(stored)
    if recorded is None:
        return None
    catalog = get_catalog(path, summary.get("managed_idb_id"))
    if catalog is None:
        # The candidates are gone, so the revision cannot be reported even
        # though the artifact still carries the changes. Preparing again
        # restores the store; claiming the revision would not.
        return None
    with catalog:
        if stored.get("catalog_key") != catalog.target_key:
            return None
        analysis = catalog.analysis(recorded)
        if analysis is None:
            return None
        if analysis["requested_backend"] != resolved:
            return None
        if analysis["artifact_path"] != idb_path:
            return None
        if analysis["capability_fingerprint"] != summary.get(
            "capability_fingerprint"
        ):
            return None
        revision = _revision(stored)
        if analysis["revision"] != revision:
            return None
        covered = catalog.pass_results(recorded)
        if not set(requested) <= {str(entry["pass"]) for entry in covered}:
            return None
        return _result(
            path=path,
            idb_path=idb_path,
            requested_backend=requested_backend,
            analysis_id=recorded,
            catalog=catalog,
            fingerprint=str(summary.get("capability_fingerprint")),
            revision=revision,
            requested=requested,
            recorded=covered,
            reused=True,
            skipped=[],
            warnings=[],
        )


# --------------------------------------------------------------------------
# Recording a run
# --------------------------------------------------------------------------


def _record(
    path: str,
    idb_path: str,
    requested_backend: str,
    resolved: str,
    requested: tuple[str, ...],
    result: dict[str, object],
) -> PreparationResult:
    """Store what one run produced, then tell the database about it.

    The order is the contract. The run has already been saved by the lease
    that made it — a failed save raised out of :func:`run_ida_passes` and
    never reached here — so the catalog is written against an artifact that
    really carries the changes. The bounded summary goes into the managed
    record last, through the one lease that saves, so a revision this returns
    is one both stores agree on. A failure at that last step raises rather
    than returning: the catalog then holds passes the record does not name,
    the next request finds no reusable revision, and preparation runs again.
    """
    fingerprint = result.get("capability_fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise PreparationError(
            "the IDA worker reported no capability fingerprint, so this"
            f" revision could never be reused: {fingerprint!r}"
        )
    revision = result.get("artifact_revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PreparationError(
            f"the IDA worker reported artifact_revision={revision!r}, which is"
            " not a revision this run could have produced"
        )
    with open_catalog(path, _text(result.get("managed_idb_id"))) as catalog:
        analysis_id = _mint(catalog.target_key, resolved, idb_path, fingerprint)
        stored = catalog.record_analysis(
            analysis_id,
            requested_backend=resolved,
            artifact_path=idb_path,
            capability_fingerprint=fingerprint,
            revision=revision,
        )
        # From the store, not from the run: what a later reuse check compares
        # against is the stored row, so that is what this reports.
        revision = int(str(stored["revision"]))
        kept = _record_passes(catalog, analysis_id, result)
        recorded = catalog.pass_results(analysis_id)
        coverage = {str(entry["pass"]): str(entry["coverage"]) for entry in recorded}
        catalog_key = catalog.target_key
        report = _result(
            path=path,
            idb_path=idb_path,
            requested_backend=requested_backend,
            analysis_id=analysis_id,
            catalog=catalog,
            fingerprint=fingerprint,
            revision=revision,
            requested=requested,
            recorded=recorded,
            reused=False,
            skipped=_skipped(result),
            warnings=[*_strings(result.get("warnings")), *kept],
        )
    invoke_ida(
        idb_path,
        _RECORD,
        {
            "analysis_id": analysis_id,
            "coverage": coverage,
            "catalog_key": catalog_key,
        },
    )
    return report


def _record_passes(
    catalog: Catalog, analysis_id: str, result: dict[str, object]
) -> list[str]:
    """Store each pass with its own candidates, keeping what it cannot beat.

    One pass at a time, each in its own transaction, because that is the unit
    the catalog replaces: re-running ``strings`` must not retire what
    ``functions`` found.

    A pass that could not read its ranges at all and applied nothing does not
    overwrite a ``complete`` result an earlier run recorded for the same
    revision. A run that is cut short is not evidence that the thing an
    earlier run saw has gone away, and replacing the stronger record with the
    weaker one would lose the only description of it that exists. The skip is
    returned as a warning rather than performed silently.
    """
    candidates = _candidates_by_id(result)
    # The caller recorded the analysis row just now, so these are the passes
    # an *earlier* run of this same revision left behind.
    held = {str(entry["pass"]): entry for entry in catalog.pass_results(analysis_id)}
    kept: list[str] = []
    for entry in _entries(result.get("passes")):
        name = str(entry.get("pass"))
        previous = held.get(name)
        if (
            previous is not None
            and previous["coverage"] == "complete"
            and entry.get("coverage") == "unavailable"
            and not entry.get("applied_ids")
        ):
            kept.append(
                f"this run could not read any range of the {name!r} pass and"
                " applied nothing, so the complete result an earlier run"
                " recorded for this revision is kept rather than replaced"
            )
            continue
        catalog.record_pass(analysis_id, _pass_payload(entry, candidates))
    return kept


def _pass_payload(
    entry: dict[str, Any], candidates: dict[str, dict[str, Any]]
) -> dict[str, object]:
    """One pass result, carrying the candidate rows it names and no others."""
    named = [str(item) for item in _strings(entry.get("candidate_ids"))]
    missing = [item for item in named if item not in candidates]
    if missing:
        raise PreparationError(
            f"the IDA worker's {entry.get('pass')!r} pass named candidates it"
            f" did not return: {', '.join(sorted(missing))}"
        )
    payload = dict(entry)
    payload["candidates"] = [candidates[item] for item in named]
    return payload


def _candidates_by_id(result: dict[str, object]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in _entries(result.get("candidates")):
        identifier = row.get("candidate_id")
        if not isinstance(identifier, str) or not identifier:
            raise PreparationError(f"a recovered candidate carries no id: {row!r}")
        rows[identifier] = row
    return rows


def _mint(target_key: str, backend: str, artifact: str, fingerprint: str) -> str:
    """The id of the revision these four facts describe.

    Derived rather than minted at random, so a second run of the same
    preparation against the same artifact updates one revision instead of
    accumulating a new one per call, and so a changed capability or a changed
    artifact is a *different* revision rather than a quiet overwrite of the
    one that is there.
    """
    digest = hashlib.sha256()
    for part in (target_key, backend, artifact, fingerprint):
        digest.update(part.encode("utf-8", "surrogateescape"))
        digest.update(b"\x00")
    return f"prep-{digest.hexdigest()[:32]}"


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


def _result(
    *,
    path: str,
    idb_path: str,
    requested_backend: str,
    analysis_id: str,
    catalog: Catalog,
    fingerprint: str,
    revision: int,
    requested: tuple[str, ...],
    recorded: list[dict[str, object]],
    reused: bool,
    skipped: list[dict[str, object]],
    warnings: list[str],
) -> PreparationResult:
    """One revision, reported from the catalog that holds it.

    Both branches build the result the same way and from the same place: a
    reused revision and a fresh one are the same object, and a reader cannot
    be shown a field on one that the other could not produce.
    """
    page = catalog.page_candidates(analysis_id, 0, INLINE_CANDIDATES)
    applied = catalog.applied_candidates(analysis_id)
    return {
        "path": path,
        "idb_path": idb_path,
        "backend": BACKEND,
        "requested_backend": requested_backend,
        "analysis_id": analysis_id,
        "target_key": catalog.target_key,
        "source_sha256": catalog.source_sha256,
        "managed_idb_id": catalog.managed_idb_id,
        "source_association": catalog.source_association,
        "capability_fingerprint": fingerprint,
        "preparation_revision": revision,
        "reused": reused,
        "requested_passes": list(requested),
        "passes": recorded,
        "coverage": _coverage(recorded),
        "candidates": _candidates(page["candidates"]),
        "candidate_total": page["total"],
        "applied_ids": applied[:INLINE_APPLIED],
        "applied_total": len(applied),
        "skipped_prerequisites": skipped,
        "artifact_paths": {
            "managed_idb": idb_path,
            "catalog": str(catalog.database_path),
        },
        "catalog_available": True,
        "warnings": _warnings([*warnings, *_pass_warnings(recorded)]),
    }


def _unavailable(
    path: str,
    idb_path: str | None,
    revision: int | None,
    reason: str,
    offset: int,
    limit: int,
) -> PreparationPage:
    """No candidate store answered, and this says which one and why."""
    return {
        "path": path,
        "idb_path": idb_path,
        "backend": BACKEND,
        "available": False,
        "reason": reason,
        "analysis_id": None,
        "target_key": None,
        "source_sha256": None,
        "managed_idb_id": None,
        "source_association": None,
        "preparation_revision": revision,
        "offset": offset,
        "limit": limit,
        "total": 0,
        "loaded": 0,
        "candidates": [],
        "passes": [],
        "warnings": [reason],
    }


def _candidates(rows: object) -> list[Candidate]:
    """The catalog's candidate rows, as the published contract spells them.

    The catalog also stores which pass produced each row. ``kind`` already
    says that — one pass produces one kind of candidate — and the published
    :class:`vulfi_mcp.contracts.Candidate` is what a client validates a
    result against, so what crosses the boundary is exactly those fields and
    not a superset the advertised schema forbids.
    """
    return [
        {field: row[field] for field in _CANDIDATE_FIELDS} for row in _entries(rows)
    ]


def _coverage(recorded: list[dict[str, object]]) -> str:
    """The weakest thing any recorded pass claims about any of its ranges.

    One partial range makes the whole revision partial, which is the ordinary
    outcome on a real image rather than a failure: ``pointer_tables`` reaches
    ranges no relocation covers on almost every binary, and says so.
    """
    states = {str(entry["coverage"]) for entry in recorded}
    if not states or states == {"unavailable"}:
        return "unavailable"
    if states == {"complete"}:
        return "complete"
    return "partial"


def _pass_warnings(recorded: list[dict[str, object]]) -> list[str]:
    return [
        str(warning)
        for entry in recorded
        for warning in _strings(entry.get("warnings"))
    ]


def _warnings(warnings: list[str]) -> list[str]:
    """Each warning once, in the order it was first said, within the bound."""
    seen: list[str] = []
    for warning in warnings:
        if warning not in seen:
            seen.append(warning)
    return seen[:MAX_PREPARE_WARNINGS]


def _skipped(result: dict[str, object]) -> list[dict[str, object]]:
    return _entries(result.get("skipped_prerequisites"))


def _entries(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
