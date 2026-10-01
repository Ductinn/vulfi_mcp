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

Five rules shape the orchestration on top of that.

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

**A shorter run never replaces a longer one.** A pass is recorded unless the
result an earlier run stored for the same revision read every address this
one read and more besides, measured from the ranges rather than from how the
run ended: the cancellation this design produces is an exhausted budget,
which reports *partial* and names what it never reached. The skip is said out
loud as a warning, and the coverage the managed record carries is read back
from the catalog afterwards, so what a later reuse sees is what is stored.

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
import json
import shlex
from pathlib import Path
from typing import Any, Final, TypedDict

from vulfi_mcp.catalog import (
    CATALOG_UNAVAILABLE_REASON,
    Catalog,
    CatalogError,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.contracts import (
    Candidate,
    JsonValue,
    PreparationPage,
    PreparationResult,
)
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
    proposal_payload,
    validate_proposal,
    validate_proposal_request,
)

__all__ = [
    "BACKENDS",
    "CATALOG_UNAVAILABLE_REASON",
    "IMPLEMENTED_BACKENDS",
    "LIMITS",
    "NOTHING_PREPARED_REASON",
    "NO_MANAGED_DATABASE_REASON",
    "PASSES",
    "PROPOSALS_ARE_INERT",
    "WRITABLE_BACKENDS",
    "PreparationError",
    "ProposalResult",
    "ProposalSubmission",
    "check_proposal_against_candidate",
    "ensure_prepared",
    "mint_proposal_id",
    "prepare_target",
    "preparation_page",
    "propose_recovery",
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
_EVIDENCE: Final = "proposal_evidence"

#: Backends whose candidates this build can write a reviewed change back to.
#: Plan 3 adds the external providers; until one of them can write safely, a
#: proposal against its candidate is refused by name rather than applied
#: against the IDA analysis as if that were the same thing.
WRITABLE_BACKENDS: Final[tuple[str, ...]] = (BACKEND,)

#: The candidate kinds each proposed change may be made to. A name can be
#: given to anything preparation found; the other four are changes to one
#: particular kind of thing and are refused against any other.
_PROPOSAL_CANDIDATES: Final[dict[str, tuple[str, ...]]] = {
    "name": ("function", "string", "structure", "pointer_table"),
    "function_boundary": ("function",),
    "string_decode": ("string",),
    "structure_field": ("structure",),
    "pointer_table": ("pointer_table",),
}

#: Said on every proposal result, because it is the one thing a reader of one
#: must not get wrong.
PROPOSALS_ARE_INERT: Final = (
    "a stored proposal changes nothing: no managed database was opened for"
    " writing, no artifact revision moved, and no VulFi MCP tool can approve"
    " one. An operator applies a proposal with 'vulfi-mcp review approve',"
    " which revalidates its evidence against the current revision first"
)

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


class ProposalSubmission(TypedDict):
    """What became of one submitted proposal.

    ``accepted`` is the whole claim, and it is a claim about *storage*:
    ``True`` means this proposal is recorded ``pending`` and is waiting for
    an operator, not that anything has changed. ``False`` means it was not
    stored at all, and ``reason`` says what was wrong with it — an
    unpermitted kind, a value that is not an identifier, evidence the
    candidate does not carry, an address that is not the candidate's, a
    definition already there, or a backend with no safe writer.

    ``effect`` is the one-line description of what approving it would do, as
    the reviewer will be shown it, so the agent that proposed it and the
    operator who decides on it read the same sentence.
    """

    index: int
    accepted: bool
    proposal_id: str | None
    candidate_id: str | None
    kind: str | None
    address_space: str | None
    start: int | None
    end: int | None
    value: dict[str, JsonValue]
    evidence: dict[str, JsonValue]
    rationale: str | None
    state: str | None
    effect: str | None
    expected_revision: int | None
    reason: str | None


class ProposalResult(TypedDict):
    """What one ``vulfi_propose_recovery`` call stored, and what it did not.

    ``applied`` is always ``False``. It is in the result because the one
    thing a reader of a proposal result must not conclude is that something
    happened: this tool writes rows in the catalog and nothing else.
    ``preparation_revision`` is the artifact revision these proposals were
    written against, and is what an operator passes to the review command as
    ``--expected-revision``; an approval made against a revision the artifact
    has since left is refused rather than applied.

    The contracts for this tool live here rather than in
    :mod:`vulfi_mcp.contracts` because the proposal path is this module's,
    and :mod:`vulfi_mcp.server` imports the published type from here exactly
    as it imports the others from there.
    """

    path: str
    idb_path: str
    backend: str
    analysis_id: str
    target_key: str
    source_sha256: str | None
    managed_idb_id: str | None
    preparation_revision: int
    applied: bool
    accepted_total: int
    refused_total: int
    proposals: list[ProposalSubmission]
    review_command: str
    notice: str
    warnings: list[str]


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
# Proposals: stored, never applied
# --------------------------------------------------------------------------


def propose_recovery(
    path: str, analysis_id: str, proposals: list[dict[str, object]]
) -> ProposalResult:
    """Store what an agent proposes for one recorded preparation revision.

    This is the only mutation the proposal path exposes through MCP, and the
    only thing it mutates is the catalog. Nothing here opens a database for
    writing, nothing here moves an artifact revision, and nothing here can
    approve anything: an accepted proposal is stored ``pending`` and takes
    effect only when an operator approves it with ``vulfi-mcp review``, which
    is a different program run with a different principal's credentials.

    Each proposal is answered on its own. A proposal that is refused is
    refused with the reason — an unpermitted kind, a value that is not an
    identifier, no evidence, evidence the named candidate does not carry, an
    address that is not the candidate's, a range already defined, a backend
    this build cannot write back to — and the rest of the request still
    stands. Nothing refused is stored.

    Raises :class:`PreparationError` when the request itself cannot be
    answered: a target nothing has prepared, a catalog that is not there, or
    a revision this target does not hold. None of those creates anything.
    """
    wanted = _analysis_argument(analysis_id)
    requested = _proposal_request(proposals)
    # A read of an existing analysis, so it resolves the managed database and
    # never makes one: only vulfi_scan and vulfi_prepare may do that.
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        raise PreparationError(
            f"nothing can be proposed for {path!r}: {NO_MANAGED_DATABASE_REASON}."
            " Nothing was analyzed, created or stored"
        )
    checked = [_checked_proposal(item) for item in requested]
    accepted = [body for body, _ in checked if body is not None]
    # One lease, read-only: the current state of every proposed range, and
    # the managed record's own summary, from the one operation that reports
    # both. A submission never costs a save.
    observed = invoke_ida(
        idb_path,
        _EVIDENCE,
        {"proposals": [proposal_payload(body) for body in accepted]},
    )
    sites = _sites(observed, accepted)
    revision = _revision(_preparation(observed))
    managed_idb_id = _text(observed.get("managed_idb_id"))
    probe = get_catalog(path, managed_idb_id)
    if probe is None:
        raise PreparationError(
            f"nothing can be proposed for {path!r}: {CATALOG_UNAVAILABLE_REASON}"
        )
    probe.close()
    with open_catalog(path, managed_idb_id) as catalog:
        if catalog.analysis(wanted) is None:
            raise PreparationError(
                f"analysis_id={analysis_id!r} names no preparation revision of"
                " this target, so there are no candidates to propose anything"
                " about. Call vulfi_preparation to see the revision this"
                " target holds. Nothing was stored"
            )
        taken: set[int] = set()
        submissions = [
            _submit(catalog, wanted, index, body, refusal, sites, taken, revision)
            for index, (body, refusal) in enumerate(checked)
        ]
        report: ProposalResult = {
            "path": path,
            "idb_path": idb_path,
            "backend": BACKEND,
            "analysis_id": wanted,
            "target_key": catalog.target_key,
            "source_sha256": catalog.source_sha256,
            "managed_idb_id": catalog.managed_idb_id,
            "preparation_revision": revision,
            "applied": False,
            "accepted_total": sum(1 for row in submissions if row["accepted"]),
            "refused_total": sum(1 for row in submissions if not row["accepted"]),
            "proposals": submissions,
            "review_command": _review_command(path),
            "notice": PROPOSALS_ARE_INERT,
            "warnings": [
                f"proposal {row['index']} was not stored: {row['reason']}"
                for row in submissions
                if not row["accepted"]
            ],
        }
    return report


def check_proposal_against_candidate(
    proposal: dict[str, Any], candidate: dict[str, Any]
) -> None:
    """Refuse a proposal that is not about the candidate it names.

    :func:`vulfi_mcp.ida_runtime.validate_proposal` has already decided the
    proposal is well formed on its own. This is the other half: whether the
    thing it claims to be about exists, was produced by a backend with a safe
    writer, is the kind of thing this change can be made to, sits where the
    proposal says it does, and really records the evidence the proposal
    quotes back at it.
    """
    backend = candidate.get("backend")
    if backend not in WRITABLE_BACKENDS:
        raise PreparationError(
            f"candidate {proposal['candidate_id']!r} was recovered by the"
            f" {backend!r} backend, and this build has no safe way to write a"
            f" change back to a {backend} analysis: that provider arrives with"
            " Plan 3. The proposal is refused rather than applied somewhere"
            " else — nothing was applied, nothing was stored, and no change"
            " was made on that backend's behalf"
        )
    permitted = _PROPOSAL_CANDIDATES[proposal["kind"]]
    if candidate.get("kind") not in permitted:
        raise PreparationError(
            f"a {proposal['kind']!r} proposal is a change to a candidate of"
            f" kind {', '.join(permitted)}, and {proposal['candidate_id']!r}"
            f" is a {candidate.get('kind')!r} candidate"
        )
    if proposal["address_space"] != candidate.get("address_space"):
        raise PreparationError(
            f"this proposal is about address space"
            f" {proposal['address_space']!r} and candidate"
            f" {proposal['candidate_id']!r} is in"
            f" {candidate.get('address_space')!r}"
        )
    if proposal["address"] != candidate.get("address"):
        held = candidate.get("address")
        where = "no provable address" if held is None else f"{held:#x}"
        raise PreparationError(
            f"this proposal is about {proposal['address']:#x} and candidate"
            f" {proposal['candidate_id']!r} is at {where}: a proposal changes"
            " the thing its candidate describes, at the address the candidate"
            " was recovered from"
        )
    evidence = candidate.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    for fact, claimed in proposal["evidence"].items():
        if fact not in evidence:
            raise PreparationError(
                f"this proposal quotes {fact!r} as evidence and candidate"
                f" {proposal['candidate_id']!r} records no such fact; quote"
                " the evidence the candidate really carries"
            )
        if evidence[fact] != claimed:
            raise PreparationError(
                f"this proposal quotes {fact}={claimed!r} and candidate"
                f" {proposal['candidate_id']!r} records"
                f" {fact}={evidence[fact]!r}"
            )


def mint_proposal_id(analysis_id: str, proposal: dict[str, Any]) -> str:
    """The id of the change these facts describe.

    Derived rather than random, so submitting the same proposal twice names
    the one that is already there — with whatever an operator has since
    decided about it — instead of quietly opening a second review of the same
    change.
    """
    digest = hashlib.sha256()
    for part in (
        analysis_id,
        proposal["candidate_id"],
        proposal["kind"],
        str(proposal["address"]),
        json.dumps(proposal["value"], sort_keys=True, separators=(",", ":")),
    ):
        digest.update(part.encode("utf-8", "surrogateescape"))
        digest.update(b"\x00")
    return f"prop-{digest.hexdigest()[:32]}"


def _proposal_request(proposals: object) -> list[object]:
    try:
        return validate_proposal_request(proposals)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused


def _checked_proposal(item: object) -> tuple[dict[str, Any] | None, str | None]:
    """One proposal as validated data, or exactly what is wrong with it."""
    try:
        return validate_proposal(item), None
    except OperationError as refused:
        return None, str(refused)


def _sites(
    observed: dict[str, object], accepted: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The worker's report on each accepted range, in the order it was sent."""
    reviewed = _entries(observed.get("proposals"))
    if len(reviewed) != len(accepted):
        raise PreparationError(
            f"the IDA worker reported on {len(reviewed)} of the"
            f" {len(accepted)} proposed ranges, so there is no way to tell"
            " which answer belongs to which proposal"
        )
    return reviewed


def _preparation(observed: dict[str, object]) -> dict[str, Any]:
    stored = observed.get("preparation")
    if not isinstance(stored, dict):
        raise PreparationError(
            f"the managed record carries no preparation summary: {stored!r}"
        )
    return stored


def _submit(
    catalog: Catalog,
    analysis_id: str,
    index: int,
    body: dict[str, Any] | None,
    refusal: str | None,
    sites: list[dict[str, Any]],
    taken: set[int],
    revision: int,
) -> ProposalSubmission:
    """Store one accepted proposal, or report why this one is not stored."""
    if body is None:
        return _refused(index, {}, str(refusal))
    # Each site report names the range it is about, so a report is matched to
    # its proposal rather than trusted to arrive in the order it was sent.
    position = _position(sites, body, taken)
    taken.add(position)
    site = sites[position]
    try:
        candidate = catalog.candidate(analysis_id, body["candidate_id"])
        if candidate is None:
            raise PreparationError(
                f"no candidate {body['candidate_id']!r} is recorded under"
                f" analysis {analysis_id!r} of this target, so there is"
                " nothing for this proposal to be about"
            )
        check_proposal_against_candidate(body, candidate)
        refusal = _text(site.get("refusal"))
        if refusal is not None:
            raise PreparationError(refusal)
        proposal_id = mint_proposal_id(analysis_id, body)
        held = catalog.proposal(proposal_id)
        if held is not None:
            return _refused(
                index,
                body,
                f"this exact change is already recorded as {proposal_id},"
                f" whose state is {held['state']!r}; a second submission of it"
                " would open a second review of one change",
                proposal_id=proposal_id,
                state=str(held["state"]),
            )
        stored = catalog.record_proposal(
            analysis_id,
            proposal_id=proposal_id,
            candidate_id=body["candidate_id"],
            kind=body["kind"],
            address_space=body["address_space"],
            address=body["address"],
            value=body["value"],
            evidence=body["evidence"],
            rationale=body["rationale"],
        )
    except (PreparationError, CatalogError) as refused:
        return _refused(index, body, str(refused))
    return {
        "index": index,
        "accepted": True,
        "proposal_id": str(stored["proposal_id"]),
        "candidate_id": body["candidate_id"],
        "kind": body["kind"],
        "address_space": body["address_space"],
        "start": body["start"],
        "end": body["end"],
        "value": body["value"],
        "evidence": body["evidence"],
        "rationale": body["rationale"],
        "state": str(stored["state"]),
        "effect": _text(site.get("effect")),
        "expected_revision": revision,
        "reason": None,
    }


def _position(
    sites: list[dict[str, Any]], body: dict[str, Any], taken: set[int]
) -> int:
    """Where this proposal's site report is, by the range it asked about.

    One request may carry two accepted proposals over the same candidate,
    kind and range with different values — two alternative names for one
    address, say, which ``mint_proposal_id`` keeps apart because the value is
    part of the identity. The site report does not carry the value, so the
    range alone cannot tell those two apart; each report is therefore handed
    out once, in the order the ranges were sent, so the second proposal is
    answered with its own report rather than the first one's.
    """
    for index, site in enumerate(sites):
        if index in taken:
            continue
        if (
            site.get("candidate_id") == body["candidate_id"]
            and site.get("kind") == body["kind"]
            and site.get("start") == body["start"]
            and site.get("end") == body["end"]
        ):
            return index
    raise PreparationError(
        f"the IDA worker reported on no range matching candidate"
        f" {body['candidate_id']!r} at {body['start']:#x}"
    )


def _refused(
    index: int,
    body: dict[str, Any],
    reason: str,
    *,
    proposal_id: str | None = None,
    state: str | None = None,
) -> ProposalSubmission:
    """One proposal that was not stored, and exactly why it was not."""
    return {
        "index": index,
        "accepted": False,
        "proposal_id": proposal_id,
        "candidate_id": _text(body.get("candidate_id")),
        "kind": _text(body.get("kind")),
        "address_space": _text(body.get("address_space")),
        "start": body.get("start"),
        "end": body.get("end"),
        "value": body.get("value", {}),
        "evidence": body.get("evidence", {}),
        "rationale": _text(body.get("rationale")),
        "state": state,
        "effect": None,
        "expected_revision": None,
        "reason": reason,
    }


def _review_command(path: str) -> str:
    """The command an operator runs to see what is waiting for them."""
    return f"vulfi-mcp review list --path {shlex.quote(path)}"


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
        # Read back after recording, for the same reason: a pass this run did
        # not beat kept its earlier result, and the summary the managed record
        # carries — the one that decides a later reuse — has to name the
        # coverage the catalog really holds rather than the one this run
        # produced and did not store.
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

    A pass is stored unless the result an earlier run recorded for this same
    revision covered strictly more — read every address this run read, and
    some this run never reached. A run that is cut short is not evidence that
    the thing an earlier run saw has gone away, and replacing the stronger
    record with the weaker one would delete the candidates that are the only
    description of it. The skip is returned as a warning rather than
    performed silently.

    What is compared is what each run really covered, not how it ended. The
    cancellation this design actually produces is an exhausted budget, which
    reports ``partial`` and names the addresses it never reached; a rule
    phrased on a pass that failed outright would never fire on that, which is
    the ordinary case rather than the exotic one.
    """
    candidates = _candidates_by_id(result)
    # The caller recorded the analysis row just now, so these are the passes
    # an *earlier* run of this same revision left behind.
    held = {str(entry["pass"]): entry for entry in catalog.pass_results(analysis_id)}
    kept: list[str] = []
    for entry in _entries(result.get("passes")):
        name = str(entry.get("pass"))
        previous = held.get(name)
        if previous is not None and _covers_more(previous, entry):
            kept.append(_kept_reason(name, previous, entry))
            continue
        catalog.record_pass(analysis_id, _pass_payload(entry, candidates))
    return kept


#: How much of its ranges one recorded pass claims, weakest first. Only ever
#: consulted to separate two records that read exactly the same addresses.
_COVERAGE_RANK: Final[dict[str, int]] = {
    "unavailable": 0,
    "partial": 1,
    "complete": 2,
}


def _covers_more(stored: dict[str, Any], fresh: dict[str, Any]) -> bool:
    """``stored`` read every address ``fresh`` read, and more besides.

    Measured from the ranges, because the coverage word cannot separate a
    ``partial`` that stopped one segment short from a ``partial`` that
    stopped in the first kilobyte, and both are what an exhausted budget
    produces. The word is still the tie-break for the pass whose ranges carry
    no addresses at all, where there is nothing to measure.

    A run that applied a change the stored record does not name is always
    stored, whatever it covered: the catalog's rows are what says which
    changes the managed artifact now carries, and dropping that result would
    leave a change in the artifact that nothing describes.
    """
    held = _visited(stored)
    now = _visited(fresh)
    if not _within(now, held):
        return False
    if not set(_strings(fresh.get("applied_ids"))) <= set(
        _strings(stored.get("applied_ids"))
    ):
        return False
    if _extent(held) > _extent(now):
        return True
    # Containment made the extents equal, so the two read the same addresses.
    return _rank(stored) > _rank(fresh)


def _kept_reason(name: str, stored: dict[str, Any], fresh: dict[str, Any]) -> str:
    """Why this run's pass was not written down, in what it covered."""
    return (
        f"this run's {name!r} pass read {_extent(_visited(fresh))} bytes of the"
        f" {_extent(_visited(stored))} the {stored.get('coverage')} result"
        " an earlier run recorded for this revision had already read, so that"
        " result and its candidates are kept rather than replaced by this"
        " shorter one"
    )


def _rank(entry: dict[str, Any]) -> int:
    return _COVERAGE_RANK.get(str(entry.get("coverage")), 0)


def _visited(entry: dict[str, Any]) -> list[tuple[int, int]]:
    """The addresses one recorded pass really read, as merged intervals.

    A range is what the pass was given, ``unvisited`` is what it never got
    to, and a range it could not read at all contributes nothing.
    """
    spans: list[tuple[int, int]] = []
    for item in _entries(entry.get("ranges")):
        bounds = _span(item)
        if bounds is None or item.get("coverage") == "unavailable":
            continue
        spans.extend(_without(bounds, _entries(item.get("unvisited"))))
    return _merged(spans)


def _span(item: dict[str, Any]) -> tuple[int, int] | None:
    """One ``[start, end)`` an entry describes, or ``None`` if it describes none."""
    start = item.get("start")
    end = item.get("end")
    if isinstance(start, bool) or isinstance(end, bool):
        return None
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        return None
    return start, end


def _without(
    bounds: tuple[int, int], holes: list[dict[str, Any]]
) -> list[tuple[int, int]]:
    """``bounds`` with every hole cut out of what is left of it."""
    spans = [bounds]
    for hole in holes:
        cut = _span(hole)
        if cut is None:
            continue
        spans = [piece for span in spans for piece in _cut(span, cut)]
    return spans


def _cut(span: tuple[int, int], hole: tuple[int, int]) -> list[tuple[int, int]]:
    start, end = span
    low, high = hole
    if high <= start or low >= end:
        return [span]
    pieces: list[tuple[int, int]] = []
    if low > start:
        pieces.append((start, low))
    if high < end:
        pieces.append((high, end))
    return pieces


def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The same addresses, as the fewest non-touching intervals that hold them."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            low, high = merged[-1]
            merged[-1] = (low, max(high, end))
            continue
        merged.append((start, end))
    return merged


def _within(
    spans: list[tuple[int, int]], outer: list[tuple[int, int]]
) -> bool:
    """Every address of ``spans`` is an address of ``outer``.

    Both sides are merged, so each span has to fit inside one interval of
    ``outer`` rather than being spread across two that touch.
    """
    return all(
        any(low <= start and end <= high for low, high in outer)
        for start, end in spans
    )


def _extent(spans: list[tuple[int, int]]) -> int:
    return sum(end - start for start, end in spans)


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
