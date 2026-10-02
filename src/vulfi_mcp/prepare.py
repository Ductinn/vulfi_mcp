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

import asyncio
import hashlib
import json
import shlex
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from collections.abc import Mapping
from typing import Any, Final, NamedTuple, TypedDict

from vulfi_mcp.catalog import (
    ASSOCIATION_ASSERTED,
    ASSOCIATION_VERIFIED,
    CATALOG_UNAVAILABLE_REASON,
    EXTERNAL_BACKENDS,
    Catalog,
    CatalogError,
    UnknownAnalysisError,
    UnverifiedAssociationError,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.contracts import (
    BackendAttempt,
    Candidate,
    Finding,
    FindingsPage,
    JsonValue,
    PassRouting,
    PreparationPage,
    PreparationResult,
    RuleCoverage,
    RuleEvidence,
    RuleRouting,
    ScanResult,
    TriageResult,
)
from vulfi_mcp.ida_adapter import (
    BACKEND,
    IDB_SUFFIXES,
    NO_DATABASE_REASON,
    MAX_SCAN_FINDINGS,
    SYNC_STATE,
    ManagedDatabaseError,
    _CATALOG_REASON,
    _CATALOG_WARNING,
    ensure_managed_idb,
    existing_managed_idb,
    findings_ida,
    invoke_ida,
    scan_ida,
    triage_ida,
    unscanned_findings_page,
)
from vulfi_mcp.ida_runtime import (
    MAX_PREPARE_WARNINGS,
    PROPOSAL_KINDS,
    PREPARE_LIMITS,
    PREPARE_PASSES,
    PRIORITIES,
    TRIAGE_STATUSES,
    ExpressionError,
    OperationError,
    UnavailableEvidenceError,
    UnknownFindingError,
    evaluate_rule,
    utc_now,
    validate_analysis_id,
    validate_page,
    validate_prepare_limits,
    validate_prepare_passes,
    validate_rationale,
    validate_scope,
    validate_status,
    proposal_payload,
    validate_proposal,
    validate_proposal_request,
)
from vulfi_mcp.providers import (
    ProviderError,
    ProviderIdentityError,
    load_provider_config,
    rule_contexts,
)
from vulfi_mcp.providers import ghidra as ghidra_provider
from vulfi_mcp.providers import r2 as r2_provider
from vulfi_mcp.rules import Rule, canonical_rule_digest

__all__ = [
    "BACKENDS",
    "BACKEND_CHAINS",
    "CATALOG_UNAVAILABLE_REASON",
    "EXTERNAL_BACKENDS",
    "LIMITS",
    "NOTHING_PREPARED_REASON",
    "NO_MANAGED_DATABASE_REASON",
    "PASSES",
    "PROPOSALS_ARE_INERT",
    "WRITABLE_BACKENDS",
    "PreparationError",
    "ProposalResult",
    "ProposalSubmission",
    "UnverifiedBinaryError",
    "adapter_fingerprint",
    "backend_chain",
    "check_proposal_against_candidate",
    "ensure_prepared",
    "findings_across_backends",
    "identity_established",
    "mint_proposal_id",
    "prepare_target",
    "preparation_page",
    "propose_recovery",
    "resolve_backend",
    "run_provider",
    "run_ida_passes",
    "scan_target",
    "triage_across_backends",
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

#: The chain each selector runs, in the order it runs it.
#:
#: ``auto`` is the design's own priority — IDA, then a configured Ghidra MCP,
#: then a configured radare2 MCP — and it is a chain rather than a choice
#: because the decision is made **per pass and per rule**, not per scan: IDA
#: answers what it can, and only what IDA could not establish is asked of the
#: next backend.
#:
#: Naming a backend explicitly runs exactly that backend and nothing else.
#: There is no fallback out of an explicit choice, for the reason this
#: project refuses every other quiet substitution: a result produced by IDA
#: is not a Ghidra result, and a caller who asked for one would be handed the
#: other with no way to tell.
BACKEND_CHAINS: Final[dict[str, tuple[str, ...]]] = {
    "auto": (BACKEND, "ghidra", "r2"),
    "ida": (BACKEND,),
    "ghidra": ("ghidra",),
    "r2": ("r2",),
}

#: The adapter module each external backend is reached through, and the two
#: entry points this module calls on it. Constant maps, so nothing a caller
#: supplies can name a module or a function: a backend selector indexes
#: these, and a selector outside them was refused long before here.
_ADAPTERS: Final[dict[str, Any]] = {
    "ghidra": ghidra_provider,
    "r2": r2_provider,
}
_PREPARE: Final[dict[str, Any]] = {
    "ghidra": ghidra_provider.prepare_ghidra,
    "r2": r2_provider.prepare_r2,
}
_EVIDENCE_OF: Final[dict[str, Any]] = {
    "ghidra": ghidra_provider.evidence_ghidra,
    "r2": r2_provider.evidence_r2,
}

#: The worker operations this module sends.
_RUN: Final = "prepare"
_SUMMARY: Final = "preparation_summary"
_RECORD: Final = "record_preparation"
_EVIDENCE: Final = "proposal_evidence"

#: Backends whose candidates this build can write a reviewed change back to.
#: Ghidra joins IDA here because :func:`vulfi_mcp.providers.ghidra
#: .apply_ghidra_review` validates the write against the managed project and
#: saves it. radare2 deliberately does not: that provider has no project and
#: no save, so a mutation would not outlive the session that made it, and a
#: proposal against one of its candidates is refused by name rather than
#: applied against some other backend's analysis as if that were the same
#: thing.
WRITABLE_BACKENDS: Final[tuple[str, ...]] = (BACKEND, "ghidra")

#: Which proposal kinds each backend's writer can really apply.
#:
#: A backend is not writable in general; it is writable for the changes its
#: safe writer implements. ``apply_ghidra_review`` applies a function
#: boundary and a structure layout and nothing else — it answers
#: ``applied=False`` for the other three — so storing one of those would send
#: an operator through a human review of a change that could never land,
#: which is precisely what the submission gate exists to prevent.
WRITABLE_KINDS: Final[dict[str, tuple[str, ...]]] = {
    BACKEND: PROPOSAL_KINDS,
    "ghidra": ("function_boundary", "structure_field"),
}

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
    empty list, a pass this build does not run and a backend it does not
    name are all refused here, before a managed database or a catalog file
    can exist because of them.

    The chain ``backend`` selects is walked **per pass**. Under ``auto`` IDA
    runs first and answers what it can; each pass it could not establish is
    then asked of a configured Ghidra MCP, and each pass still unanswered of
    a configured radare2 MCP. A pass no backend could run is named in
    ``routing`` with what every backend said about it, rather than left out
    of the result as if it had run and found nothing.

    A recorded revision is reused — nothing runs, nothing is applied and the
    artifact revision does not move — only when the target's source identity,
    the managed artifact, the backend capability fingerprint and the recorded
    pass coverage all still match this request. The result says so in
    ``reused``. Only an IDA-headed chain can reuse: an external revision's
    reusability would be a claim about a provider that is there *now*, and
    nothing short of opening a session can make it.
    """
    chain = backend_chain(backend)
    requested_backend = str(backend)
    requested = _requested_passes(passes)
    if chain[0] == BACKEND:
        reused = _reuse(path, requested_backend, BACKEND, requested)
        if reused is not None:
            return reused
    # Only now may a database exist: no malformed request above this line can
    # be the reason one was created.
    routed = _route_passes(path, chain, requested)
    return _record(path, requested_backend, chain, requested, routed)


def preparation_page(
    path: str,
    analysis_id: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> PreparationPage:
    """One window of a recorded preparation, without re-running anything.

    ``0 <= offset`` and ``1 <= limit <= 200``, enforced before the workspace
    is consulted. Nothing here analyzes, creates or writes: a target with no
    recorded preparation at all, a missing catalog and a database nothing has
    prepared are each reported as an unavailable store with the reason, never
    as an empty page.

    A target with no managed IDB is **not** automatically a target with no
    preparation: a Ghidra- or radare2-headed chain records its passes in the
    catalog and makes no IDA database at all. The managed record is consulted
    when there is one, and the catalog answers either way.
    """
    offset, limit = validate_page(offset, limit)
    wanted = None if analysis_id is None else _analysis_argument(analysis_id)
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        return _external_page(path, wanted, offset, limit)
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


def _external_page(
    path: str, wanted: str | None, offset: int, limit: int
) -> PreparationPage:
    """One window of a preparation that produced no managed IDA database.

    This is the Ghidra- or radare2-headed chain's own read. There is no
    managed record to consult and no artifact revision to report, so both are
    reported as what they are rather than as zero. A target the catalog has
    never heard of is still unavailable with the reason it always was.
    """
    catalog = get_catalog(path)
    if catalog is None:
        return _unavailable(
            path, None, None, NO_MANAGED_DATABASE_REASON, offset, limit
        )
    with catalog:
        chosen = wanted or catalog.latest_analysis()
        if chosen is None:
            return _unavailable(
                path, None, None, NO_MANAGED_DATABASE_REASON, offset, limit
            )
        page = catalog.page_candidates(chosen, offset, limit)
        recorded = catalog.pass_results(chosen)
        backends = [str(entry["backend"]) for entry in recorded]
        return {
            "path": path,
            "idb_path": None,
            "backend": backends[0] if backends else BACKEND,
            "available": True,
            "reason": None,
            "analysis_id": chosen,
            "target_key": catalog.target_key,
            "source_sha256": catalog.source_sha256,
            "managed_idb_id": catalog.managed_idb_id,
            "source_association": catalog.source_association,
            "preparation_revision": None,
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

    Only an IDA-headed chain has a reusable revision at all — see
    :func:`prepare_target` — so naming one against an external chain is
    refused rather than answered with a revision that was made by something
    else.
    """
    chain = backend_chain(backend)
    requested_backend = str(backend)
    if analysis_id is None:
        return prepare_target(path, backend=backend, passes=None)
    wanted = _analysis_argument(analysis_id)
    reused = (
        _reuse(path, requested_backend, BACKEND, _requested_passes(None))
        if chain[0] == BACKEND
        else None
    )
    if reused is not None and reused["analysis_id"] == wanted:
        return reused
    held = "nothing matching this request has been prepared for this target"
    if reused is not None:
        held = f"the reusable revision recorded here is {reused['analysis_id']!r}"
    elif chain[0] != BACKEND:
        held = (
            f"the {chain[0]} backend records no reusable revision: its"
            " reusability would be a claim about a provider session that is"
            " open now, and nothing short of opening one can make it"
        )
    raise PreparationError(
        f"analysis_id={analysis_id!r} names no reusable preparation revision"
        f" of this target: {held}. A revision is reusable only for the same"
        " source identity, the same managed artifact, the same backend"
        " capability fingerprint and the requested pass coverage. Omit"
        " analysis_id to prepare the target, or call vulfi_prepare first."
        " Nothing was analyzed, nothing was created and nothing was scanned."
    )


# --------------------------------------------------------------------------
# Scanning across backends
# --------------------------------------------------------------------------

#: Address space of an external backend's findings.
#:
#: Deliberately *not* ``image``, which is the IDA store's own space. The
#: design is explicit that numeric addresses from two backends never imply
#: the same call site, and a shared space name is precisely what would make
#: them look as if they did. Plan 4's reviewer-created link is what joins two
#: spaces, after it has verified the mapping.
def external_space(backend: str) -> str:
    return f"{backend}:image"


#: Why the IDA store did not answer a scan that never asked it.
_IDA_NOT_IN_CHAIN: Final = (
    "this request named an external backend, so the managed IDA database was"
    " not opened and its rows were not counted; that is a store nothing"
    " looked at, not a store with nothing in it"
)


class _RoutedRules(NamedTuple):
    """What the chain made of every rule, and the rows it produced."""

    routing: list[RuleRouting]
    coverage: list[RuleCoverage]
    findings: dict[str, list[Finding]]
    scopes: dict[str, dict[str, Any]]
    warnings: list[str]


def scan_target(
    path: str,
    rules: tuple[Rule, ...],
    scope: str,
    *,
    backend: str = "auto",
    analysis_id: str | None = None,
    decompiler: str = "auto",
) -> ScanResult:
    """Scan ``path`` with ``rules``, routing each rule across the chain.

    The target is prepared first — reused when a recorded revision matches —
    and then every rule is decided on its own. IDA evaluates the rules its
    evidence supports. Each rule it reported ``unsupported`` or ``failed``,
    and every rule at all when IDA is not in the chain, is then asked of a
    configured Ghidra MCP and then of a configured radare2 MCP, and the first
    backend that establishes *complete* facts for it is the one whose verdict
    is stored. Partial facts are not a weaker verdict: they stay
    ``unsupported``.

    Every backend's rows live in that backend's own scope, so none of this
    can touch another's. An external scope is retired only by a scan that
    really ran, covered the whole image and was asked every rule in the scan;
    anything less keeps the rows it did not observe and marks them stale.

    ``decompiler`` is not an MCP parameter and never was. It exists so a test
    can run the disassembly-only extraction IDA itself falls back to when
    Hex-Rays is absent, against a real database, which is the condition this
    whole plan is about.
    """
    chain = backend_chain(backend)
    if not rules:
        raise PreparationError("a scan needs at least one rule")
    try:
        scope = validate_scope(scope)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused
    prepared = ensure_prepared(path, backend=backend, analysis_id=analysis_id)
    idb_path = prepared["idb_path"]
    if chain[0] == BACKEND and idb_path:
        result = scan_ida(idb_path, rules, scope, path=path, decompiler=decompiler)
    else:
        result = _unscanned_ida(path, prepared, scope)
    answered = {
        int(entry["rule_index"]): entry
        for entry in result["rule_coverage"]
        if str(entry["backend"]) == BACKEND
    }
    routed = _route_rules(path, chain, rules, scope, answered, prepared)
    result["analysis_id"] = prepared["analysis_id"]
    result["preparation_revision"] = prepared["preparation_revision"]
    result["warnings"] = [
        *result["warnings"],
        *prepared["warnings"],
        *routed.warnings,
    ]
    return _merge_scan(path, result, routed, prepared, scope, rules)


def _unscanned_ida(
    path: str, prepared: PreparationResult, scope: str
) -> ScanResult:
    """The shape a scan takes when IDA was never in the chain.

    Zero IDA rows and the IDA store reported *unavailable with a reason*,
    never as a store that answered nothing. A caller that asked for Ghidra
    gets Ghidra's answer and an explicit statement that nobody looked in the
    managed database, which is not the same as the managed database being
    empty.
    """
    return {
        "path": path,
        "idb_path": prepared["idb_path"],
        "binary_sha256": prepared["source_sha256"],
        "analysis_id": prepared["analysis_id"],
        "preparation_revision": prepared["preparation_revision"],
        "backend": str(prepared["backend"]),
        "scope": scope,
        "scan_id": "",
        "scanned_at": utc_now(),
        "coverage": "partial",
        "rule_coverage": [],
        "findings": [],
        "scope_total": 0,
        "target_total": 0,
        "target_total_complete": False,
        "status_counts": {},
        "scope_health": {},
        "store_health": {
            BACKEND: {"available": False, "reason": _IDA_NOT_IN_CHAIN}
        },
        "sync_state": SYNC_STATE,
        "warnings": [_IDA_NOT_IN_CHAIN],
    }


def _route_rules(
    path: str,
    chain: tuple[str, ...],
    rules: tuple[Rule, ...],
    scope: str,
    answered: dict[int, RuleCoverage],
    prepared: PreparationResult,
) -> _RoutedRules:
    """Decide every rule separately, down the chain, and keep every answer.

    A rule IDA evaluated is finished: no provider is asked about it, because
    the first backend that can establish a rule's facts is the one whose
    verdict stands. Everything else walks the rest of the chain, and what
    each backend said is kept whether or not a later one answered — a clean
    answer is reported *alongside* an earlier failure, never instead of it.
    """
    routing: list[RuleRouting] = []
    coverage: list[RuleCoverage] = []
    findings: dict[str, list[Finding]] = {}
    asked: dict[str, list[int]] = {}
    states: dict[str, dict[int, tuple[str, str | None]]] = {}
    complete: dict[str, bool] = {}
    reasons: dict[str, tuple[str, str]] = {}
    warnings: list[str] = []
    sha256 = prepared["source_sha256"]

    for index, rule in enumerate(rules):
        attempts: list[BackendAttempt] = []
        held = answered.get(index)
        if held is not None:
            attempts.append(
                _attempt(BACKEND, _outcome_of(str(held["state"])), held["reason"])
            )
            if str(held["state"]) == "evaluated":
                routing.append(_rule_routing(index, rule, BACKEND, "answered", None, attempts))
                continue
        settled: tuple[str, str, str | None] | None = None
        for backend in chain:
            if backend == BACKEND:
                continue
            refusal = _identity_refusal(backend, path)
            if refusal is not None:
                attempts.append(_attempt(backend, "unverified", refusal))
                reasons.setdefault(backend, ("unverified", refusal))
                settled = ("unverified", backend, refusal)
                break
            outcome, evidence, reason = _rule_evidence(backend, path, rule, index)
            attempts.append(_attempt(backend, outcome, reason))
            if outcome in ("unavailable", "unverified", "failed"):
                reasons.setdefault(backend, (outcome, reason or ""))
                if outcome == "unverified":
                    settled = ("unverified", backend, reason)
                    break
                if outcome == "failed":
                    # Recorded against this backend's scope *before* the chain
                    # advances. Left in ``attempts`` alone it would vanish the
                    # moment the same backend evaluated any other rule, and a
                    # failure that does not survive its own function is not
                    # the sticky failure the ruling requires.
                    asked.setdefault(backend, []).append(index)
                    states.setdefault(backend, {})[index] = ("failed", reason)
                    complete[backend] = False
                continue
            asked.setdefault(backend, []).append(index)
            if evidence is None:  # pragma: no cover - outcome implies evidence
                continue
            if outcome != "answered":
                states.setdefault(backend, {})[index] = ("unsupported", reason)
                complete[backend] = False
                continue
            rows, state, why = _evidence_findings(
                backend, scope, rule, index, evidence, sha256
            )
            states.setdefault(backend, {})[index] = (state, why)
            if state != "evaluated":
                complete[backend] = False
                attempts[-1] = _attempt(backend, _outcome_of(state), why)
                continue
            if not _ranges_complete(evidence):
                # Partial or empty coverage is not an answer. The measured
                # rows stay — they are alongside, not instead — and the next
                # backend is asked for what this one did not establish.
                # Discarding them so a later backend can answer instead is
                # the collapse this branch already refused at pass level.
                complete[backend] = False
                findings.setdefault(backend, []).extend(rows)
                gap = why or _incomplete_coverage(evidence)
                attempts[-1] = _attempt(backend, "unsupported", gap)
                states[backend][index] = ("unsupported", gap)
                continue
            findings.setdefault(backend, []).extend(rows)
            settled = ("answered", backend, None)
            break
        if settled is None:
            state = _chain_state([item["outcome"] for item in attempts])
            routing.append(
                _rule_routing(index, rule, None, state, _joined(attempts), attempts)
            )
        else:
            kind, backend, reason = settled
            routing.append(
                _rule_routing(
                    index,
                    rule,
                    backend if kind == "answered" else None,
                    kind,
                    reason,
                    attempts,
                )
            )
        for attempt in attempts:
            if attempt["outcome"] == "failed":
                warnings.append(
                    f"the {attempt['backend']} backend failed on rule"
                    f" {index} ({rule['name']!r}): {attempt['reason']}"
                )

    for backend, table in states.items():
        for index, (state, reason) in sorted(table.items()):
            coverage.append(
                {
                    "rule_index": index,
                    "backend": backend,
                    "state": state,
                    "reason": reason,
                }
            )
    scopes = {
        backend: _external_scope_report(
            backend,
            rules,
            asked.get(backend, []),
            states.get(backend, {}),
            complete.get(backend, True),
            reasons.get(backend),
        )
        for backend in {*asked, *reasons}
    }
    return _RoutedRules(routing, coverage, findings, scopes, warnings)


def _rule_evidence(
    backend: str, path: str, rule: Rule, index: int
) -> tuple[str, RuleEvidence | None, str | None]:
    """Ask one backend about one rule, in the five-outcome vocabulary."""
    unavailable = _unavailable_error(backend)
    try:
        evidence = run_provider(_EVIDENCE_OF[backend](path, rule, index))
    except ProviderIdentityError as refused:
        return "unverified", None, str(refused)
    except unavailable as refused:
        return "unavailable", None, str(refused)
    except ProviderError as refused:
        return "failed", None, str(refused)
    state = str(evidence["state"])
    if state == "evaluated":
        return "answered", evidence, None
    return _outcome_of(state), evidence, evidence["reason"]


def _outcome_of(state: str) -> str:
    """One ``RuleState`` in the routing vocabulary."""
    return "answered" if state == "evaluated" else state


def _chain_state(outcomes: list[str]) -> str:
    for candidate in ("failed", "unsupported", "unavailable", "unverified"):
        if candidate in outcomes:
            return candidate
    return "unavailable"


def _joined(attempts: list[BackendAttempt]) -> str:
    return "; ".join(
        f"{item['backend']}: {item['outcome']}"
        + (f" ({item['reason']})" if item["reason"] else "")
        for item in attempts
    ) or (
        "no backend in this chain was asked about this rule, which is not the"
        " same as a rule that ran and matched nothing"
    )


def _rule_routing(
    index: int,
    rule: Rule,
    backend: str | None,
    state: str,
    reason: str | None,
    attempts: list[BackendAttempt],
) -> RuleRouting:
    return {
        "rule_index": index,
        "rule_name": rule["name"],
        "backend": backend,
        "state": state,
        "reason": reason,
        "attempts": attempts,
    }


def _ranges_complete(evidence: RuleEvidence) -> bool:
    """Whether this evidence was established over every address it names.

    An empty range list names nothing. ``all([])`` is true, and reading that
    as complete coverage is how a scan that never looked retires a row it
    did not see. No address named is not every address read.
    """
    ranges = _entries(evidence.get("ranges"))
    if not ranges:
        return False
    return all(str(item.get("coverage")) == "complete" for item in ranges)


def _incomplete_coverage(evidence: RuleEvidence) -> str:
    """Why this evidence does not answer the rule it was asked."""
    ranges = _entries(evidence.get("ranges"))
    if not ranges:
        return (
            "this backend returned no address range for this rule, and an"
            " empty range list is not complete coverage"
        )
    unread = [
        str(item.get("coverage"))
        for item in ranges
        if str(item.get("coverage")) != "complete"
    ]
    return (
        "at least one range this backend returned was not read in full"
        f" ({', '.join(unread[:4])}), so the rule is not answered"
    )


def _evidence_findings(
    backend: str,
    scope: str,
    rule: Rule,
    index: int,
    evidence: RuleEvidence,
    sha256: str | None,
) -> tuple[list[Finding], str, str | None]:
    """Turn one backend's established facts into this rule's stored rows.

    :func:`vulfi_mcp.ida_runtime.evaluate_rule` is the only thing that decides
    a priority, here as on the IDA path, so a second backend cannot reach a
    different conclusion from the same facts. A context that still cannot
    answer — the adapter probed, and the evaluator wants a fact nothing
    states — makes the whole rule ``unsupported`` on this backend rather than
    a weaker verdict over the sites that could answer.

    The call site each context describes is read out of the evidence's own
    ranges: the adapters append one readable range per context, in context
    order, and name the containing function on it. If those two do not line
    up, this refuses rather than pairing a verdict with an address it cannot
    show belongs to it.
    """
    try:
        contexts = rule_contexts(evidence)
    except ProviderError as refused:
        return [], "failed", str(refused)
    if not contexts:
        return [], "evaluated", None
    sites = [
        item
        for item in _entries(evidence.get("ranges"))
        if str(item.get("coverage")) != "unavailable"
    ]
    if len(sites) != len(contexts):
        return (
            [],
            "failed",
            f"the {backend} backend returned {len(contexts)} call-site"
            f" contexts over {len(sites)} readable ranges, so no verdict here"
            " can be shown to belong to the address it would be stored at",
        )
    if not sha256:
        # An external row is identified inside the original binary's SHA-256
        # namespace. Without that digest there is no namespace to mint one
        # in, and minting outside it is how one image's rows collide with
        # another's in a catalog every target shares.
        return (
            [],
            "unsupported",
            f"the {backend} backend established facts for this rule, and this"
            " target's original binary digest is not known, so no finding can"
            " be identified: an external finding belongs to the original"
            " binary's SHA-256 namespace. Nothing was stored.",
        )
    digest = canonical_rule_digest(rule)
    space = external_space(backend)
    names = sorted(rule["function_names"])
    rows: list[Finding] = []
    occurrences: dict[int, int] = {}
    for position, (context, site) in enumerate(zip(contexts, sites, strict=True)):
        try:
            priority = evaluate_rule(rule, context)
        except UnavailableEvidenceError as missing:
            return [], "unsupported", str(missing)
        except ExpressionError as broken:
            return [], "failed", str(broken)
        if priority is None:
            continue
        address = int(site["start"])
        occurrence = occurrences.get(address, 0)
        occurrences[address] = occurrence + 1
        branch = priority if priority in PRIORITIES else None
        rows.append(
            {
                # The source digest sits in the id because every target
                # shares one catalog and ``external_findings.finding_id`` is
                # that catalog's primary key. Without it two binaries with the
                # same backend, scope, rule, address and occurrence mint the
                # same id, and the second scan's upsert rewrites the first
                # target's row with the wrong image's evidence.
                "id": (
                    f"{backend}:{sha256}:{scope}:{index}:{digest}"
                    f":{space}:0x{address:x}:{occurrence}"
                ),
                "backend": backend,
                "source": scope,
                "binary_sha256": sha256,
                "rule_index": index,
                "rule_digest": digest,
                "rule_name": rule["name"],
                # Which of the rule's names this site called is a fact this
                # backend's evidence does not state, and one name out of
                # several would be a guess. It is given only where the rule
                # leaves no room for one.
                "function_name": names[0] if len(names) == 1 else "",
                "found_in": str(site.get("name") or ""),
                "address_space": space,
                "address": f"0x{address:x}",
                "relative_address": None,
                "occurrence": occurrence,
                "priority": priority,
                "status": "Not Checked",
                "rationale": "",
                "assessed_at": None,
                "triage_revision": 0,
                "link_id": None,
                "link_revision": None,
                "last_seen_scan_id": "",
                "stale": False,
                "evidence": {
                    "matched_branch": branch,
                    "expression": rule["mark_if"][branch] if branch else None,
                    "rule_function_names": names,
                    "matched_name": names[0] if len(names) == 1 else None,
                    "site_coverage": site.get("coverage"),
                    "site_reason": site.get("reason"),
                    # The position of *this* site among the paired
                    # contexts, not the number of findings so far: one clean
                    # site before a matching one would otherwise shift every
                    # later finding's evidence onto a different call site.
                    "facts": evidence["contexts"][position]
                    if position < len(evidence["contexts"])
                    else None,
                },
            }
        )
    return rows, "evaluated", None


def _external_scope_report(
    backend: str,
    rules: tuple[Rule, ...],
    asked: list[int],
    states: dict[int, tuple[str, str | None]],
    ranges_complete: bool,
    refusal: tuple[str, str] | None,
) -> dict[str, Any]:
    """What this backend's scope will record about the scan that just ran.

    ``coverage`` is ``complete`` under three conditions together, and all
    three are load-bearing because ``complete`` is the only thing that may
    retire a stored row: this backend was asked **every** rule in the scan,
    it evaluated every one of them, and each answer was established over
    ranges it read in full. A backend asked only the rules an earlier one
    could not answer has not looked at the others, so it may not retire their
    rows.
    """
    if not asked:
        outcome, reason = refusal or (
            "unavailable",
            f"the {backend} backend was never asked about any rule in this"
            " scan",
        )
        return {
            "state": "unverified" if outcome == "unverified" else outcome,
            "coverage": None,
            "reason": reason,
            "rule_coverage": [],
        }
    evaluated = [
        index for index in asked if states.get(index, ("", None))[0] == "evaluated"
    ]
    coverage_rows = [
        {
            "rule_index": index,
            "backend": backend,
            "state": states[index][0],
            "reason": states[index][1],
        }
        for index in sorted(states)
    ]
    if not evaluated:
        # A non-empty ``asked`` is not a scan that ran. Plan 4 reading
        # ``state == "evaluated"`` would treat a total failure as one.
        # ``evaluated`` + ``complete`` remains the only retirement pair, and
        # a scope that did not evaluate a rule has no coverage to claim.
        return {
            "state": _unevaluated_scope_state(states, refusal),
            "coverage": None,
            "reason": _scope_reason(backend, rules, asked, states, False),
            "rule_coverage": coverage_rows,
        }
    whole = len(asked) == len(rules) and len(evaluated) == len(rules)
    return {
        "state": "evaluated",
        "coverage": "complete" if whole and ranges_complete else "partial",
        "reason": None
        if whole and ranges_complete
        else _scope_reason(backend, rules, asked, states, ranges_complete),
        "rule_coverage": coverage_rows,
    }


def _unevaluated_scope_state(
    states: dict[int, tuple[str, str | None]],
    refusal: tuple[str, str] | None,
) -> str:
    """The scope state when every asked rule failed to evaluate.

    ``failed`` is the ordinary outcome. ``unverified`` and ``unavailable``
    are kept when that is what the backend actually reported, so a provider
    that was never reached is not stored as a scan that tried and died.
    """
    outcomes = {state for state, _reason in states.values()}
    if outcomes == {"unverified"} or (
        refusal is not None and refusal[0] == "unverified" and not outcomes
    ):
        return "unverified"
    if outcomes == {"unavailable"} or (
        refusal is not None and refusal[0] == "unavailable" and not outcomes
    ):
        return "unavailable"
    return "failed"


def _scope_reason(
    backend: str,
    rules: tuple[Rule, ...],
    asked: list[int],
    states: dict[int, tuple[str, str | None]],
    ranges_complete: bool,
) -> str:
    notes: list[str] = []
    if len(asked) != len(rules):
        notes.append(
            f"{len(rules) - len(asked)} of this scan's {len(rules)} rules were"
            f" answered before the {backend} backend was reached, so it did"
            " not look at them and may not retire their rows"
        )
    unresolved = [
        index for index, (state, _) in states.items() if state != "evaluated"
    ]
    if unresolved:
        notes.append(
            f"{len(unresolved)} rule(s) came back unsupported or failed on"
            f" this backend: {sorted(unresolved)}"
        )
    if not ranges_complete:
        notes.append(
            "at least one rule was established over addresses this backend"
            " could not read in full"
        )
    return "; ".join(notes)


# --------------------------------------------------------------------------
# Storing an external scope, and reporting both stores together
# --------------------------------------------------------------------------


def _session_never_opened(report: Mapping[str, Any], findings: list[Finding]) -> bool:
    """Whether this scope never opened a session and has nothing to store.

    ``unverified`` and ``unavailable`` are refusals that happen before a
    session exists. Recording one with no findings is what flips ``stale``
    on rows the scan did not look at, while the stored reason still says
    nothing was written.
    """
    return str(report.get("state")) in ("unverified", "unavailable") and not findings


def _merge_scan(
    path: str,
    result: ScanResult,
    routed: _RoutedRules,
    prepared: PreparationResult,
    scope: str,
    rules: tuple[Rule, ...],
) -> ScanResult:
    """Commit each external scope, then report both stores as one answer."""
    # A timestamp is not an identity: two scans in the same second would
    # share one, and ``record_external_scan`` would read the first scan's
    # rows as seen by the second and refuse to retire them. The id is minted
    # and written back, so the result names the scan the store really holds.
    if not result["scan_id"]:
        result["scan_id"] = uuid.uuid4().hex
    scan_id = str(result["scan_id"])
    stored: dict[str, dict[str, Any]] = {}
    counts: dict[str, dict[str, int]] = {}
    totals: dict[str, Any] = {"by_backend": {}, "total": 0, "stale": 0}
    scopes: list[dict[str, object]] = []
    rows: list[Finding] = []
    catalog_reason: str | None = None
    try:
        catalog = open_catalog(path, prepared["managed_idb_id"])
    except (CatalogError, OSError) as refused:
        catalog = None
        catalog_reason = str(refused)
    if catalog is not None:
        with catalog:
            for backend, report in sorted(routed.scopes.items()):
                if _session_never_opened(report, routed.findings.get(backend, [])):
                    # An identity refusal or an unreachable provider did not
                    # open a session and produced no rows. Writing that scope
                    # would stale every prior finding and store a reason that
                    # says nothing was written. Leave the prior rows alone.
                    continue
                try:
                    stored[backend] = catalog.record_external_scan(
                        backend=backend,
                        scope=scope,
                        scan_id=scan_id,
                        scanned_at=result["scanned_at"],
                        state=str(report["state"]),
                        coverage=report["coverage"],
                        reason=report["reason"],
                        capability_fingerprint=adapter_fingerprint(backend),
                        # The validated rule definitions themselves, not a
                        # count: after a restart a clean or unsupported rule
                        # with no finding survives only as an ordinal, and an
                        # ordinal is not a rule anyone can read.
                        rules=[dict(rule) for rule in rules],
                        rule_coverage=report["rule_coverage"],
                        warnings=[],
                        findings=[
                            {**row, "last_seen_scan_id": scan_id}
                            for row in routed.findings.get(backend, [])
                        ],
                    )
                except UnverifiedAssociationError as refused:
                    # Rows that cannot be filed under the original binary's
                    # digest are not filed somewhere else; the scan says so.
                    routed.warnings.append(str(refused))
            counts = catalog.external_status_counts()
            totals = catalog.external_totals()
            scopes = catalog.external_scopes()
            rows = catalog.page_external_findings(
                0, MAX_SCAN_FINDINGS, scope=scope
            )["findings"]
    for backend, report in sorted(routed.scopes.items()):
        result["scope_health"][backend] = {
            "state": report["state"],
            "coverage": report["coverage"],
            "reason": report["reason"],
            "observed_findings": len(routed.findings.get(backend, [])),
            "stored": stored.get(backend, {}).get("scope"),
            "retired": stored.get(backend, {}).get("retired", []),
            "stale": stored.get(backend, {}).get("stale", []),
        }
    result["scope_health"]["routing"] = routed.routing
    result["rule_coverage"] = [*result["rule_coverage"], *routed.coverage]
    result["findings"] = [*result["findings"], *rows][:MAX_SCAN_FINDINGS]
    result["scope_total"] = int(result["scope_total"]) + sum(
        int(entry["total"])
        for entry in scopes
        if str(entry["scope"]) == scope
    )
    result["target_total"] = int(result["target_total"]) + int(totals["total"])
    ida_available = bool(
        _mapping(result["store_health"].get(BACKEND)).get("available")
    )
    result["target_total_complete"] = _stores_complete(
        idb_present=bool(result.get("idb_path")),
        ida_counted=ida_available,
        catalog_answered=catalog is not None,
    )
    result["status_counts"] = _merged_counts(result["status_counts"], counts)
    result["store_health"]["catalog"] = _catalog_health(
        catalog_reason, totals, scopes
    )
    if not _routing_clean(routed.routing):
        result["coverage"] = "partial"
    result["warnings"] = _without_milestone(
        [*result["warnings"], *routed.warnings]
    )
    return result


def _routing_clean(routing: list[RuleRouting]) -> bool:
    """Whether every rule was answered and nothing failed on the way.

    A failure anywhere in a rule's attempts keeps the scan ``partial`` even
    when a later backend answered that rule. The answer is reported, and so
    is the failure; what may not happen is the scan calling itself complete
    over a backend that could not finish.
    """
    return all(
        row["state"] == "answered"
        and all(item["outcome"] != "failed" for item in row["attempts"])
        for row in routing
    )


def _merged_counts(
    stored: dict[str, dict[str, int]], external: dict[str, dict[str, int]]
) -> dict[str, dict[str, int]]:
    """Triage counts per backend plus an aggregate over all of them.

    The aggregate counts *findings*, not deduplicated vulnerabilities: a
    reviewer-linked pair contributes two rows, exactly as the design says it
    must.

    No backend answered means no counts at all, not an aggregate of zeroes.
    An empty mapping says "nothing to count these from"; a table of zeroes
    says "every store answered and held nothing", and only one of those is
    true of a target with no store.
    """
    merged = {
        name: dict(table) for name, table in stored.items() if name != "aggregate"
    }
    for name, table in external.items():
        merged[name] = dict(table)
    if not merged:
        return {}
    aggregate = {status: 0 for status in TRIAGE_STATUSES}
    for table in merged.values():
        for status, count in table.items():
            aggregate[status] = aggregate.get(status, 0) + int(count)
    merged["aggregate"] = aggregate
    return merged


def _catalog_health(
    reason: str | None, totals: dict[str, Any], scopes: list[dict[str, object]]
) -> dict[str, object]:
    """Whether the external store answered, and what it holds if it did."""
    if reason is not None:
        return {"available": False, "reason": reason}
    return {
        "available": True,
        "total": totals["total"],
        "stale_total": totals["stale"],
        "by_backend": totals["by_backend"],
        "scopes": scopes,
    }


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _stores_complete(
    *, idb_present: bool, ida_counted: bool, catalog_answered: bool
) -> bool:
    """Whether every available store was counted.

    An absent IDB is unavailable, not a store this read failed to count, so
    it does not make the total incomplete. A catalog that did not answer is
    a store that was not counted.
    """
    if not catalog_answered:
        return False
    if not idb_present:
        return True
    return ida_counted


def _without_milestone(warnings: list[str]) -> list[str]:
    """Drop the IDA-only milestone sentences from an aggregated page.

    Those sentences tell an agent to ignore the catalog. The catalog is in
    this milestone; an aggregated read must not repeat them.
    """
    dropped = {_CATALOG_WARNING, _CATALOG_REASON}
    return _warnings([item for item in warnings if item not in dropped])


def _without_milestone_health(health: dict[str, object]) -> dict[str, object]:
    """The same drop, for a catalog reason copied off the IDA page."""
    copied = dict(health)
    catalog = copied.get("catalog")
    if isinstance(catalog, dict) and catalog.get("reason") in (
        _CATALOG_WARNING,
        _CATALOG_REASON,
    ):
        copied["catalog"] = {
            key: value for key, value in catalog.items() if key != "reason"
        }
    return copied




# --------------------------------------------------------------------------
# Reading and assessing rows across both stores
# --------------------------------------------------------------------------


def findings_across_backends(
    path: str,
    binary_path: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> FindingsPage:
    """One page of stored rows across every backend, without rescanning.

    Rows from the managed IDB and rows from the catalog are ordered together
    by verified address space, then location, then finding id — and the two
    never share an address space, so a reader is never shown two backends'
    addresses as if they were the same place.

    Aggregation happens only when source identity really verifies.
    ``binary_path`` is how an IDB-only target supplies the original bytes, and
    it is *proved* against the digest the database itself records rather than
    accepted on a matching name. An unrelated binary is refused outright: the
    IDA rows are still readable, but the two stores are not joined, because a
    join on anything less is how one image's findings end up reported against
    another's.
    """
    offset, limit = validate_page(offset, limit)
    idb_path = existing_managed_idb(path)
    catalog, reason = _verified_catalog(path, binary_path)
    if idb_path is None:
        ida_page = unscanned_findings_page(path, 0, limit)
        ida_rows: list[Finding] = []
        ida_total = 0
    else:
        ida_page = findings_ida(idb_path, 0, 1, path=path)
        ida_rows = _ida_rows(idb_path, offset + limit)
        ida_total = int(ida_page["target_total"])
    rows: list[Finding] = []
    external_total = 0
    stale = 0
    counts: dict[str, dict[str, int]] = {}
    health: dict[str, object] = {"available": False, "reason": reason}
    if catalog is not None:
        with catalog:
            rows = _external_rows(catalog, offset + limit)
            totals = catalog.external_totals()
            external_total = int(totals["total"])
            stale = int(totals["stale"])
            counts = catalog.external_status_counts()
            health = _catalog_health(None, totals, catalog.external_scopes())
    merged = sorted(ida_rows + rows, key=_row_order)
    page = merged[offset : offset + limit]
    store_health = dict(ida_page["store_health"])
    store_health["catalog"] = health
    return {
        "path": path,
        "idb_path": idb_path or "",
        "offset": offset,
        "limit": limit,
        "findings": page,
        "page_total": len(page),
        "target_total": ida_total + external_total,
        "target_total_complete": _stores_complete(
            idb_present=idb_path is not None,
            ida_counted=idb_path is not None,
            catalog_answered=catalog is not None,
        ),
        "stale_total": int(ida_page["stale_total"]) + stale,
        "status_counts": _merged_counts(ida_page["status_counts"], counts),
        "store_health": _without_milestone_health(store_health),
        "sync_state": SYNC_STATE,
        "warnings": _without_milestone(
            [*ida_page["warnings"], *([reason] if reason is not None else [])]
        ),
    }


def _row_order(row: Finding) -> tuple[str, int, str]:
    """Verified address space, then location, then id. Total and stable."""
    address = str(row.get("address") or "")
    try:
        location = int(address, 16 if address.lower().startswith("0x") else 10)
    except ValueError:
        location = -1
    return str(row.get("address_space") or ""), location, str(row.get("id") or "")


def _ida_rows(idb_path: str, needed: int) -> list[Finding]:
    """Up to ``needed`` stored IDA rows, in the record's own order."""
    rows: list[Finding] = []
    while len(rows) < needed:
        window = invoke_ida(
            idb_path,
            "findings_page",
            {"offset": len(rows), "limit": min(200, needed - len(rows))},
        )
        page = [item for item in _entries(window.get("findings"))]
        rows.extend(page)
        if not page:
            break
    return rows


def _external_rows(catalog: Catalog, needed: int) -> list[Finding]:
    rows: list[Finding] = []
    while len(rows) < needed:
        window = catalog.page_external_findings(
            len(rows), min(200, needed - len(rows))
        )
        page = [item for item in _entries(window.get("findings"))]
        rows.extend(page)
        if not page:
            break
    return rows


def triage_across_backends(
    path: str,
    finding_id: str,
    status: str,
    rationale: str,
    binary_path: str | None = None,
) -> TriageResult:
    """Assess one stored row, in whichever store authored it.

    The row's own authority and nothing else. An IDA row is committed to the
    managed database's record; an external row is committed to the catalog;
    neither is copied into the other, because this build creates no links and
    a copy without one would be a second answer to the same question.
    """
    if not isinstance(finding_id, str) or not finding_id:
        raise PreparationError("finding_id must be a non-empty string")
    try:
        status = validate_status(status)
        rationale = validate_rationale(rationale)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused
    backend = finding_id.split(":", 1)[0]
    if backend not in EXTERNAL_BACKENDS:
        idb_path = existing_managed_idb(path)
        if idb_path is None:
            raise UnknownFindingError(
                f"no stored finding carries the id {finding_id!r}:"
                f" {NO_DATABASE_REASON}. Nothing was written"
            )
        # Identity is settled *before* the write, not reported after it. A
        # refusal that arrives once the status, rationale and revision have
        # already changed is not a refusal; it is a mutation with an error
        # message, and retrying it increments the revision again.
        joined, catalog_reason = _verified_catalog(path, binary_path)
        result = triage_ida(idb_path, finding_id, status, rationale, path=path)
        return _completed_triage(result, joined, catalog_reason)
    catalog, reason = _verified_catalog(path, binary_path, writable=True)
    if catalog is None:
        raise UnknownFindingError(
            f"the id {finding_id!r} names a {backend} row, and this target's"
            f" external store cannot be reached: {reason}. Nothing was written"
        )
    with catalog:
        stored = catalog.assess_external_finding(finding_id, status, rationale)
        totals = catalog.external_totals()
        counts = catalog.external_status_counts()
        health = _catalog_health(None, totals, catalog.external_scopes())
    idb_path = existing_managed_idb(path)
    ida_total = 0
    ida_counts: dict[str, dict[str, int]] = {}
    store_health: dict[str, JsonValue] = {
        BACKEND: {
            "available": False,
            "reason": "this target has no managed IDA database",
        }
    }
    if idb_path is not None:
        page = findings_ida(idb_path, 0, 1, path=path)
        ida_total = int(page["target_total"])
        ida_counts = page["status_counts"]
        store_health = dict(page["store_health"])
    store_health["catalog"] = health
    return {
        "path": path,
        "idb_path": idb_path or "",
        "finding": stored,
        "triage_revision": int(stored["triage_revision"]),
        "target_total": ida_total + int(totals["total"]),
        "target_total_complete": True,
        "status_counts": _merged_counts(ida_counts, counts),
        "store_health": store_health,
        "sync_state": SYNC_STATE,
        "warnings": [],
    }


def _completed_triage(
    result: TriageResult, catalog: Catalog | None, reason: str | None
) -> TriageResult:
    """One IDA assessment, with the external store's own counts beside it.

    The catalog is handed in already opened, because deciding whether the two
    stores may be joined is an identity question and has to be answered
    before the assessment is written, not after.
    """
    if catalog is None:
        result["store_health"] = _without_milestone_health(
            {
                **result["store_health"],
                "catalog": {"available": False, "reason": reason},
            }
        )
        result["warnings"] = _without_milestone(list(result.get("warnings") or []))
        return result
    with catalog:
        totals = catalog.external_totals()
        counts = catalog.external_status_counts()
        health = _catalog_health(None, totals, catalog.external_scopes())
    result["target_total"] = int(result["target_total"]) + int(totals["total"])
    result["target_total_complete"] = True
    result["status_counts"] = _merged_counts(result["status_counts"], counts)
    result["store_health"] = _without_milestone_health(
        {**result["store_health"], "catalog": health}
    )
    result["warnings"] = _without_milestone(list(result.get("warnings") or []))
    return result


def identity_established(catalog: Catalog, *, is_database: bool) -> bool:
    """Whether this target's original bytes are *proved*, not merely recorded.

    The two cases differ and the difference is the whole of the aggregation
    gate. When the request named the binary, this process hashed those very
    bytes while opening the catalog, so the digest is proof. When it named a
    database, the stored digest is proof only if
    :meth:`~vulfi_mcp.catalog.Catalog.attach_source` compared bytes for it —
    :data:`~vulfi_mcp.catalog.ASSOCIATION_ASSERTED` records that a caller
    presented both identities together and **nobody checked**, and that is
    exactly the claim that may not become an aggregation.
    """
    if catalog.source_sha256 is None:
        return False
    return not is_database or catalog.source_association == ASSOCIATION_VERIFIED


def _verified_catalog(
    path: str, binary_path: str | None, *, writable: bool = False
) -> tuple[Catalog | None, str | None]:
    """This target's catalog, but only when its source identity verifies.

    External rows belong to the original binary's SHA-256 namespace, so they
    may only be joined to a target whose bytes this process has really
    hashed. That is automatic when ``path`` *is* the binary. When ``path`` is
    a database, ``binary_path`` supplies the bytes and they are checked
    against the input digest the database itself records — never against a
    matching file name, and never on a caller's say-so.

    A refusal returns ``(None, reason)`` rather than raising, so a read still
    answers with the rows it really has and says which store it could not
    join. The one exception is a supplied binary that is simply the wrong
    binary: that is a caller error and is raised, because quietly answering
    about a different image is the failure this whole check exists to stop.
    """
    idb_path = existing_managed_idb(path)
    is_database = Path(path).suffix.lower() in IDB_SUFFIXES
    managed_idb_id: str | None = None
    recorded_sha: str | None = None
    if idb_path is not None:
        summary = _summary(idb_path)
        managed_idb_id = _text(summary.get("managed_idb_id"))
        recorded_sha = _text(summary.get("input_sha256"))
    if binary_path is not None:
        source = Path(binary_path).expanduser()
        if not source.is_file():
            raise UnverifiedBinaryError(
                f"binary_path={binary_path!r} is not a file, so it cannot"
                " identify this target's original bytes. Nothing was joined"
            )
        supplied = _digest(source.resolve())
        if recorded_sha is not None and supplied != recorded_sha:
            raise UnverifiedBinaryError(
                f"binary_path={binary_path!r} hashes to {supplied}, and this"
                f" target's managed database was built from {recorded_sha}."
                " These are different images, so their stores were not joined"
                " and nothing was read from the other one."
            )
        if not is_database and _digest(Path(path).expanduser().resolve()) != supplied:
            raise UnverifiedBinaryError(
                f"binary_path={binary_path!r} hashes to {supplied}, which is"
                f" not the file named by path={path!r}. One request names one"
                " image; nothing was joined."
            )
    catalog = get_catalog(path, managed_idb_id)
    if catalog is None:
        return None, CATALOG_UNAVAILABLE_REASON
    # What counts as established, and why the two cases differ. When ``path``
    # *is* the binary, this process hashed those very bytes a moment ago in
    # :func:`~vulfi_mcp.catalog.open_catalog`'s identity step, so the digest
    # is proof. When ``path`` is a database, the stored digest is only proof
    # if :meth:`~vulfi_mcp.catalog.Catalog.attach_source` compared bytes for
    # it — ``ASSOCIATION_ASSERTED`` records that a caller presented both
    # identities together and **nobody checked**, which is precisely the
    # claim that may not become an aggregation.
    established = identity_established(catalog, is_database=is_database)
    association = catalog.source_association
    catalog.close()
    if not established:
        if binary_path is None:
            held = (
                "not established"
                if association != ASSOCIATION_ASSERTED
                else "recorded only on a caller's say-so, with nothing"
                " compared"
            )
            return None, (
                f"{path} is a database, and this target's original bytes are"
                f" {held}, so its external scopes cannot be identified: an"
                " external row belongs to the original binary's SHA-256"
                " namespace. Supply binary_path to prove them."
            )
        if recorded_sha is None:
            raise UnverifiedBinaryError(
                f"this target's managed database records no input digest, so"
                f" binary_path={binary_path!r} cannot be checked against the"
                " bytes it was built from. The two stores were not joined."
            )
        # Proving the association is a write, and it is made only because a
        # caller explicitly asked to join the two stores. A read that was
        # never asked to join anything never reaches here and never creates
        # a thing.
        try:
            with open_catalog(path, managed_idb_id) as writer:
                writer.attach_source(
                    str(Path(binary_path).expanduser().resolve()),
                    {"kind": "input_fingerprint", "sha256": recorded_sha},
                )
        except CatalogError as refused:
            raise UnverifiedBinaryError(
                f"binary_path={binary_path!r} could not be shown to be this"
                f" target's original bytes: {refused}. The two stores were not"
                " joined and nothing was read from the external one."
            ) from refused
    opener = open_catalog if writable else get_catalog
    try:
        joined = opener(path, managed_idb_id)
    except CatalogError as refused:
        return None, str(refused)
    if joined is None:  # pragma: no cover - it answered a moment ago
        return None, CATALOG_UNAVAILABLE_REASON
    return joined, None


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

    A proposal about a candidate an external backend recovered is not
    answered from the IDA database — that candidate's address is in the
    provider's space, and refusing it because *IDA* already defines something
    there would be a cross-backend conflation this project does not make. It
    is checked against the candidate the catalog holds, stored against that
    backend's own artifact revision, and revalidated by that backend's own
    writer at the moment an operator approves it.
    """
    wanted = _analysis_argument(analysis_id)
    requested = _proposal_request(proposals)
    # A read of an existing analysis, so it resolves the managed database and
    # never makes one: only vulfi_scan and vulfi_prepare may do that.
    idb_path = existing_managed_idb(path)
    checked = [_checked_proposal(item) for item in requested]
    accepted = [body for body, _ in checked if body is not None]
    probe = get_catalog(path, _managed_identity(idb_path, path))
    if probe is None:
        raise PreparationError(
            f"nothing can be proposed for {path!r}: {CATALOG_UNAVAILABLE_REASON}"
        )
    with probe:
        if probe.analysis(wanted) is None:
            raise PreparationError(
                f"analysis_id={analysis_id!r} names no preparation revision of"
                " this target, so there are no candidates to propose anything"
                " about. Call vulfi_preparation to see the revision this"
                " target holds. Nothing was stored"
            )
        owners = {
            body["candidate_id"]: _candidate_backend(probe, wanted, body)
            for body in accepted
        }
        revisions = {
            str(entry["backend"]): int(entry["artifact_revision"] or 0)
            for entry in probe.pass_results(wanted)
        }
    mine = [body for body in accepted if owners[body["candidate_id"]] == BACKEND]
    if mine and idb_path is None:
        raise PreparationError(
            f"nothing can be proposed for {path!r}: {NO_MANAGED_DATABASE_REASON}."
            " Nothing was analyzed, created or stored"
        )
    sites: list[dict[str, Any]] = []
    managed_idb_id: str | None = None
    if idb_path is not None:
        # One lease, read-only: the current state of every proposed IDA range,
        # and the managed record's own summary, from the one operation that
        # reports both. A submission never costs a save.
        observed = invoke_ida(
            idb_path,
            _EVIDENCE,
            {"proposals": [proposal_payload(body) for body in mine]},
        )
        sites = _sites(observed, mine)
        revisions[BACKEND] = _revision(_preparation(observed))
        managed_idb_id = _text(observed.get("managed_idb_id"))
    sites.extend(
        _external_site(owners[body["candidate_id"]], body)
        for body in accepted
        if owners[body["candidate_id"]] != BACKEND
    )
    revision = revisions.get(BACKEND, 0)
    with open_catalog(path, managed_idb_id) as catalog:
        taken: set[int] = set()
        submissions = [
            _submit(catalog, wanted, index, body, refusal, sites, taken, revisions)
            for index, (body, refusal) in enumerate(checked)
        ]
        report: ProposalResult = {
            "path": path,
            "idb_path": idb_path or "",
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


def _managed_identity(idb_path: str | None, path: str) -> str | None:
    """The provisional netnode identity, when the target needs one."""
    if idb_path is None or Path(path).suffix.lower() not in IDB_SUFFIXES:
        return None
    return _text(invoke_ida(idb_path, _SUMMARY, {}).get("managed_idb_id"))


def _candidate_backend(
    catalog: Catalog, analysis_id: str, body: dict[str, Any]
) -> str:
    """Which backend recovered the candidate one proposal names.

    A candidate the catalog does not hold answers ``ida``, so the refusal is
    the one :func:`_submit` already writes — "no candidate is recorded under
    this analysis" — rather than a second wording of it here.
    """
    candidate = catalog.candidate(analysis_id, body["candidate_id"])
    if candidate is None:
        return BACKEND
    return str(candidate.get("backend") or BACKEND)


def _external_site(backend: str, body: dict[str, Any]) -> dict[str, Any]:
    """The site report for a range the managed IDA database does not own.

    It carries no refusal, and that is the honest shape: this server has not
    read the provider's artifact here, so it has nothing to refuse the
    proposal *with*. What checks the range is the provider's own writer, at
    the moment the operator approves — and it refuses there.
    """
    return {
        "candidate_id": body["candidate_id"],
        "kind": body["kind"],
        "start": body["start"],
        "end": body["end"],
        "effect": (
            f"{body['kind']} over {body['start']:#x}..{body['end']:#x} in the"
            f" managed {backend} project"
        ),
        "refusal": None,
    }


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
            f" change back to a {backend} analysis: that provider exposes no"
            " typed writer whose result outlives the session that made it."
            " The proposal is refused rather than applied somewhere else —"
            " nothing was applied, nothing was stored, and no change was made"
            " on that backend's behalf"
        )
    writable = WRITABLE_KINDS[str(backend)]
    if proposal["kind"] not in writable:
        raise PreparationError(
            f"candidate {proposal['candidate_id']!r} was recovered by the"
            f" {backend!r} backend, whose safe writer applies"
            f" {', '.join(writable)} and nothing else, so a"
            f" {proposal['kind']!r} proposal against it could never be"
            " applied. It is refused here rather than stored and sent through"
            " a human review that could only ever end in a refusal"
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
    revisions: dict[str, int],
) -> ProposalSubmission:
    """Store one accepted proposal, or report why this one is not stored.

    ``revisions`` holds one artifact revision per backend, and the one this
    proposal is recorded against is the one belonging to the backend that
    recovered its candidate. An approval is compared against that artifact's
    revision and no other: a Ghidra proposal is not made stale by the managed
    IDA database moving on, and an IDA proposal is not made stale by Ghidra's
    project moving on.
    """
    if body is None:
        return _refused(index, {}, str(refusal))
    # Each site report names the range it is about, so a report is matched to
    # its proposal rather than trusted to arrive in the order it was sent.
    position = _position(sites, body, taken)
    taken.add(position)
    site = sites[position]
    revision = revisions.get(BACKEND, 0)
    try:
        candidate = catalog.candidate(analysis_id, body["candidate_id"])
        if candidate is None:
            raise PreparationError(
                f"no candidate {body['candidate_id']!r} is recorded under"
                f" analysis {analysis_id!r} of this target, so there is"
                " nothing for this proposal to be about"
            )
        revision = revisions.get(str(candidate.get("backend")), revision)
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
            expected_revision=revision,
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


def backend_chain(backend: object) -> tuple[str, ...]:
    """The backends one selector runs, in order, or a refusal naming it.

    One wording, used by every tool that takes a ``backend`` selector, so a
    caller never has to learn two ways of being told the same thing.
    """
    chain = BACKEND_CHAINS.get(backend) if isinstance(backend, str) else None
    if chain is None:
        raise PreparationError(
            f"backend={backend!r} is not a backend this design names; the"
            f" selectors are {', '.join(BACKENDS)}"
        )
    return chain


def resolve_backend(backend: object) -> str:
    """The backend a selector starts at, or a refusal naming what will not.

    The *head* of the chain, not the whole of it: this is the backend whose
    analysis record a preparation hangs from, and the one a scope is recorded
    under when it is the only one that answers. Which backend really answered
    each pass and each rule is in the routing rows, because under ``auto``
    that is a different question for every one of them.
    """
    return backend_chain(backend)[0]


def adapter_fingerprint(backend: str) -> str:
    """What an external adapter's contract was when it produced a revision.

    A digest of the backend name and the tool schemas the adapter is pinned
    against. It attests exactly that much: a recorded revision was produced
    by this code against these pins, and a session whose provider had drifted
    off them would have refused the call rather than answered it.

    It is deliberately **not** the live provider's capability fingerprint,
    which only an open session can state, and that is why an external
    revision is never reused: reuse needs a claim about the provider that is
    there now, and this is a claim about the adapter that ran then.
    """
    adapter = _ADAPTERS[backend]
    digest = hashlib.sha256()
    digest.update(backend.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(
        json.dumps(adapter.PINNED_SCHEMAS, sort_keys=True).encode("utf-8")
    )
    return f"adapter-{digest.hexdigest()}"


def run_provider(coroutine: Any) -> Any:
    """Drive one provider coroutine from this synchronous call.

    The MCP tools this module serves are ordinary functions and the adapters
    are coroutines, so somebody has to own an event loop. If this thread has
    none, it gets one for the duration. If it already has one running — a
    caller that embedded this in an async host — the provider is given its
    own loop on its own thread rather than this one being reentered, which
    ``asyncio`` does not allow and which would otherwise surface as a failure
    that has nothing to do with the provider.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coroutine).result()


def _attempt(backend: str, outcome: str, reason: str | None) -> BackendAttempt:
    return {"backend": backend, "outcome": outcome, "reason": reason}


#: How a stored pass row says it is a failure rather than a capability
#: statement. Both are recorded with ``coverage="unavailable"`` — neither
#: established anything — but "this backend tried and could not finish" and
#: "this backend cannot do this at all" are different facts, and a reader
#: after a restart has to be able to tell them apart. The prefix is on the
#: warning because that is the one free-text field a stored pass has.
FAILED_ATTEMPT: Final = "failed attempt: "


def _failed_pass(name: str, backend: str, reason: str) -> dict[str, Any]:
    """One pass a backend opened a session for and could not finish.

    Recorded, not merely warned about. The ``failed`` ruling lets the chain
    advance past a failure precisely because the failure is kept — so it has
    to survive into the catalog, where a later read and a reused revision
    both find it, and where it keeps the revision's own coverage off
    ``complete`` whatever a later backend answered.
    """
    return {
        "pass": name,
        "backend": backend,
        "ranges": [],
        "coverage": "unavailable",
        "applied_ids": [],
        "candidate_ids": [],
        "candidates": [],
        "warnings": [f"{FAILED_ATTEMPT}{reason}"],
        "artifact_revision": None,
    }


def _failure_reason(entry: Mapping[str, Any]) -> str | None:
    """The failure a stored pass row carries, or ``None`` if it carries none."""
    for warning in _strings(entry.get("warnings")):
        if warning.startswith(FAILED_ATTEMPT):
            return warning[len(FAILED_ATTEMPT) :]
    return None


class UnverifiedBinaryError(PreparationError):
    """The bytes a backend would read could not be shown to be these bytes."""


def _identity_refusal(backend: str, path: str) -> str | None:
    """Why this backend cannot be shown to be looking at ``path``, or ``None``.

    Checked here, before a session is opened, for one reason: an identity
    that cannot be proven must **stop** this pass or rule rather than fall
    through to the next backend. "We cannot prove this provider is reading
    the same binary" is not "this provider had nothing to offer", and
    advancing past it is exactly how a result from one image ends up
    aggregated against another.

    The two checks the operator's configuration makes possible are made.
    A path outside the configured map is refused by name. A mapped path this
    host can read is hashed and compared, so a same-name different-bytes file
    is caught before anything is analysed. A mapped path this host cannot
    read is left to the session's own attestation, and
    :class:`~vulfi_mcp.providers.ProviderIdentityError` from there is caught
    by the caller and reported as the same refusal.

    A saved database is refused outright, before any of that. Matching the
    bytes of an ``.i64`` against a mapped copy of the same ``.i64`` proves
    the container, not the image it was built from, and neither
    ``vulfi_prepare`` nor ``vulfi_scan`` takes the original binary to
    establish it with. Letting it through would open a provider session on a
    database container and create artefacts against it.
    """
    if Path(path).suffix.lower() in IDB_SUFFIXES:
        return (
            f"{path} is a saved IDA database, not the original binary, and an"
            f" external backend analyses the image: matching the database"
            f" container's own bytes would prove the container and not what"
            f" it was built from, so the {backend} backend was not opened and"
            " nothing was analysed. Prepare or scan the original binary."
        )
    try:
        config = load_provider_config().get(backend)
    except Exception as refused:  # noqa: BLE001 - any config fault is a refusal
        return (
            f"the {backend} provider's configuration could not be read, so"
            f" nothing can be said about the bytes it would open: {refused}"
        )
    if config is None:
        return None
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        return f"{source} is not a file, so there are no bytes to identify"
    try:
        remote = config.remote_path(str(source))
    except KeyError:
        return (
            f"{source} is not in the operator-configured binary map for the"
            f" {backend} provider, so it is not a file this server will ask"
            " that provider about"
        )
    mapped = Path(remote)
    if not mapped.is_file():
        return None
    here, there = _digest(source), _digest(mapped)
    if here != there:
        return (
            f"the {backend} provider's path for {source} is {remote}, which"
            f" does not hash to the same bytes: the original is {here} and the"
            f" mapped file is {there}. Nothing was analysed and nothing was"
            " written."
        )
    return None


def _digest(source: Path) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
            backend=BACKEND,
            analysis_id=recorded,
            catalog=catalog,
            fingerprint=str(summary.get("capability_fingerprint")),
            revision=revision,
            requested=requested,
            recorded=covered,
            routing=_reused_routing(requested, covered),
            reused=True,
            skipped=[],
            warnings=[],
        )


class _Routed(NamedTuple):
    """What one routed preparation run produced, before anything is stored.

    ``results`` is one entry per pass a backend really answered, paired with
    the candidate rows that pass named. ``routing`` is one row per *requested*
    pass, answered or not. ``ida`` is the IDA worker's own report when IDA
    ran, and ``None`` when the chain never reached it — which is what decides
    whether there is a managed database to record a summary into.
    """

    results: list[tuple[dict[str, Any], dict[str, dict[str, Any]]]]
    routing: list[PassRouting]
    skipped: list[dict[str, object]]
    warnings: list[str]
    idb_path: str | None
    ida: dict[str, Any] | None
    answered_by: list[str]


def _route_passes(
    path: str, chain: tuple[str, ...], requested: tuple[str, ...]
) -> _Routed:
    """Ask each backend in turn for the passes nobody has answered yet.

    The loop below is the whole of per-pass routing, and every branch in it
    is one of the five outcomes :data:`vulfi_mcp.contracts.AttemptOutcome`
    names. A pass a backend produced a result for is answered and is never
    asked of another backend, unless a catch marked ``refusal`` on a pass that had not yet measured
    a range, or on any of its ranges. That mark is a call the session opened and
    could not finish — failed, for that pass alone, even when a sibling
    range is an intentional skip and the coverage word is ``partial``.
    A refusal on a pass that already measured bytes is the same failed
    attempt, kept beside those bytes: the chain does not advance over a
    read that succeeded. ``unavailable`` without the mark is no typed tool: ``unsupported``, and
    the chain advances. A backend that could not be reached advances the
    chain too. A backend that opened a session and failed the call outright
    advances it as well — and its failure stays in ``attempts``, is carried
    into the stored revision's warnings, and keeps the pass from being read
    as clean.

    The one outcome that stops a pass is an identity this server could not
    prove, because no other backend can stand in for that: "we cannot show
    this provider is reading the same bytes" is not "this provider had
    nothing to offer".
    """
    answered: dict[str, dict[str, Any]] = {}
    owners: dict[str, dict[str, dict[str, Any]]] = {}
    attempts: dict[str, list[BackendAttempt]] = {name: [] for name in requested}
    stopped: dict[str, str] = {}
    warnings: list[str] = []
    skipped: list[dict[str, object]] = []
    idb_path: str | None = None
    ida_result: dict[str, Any] | None = None
    answered_by: list[str] = []
    extra: list[tuple[dict[str, Any], dict[str, dict[str, Any]]]] = []

    for backend in chain:
        pending = tuple(
            name
            for name in requested
            if name not in answered and name not in stopped
        )
        if not pending:
            break
        if backend == BACKEND:
            produced, candidates, note, idb_path, ida_result = _ida_passes(
                path, pending
            )
            if ida_result is not None:
                skipped.extend(_skipped(ida_result))
                warnings.extend(_strings(ida_result.get("warnings")))
        else:
            produced, candidates, note = _external_passes(backend, path, pending)
        if note is not None:
            outcome, reason = note
            for name in pending:
                attempts[name].append(_attempt(backend, outcome, reason))
                if outcome == "unverified":
                    stopped[name] = reason
                elif outcome == "failed":
                    extra.append((_failed_pass(name, backend, reason), {}))
            continue
        by_name = {str(entry.get("pass")): entry for entry in produced}
        for name in pending:
            entry = by_name.get(name)
            if entry is None:
                missing = (
                    f"the {backend} backend ran and returned no result for the"
                    f" {name!r} pass, so nothing is known about it from there"
                )
                attempts[name].append(_attempt(backend, "failed", missing))
                extra.append((_failed_pass(name, backend, missing), {}))
                continue
            # A refused call is failed even when coverage is partial: an
            # intentional skip on a sibling range must not launder a dead
            # provider into an answered row. The field is set at the catch.
            # Warning prose is not consulted — the next catch would speak a
            # sentence this has not heard.
            # Two shapes, one field. A sweep that established nothing is
            # replaced and the chain advances. A later call that refused
            # after bytes were already read keeps those bytes, records the
            # attempt, and does not advance.
            corroboration = _corroboration_refusal(entry)
            if corroboration is not None:
                attempts[name].append(_attempt(backend, "failed", corroboration))
                _stick_failure(entry, corroboration)
                attempts[name].append(_attempt(backend, "answered", None))
                answered[name] = entry
                owners[name] = candidates
                if backend not in answered_by:
                    answered_by.append(backend)
                continue
            refusal = _call_refusal(entry)
            if refusal is not None:
                attempts[name].append(_attempt(backend, "failed", refusal))
                extra.append((_failed_pass(name, backend, refusal), {}))
                continue
            if str(entry.get("coverage")) == "unavailable":
                attempts[name].append(
                    _attempt(backend, "unsupported", _range_reason(entry))
                )
                # Recorded anyway. "This backend looked and cannot establish
                # this" is a fact about the image worth keeping, and it is
                # what lets a later read tell it from a pass nobody asked
                # about — but it does not answer the pass, so the chain
                # advances.
                extra.append((entry, candidates))
                continue
            attempts[name].append(_attempt(backend, "answered", None))
            answered[name] = entry
            owners[name] = candidates
            if backend not in answered_by:
                answered_by.append(backend)

    results = [(answered[name], owners[name]) for name in answered]
    results.extend(extra)
    routing = [
        _pass_routing(name, answered.get(name), attempts[name], stopped.get(name))
        for name in requested
    ]
    return _Routed(
        results=results,
        routing=routing,
        skipped=skipped,
        warnings=warnings,
        idb_path=idb_path,
        ida=ida_result,
        answered_by=answered_by,
    )


def _ida_passes(
    path: str, pending: tuple[str, ...]
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    tuple[str, str] | None,
    str | None,
    dict[str, Any] | None,
]:
    """Run the IDA passes, or say why this backend could not be asked."""
    try:
        idb_path = ensure_managed_idb(path)
        result = run_ida_passes(idb_path, pending)
    except ManagedDatabaseError as refused:
        # A save that did not land is the operator's failure, not a reason to
        # ask the next backend and then report that one as absent. Opening a
        # database that does not exist is the other case: nobody looked, and
        # the chain may go on.
        if _save_was_refused(refused):
            raise
        return [], {}, ("unavailable", str(refused)), None, None
    return (
        _entries(result.get("passes")),
        _candidates_by_id(result),
        None,
        idb_path,
        result,
    )


def _external_passes(
    backend: str, path: str, pending: tuple[str, ...]
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], tuple[str, str] | None]:
    """Run one provider's passes, or say which outcome happened instead."""
    refusal = _identity_refusal(backend, path)
    if refusal is not None:
        return [], {}, ("unverified", refusal)
    unavailable = _unavailable_error(backend)
    try:
        produced = run_provider(_PREPARE[backend](path, pending))
    except ProviderIdentityError as refused:
        return [], {}, ("unverified", str(refused))
    except unavailable as refused:
        return [], {}, ("unavailable", str(refused))
    except ProviderError as refused:
        return [], {}, ("failed", str(refused))
    entries = [dict(entry) for entry in produced]
    candidates: dict[str, dict[str, Any]] = {}
    for entry in entries:
        for row in _entries(entry.pop("candidates", None)):
            identifier = row.get("candidate_id")
            if not isinstance(identifier, str) or not identifier:
                raise PreparationError(
                    f"the {backend} adapter returned a candidate with no id:"
                    f" {row!r}"
                )
            candidates[identifier] = row
        # The provider's own image base rides along beside each pass and is
        # not part of the published contract. It is dropped rather than
        # defaulted: an address space this server cannot state is one it does
        # not state, and a base of zero is a claim, not an absence.
        entry.pop("image_base", None)
    return entries, candidates, None


def _save_was_refused(error: BaseException) -> bool:
    """Whether ``error`` is a save that did not land, not a missing database.

    Those two share :class:`ManagedDatabaseError`. Only the missing database
    may be reported as this backend being unavailable so the chain can ask
    the next one. A refused save has to stay the exception the operator sees.
    """
    text = str(error)
    return (
        "IDA reported no save" in text
        or "the save before this one left a database it cannot read" in text
        or "could not read back" in text
        or "neither can the copy taken before its last save" in text
    )


def _unavailable_error(backend: str) -> type[BaseException]:
    """The adapter's own "there was no provider to ask" exception type."""
    adapter = _ADAPTERS[backend]
    for name in ("GhidraUnavailableError", "R2UnavailableError"):
        error = getattr(adapter, name, None)
        if isinstance(error, type) and issubclass(error, BaseException):
            return error
    raise PreparationError(  # pragma: no cover - both adapters define one
        f"the {backend} adapter declares no unavailability type, so a provider"
        " that is simply absent could not be told from one that failed"
    )



def _whole_skip(item: Mapping[str, Any]) -> bool:
    """Whether this range names itself unvisited and nothing else.

    An intentional skip and a range that was never started both look like
    this. A range some bytes of which were read does not.
    """
    start = item.get("start")
    end = item.get("end")
    unvisited = item.get("unvisited")
    if not isinstance(unvisited, list) or len(unvisited) != 1:
        return False
    hole = unvisited[0]
    return (
        isinstance(hole, dict)
        and hole.get("start") == start
        and hole.get("end") == end
    )


def _measured_pass(entry: Mapping[str, Any]) -> bool:
    """Whether this pass kept a read, not only a skip or a dead range."""
    if _strings(entry.get("candidate_ids")) or _entries(entry.get("candidates")):
        return True
    for item in _entries(entry.get("ranges")):
        if item.get("refusal"):
            continue
        coverage = item.get("coverage")
        if coverage == "complete":
            return True
        if coverage == "partial" and not _whole_skip(item):
            return True
    return False


def _corroboration_refusal(entry: Mapping[str, Any]) -> str | None:
    """A later call refused after this pass had already measured something.

    A refusal on a range is the sweep's own tool, and a pass-level refusal
    with nothing measured is a sweep that never started. Both still advance.
    This one does not: the bytes are already in hand.
    """
    for item in _entries(entry.get("ranges")):
        marked = item.get("refusal")
        if isinstance(marked, str) and marked:
            return None
    refusal = entry.get("refusal")
    if not isinstance(refusal, str) or not refusal or not _measured_pass(entry):
        return None
    return refusal


def _stick_failure(entry: dict[str, Any], reason: str) -> None:
    """Put the failed attempt where a restart can read it back.

    The catalog has no attempts column. The measured row is the only row
    this pass of this backend can store, so the failure rides on its
    warning, beside the ranges, rather than on a synthetic row that would
    overwrite them.
    """
    note = f"{FAILED_ATTEMPT}{reason}"
    warnings = list(_strings(entry.get("warnings")))
    if note not in warnings:
        warnings.append(note)
    entry["warnings"] = warnings


def _call_refusal(entry: Mapping[str, Any]) -> str | None:
    """The provider's refusal, if a catch marked this pass or any range.

    Adapters set ``refusal`` at the catch that saw ``ProviderError``. This
    does not read warning prose. One marked range fails the pass even when
    a sibling range is an intentional skip and the coverage word is
    ``partial``. A missing tool, a budget stop, and a short read that is
    not a provider error do not set the field, and are not this.
    """
    refusal = entry.get("refusal")
    if isinstance(refusal, str) and refusal:
        return refusal
    for item in _entries(entry.get("ranges")):
        refusal = item.get("refusal")
        if isinstance(refusal, str) and refusal:
            return refusal
    return None


def _range_reason(entry: dict[str, Any]) -> str:
    """Why a pass reported ``unavailable``, in the backend's own words."""
    for item in _entries(entry.get("ranges")):
        reason = item.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return (
        f"the {entry.get('backend')} backend reports the"
        f" {entry.get('pass')!r} pass unavailable and named no reason"
    )


def _summary_coverage(coverage: str, attempts: list[BackendAttempt]) -> str:
    """The coverage a routing row may report once a failure is known.

    The answering pass's own coverage is carried through. The one exception
    is ``complete`` on a pass a ``failed`` attempt touched: that would be the
    later answer *instead of* the failure, and the aggregate inherits the
    weaker claim. ``unavailable`` is never upgraded.
    """
    if coverage == "complete" and any(
        item["outcome"] == "failed" for item in attempts
    ):
        return "partial"
    return coverage


def _pass_routing(
    name: str,
    answered: dict[str, Any] | None,
    attempts: list[BackendAttempt],
    stopped: str | None,
) -> PassRouting:
    """One requested pass, and what the whole chain made of it.

    ``coverage`` is the answering pass's own coverage, carried through
    untouched, except that a ``failed`` attempt on the way keeps a
    ``complete`` summary from standing in for the failure: the row reports
    ``partial`` instead. Routing never upgrades a pass summary, and
    ``unavailable`` is not upgraded by anything.
    """
    if answered is not None:
        return {
            "pass": name,
            "backend": str(answered.get("backend")),
            "state": "answered",
            "coverage": _summary_coverage(str(answered.get("coverage")), attempts),
            "attempts": attempts,
            "reason": None,
        }
    if stopped is not None:
        return {
            "pass": name,
            "backend": None,
            "state": "unverified",
            "coverage": "unavailable",
            "attempts": attempts,
            "reason": stopped,
        }
    outcomes = [item["outcome"] for item in attempts]
    state = "unavailable"
    for candidate in ("failed", "unsupported", "unavailable"):
        if candidate in outcomes:
            state = candidate
            break
    reason = "; ".join(
        f"{item['backend']}: {item['outcome']}"
        + (f" ({item['reason']})" if item["reason"] else "")
        for item in attempts
    ) or (
        "no backend in this chain was asked for this pass, which is not the"
        " same as a pass that ran and found nothing"
    )
    return {
        "pass": name,
        "backend": None,
        "state": state,
        "coverage": "unavailable",
        "attempts": attempts,
        "reason": reason,
    }


def _reused_routing(
    requested: tuple[str, ...], recorded: list[dict[str, object]]
) -> list[PassRouting]:
    """Routing rows for a revision nothing was asked for.

    This call consulted no backend. An empty ``attempts`` list is honest
    only when the store holds no failure for that pass: a stored failure is
    read back into ``attempts``, with the refusal it was recorded under, and
    the row does not report ``complete`` or a clean ``answered`` over it.
    What each row carries otherwise is which backend's result the store
    already holds.
    """
    held: dict[str, dict[str, object]] = {}
    failures: dict[str, list[BackendAttempt]] = {}
    for entry in recorded:
        name = str(entry["pass"])
        reason = _failure_reason(entry)
        if reason is not None:
            # A stored failure is read back as the attempt it was. This is
            # what "sticky" means: a reused revision carries the failure the
            # run that made it had, so no restart can turn a chain that broke
            # into a chain that was clean.
            failures.setdefault(name, []).append(
                _attempt(str(entry["backend"]), "failed", reason)
            )
            if not _measured_pass(entry):
                continue
        if str(entry["coverage"]) == "unavailable" and name in held:
            continue
        if name not in held or str(held[name]["coverage"]) == "unavailable":
            held[name] = entry
    rows: list[PassRouting] = []
    for name in requested:
        entry = held.get(name)
        attempts = failures.get(name, [])
        if entry is None:
            rows.append(_pass_routing(name, None, attempts, None))
            continue
        rows.append(
            {
                "pass": name,
                "backend": str(entry["backend"]),
                "state": "answered",
                "coverage": _summary_coverage(str(entry["coverage"]), attempts),
                "attempts": attempts,
                "reason": None,
            }
        )
    return rows


# --------------------------------------------------------------------------
# Recording a run
# --------------------------------------------------------------------------


def _refused_preparation(
    path: str,
    requested_backend: str,
    primary: str,
    requested: tuple[str, ...],
    routed: _Routed,
) -> PreparationResult:
    """The routing refusal, returned without opening the catalog.

    An external-only run that stored no pass has no analysis row. Reading
    one back raises ``UnknownAnalysisError``. Opening the catalog for a
    saved database raises ``CatalogError``. Either one replaces the identity
    sentence the operator has to see, and either one is a write the refusal
    said did not happen.
    """
    wording = _routing_summary(routed.routing)
    return {
        "path": path,
        "idb_path": None,
        "backend": primary,
        "requested_backend": requested_backend,
        "analysis_id": "",
        "target_key": "",
        "source_sha256": None,
        "managed_idb_id": None,
        "source_association": None,
        "capability_fingerprint": "",
        "preparation_revision": 0,
        "reused": False,
        "requested_passes": list(requested),
        "passes": [],
        "coverage": "unavailable",
        "candidates": [],
        "candidate_total": 0,
        "applied_ids": [],
        "applied_total": 0,
        "skipped_prerequisites": routed.skipped,
        "routing": routed.routing,
        "artifact_paths": {"managed_idb": None, "catalog": None},
        "catalog_available": False,
        "warnings": _warnings(
            [*routed.warnings, *_routing_warnings(routed.routing), wording]
        ),
    }


def _record(
    path: str,
    requested_backend: str,
    chain: tuple[str, ...],
    requested: tuple[str, ...],
    routed: _Routed,
) -> PreparationResult:
    """Store what one routed run produced, then tell the database about it.

    The order is the contract. An IDA run has already been saved by the lease
    that made it — a failed save raised out of :func:`run_ida_passes` and
    never reached here — so the catalog is written against an artifact that
    really carries the changes. The bounded summary goes into the managed
    record last, through the one lease that saves, so a revision this returns
    is one both stores agree on. A failure at that last step raises rather
    than returning: the catalog then holds passes the record does not name,
    the next request finds no reusable revision, and preparation runs again.

    A run with no IDA in it has no managed record to tell and no artifact
    whose revision it could claim. It is recorded in the catalog alone, under
    a fingerprint that attests the adapter's pinned contract and nothing
    about the provider that is there now — which is exactly why
    :meth:`~vulfi_mcp.catalog.Catalog.record_analysis` is not called for it
    and a later request runs the passes again rather than reusing them.
    """
    ida = routed.ida
    idb_path = routed.idb_path
    primary = routed.answered_by[0] if routed.answered_by else chain[0]
    managed_idb_id: str | None = None
    if ida is not None and idb_path is not None:
        fingerprint = ida.get("capability_fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise PreparationError(
                "the IDA worker reported no capability fingerprint, so this"
                f" revision could never be reused: {fingerprint!r}"
            )
        revision = ida.get("artifact_revision")
        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
        ):
            raise PreparationError(
                f"the IDA worker reported artifact_revision={revision!r},"
                " which is not a revision this run could have produced"
            )
        managed_idb_id = _text(ida.get("managed_idb_id"))
    elif primary == BACKEND:
        raise PreparationError(
            f"no backend in the {requested_backend!r} chain prepared this"
            " target, and this build will not record a revision nothing"
            " made: "
            + _routing_summary(routed.routing)
        )
    else:
        if not routed.results:
            # Nothing was stored, so there is no analysis row to read back.
            # Calling ``pass_results`` here raises ``UnknownAnalysisError``
            # and drops the identity sentence; opening the catalog on a
            # saved database raises ``CatalogError`` (``managed_idb_id`` is
            # required) and drops it the same way. The routing refusal is
            # the result.
            return _refused_preparation(
                path, requested_backend, primary, requested, routed
            )
        fingerprint = adapter_fingerprint(primary)
        revision = max(
            (
                int(entry.get("artifact_revision") or 0)
                for entry, _ in routed.results
            ),
            default=0,
        )
    artifact = idb_path or str(_external_artifact(primary, path))
    with open_catalog(path, managed_idb_id) as catalog:
        analysis_id = _mint(catalog.target_key, primary, artifact, fingerprint)
        if ida is not None and idb_path is not None:
            stored = catalog.record_analysis(
                analysis_id,
                requested_backend=primary,
                artifact_path=artifact,
                capability_fingerprint=fingerprint,
                revision=revision,
            )
            # From the store, not from the run: what a later reuse check
            # compares against is the stored row, so that is what this
            # reports.
            revision = int(str(stored["revision"]))
        kept = _record_passes(catalog, analysis_id, routed.results)
        # Read back after recording, for the same reason: a pass this run did
        # not beat kept its earlier result, and the summary the managed record
        # carries — the one that decides a later reuse — has to name the
        # coverage the catalog really holds rather than the one this run
        # produced and did not store.
        recorded = catalog.pass_results(analysis_id)
        coverage = {
            str(entry["pass"]): str(entry["coverage"])
            for entry in recorded
            if str(entry["backend"]) == BACKEND
        }
        catalog_key = catalog.target_key
        report = _result(
            path=path,
            idb_path=idb_path,
            requested_backend=requested_backend,
            backend=primary,
            analysis_id=analysis_id,
            catalog=catalog,
            fingerprint=fingerprint,
            revision=revision,
            requested=requested,
            recorded=recorded,
            routing=routed.routing,
            reused=False,
            skipped=routed.skipped,
            warnings=[*routed.warnings, *kept, *_routing_warnings(routed.routing)],
        )
    if idb_path is not None:
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


def _external_artifact(backend: str, path: str) -> Path:
    """Where an external backend keeps whatever it keeps for this target.

    A real directory for Ghidra, which holds the managed project record. For
    radare2 it is the directory that *would* hold one, and every pass
    recorded under it carries ``artifact_revision: null`` because that
    provider keeps nothing at all between sessions.
    """
    from vulfi_mcp.ida_adapter import data_dir

    return data_dir() / backend / Path(path).name


def _routing_summary(routing: list[PassRouting]) -> str:
    return "; ".join(
        f"{row['pass']}: {row['state']}"
        + (f" ({row['reason']})" if row["reason"] else "")
        for row in routing
    )


def _routing_warnings(routing: list[PassRouting]) -> list[str]:
    """One warning per failure on the way, and per pass nobody answered.

    A failure is sticky: it is said here even when a later backend answered
    the same pass, because a clean answer reported *instead of* an earlier
    failure is the one shape this project exists to rule out.
    """
    notes: list[str] = []
    for row in routing:
        for attempt in row["attempts"]:
            if attempt["outcome"] == "failed":
                notes.append(
                    f"the {attempt['backend']} backend failed on the"
                    f" {row['pass']!r} pass: {attempt['reason']}"
                )
        if row["state"] != "answered":
            notes.append(
                f"no backend established the {row['pass']!r} pass"
                f" ({row['state']}): {row['reason']}"
            )
    return notes


def _record_passes(
    catalog: Catalog,
    analysis_id: str,
    results: list[tuple[dict[str, Any], dict[str, dict[str, Any]]]],
) -> list[str]:
    """Store each pass with its own candidates, keeping what it cannot beat.

    One pass at a time, each in its own transaction, because that is the unit
    the catalog replaces: re-running ``strings`` must not retire what
    ``functions`` found.

    The unit is one pass **of one backend**, which is what makes the fallback
    in this plan storable at all: Ghidra's ``strings`` and IDA's ``strings``
    are two records of two different reads, and the catalog's own key is
    ``(analysis, pass, backend)`` for exactly that reason. A run that routed
    a pass to a second backend does not overwrite what the first one said
    about a different pass, and neither of them can retire the other's
    candidates.

    A pass is stored unless the result an earlier run recorded for this same
    revision *and the same backend* covered strictly more — read every
    address this run read, and some this run never reached. A run that is cut
    short is not evidence that the thing an earlier run saw has gone away,
    and replacing the stronger record with the weaker one would delete the
    candidates that are the only description of it. The skip is returned as a
    warning rather than performed silently.

    What is compared is what each run really covered, not how it ended. The
    cancellation this design actually produces is an exhausted budget, which
    reports ``partial`` and names the addresses it never reached; a rule
    phrased on a pass that failed outright would never fire on that, which is
    the ordinary case rather than the exotic one.
    """
    # The caller recorded the analysis row just now, so these are the passes
    # an *earlier* run of this same revision left behind.
    try:
        previous_results = catalog.pass_results(analysis_id)
    except UnknownAnalysisError:
        # An external-only revision has no ``analyses`` row until the first
        # pass writes one: ``record_analysis`` is deliberately not called for
        # it, because its four columns are a claim about reusability that
        # only an open provider session could make. Nothing was recorded
        # earlier, so there is nothing for this run to lose to.
        previous_results = []
    held = {
        (str(entry["pass"]), str(entry["backend"])): entry
        for entry in previous_results
    }
    kept: list[str] = []
    for entry, candidates in results:
        name = str(entry.get("pass"))
        backend = str(entry.get("backend"))
        previous = held.get((name, backend))
        if previous is not None and _covers_more(previous, entry):
            kept.append(_kept_reason(f"{backend} {name}", previous, entry))
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
            f"the {entry.get('backend')} backend's {entry.get('pass')!r} pass"
            f" named candidates it did not return:"
            f" {', '.join(sorted(missing))}"
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
    idb_path: str | None,
    requested_backend: str,
    backend: str,
    analysis_id: str,
    catalog: Catalog,
    fingerprint: str,
    revision: int,
    requested: tuple[str, ...],
    recorded: list[dict[str, object]],
    routing: list[PassRouting],
    reused: bool,
    skipped: list[dict[str, object]],
    warnings: list[str],
) -> PreparationResult:
    """One revision, reported from the catalog that holds it.

    Both branches build the result the same way and from the same place: a
    reused revision and a fresh one are the same object, and a reader cannot
    be shown a field on one that the other could not produce.

    ``backend`` is the one whose analysis record this revision hangs from —
    the first backend in the chain that answered anything. It is not a claim
    about who answered each pass: under ``auto`` that is a different answer
    per pass, and ``routing`` is where it is said.
    """
    page = catalog.page_candidates(analysis_id, 0, INLINE_CANDIDATES)
    applied = catalog.applied_candidates(analysis_id)
    return {
        "path": path,
        "idb_path": idb_path,
        "backend": backend,
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
        "routing": routing,
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

    A recorded failure is one of those weakest things, and it is counted here
    rather than only in the routing rows. A backend that opened a session and
    could not finish leaves a revision this server may not summarise as
    ``complete``, however well a later backend answered the same pass — which
    is the second of the three invariants the ``failed`` ruling rests on, and
    it has to hold for a reused revision too.
    """
    states = {str(entry["coverage"]) for entry in recorded}
    if not states or states == {"unavailable"}:
        return "unavailable"
    if states == {"complete"} and any(
        _failure_reason(entry) is not None for entry in recorded
    ):
        return "partial"
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
