"""The operator's review command: the only place a proposal becomes a change.

Nothing an agent can reach lives here. :mod:`vulfi_mcp.server` publishes seven
MCP tools and not one of them approves anything; ``vulfi_propose_recovery``
writes a row in the catalog and stops. What is below is reached only by
running ``vulfi-mcp review`` — a separate invocation of the same program, by a
person at a shell, who is shown the bytes, the definitions already in the
database, the change being asked for and its expected effect, and who has to
type the decision out before anything happens.

**This separation is procedural, and that is worth saying plainly.** Anything
running with the operator's own OS credentials — including a shell-capable
agent — can run this command, because it is an ordinary program on an ordinary
PATH. The split stops an MCP client from applying its own proposals through
the protocol it is talking; it does not stop a process that already has the
operator's shell. An installation that needs enforced human separation has to
restrict who can run this command and who can reach the managed workspace, by
running the MCP server as a different principal from the reviewer.

Four rules shape every approval.

**The database decides, not the decision.** An approval names the revision it
was made against. If the artifact has moved on since, or the candidate's own
evidence no longer describes what is there, nothing is applied and the
proposal is marked ``stale`` to be regenerated. An operator's approval is a
statement about a database they could see.

**Nothing already there is replaced.** A name, a function, an item or a type
already covering the range is a refusal, never an overwrite.

**The order is checkpoint, apply, save, observe, record.** The decision is
written to the catalog as ``approved`` *before* the write it authorizes, so a
decision that never became durable is still visible afterwards instead of
being lost; the change is applied through
:func:`vulfi_mcp.ida_adapter.invoke_ida`, which saves behind the rescue copy
it keeps of the bytes it replaces; and only then is the approval confirmed as
``applied``.

**A durable approved revision is reported only when both stores hold it.** A
stale approval, a save that failed and a catalog that could not record the
approval all return ``approved_revision: None``. The last of those also takes
the change back off the artifact, from the checkpoint the apply recorded, so
the two stores are not left disagreeing about what happened.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any, Final, Literal, TypedDict

from vulfi_mcp.catalog import (
    CATALOG_UNAVAILABLE_REASON,
    Catalog,
    CatalogError,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.contracts import JsonValue
from vulfi_mcp.ida_adapter import (
    BACKEND,
    IDB_SUFFIXES,
    ManagedDatabaseError,
    existing_managed_idb,
    invoke_ida,
)
from vulfi_mcp.ida_runtime import (
    PROPOSAL_STATES,
    OperationError,
    proposal_payload,
    validate_page,
    validate_proposal,
)
from vulfi_mcp.prepare import (
    NO_MANAGED_DATABASE_REASON,
    PreparationError,
    check_proposal_against_candidate,
)

__all__ = [
    "Briefing",
    "DECISIONS",
    "ReviewError",
    "ReviewResult",
    "list_proposals",
    "main",
    "proposal_briefing",
    "review_proposal",
]

#: What a reviewer may decide. There is no third answer: a proposal is
#: applied or it is refused, and "later" is simply leaving it pending.
DECISIONS: Final[tuple[str, ...]] = ("approve", "reject")

#: The worker operations this module sends.
_EVIDENCE: Final = "proposal_evidence"
_APPLY: Final = "apply_reviewed_proposal"
_RECOVER: Final = "recover_reviewed_proposal"
_SUMMARY: Final = "preparation_summary"

#: Who an unattended run records as the reviewer when the OS cannot say.
_UNKNOWN_REVIEWER: Final = "operator"

#: Bytes of the original run quoted in a briefing, in hexadecimal pairs.
_QUOTED_BRIEFING_BYTES: Final = 32


class ReviewError(ValueError):
    """A review was refused before it changed anything."""


class ReviewResult(TypedDict):
    """What one decision did, and what it deliberately did not do.

    ``confirmed`` is the whole claim: ``True`` means the decision took effect
    exactly as asked — a rejection recorded, or a change applied, saved and
    recorded. Everything else is ``False`` with a ``reason``.

    ``approved_revision`` is the artifact revision an approval made durable,
    and is ``None`` unless both stores hold it. A stale approval, a failed
    save and a catalog that could not record the approval all answer ``None``
    there, because each of them would otherwise be a revision this server
    told a caller about and cannot show them.

    ``reconciliation`` is set only when the change reached the artifact and
    the catalog could not be told. It carries what was done about that.
    """

    path: str
    idb_path: str
    backend: str
    proposal_id: str
    analysis_id: str
    candidate_id: str
    kind: str
    address_space: str
    start: int
    end: int
    value: dict[str, JsonValue]
    evidence: dict[str, JsonValue]
    rationale: str
    effect: str
    decision: str
    state: str
    confirmed: bool
    applied: bool
    expected_revision: int
    artifact_revision: int | None
    approved_revision: int | None
    decided_by: str
    decided_at: str | None
    reconciliation: dict[str, JsonValue] | None
    reason: str | None


class Briefing(TypedDict):
    """Everything a reviewer is shown before they are asked to decide."""

    path: str
    idb_path: str
    backend: str
    artifact_revision: int
    proposal: dict[str, JsonValue]
    candidate: dict[str, JsonValue] | None
    site: dict[str, JsonValue]
    conflicts: list[str]
    effect: str
    reviewable: bool
    reason: str | None


# --------------------------------------------------------------------------
# Reading what is waiting
# --------------------------------------------------------------------------


def list_proposals(
    path: str,
    analysis_id: str | None = None,
    state: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> dict[str, object]:
    """The proposals recorded for one target, newest last.

    A read, and only a read: no database is opened, nothing is analyzed and
    no store is created to answer with an empty queue.
    """
    try:
        offset, limit = validate_page(offset, limit)
    except OperationError as refused:
        raise ReviewError(str(refused)) from refused
    if state is not None and state not in PROPOSAL_STATES:
        raise ReviewError(
            f"state={state!r} is not one of {', '.join(PROPOSAL_STATES)}"
        )
    idb_path = _managed_database(path)
    with _catalog(path, idb_path) as catalog:
        page = catalog.page_proposals(
            analysis_id, state=state, offset=offset, limit=limit
        )
    return {"path": path, "idb_path": idb_path, "backend": BACKEND, **page}


def proposal_briefing(path: str, proposal_id: str) -> Briefing:
    """One proposal, and the state of the database it is about right now.

    This is what the command prints before it asks, and it is read fresh out
    of the managed artifact every time: a reviewer is never shown a cached
    description of a database that has since changed.
    """
    idb_path = _managed_database(path)
    with _catalog(path, idb_path) as catalog:
        held = _held(catalog, proposal_id, path)
        candidate = catalog.candidate(
            str(held["analysis_id"]), str(held["candidate_id"])
        )
    body = _body(held)
    observed = invoke_ida(idb_path, _EVIDENCE, {"proposals": [proposal_payload(body)]})
    reviewed = _reviewed(observed)
    reason = _unreviewable(held, candidate, body)
    return {
        "path": path,
        "idb_path": idb_path,
        "backend": BACKEND,
        "artifact_revision": _revision(observed),
        "proposal": dict(held),
        "candidate": candidate,
        "site": reviewed["site"],
        "conflicts": [str(entry) for entry in reviewed["conflicts"]],
        "effect": str(reviewed["effect"]),
        "reviewable": reason is None and not reviewed.get("refusal"),
        "reason": reason,
    }


# --------------------------------------------------------------------------
# Deciding
# --------------------------------------------------------------------------


def review_proposal(
    path: str,
    proposal_id: str,
    decision: Literal["approve", "reject"],
    expected_revision: int,
    *,
    reason: str | None = None,
    reviewer: str | None = None,
) -> ReviewResult:
    """Approve or reject one proposal, against the artifact as it is now.

    An approval revalidates before it applies: the proposal's candidate must
    still be in the catalog and still carry the evidence the proposal quotes,
    the artifact must still be at ``expected_revision``, the bytes under the
    range must still be the ones the candidate recorded, and nothing may have
    been defined over it. A failure of any of those marks the proposal
    ``stale`` and applies nothing — it has to be regenerated against the
    analysis as it now is.

    A rejection is recorded with its reason and changes no artifact at all.
    """
    if decision not in DECISIONS:
        raise ReviewError(
            f"decision={decision!r} is not one of {', '.join(DECISIONS)}"
        )
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise ReviewError(
            f"expected_revision must be an integer, got {expected_revision!r}"
        )
    if decision == "reject" and not (reason or "").strip():
        raise ReviewError(
            "rejecting a proposal needs a reason: the agent that proposed it,"
            " and the next reviewer, both read it"
        )
    who = (reviewer or _reviewer()).strip() or _UNKNOWN_REVIEWER
    idb_path = _managed_database(path)
    with _catalog(path, idb_path, writable=True) as catalog:
        held = _held(catalog, proposal_id, path)
        body = _body(held)
        candidate = catalog.candidate(
            str(held["analysis_id"]), str(held["candidate_id"])
        )
        observed = invoke_ida(
            idb_path, _EVIDENCE, {"proposals": [proposal_payload(body)]}
        )
        reviewed = _reviewed(observed)
        revision = _revision(observed)
        report = _outcome(
            path,
            idb_path,
            held,
            body,
            str(reviewed["effect"]),
            decision,
            expected_revision,
            who,
            revision,
        )
        if held["state"] != "pending":
            # A refusal rather than an exception: a caller asking about a
            # decided proposal is owed what its state is and what the
            # artifact looks like, which is exactly this result with
            # ``confirmed`` false.
            report["reason"] = (
                f"proposal {proposal_id} is {held['state']!r} and only a"
                " pending proposal can be decided. Nothing was applied and no"
                " revision was approved; a decision an operator already made"
                " is not overwritten by a second one"
            )
            return report
        drift = _unreviewable(held, candidate, body)
        if drift is None and revision != expected_revision:
            drift = (
                f"this decision was made against revision {expected_revision}"
                f" and the managed artifact now carries revision {revision},"
                " so it is a decision about an analysis that has moved on"
            )
        if drift is not None:
            return _stale(catalog, report, who, drift)
        if decision == "reject":
            stored = catalog.decide_proposal(
                proposal_id, state="rejected", decided_by=who, reason=str(reason)
            )
            report.update(
                state=str(stored["state"]),
                confirmed=True,
                decided_at=_text(stored["decided_at"]),
                reason=str(reason),
            )
            return report
        refusal = _text(reviewed.get("refusal"))
        if refusal is not None:
            return _stale(catalog, report, who, refusal)
        return _approve(
            catalog, idb_path, report, body, candidate, who, reason, expected_revision
        )


def _approve(
    catalog: Catalog,
    idb_path: str,
    report: ReviewResult,
    body: dict[str, Any],
    candidate: dict[str, Any] | None,
    who: str,
    reason: str | None,
    expected_revision: int,
) -> ReviewResult:
    """Record the decision, apply it, and confirm only what is really durable.

    The approval is written down *first*, deliberately. Everything after it
    can fail, and when it does, the row says an operator approved this change
    and the result says what became of that approval — which is a state an
    operator can act on. The alternative, recording the decision only once
    everything worked, loses the fact that a decision was ever made.
    """
    proposal_id = report["proposal_id"]
    why = (reason or "").strip() or "approved after reviewing the evidence"
    catalog.decide_proposal(
        proposal_id,
        state="approved",
        decided_by=who,
        reason=why,
        expected_revision=expected_revision,
    )
    try:
        applied = invoke_ida(
            idb_path,
            _APPLY,
            {
                "proposal": proposal_payload(body),
                "candidate": candidate or {},
                "expected_revision": expected_revision,
            },
        )
    except Exception as failed:  # noqa: BLE001 - every failure is reported
        # The lease never saved, so the artifact is exactly as it was and the
        # approval goes back to pending with what went wrong.
        return _return_to_pending(
            catalog,
            report,
            who,
            f"the change was not applied and nothing was saved: {failed}",
        )
    report["artifact_revision"] = _whole(applied.get("revision"))
    if not applied.get("applied"):
        refused = _text(applied.get("reason")) or "the IDA worker applied nothing"
        if applied.get("stale"):
            return _stale(catalog, report, who, refused)
        return _return_to_pending(catalog, report, who, refused)
    # The write is saved: `invoke_ida` saved it inside the lease and raised
    # rather than returning if it could not. What is left is telling the
    # catalog, and that is the one step whose failure leaves the two stores
    # saying different things.
    try:
        _record_revision(catalog, report, idb_path, applied)
        stored = catalog.decide_proposal(
            proposal_id, state="applied", decided_by=who, reason=why
        )
    except Exception as unrecorded:  # noqa: BLE001 - every failure is reported
        return _reconcile(idb_path, report, applied, unrecorded)
    report.update(
        state=str(stored["state"]),
        confirmed=True,
        applied=True,
        approved_revision=report["artifact_revision"],
        decided_at=_text(stored["decided_at"]),
        reason=None,
    )
    return report


def _record_revision(
    catalog: Catalog,
    report: ReviewResult,
    idb_path: str,
    applied: dict[str, object],
) -> None:
    """Move the catalog's analysis revision to the one the artifact now has."""
    analysis = catalog.analysis(report["analysis_id"])
    if analysis is None:  # pragma: no cover - the proposal hangs off it
        raise CatalogError(
            f"analysis {report['analysis_id']!r} is no longer in the catalog"
        )
    catalog.record_analysis(
        report["analysis_id"],
        requested_backend=str(analysis["requested_backend"]),
        artifact_path=str(analysis["artifact_path"] or idb_path),
        capability_fingerprint=str(
            applied.get("capability_fingerprint")
            or analysis["capability_fingerprint"]
        ),
        revision=_whole(applied.get("revision")),
    )


def _reconcile(
    idb_path: str,
    report: ReviewResult,
    applied: dict[str, object],
    unrecorded: BaseException,
) -> ReviewResult:
    """The change landed and the catalog could not be told. Put it back.

    The apply refused every conflict before it wrote, so the range held
    nothing of ours and taking the change off again is exact. Doing that
    leaves both stores agreeing that nothing happened, which an operator can
    act on; leaving the artifact changed and the catalog silent would leave
    a revision nobody recorded and a proposal nobody can see the outcome of.

    Either way this reports ``approved`` and no durable revision: the
    decision is still on the row, as the anchor for whatever reconciliation
    the operator chooses, and nothing here claims the approval completed.
    """
    recovery: dict[str, Any] = {
        "recovered": False,
        "applied_revision": report["artifact_revision"],
        "checkpoint": applied.get("checkpoint"),
        "catalog_error": f"{type(unrecorded).__name__}: {unrecorded}",
        "recovery_error": None,
        "artifact_revision": report["artifact_revision"],
    }
    try:
        restored = invoke_ida(
            idb_path, _RECOVER, {"checkpoint": applied.get("checkpoint")}
        )
    except Exception as failed:  # noqa: BLE001 - every failure is reported
        recovery["recovery_error"] = f"{type(failed).__name__}: {failed}"
    else:
        recovery["recovered"] = bool(restored.get("recovered"))
        recovery["recovery_error"] = _text(restored.get("reason"))
        recovery["artifact_revision"] = _whole(restored.get("revision"))
        report["artifact_revision"] = recovery["artifact_revision"]
    report.update(
        state="approved",
        applied=not recovery["recovered"],
        approved_revision=None,
        reconciliation=recovery,
        reason=(
            "the change was applied and saved, and the catalog could not"
            f" record it: {recovery['catalog_error']}. "
            + (
                "It was taken back off the managed artifact from the"
                " checkpoint, so both stores agree nothing happened, and the"
                " approval has to be made again once the catalog is readable"
                if recovery["recovered"]
                else "It could not be taken back off either"
                f" ({recovery['recovery_error']}), so the managed artifact"
                " carries a change the catalog does not record"
            )
            + ". No revision was approved"
        ),
    )
    return report


def _return_to_pending(
    catalog: Catalog, report: ReviewResult, who: str, why: str
) -> ReviewResult:
    """Undo an approval the write never earned, and say why it was undone.

    Nothing reached the artifact on this path — the lease either refused or
    never saved — so the proposal belongs back where it was, available to
    approve again once whatever failed is fixed.
    """
    try:
        stored = catalog.decide_proposal(
            report["proposal_id"], state="pending", decided_by=who, reason=why
        )
    except Exception as refused:  # noqa: BLE001 - every failure is reported
        report["reason"] = (
            f"{why}. No revision was approved. The approval could not be"
            f" withdrawn either ({refused}), so this proposal is still"
            " recorded approved against a change that never happened"
        )
        return report
    report.update(
        state=str(stored["state"]),
        reason=f"{why}. The proposal is pending again and no revision was approved",
    )
    return report


def _stale(
    catalog: Catalog, report: ReviewResult, who: str, why: str
) -> ReviewResult:
    """Mark a proposal that can no longer be decided, and say why."""
    try:
        stored = catalog.decide_proposal(
            report["proposal_id"], state="stale", decided_by=who, reason=why
        )
    except Exception as refused:  # noqa: BLE001 - every failure is reported
        report["reason"] = (
            f"{why}. Nothing was applied and no revision was approved, and the"
            f" catalog could not record that either: {refused}"
        )
        return report
    report.update(
        state=str(stored["state"]),
        decided_at=_text(stored["decided_at"]),
        reason=(
            f"{why}. Nothing was applied and no revision was approved; this"
            " proposal is stale and has to be made again against the analysis"
            " as it now is"
        ),
    )
    return report


def _outcome(
    path: str,
    idb_path: str,
    held: dict[str, object],
    body: dict[str, Any],
    effect: str,
    decision: str,
    expected_revision: int,
    who: str,
    revision: int,
) -> ReviewResult:
    """The result every path below fills in, refused by default."""
    return {
        "path": path,
        "idb_path": idb_path,
        "backend": BACKEND,
        "proposal_id": str(held["proposal_id"]),
        "analysis_id": str(held["analysis_id"]),
        "candidate_id": str(held["candidate_id"]),
        "kind": body["kind"],
        "address_space": body["address_space"],
        "start": body["start"],
        "end": body["end"],
        "value": body["value"],
        "evidence": body["evidence"],
        "rationale": body["rationale"],
        "effect": effect,
        "decision": decision,
        "state": str(held["state"]),
        "confirmed": False,
        "applied": False,
        "expected_revision": expected_revision,
        "artifact_revision": revision,
        "approved_revision": None,
        "decided_by": who,
        "decided_at": None,
        "reconciliation": None,
        "reason": None,
    }


# --------------------------------------------------------------------------
# The pieces both paths need
# --------------------------------------------------------------------------


def _managed_database(path: str) -> str:
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        raise ReviewError(
            f"there is nothing to review for {path!r}:"
            f" {NO_MANAGED_DATABASE_REASON}"
        )
    return idb_path


def _catalog(path: str, idb_path: str, *, writable: bool = False) -> Catalog:
    """This target's catalog, opened for reading or for a decision.

    A database-only target is keyed by the provisional identity its managed
    record minted, which costs one read of that record; a target whose
    original bytes are in hand is keyed by their digest and costs nothing.
    Either way the catalog has to already exist: a review never creates one.
    """
    identity = None
    if Path(path).suffix.lower() in IDB_SUFFIXES:
        summary = invoke_ida(idb_path, _SUMMARY, {})
        identity = _text(summary.get("managed_idb_id"))
    probe = get_catalog(path, identity)
    if probe is None:
        raise ReviewError(
            f"there is nothing to review for {path!r}:"
            f" {CATALOG_UNAVAILABLE_REASON}"
        )
    if not writable:
        return probe
    probe.close()
    return open_catalog(path, identity)


def _held(catalog: Catalog, proposal_id: str, path: str) -> dict[str, object]:
    if not isinstance(proposal_id, str) or not proposal_id.strip():
        raise ReviewError("proposal_id must be a non-empty string")
    try:
        held = catalog.proposal(proposal_id)
    except CatalogError as refused:
        raise ReviewError(str(refused)) from refused
    if held is None:
        raise ReviewError(
            f"no proposal {proposal_id!r} is recorded for {path!r}; run"
            f" 'vulfi-mcp review list --path {shlex.quote(path)}' to see"
            " what is"
        )
    return held


def _body(held: dict[str, object]) -> dict[str, Any]:
    """The stored proposal, back through the validator that accepted it."""
    try:
        return validate_proposal(
            {
                "candidate_id": held["candidate_id"],
                "kind": held["kind"],
                "address_space": held["address_space"],
                "address": held["address"],
                "value": held["value"],
                "evidence": held["evidence"],
                "rationale": held["rationale"],
            }
        )
    except OperationError as refused:
        raise ReviewError(
            f"the stored proposal {held['proposal_id']!r} is not one this"
            f" build can act on: {refused}"
        ) from refused


def _unreviewable(
    held: dict[str, object], candidate: dict[str, Any] | None, body: dict[str, Any]
) -> str | None:
    """Why this proposal can no longer be decided, or ``None``."""
    if candidate is None:
        return (
            f"candidate {held['candidate_id']!r} is no longer recorded under"
            f" analysis {held['analysis_id']!r}: a later preparation run"
            " dropped it, so the evidence this proposal rests on is gone"
        )
    try:
        check_proposal_against_candidate(body, candidate)
    except PreparationError as refused:
        return str(refused)
    return None


def _reviewed(observed: dict[str, object]) -> dict[str, Any]:
    reviewed = observed.get("proposals")
    if not isinstance(reviewed, list) or len(reviewed) != 1:
        raise ReviewError(
            f"the IDA worker reported on {reviewed!r}, not on the one range"
            " this review is about"
        )
    return reviewed[0]


def _revision(observed: dict[str, object]) -> int:
    stored = observed.get("preparation")
    if not isinstance(stored, dict):
        raise ReviewError(
            f"the managed record carries no preparation summary: {stored!r}"
        )
    return _whole(stored.get("revision"))


def _whole(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _reviewer() -> str:
    """Who this run records as having decided.

    The OS user, because that is the principal whose permissions let this
    command run at all, and recording anything else would make the audit
    trail say something the system cannot back up.
    """
    for source in (
        lambda: os.environ.get("VULFI_MCP_REVIEWER", ""),
        getpass.getuser,
    ):
        try:
            who = (source() or "").strip()
        except Exception:  # noqa: BLE001 - getuser raises on an unnamed uid
            continue
        if who:
            return who
    return _UNKNOWN_REVIEWER


# --------------------------------------------------------------------------
# The command itself
# --------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulfi-mcp review",
        description=(
            "Review the recovery proposals an agent stored for a target."
            " This is the only path that applies one, and it applies one only"
            " after revalidating its evidence against the managed analysis as"
            " it is now. Anything able to run this command with the"
            " operator's permissions can approve a proposal; restrict who can"
            " run it if your installation needs enforced human separation."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list", help="what is waiting for a decision")
    listing.add_argument("--path", required=True, help="the reviewed target")
    listing.add_argument("--analysis-id", default=None, help="one revision only")
    listing.add_argument(
        "--state", default=None, choices=PROPOSAL_STATES, help="one state only"
    )
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--json", action="store_true", help="machine-readable")

    showing = commands.add_parser("show", help="one proposal and its evidence")
    showing.add_argument("--path", required=True)
    showing.add_argument("--proposal-id", required=True)
    showing.add_argument("--json", action="store_true")

    for name, verb in (("approve", "apply"), ("reject", "refuse")):
        decide = commands.add_parser(name, help=f"{verb} one proposal")
        decide.add_argument("--path", required=True)
        decide.add_argument("--proposal-id", required=True)
        decide.add_argument(
            "--expected-revision",
            type=int,
            required=True,
            help=(
                "the artifact revision you are deciding against, as"
                " 'review show' reports it; a decision made against an older"
                " one is refused rather than applied"
            ),
        )
        decide.add_argument(
            "--reason",
            default=None,
            required=name == "reject",
            help="why, recorded with the decision",
        )
        decide.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one review command. Returns the process exit status.

    ``0`` means the command did what it was asked. ``1`` means it did not —
    a refusal, a stale proposal, a failed write, or an operator who did not
    confirm — and in every one of those cases nothing was applied.
    """
    arguments = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    # With `--json` the one document on stdout is the result, so the dialogue
    # — the evidence and the prompt — goes to stderr. Without it, both go to
    # stdout in the order they happened, which is what a person reading their
    # terminal needs.
    dialogue = sys.stderr if arguments.json else sys.stdout
    try:
        if arguments.command == "list":
            page = list_proposals(
                arguments.path,
                arguments.analysis_id,
                arguments.state,
                arguments.offset,
                arguments.limit,
            )
            _emit(page, arguments.json, _render_list(page), dialogue)
            return 0
        briefing = proposal_briefing(arguments.path, arguments.proposal_id)
        if arguments.command == "show":
            _emit(briefing, arguments.json, _render_briefing(briefing), dialogue)
            return 0
        print(_render_briefing(briefing), file=dialogue)
        if briefing["proposal"]["state"] != "pending":
            print(
                f"This proposal is {briefing['proposal']['state']}, and only a"
                " pending proposal can be decided. Nothing was changed.",
                file=dialogue,
            )
            return 1
        if not _confirmed(arguments.command, dialogue):
            print(
                f"Nothing was {arguments.command}d and nothing was changed.",
                file=dialogue,
            )
            return 1
        result = review_proposal(
            arguments.path,
            arguments.proposal_id,
            arguments.command,
            arguments.expected_revision,
            reason=arguments.reason,
        )
    except (
        ReviewError,
        PreparationError,
        CatalogError,
        OperationError,
        ManagedDatabaseError,
        FileNotFoundError,
    ) as refused:
        print(f"vulfi-mcp review: {refused}", file=sys.stderr)
        return 1
    _emit(result, arguments.json, _render_result(result), dialogue)
    return 0 if result["confirmed"] else 1


def _emit(
    payload: dict[str, Any], as_json: bool, rendered: str, dialogue: Any
) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(rendered, file=dialogue)


def _confirmed(decision: str, dialogue: Any) -> bool:
    """Ask, and accept only the decision typed out in full."""
    print(
        f"\nThis {decision}s the proposal above."
        + (
            " Approving applies the change to the managed analysis and moves"
            " its revision."
            if decision == "approve"
            else " Rejecting records the decision and changes no analysis."
        ),
        file=dialogue,
    )
    print(
        f"Type '{decision}' to confirm, anything else to abort: ",
        end="",
        file=dialogue,
        flush=True,
    )
    try:
        answer = sys.stdin.readline()
    except (EOFError, KeyboardInterrupt):  # pragma: no cover - interactive only
        answer = ""
    print("", file=dialogue)
    return answer.strip() == decision


def _render_list(page: dict[str, Any]) -> str:
    lines = [
        f"{page['total']} proposal(s) for {page['path']}",
        f"  showing {page['loaded']} from offset {page['offset']}",
    ]
    for row in page["proposals"]:
        where = "-" if row["address"] is None else f"{row['address']:#x}"
        lines.append(
            f"  {row['proposal_id']}  {row['state']:<9} {row['kind']:<18}"
            f" {where:<12} {row['candidate_id']}"
        )
        lines.append(f"      {row['rationale']}")
    return "\n".join(lines)


def _render_briefing(briefing: Briefing) -> str:
    proposal = briefing["proposal"]
    site = briefing["site"]
    value = json.dumps(proposal["value"], sort_keys=True)
    lines = [
        f"Proposal {proposal['proposal_id']} — {proposal['kind']}"
        f" ({proposal['state']})",
        f"  target          {briefing['path']}",
        f"  managed         {briefing['idb_path']}"
        f" at revision {briefing['artifact_revision']}",
        f"  analysis        {proposal['analysis_id']}",
        f"  candidate       {proposal['candidate_id']}",
        f"  range           {site['start']:#x} .. {site['end']:#x}"
        f" ({site['size']} bytes) in segment {site['segment']}",
        f"  proposed        {briefing['effect']}",
        f"  value           {value}",
        f"  rationale       {proposal['rationale']}",
        "  evidence this proposal quotes from its candidate",
    ]
    for fact, claimed in sorted(proposal["evidence"].items()):
        lines.append(f"      {fact} = {json.dumps(claimed, default=str)}")
    quoted = str(site["bytes_hex"])[: _QUOTED_BRIEFING_BYTES * 2]
    lines.extend(
        [
            "  what the managed analysis holds here, now",
            f"      original bytes  {quoted or '(none)'}",
            f"      bytes sha256    {site['bytes_sha256']}",
            f"      name            {site['name'] or '(none)'}",
            f"      function        {_render_function(site['function'])}",
            f"      type            {_render_type(site['existing_type'])}",
            f"      defined items   {_render_items(site['items'])}",
        ]
    )
    if briefing["candidate"] is not None:
        candidate = briefing["candidate"]
        lines.append(
            f"  candidate state {candidate['state']} ({candidate['backend']},"
            f" confidence {candidate['confidence']})"
        )
        if candidate["reason"]:
            lines.append(f"      {candidate['reason']}")
    lines.append(
        "  conflicts       "
        + ("(none)" if not briefing["conflicts"] else "")
    )
    for conflict in briefing["conflicts"]:
        lines.append(f"      {conflict}")
    if briefing["reason"]:
        lines.append(f"  NOT REVIEWABLE  {briefing['reason']}")
    return "\n".join(lines)


def _render_function(function: object) -> str:
    if not isinstance(function, dict):
        return "(none)"
    return f"{function['name']} [{function['start']:#x}, {function['end']:#x})"


def _render_type(held: object) -> str:
    if not isinstance(held, dict):
        return "(none)"
    return f"{held['name']} ({held['shape']}, {held['size']} bytes)"


def _render_items(items: object) -> str:
    if not isinstance(items, list) or not items:
        return "(none)"
    return ", ".join(
        f"{item['size']} bytes at {item['address']:#x}" for item in items
    )


def _render_result(result: ReviewResult) -> str:
    lines = [
        f"{result['decision']} {result['proposal_id']}: "
        + ("recorded" if result["confirmed"] else "NOT recorded as asked"),
        f"  state             {result['state']}",
        f"  applied           {result['applied']}",
        f"  expected revision {result['expected_revision']}",
        f"  artifact revision {result['artifact_revision']}",
        f"  approved revision {result['approved_revision']}",
        f"  reviewer          {result['decided_by']}",
    ]
    if result["reason"]:
        lines.append(f"  reason            {result['reason']}")
    if result["reconciliation"] is not None:
        lines.append(f"  reconciliation    {json.dumps(result['reconciliation'])}")
    return "\n".join(lines)
