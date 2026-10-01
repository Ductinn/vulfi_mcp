"""JSON-native result contracts shared by the VulFi MCP tools.

Every type here serializes to plain JSON (``str``/``int``/``bool``/``None``/
``list``/``dict``) so a result can cross the MCP boundary and be stored verbatim
in the managed IDB netnode. This module deliberately imports nothing from
:mod:`vulfi_mcp.rules`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, TypeAlias, TypedDict

__all__ = [
    "AddressGap",
    "AddressRange",
    "Backend",
    "Candidate",
    "CandidateKind",
    "CandidateState",
    "Finding",
    "FindingsPage",
    "JsonValue",
    "PassName",
    "PassResult",
    "PassStage",
    "Priority",
    "RangeCoverage",
    "RuleCoverage",
    "RuleState",
    "ScanCoverage",
    "ScanResult",
    "SyncState",
    "TriageResult",
    "TriageStatus",
]

#: One arbitrary JSON value. Spelled ``Any`` rather than ``object`` because
#: the MCP schema generator these contracts are published through maps
#: ``object`` to ``{"type": "object"}`` — "this value must itself be a JSON
#: object" — which the integers, strings and booleans the free-form fields
#: below really carry would violate. ``Any`` publishes the empty schema,
#: which is the truth about them: any JSON value at all.
JsonValue: TypeAlias = Any

# The closed value sets below are ``Literal`` for a type checker and plain
# ``str`` at run time, and that split is deliberate. ``zeromcp`` derives each
# tool's advertised ``outputSchema`` from these annotations at run time, and
# maps every construct it does not recognise — ``Literal`` among them — to
# ``{"type": "object"}``. Publishing the ``Literal`` itself therefore
# advertises that ``backend`` must be a JSON *object* while every payload
# sends the string ``"ida"``, so a client that validates structured results,
# as MCP 2025-06-18 says it should, rejects every successful call. ``str``
# publishes ``{"type": "string"}``, which is what these fields are; the
# enumeration stays here for every reader and every type checker. Nothing
# inspects these aliases at run time.
if TYPE_CHECKING:
    Backend = Literal["ida", "ghidra", "r2"]
    Priority = Literal["High", "Medium", "Low", "Info"]
    TriageStatus = Literal["Not Checked", "False Positive", "Suspicious", "Vulnerable"]
    ScanCoverage = Literal["complete", "partial"]
    RuleState = Literal["evaluated", "unsupported", "failed"]

    #: The four preparation passes the RE preparation design defines, in
    #: dependency order. :mod:`vulfi_mcp.prepare` runs the subset this build
    #: implements and refuses the rest by name.
    PassName = Literal["strings", "functions", "structures", "pointer_tables"]

    #: The stage inside a pass that produced one range's evidence. Raw-byte
    #: discovery stands on its own; instruction-derived discovery needs the
    #: ``functions`` pass to have run first.
    PassStage = Literal["raw_bytes", "instructions", "code_scan"]

    #: What one pass may claim about one address range. There is no fourth
    #: answer: a range nothing looked at is not a range that held nothing.
    RangeCoverage = Literal["complete", "partial", "unavailable"]

    #: What preparation produced. A candidate is a description; only
    #: ``applied`` says the managed artifact changed.
    CandidateState = Literal["candidate", "applied", "rejected"]

    #: The candidate kinds this build produces. Plan 2's later tasks add the
    #: structure-field and pointer-table kinds with the passes that find them.
    CandidateKind = Literal["function", "string"]

    #: How an IDA row and its reviewer-linked external partner stand. Plan 4
    #: creates links; until then every stored row is ``unlinked``, which is not
    #: the same claim as ``synchronized``.
    SyncState = Literal["unlinked", "pending", "synchronized", "conflict", "paused"]
else:
    Backend = Priority = TriageStatus = ScanCoverage = RuleState = SyncState = str
    PassName = PassStage = RangeCoverage = CandidateState = CandidateKind = str


class Finding(TypedDict):
    """One rule match at one call site.

    ``id`` joins backend, scope, rule index, rule digest, address space,
    lowercase hexadecimal address and occurrence ordinal, so duplicate-named
    rules and distinct call sites never collide. ``stale`` marks a row that a
    later partial scan did not observe again.
    """

    id: str
    backend: Backend
    source: str
    binary_sha256: str | None
    rule_index: int
    rule_digest: str
    rule_name: str
    function_name: str
    found_in: str
    address_space: str
    address: str
    relative_address: str | None
    occurrence: int
    priority: Priority
    status: TriageStatus
    rationale: str
    assessed_at: str | None
    triage_revision: int
    link_id: str | None
    link_revision: int | None
    last_seen_scan_id: str
    stale: bool
    evidence: dict[str, JsonValue]


class RuleCoverage(TypedDict):
    """What actually happened to one submitted rule.

    ``unsupported`` means the backend could not supply the facts the rule needs
    and ``failed`` means extraction or evaluation errored; neither is reported
    as a clean negative. ``reason`` is ``None`` only for ``evaluated``.
    """

    rule_index: int
    backend: Backend
    state: RuleState
    reason: str | None


class ScanResult(TypedDict):
    """Result of one scan of one scope on one backend.

    ``findings`` holds the first page of this scope's stored rows;
    ``scope_total`` counts the scope and ``target_total`` counts every
    available store for the target, with ``target_total_complete`` false when
    a store is unavailable. ``status_counts`` maps a backend name (plus
    ``"aggregate"``) to triage status counts over the same rows
    ``target_total`` counts — every stored row of the target, across every
    scope of that backend, not this scan's own findings — and counts findings
    rather than deduplicated vulnerabilities. ``store_health`` says which
    stores answered, so a store that is absent is never read as an empty one.
    """

    path: str
    idb_path: str | None
    binary_sha256: str | None
    analysis_id: str | None
    preparation_revision: int | None
    backend: Backend
    scope: str
    scan_id: str
    scanned_at: str
    coverage: ScanCoverage
    rule_coverage: list[RuleCoverage]
    findings: list[Finding]
    scope_total: int
    target_total: int
    target_total_complete: bool
    status_counts: dict[str, dict[str, int]]
    scope_health: dict[str, JsonValue]
    store_health: dict[str, JsonValue]
    sync_state: SyncState
    warnings: list[str]


class FindingsPage(TypedDict):
    """One page of stored rows, read without rescanning anything.

    Rows are ordered by verified address space, then location, then finding
    ID, across every scope of the backend. The order is total and stable, but
    it is not a snapshot: a rescan between two pages can change what the next
    page holds.
    """

    path: str
    idb_path: str
    offset: int
    limit: int
    findings: list[Finding]
    page_total: int
    target_total: int
    target_total_complete: bool
    stale_total: int
    status_counts: dict[str, dict[str, int]]
    store_health: dict[str, JsonValue]
    sync_state: SyncState
    warnings: list[str]


class TriageResult(TypedDict):
    """One accepted assessment, as the store committed it.

    ``triage_revision`` counts accepted updates to this one finding; a
    rejected update writes nothing and leaves it where it was.
    ``target_total`` and ``status_counts`` cover every stored row of the
    target, as they do on a scan or a page, and ``target_total_complete`` is
    false while one of the target's stores is unavailable.
    """

    path: str
    idb_path: str
    finding: Finding
    triage_revision: int
    target_total: int
    target_total_complete: bool
    status_counts: dict[str, dict[str, int]]
    store_health: dict[str, JsonValue]
    sync_state: SyncState
    warnings: list[str]


class AddressGap(TypedDict):
    """One half-open stretch of addresses a bounded pass never looked at.

    Named, rather than dropped, because "the pass found nothing here" and
    "the pass never got here" are different answers and only one of them is
    evidence.
    """

    start: int
    end: int


class AddressRange(TypedDict):
    """What one pass stage did with one half-open address range.

    ``coverage`` is per range, not per pass: a run that exhausted its budget
    half way through a segment reports that segment ``partial`` and names the
    rest in ``unvisited``, while the segments it finished stay ``complete``.
    ``unavailable`` means the stage could not read this range at all — an
    uninitialized segment, or an architecture whose instructions this build
    does not model — and ``reason`` then says which.
    """

    name: str
    stage: PassStage
    start: int
    end: int
    coverage: RangeCoverage
    unvisited: list[AddressGap]
    reason: str | None


class Candidate(TypedDict):
    """One thing preparation found, and the evidence that it is there.

    ``state`` is the whole claim. ``applied`` means the managed artifact now
    carries this definition; ``candidate`` means it does not, and ``reason``
    says what was missing. ``confidence`` is a number in 0..1 and is never
    proof: a candidate with high confidence is still a candidate.

    ``evidence`` carries the bytes or the instructions the recovery rests on,
    with their addresses, so a reader can check the claim against the image
    instead of trusting the label. ``address`` is the normalized address in
    ``address_space`` where one is provable, and ``None`` where it is not.
    """

    candidate_id: str
    kind: CandidateKind
    backend: Backend
    address_space: str
    address: int | None
    evidence: dict[str, JsonValue]
    confidence: float
    state: CandidateState
    reason: str | None


#: Result of one preparation pass on one backend.
#:
#: Spelled with the functional syntax because ``pass`` is a Python keyword and
#: the design names the field ``pass``; the class syntax cannot declare it.
#:
#: ``coverage`` summarizes ``ranges``: ``complete`` only when every range is,
#: and ``partial`` as soon as one range was cut short — a pass never reports
#: ``complete`` over a range it stopped in the middle of. ``applied_ids`` and
#: ``candidate_ids`` both name rows in ``candidates``; a candidate id that is
#: not in ``applied_ids`` changed nothing. ``artifact_revision`` is the
#: managed artifact's revision these results describe.
PassResult = TypedDict(
    "PassResult",
    {
        "pass": PassName,
        "backend": Backend,
        "ranges": list[AddressRange],
        "coverage": RangeCoverage,
        "applied_ids": list[str],
        "candidate_ids": list[str],
        "warnings": list[str],
        "artifact_revision": int | None,
    },
)
