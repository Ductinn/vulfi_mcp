"""JSON-native result contracts shared by the VulFi MCP tools.

Every type here serializes to plain JSON (``str``/``int``/``bool``/``None``/
``list``/``dict``) so a result can cross the MCP boundary and be stored verbatim
in the managed IDB netnode. This module deliberately imports nothing from
:mod:`vulfi_mcp.rules`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypeAlias, TypedDict

__all__ = [
    "AddressGap",
    "AddressRange",
    "AttemptOutcome",
    "Backend",
    "BackendAttempt",
    "Candidate",
    "CandidateKind",
    "CandidateState",
    "ExternalScope",
    "Finding",
    "FindingsPage",
    "JsonValue",
    "PassName",
    "PassResult",
    "PassRouting",
    "PassStage",
    "PreparationPage",
    "PreparationResult",
    "Priority",
    "RangeCoverage",
    "RouteState",
    "RuleCoverage",
    "RuleEvidence",
    "RuleRouting",
    "RuleState",
    "ScanCoverage",
    "ScanResult",
    "ScopeState",
    "SkippedPrerequisite",
    "SyncState",
    "TriageResult",
    "TriageStatus",
    "ChosenSource",
    "LinkResult",
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

    #: The candidate kinds this build produces, one per pass that finds
    #: them. A structure or a pointer table carries the accesses or the
    #: relocation records it was inferred from, exactly as the other two
    #: carry their bytes and their instructions.
    CandidateKind = Literal["function", "string", "structure", "pointer_table"]

    #: How an IDA row and its reviewer-linked external partner stand. Plan 4
    #: creates links; until then every stored row is ``unlinked``, which is not
    #: the same claim as ``synchronized``.
    SyncState = Literal[
        "unlinked", "pending", "synchronized", "conflict", "paused", "unavailable"
    ]

    #: What one backend made of one pass or one rule when it was asked.
    #:
    #: The five are deliberately not collapsible, and each one decides what
    #: the chain does next.
    #:
    #: ``answered``
    #:     Evidence. This backend's result was recorded.
    #: ``unsupported``
    #:     A session that really opened, stating it cannot establish this
    #:     fact at all. The chain advances; this is the capability
    #:     fall-through the whole design is built on.
    #: ``failed``
    #:     A session that opened and a call that did not finish — a drifted
    #:     schema, a reply it could not read. The chain advances too, because
    #:     loudness is a property of the report and not of the search, but
    #:     the failure is sticky: it is kept against this backend, no later
    #:     answer erases it, and nothing it touched is ever summarised as
    #:     complete.
    #: ``unavailable``
    #:     Nobody looked: no configuration, no session. The chain advances.
    #: ``unverified``
    #:     This backend could not be shown to be looking at the same bytes.
    #:     The chain **stops** here for this pass or rule. "We cannot prove
    #:     it is the same binary" is not "it had nothing to offer", and
    #:     advancing past it is how a result from one image ends up
    #:     aggregated against another.
    AttemptOutcome = Literal[
        "answered", "unsupported", "failed", "unavailable", "unverified"
    ]

    #: What the whole chain made of one pass or one rule. The same five
    #: words, now describing every backend together: ``unavailable`` means no
    #: backend in the chain was reachable, ``unsupported`` means at least one
    #: answered and none could establish it, ``failed`` means at least one
    #: tried and could not finish and nothing later answered either, and
    #: ``unverified`` means the chain refused on identity.
    RouteState = AttemptOutcome

    #: What one stored external scope records about the scan that wrote it.
    #: ``evaluated`` means a backend really ran these rules over this scope;
    #: the others carry the same distinctions :data:`AttemptOutcome` does.
    ScopeState = Literal["evaluated", "failed", "unavailable", "unverified"]
    ChosenSource = Literal["ida", "external", "new"]
else:
    Backend = Priority = TriageStatus = ScanCoverage = RuleState = SyncState = str
    PassName = PassStage = RangeCoverage = CandidateState = CandidateKind = str
    AttemptOutcome = RouteState = ScopeState = ChosenSource = str


class LinkResult(TypedDict):
    """What one local ``vulfi-mcp link`` decision did.

    ``confirmed`` is true only after the IDB save and the catalog event both
    landed. ``pending`` is the crash window between those two. This is not an
    MCP tool result.
    """

    confirmed: bool
    sync_state: str
    link_id: str | None
    link_revision: int | None
    event_id: str | None
    ida_finding_id: str
    external_finding_id: str
    chosen_source: str | None
    status: str | None
    rationale: str | None
    reason: str
    proof: dict[str, JsonValue]



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
    scope_health: dict[str, JsonValue]
    store_health: dict[str, JsonValue]
    sync_state: SyncState
    #: Rows this response carries. ``target_total`` is every row the available
    #: stores hold; a missing store is not counted as zero.
    loaded: int
    #: One entry per reviewer link visible to this page. A linked pair is
    #: still two findings; this does not merge them.
    links: list[dict[str, JsonValue]]
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
    #: Both members, and only after a confirmed linked save. Absent on an
    #: unlinked assessment, which still returns ``finding`` alone.
    findings: NotRequired[list[Finding]]
    scope_health: NotRequired[dict[str, JsonValue]]
    links: NotRequired[list[dict[str, JsonValue]]]
    loaded: NotRequired[int]


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
    #: Present only when a session was open and a call that would have read
    #: this range was refused. The value is the provider's own refusal.
    #: A budget stop, an intentional skip, and a short read that is not a
    #: provider error do not set it. Routing reads this field; it does not
    #: parse ``reason`` or warnings.
    refusal: NotRequired[str]


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


class RuleEvidence(TypedDict):
    """What one backend established about one rule, before it is evaluated.

    This is the shape an external provider hands back, and it carries facts
    rather than verdicts: :mod:`vulfi_mcp.ida_runtime`'s ``evaluate_rule`` is
    still the only thing that turns facts into a priority, so a second backend
    cannot reach a different conclusion from the same evidence.

    ``contexts`` is one validated fact dictionary per call site, in the shape
    :func:`vulfi_mcp.providers.rule_contexts` converts to a
    :class:`vulfi_mcp.ida_runtime.RuleContext`. A fact that is absent from the
    dictionary is absent from the context, which is not the same as ``False``:
    a predicate that needs it refuses to answer. Nothing may be inferred from
    decompiled text here — a provider that only has pseudocode has no
    contexts, and says so with ``state`` and ``reason``.

    ``ranges`` is what the provider actually looked at, so a rule evaluated
    over half an image is not reported as if it had been evaluated over all of
    it. ``state`` is ``evaluated`` only when every context in it was proven;
    ``unsupported`` when this backend cannot establish the facts this rule
    needs, ``failed`` when it tried and could not finish, and ``reason`` says
    which in both cases.
    """

    backend: Backend
    rule_index: int
    contexts: list[dict[str, JsonValue]]
    ranges: list[AddressRange]
    state: RuleState
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
#: managed artifact's revision these results describe. ``refusal`` is
#: set when a session was open and a call was refused. A pass that had
#: not yet measured a range advances; a pass that already had bytes keeps
#: those ranges and the failed attempt, and does not advance. Routing
#: reads that field, not warning prose.
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
        "refusal": NotRequired[str],
    },
)


#: One stage a requested subset of passes could not run.
#:
#: Spelled with the functional syntax for the same reason :data:`PassResult`
#: is: the field the worker produces is named ``pass``, which the class
#: syntax cannot declare.
#:
#: A subset never reports a coverage it did not produce: the stage is named
#: here, with the pass it needed, rather than being left out of the result as
#: if it had run and found nothing.
SkippedPrerequisite = TypedDict(
    "SkippedPrerequisite",
    {
        "pass": PassName,
        "stage": PassStage,
        "requires": PassName,
        "reason": str,
    },
)


class BackendAttempt(TypedDict):
    """What one backend made of one pass or one rule when it was asked.

    This is the row that keeps "nobody looked" apart from "we looked and
    could not read it" apart from "we looked and it is clean". A router that
    reported only the backend that answered would leave a reader unable to
    tell a Ghidra that was never configured from a Ghidra whose schema had
    drifted, and those are different things to go and fix.

    ``outcome`` decides what the chain did next, and
    :data:`AttemptOutcome` spells out each one. Four of the five advance to
    the next backend; only ``unverified`` stops, because an unprovable
    identity is the one refusal another backend cannot stand in for.

    A ``failed`` attempt is **sticky**. It advances the chain so evidence we
    really have is not thrown away over a transient fault in a backend that
    may not have been the one able to answer — and it stays in this list,
    stays in the catalog, and keeps anything it touched from ever being
    summarised as complete. "ghidra: failed (reason); r2: evaluated, no
    finding" is the shape; a later answer is reported *alongside* the
    failure, never instead of it.
    """

    backend: Backend
    outcome: AttemptOutcome
    reason: str | None


#: How one requested pass was routed, and what every backend said about it.
#:
#: Spelled with the functional syntax for the same reason :data:`PassResult`
#: is: the field is named ``pass``, which the class syntax cannot declare.
#:
#: ``backend`` is the one whose :class:`PassResult` was recorded, and is
#: ``None`` when no backend produced one. ``coverage`` is that result's own
#: coverage, carried through unchanged — routing never upgrades a pass
#: summary, and ``unavailable`` is never upgraded by anything. ``attempts``
#: is every backend that was asked, in the order the chain asked them.
PassRouting = TypedDict(
    "PassRouting",
    {
        "pass": PassName,
        "backend": Backend | None,
        "state": RouteState,
        "coverage": RangeCoverage,
        "attempts": list[BackendAttempt],
        "reason": str | None,
    },
)


class RuleRouting(TypedDict):
    """How one rule was routed, and what every backend said about it.

    ``backend`` is the one whose evidence became a verdict, and is ``None``
    when none did. ``state`` is that backend's :class:`RuleCoverage` state,
    or the chain's own verdict when nothing answered: ``unsupported`` when a
    backend answered and could not establish the rule's facts, ``failed``
    when one tried and could not finish, ``unavailable`` when none opened.
    ``reason`` names the missing fact, never the provider's prose.
    """

    rule_index: int
    rule_name: str
    backend: Backend | None
    state: RouteState
    reason: str | None
    attempts: list[BackendAttempt]


class ExternalScope(TypedDict):
    """One backend's own ``default|custom:<scan_name>`` scope, as stored.

    Scopes are independent: a complete scan of one retires only that one's
    rows, and the IDA store and every other scope of every other backend are
    untouched by it. ``state`` and ``coverage`` are separate claims on
    purpose — ``state`` says whether a backend ran these rules at all, and
    ``coverage`` says how much of the image the run that did covered.
    ``stale_total`` counts rows a later partial or failed scan did not
    observe again and therefore kept rather than deleted.
    """

    backend: Backend
    scope: str
    scan_id: str | None
    scanned_at: str | None
    state: ScopeState
    coverage: ScanCoverage | None
    reason: str | None
    capability_fingerprint: str | None
    rule_coverage: list[RuleCoverage]
    rules: list[dict[str, JsonValue]]
    warnings: list[str]
    total: int
    stale_total: int



class PreparationResult(TypedDict):
    """One preparation revision of one target, as ``vulfi_prepare`` reports it.

    ``reused`` is the whole claim about whether anything ran. ``True`` means
    an already-recorded revision matched this request on all four counts the
    design requires — source identity, managed artifact, backend capability
    fingerprint and the requested pass coverage — so no pass ran, nothing was
    applied and ``preparation_revision`` is exactly where it was. ``False``
    means the passes in ``passes`` ran against the managed artifact just now.

    ``candidates`` is the *first page* of what the catalog holds, ordered the
    way :func:`vulfi_mcp.prepare.preparation_page` orders it; ``candidate_total``
    counts them all and ``vulfi_preparation`` pages the rest. ``applied_ids``
    is bounded the same way and ``applied_total`` is exact. ``coverage`` is
    the weakest coverage of any recorded pass, so one ``partial`` range makes
    the whole revision ``partial`` — which is the ordinary outcome on a real
    image, not a failure.

    ``skipped_prerequisites`` describes *this call's* run and is empty when a
    revision was reused; what each pass found is in ``passes`` either way.

    ``routing`` is one row per *requested* pass, naming every backend the
    chain asked and what each one said. ``passes`` holds only the results
    that were recorded, so a pass no backend could run is in ``routing`` and
    not in ``passes`` — named, rather than left out as if it had run and
    found nothing. ``idb_path`` is ``None`` when the chain never involved
    IDA: a Ghidra-only preparation has no managed IDB, and naming one would
    read as a database this call made.
    """

    path: str
    idb_path: str | None
    backend: Backend
    requested_backend: str
    analysis_id: str
    target_key: str
    source_sha256: str | None
    managed_idb_id: str | None
    source_association: str | None
    capability_fingerprint: str
    preparation_revision: int
    reused: bool
    requested_passes: list[PassName]
    passes: list[PassResult]
    coverage: RangeCoverage
    candidates: list[Candidate]
    candidate_total: int
    applied_ids: list[str]
    applied_total: int
    skipped_prerequisites: list[SkippedPrerequisite]
    routing: list[PassRouting]
    artifact_paths: dict[str, JsonValue]
    catalog_available: bool
    warnings: list[str]


class PreparationPage(TypedDict):
    """One window of a recorded preparation, read without re-running anything.

    ``available`` is the distinction this page exists to keep: ``False`` with
    a ``reason`` means the candidate store could not answer — no managed
    database, no catalog, or nothing prepared — and a reader must not render
    that as a target whose preparation found nothing. ``True`` with an empty
    ``candidates`` list is the other answer, and means exactly what it says.
    """

    path: str
    idb_path: str | None
    backend: Backend
    available: bool
    reason: str | None
    analysis_id: str | None
    target_key: str | None
    source_sha256: str | None
    managed_idb_id: str | None
    source_association: str | None
    preparation_revision: int | None
    offset: int
    limit: int
    total: int
    loaded: int
    candidates: list[Candidate]
    passes: list[PassResult]
    warnings: list[str]
