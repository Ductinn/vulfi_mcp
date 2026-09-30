"""JSON-native result contracts shared by the VulFi MCP tools.

Every type here serializes to plain JSON (``str``/``int``/``bool``/``None``/
``list``/``dict``) so a result can cross the MCP boundary and be stored verbatim
in the managed IDB netnode. This module deliberately imports nothing from
:mod:`vulfi_mcp.rules`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, TypeAlias, TypedDict

__all__ = [
    "Backend",
    "Finding",
    "FindingsPage",
    "JsonValue",
    "Priority",
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

    #: How an IDA row and its reviewer-linked external partner stand. Plan 4
    #: creates links; until then every stored row is ``unlinked``, which is not
    #: the same claim as ``synchronized``.
    SyncState = Literal["unlinked", "pending", "synchronized", "conflict", "paused"]
else:
    Backend = Priority = TriageStatus = ScanCoverage = RuleState = SyncState = str


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
