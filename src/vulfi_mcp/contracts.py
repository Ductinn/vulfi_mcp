"""JSON-native result contracts shared by the VulFi MCP tools.

Every type here serializes to plain JSON (``str``/``int``/``bool``/``None``/
``list``/``dict``) so a result can cross the MCP boundary and be stored verbatim
in the managed IDB netnode. This module deliberately imports nothing from
:mod:`vulfi_mcp.rules`.
"""

from __future__ import annotations

from typing import Literal, TypedDict

__all__ = [
    "Backend",
    "Finding",
    "FindingsPage",
    "Priority",
    "RuleCoverage",
    "ScanCoverage",
    "ScanResult",
    "ScopeSummary",
    "SyncState",
    "TriageResult",
    "TriageStatus",
]

Backend = Literal["ida", "ghidra", "r2"]
Priority = Literal["High", "Medium", "Low", "Info"]
TriageStatus = Literal["Not Checked", "False Positive", "Suspicious", "Vulnerable"]
ScanCoverage = Literal["complete", "partial"]

#: How an IDA row and its reviewer-linked external partner stand. Plan 4
#: creates links; until then every stored row is ``unlinked``, which is not
#: the same claim as ``synchronized``.
SyncState = Literal["unlinked", "pending", "synchronized", "conflict", "paused"]


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
    evidence: dict[str, object]


class RuleCoverage(TypedDict):
    """What actually happened to one submitted rule.

    ``unsupported`` means the backend could not supply the facts the rule needs
    and ``failed`` means extraction or evaluation errored; neither is reported
    as a clean negative. ``reason`` is ``None`` only for ``evaluated``.
    """

    rule_index: int
    backend: Backend
    state: Literal["evaluated", "unsupported", "failed"]
    reason: str | None


class ScanResult(TypedDict):
    """Result of one scan of one scope on one backend.

    ``findings`` holds the first page of this scope's stored rows;
    ``scope_total`` counts the scope and ``target_total`` counts every
    available store for the target, with ``target_total_complete`` false when
    a store is unavailable. ``status_counts`` maps a backend name (plus
    ``"aggregate"``) to triage status counts, and counts findings rather than
    deduplicated vulnerabilities. ``store_health`` says which stores answered,
    so a store that is absent is never read as an empty one.
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
    scope_health: dict[str, object]
    store_health: dict[str, object]
    sync_state: SyncState
    warnings: list[str]


class ScopeSummary(TypedDict):
    """One stored scope, as the store reports it alongside a page.

    ``stale`` counts rows the scope's last scan did not observe again: a
    partial scan keeps them rather than retiring a call site it never looked
    at, so they are reported, and labelled, instead of silently dropped.
    """

    scope: str
    backend: Backend
    scan_id: str | None
    scanned_at: str | None
    coverage: ScanCoverage | None
    total: int
    stale: int


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
    store_health: dict[str, object]
    sync_state: SyncState
    warnings: list[str]


class TriageResult(TypedDict):
    """One accepted assessment, as the store committed it.

    ``triage_revision`` counts accepted updates to this one finding; a
    rejected update writes nothing and leaves it where it was.
    """

    path: str
    idb_path: str
    finding: Finding
    triage_revision: int
    target_total: int
    status_counts: dict[str, dict[str, int]]
    store_health: dict[str, object]
    sync_state: SyncState
    warnings: list[str]
