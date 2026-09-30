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
    "Priority",
    "RuleCoverage",
    "ScanCoverage",
    "ScanResult",
    "TriageStatus",
]

Backend = Literal["ida", "ghidra", "r2"]
Priority = Literal["High", "Medium", "Low", "Info"]
TriageStatus = Literal["Not Checked", "False Positive", "Suspicious", "Vulnerable"]
ScanCoverage = Literal["complete", "partial"]


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

    ``findings`` holds the first page of this scope's rows; ``scope_total``
    counts the scope and ``target_total`` counts every available store for the
    target, with ``target_total_complete`` false when a store is unavailable.
    ``status_counts`` maps a backend name (plus ``"aggregate"``) to triage
    status counts, and counts findings rather than deduplicated vulnerabilities.
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
    warnings: list[str]
