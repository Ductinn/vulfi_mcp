"""The public MCP entry point: seven VulFi tools beside the six stock IDA ones.

Importing this module registers the VulFi tools on the process-wide server the
official ``ida-mcp`` package already owns, so one stdio connection serves the
six stock IDA tools and these seven together. There is no second MCP server
and no fork of the official one.

What this milestone implements is the IDA backend and nothing else. A caller
may pass the parameters the full design reserves — ``backend`` and
``binary_path`` — and each of them is answered honestly: an unimplemented
capability is refused by name, never served as an empty success that reads
like "nothing found". Reviewer-linked triage uses the catalog journal. An unlinked finding
still updates only its own store.

Preparation *is* built here. ``vulfi_prepare`` recovers what the evidence
justifies in a managed analysis, ``vulfi_preparation`` pages what it found
without re-running it, and ``vulfi_scan`` prepares before it scans unless a
recorded revision already matches the request.

``vulfi_propose_recovery`` is the one thing an agent may ask for that
preparation's own evidence does not justify — and it is stored, not done.
**No tool in this module approves anything.** Applying a proposal lives in
:mod:`vulfi_mcp.operator` and is reached only by running ``vulfi-mcp review``
at a shell, where an operator is shown the bytes and the definitions already
in the database and has to type the decision out. That separation is
procedural: anything holding the operator's own OS credentials can run that
command, so an installation needing enforced human separation has to run this
server as a different principal from the reviewer.

Three rules shape the order of every tool body. Untrusted input is validated
first, so a malformed rule, scan name, page window, pass list, proposal or
assessment can never be the reason a managed IDB or its netnode came into
existence. Only ``vulfi_scan`` and ``vulfi_prepare`` may bring a managed
database into existence at all; every read, and every proposal, reports an
unavailable store instead. And stdout is the MCP transport: this module
writes nothing to it.
"""

# Deliberately not `from __future__ import annotations`. The official `@tool`
# decorator wraps each function with `functools.wraps`, and the schema
# generator then resolves that wrapper's annotations against *its* module
# globals, where this module's names do not exist. Real annotation objects,
# evaluated here at definition time, are the ones that survive that wrapping.

import sys
from typing import Annotated

from ida_mcp.mcp import serve_stdio, tool

from vulfi_mcp.contracts import (
    FindingsPage,
    JsonValue,
    PreparationPage,
    PreparationResult,
    ScanResult,
    TriageResult,
)
from vulfi_mcp.ida_runtime import (
    CUSTOM_SCOPE_PREFIX,
    DEFAULT_SCOPE,
    validate_page,
    validate_scan_name,
)
from vulfi_mcp.prepare import (
    ProposalResult,
    backend_chain,
    findings_across_backends,
    prepare_target,
    preparation_page,
    propose_recovery,
    scan_target,
    triage_across_backends,
)
from vulfi_mcp.rules import Rule, load_stock_rules, rule_template, validate_rules

__all__ = [
    "apply_linked_update",
    "main",
    "replay_linked_updates",
    "vulfi_findings",
    "vulfi_prepare",
    "vulfi_preparation",
    "vulfi_propose_recovery",
    "vulfi_rule_template",
    "vulfi_scan",
    "vulfi_triage",
]


def _scope_and_rules(
    rules: list[Rule] | None, scan_name: str
) -> tuple[str, tuple[Rule, ...]]:
    """Resolve which rules run and which scope records them, validating both.

    Every rejection here happens while the rules are still JSON: an agent's
    expression is parsed and whitelist-checked, never executed, and a rule that
    fails names its own index.
    """
    name = validate_scan_name(scan_name)
    if rules is None:
        # The stock scope is `default` whatever `scan_name` says; `scan_name`
        # only names a scope that custom rules created.
        return DEFAULT_SCOPE, load_stock_rules()
    validated = validate_rules(rules)
    if not validated:
        raise ValueError(
            "rules: an empty list selects no rule at all; supply at least one"
            " rule, or omit 'rules' to run the 24 stock rules in scope"
            f" {DEFAULT_SCOPE!r}"
        )
    return f"{CUSTOM_SCOPE_PREFIX}{name}", validated


@tool(title="Describe the VulFi rule format", read_only=True)
def vulfi_rule_template() -> dict[str, JsonValue]:
    """Describe the VulFi rule format: the schema one rule object must follow,
    worked examples, the restricted expression language a `mark_if` branch may
    use, its limits, and what the scanner reports when a rule cannot be
    evaluated. Read this before authoring rules for vulfi_scan; expressions are
    interpreted from a restricted syntax tree, never with Python eval, and any
    unsupported syntax is refused with a rule-indexed error.
    """
    return rule_template()


@tool(title="Scan a binary for VulFi rule matches")
def vulfi_scan(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb to scan. It is copied into a"
        " managed workspace and only the copy is analyzed; the supplied file is"
        " never modified.",
    ],
    rules: Annotated[
        list[Rule] | None,
        "Rules to run. Omit or pass null to run the 24 stock VulFi rules in"
        " scope 'default'. A nonempty list runs only those rules, in scope"
        " 'custom:<scan_name>'. An empty list is an error. Call"
        " vulfi_rule_template for the schema.",
    ] = None,
    scan_name: Annotated[
        str,
        "ASCII identifier naming the scope custom rules are recorded in"
        " ('custom:<scan_name>'). Rescanning the same scope replaces its rows"
        " and carries earlier assessments forward.",
    ] = "agent",
    backend: Annotated[
        str,
        "Analysis backend: 'auto', 'ida', 'ghidra' or 'r2'. 'auto' decides"
        " per rule — IDA first, then a configured Ghidra MCP, then a"
        " configured radare2 MCP — and only for rules the previous backend"
        " could not establish the facts for. Naming one backend runs exactly"
        " that one, with no fallback: a result produced by IDA is not a"
        " Ghidra result.",
    ] = "auto",
    analysis_id: Annotated[
        str | None,
        "Preparation revision to scan. Omit to use the recorded revision that"
        " matches this target, preparing one first if there is none. A value"
        " that names no reusable revision is refused rather than replaced"
        " with a different one.",
    ] = None,
) -> ScanResult:
    """Scan a binary or IDA database for VulFi rule matches and store the rows
    in each backend's own scope. Rules are validated in full before any
    database is created or opened. The target is then prepared — hidden
    functions, undefined strings, structure fields and pointer tables
    recovered where the evidence justifies it, by whichever backend can
    justify each pass — unless a recorded preparation revision already
    matches this request, in which case it is reused and nothing is applied
    again. Every rule is then routed on its own: IDA evaluates what its
    evidence supports, and each rule it reported unsupported or failed is
    asked of the configured external providers in turn. Only complete facts
    become a verdict; partial facts stay unsupported, and a decompiled-C
    mention of a dangerous call is never one. Every `mark_if` branch is
    evaluated outside every backend by one restricted interpreter, so two
    backends cannot reach different conclusions from the same facts. The
    result reports the preparation revision it read, per-rule coverage per
    backend (evaluated, unsupported or failed with a reason), which backend
    answered each rule and what every other one said, the first page of this
    scope's stored rows, triage counts per backend and in aggregate, and
    store health — an unsupported rule is never reported as a clean negative
    and a store that was not consulted is never reported as an empty one.
    Rescanning a scope preserves earlier assessments by exact finding ID and
    touches no other backend's scope.
    """
    backend_chain(backend)
    scope, selected = _scope_and_rules(rules, scan_name)
    # Only now may a database exist: no malformed rule and no malformed scan
    # name can be the reason a managed IDB or its netnode was ever created.
    return scan_target(
        path, selected, scope, backend=backend, analysis_id=analysis_id
    )


@tool(title="Prepare a target's managed analysis before scanning")
def vulfi_prepare(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb to prepare. It is copied into"
        " a managed workspace and only the copy is analyzed or changed; the"
        " supplied file is never modified.",
    ],
    backend: Annotated[
        str,
        "Analysis backend: 'auto', 'ida', 'ghidra' or 'r2'. 'auto' decides"
        " per pass — IDA first, then a configured Ghidra MCP, then a"
        " configured radare2 MCP — and only for passes the previous backend"
        " could not establish. Naming one backend runs exactly that one, with"
        " no fallback.",
    ] = "auto",
    passes: Annotated[
        list[str] | None,
        "Passes to run, from 'functions', 'strings', 'structures' and"
        " 'pointer_tables'. Omit or pass null to run all four in dependency"
        " order. A nonempty subset runs only those and reports which stages"
        " its missing prerequisites cost. An empty list is an error.",
    ] = None,
) -> PreparationResult:
    """Recover what a managed analysis can justify before it is scanned:
    functions in executable bytes nothing references, strings in mapped bytes
    and in the instructions that assemble them, structure layouts proven from
    consistent sized accesses, and pointer tables every slot of which carries
    a relocation. Each requested pass is routed on its own, and `routing`
    reports which backend answered it, what every other backend in the chain
    said, and — for a pass none of them could establish — the reason each
    one gave, rather than leaving it out as if it had run and found nothing.
    Every recovery carries the bytes, instructions, accesses or relocation
    records it rests on, and anything that cannot be justified stays a
    candidate with the reason — `state` is `applied` only where the managed
    artifact really changed. Coverage is reported per address range:
    `partial` is the ordinary answer on a real image and means some range was
    not reached, not that the pass failed, and nothing a later backend
    answers upgrades an earlier `unavailable`. Candidates are stored in the
    preparation catalog and paged by vulfi_preparation; only the first page
    is returned here. Re-running an unchanged target reuses the recorded
    revision and applies nothing, which `reused` reports; only an IDA-headed
    chain has a reusable revision, because an external one would be a claim
    about a provider session that is open now. Passes and backend are
    validated before any database or catalog is created.
    """
    return prepare_target(path, backend=backend, passes=passes)


@tool(title="Read a target's recorded preparation", read_only=True)
def vulfi_preparation(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb whose preparation to read. The"
        " same file always resolves to the same managed database.",
    ],
    analysis_id: Annotated[
        str | None,
        "Preparation revision to page. Omit to read the revision the managed"
        " database records. An id this target does not hold is refused.",
    ] = None,
    offset: Annotated[int, "Zero-based index of the first candidate."] = 0,
    limit: Annotated[int, "Candidates to return; 1 to 200."] = 100,
) -> PreparationPage:
    """Read what a preparation already recovered: one page of candidates in a
    stable order, with the evidence each rests on, plus every recorded pass
    and its per-range coverage. Nothing is analyzed, re-run, applied or
    created — a target no vulfi_prepare or vulfi_scan has run against has no
    managed database, and that is reported as an unavailable store with a
    reason, never as a preparation that recovered nothing. A missing
    preparation catalog is reported the same way. The page window is checked
    before the workspace is consulted: `0 <= offset` and `1 <= limit <= 200`.
    """
    return preparation_page(path, analysis_id, offset, limit)


@tool(title="Propose a recovery for an operator to review")
def vulfi_propose_recovery(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb whose preparation the"
        " proposals are about. The target must already have been prepared;"
        " this tool never creates a managed database.",
    ],
    analysis_id: Annotated[
        str,
        "The preparation revision the proposals are about, exactly as"
        " vulfi_prepare or vulfi_preparation reported it.",
    ],
    proposals: Annotated[
        list[dict[str, JsonValue]],
        "Up to 50 proposals. Each is an object with 'candidate_id' (a"
        " candidate this revision holds), 'kind' ('name',"
        " 'function_boundary', 'string_decode', 'structure_field' or"
        " 'pointer_table'), 'address_space' and 'address' (the candidate's"
        " own), 'value' (that kind's fields and no others: {'name': ident} /"
        " {'end': int} / {'encoding': 'ascii'|'utf-16le', 'length': int} /"
        " {'type_name': ident, 'fields': [{'offset','width','name'}]} /"
        " {'entry_count': int, 'pointer_width': 4|8}), 'evidence' (facts"
        " quoted verbatim from that candidate's own evidence) and"
        " 'rationale'. Every name is an ASCII identifier; there is no field"
        " that can carry a script, a command or an expression.",
    ],
) -> ProposalResult:
    """Store evidence-linked recovery proposals for an operator to review.
    This changes no analysis: it writes rows in the preparation catalog and
    nothing else. No managed database is opened for writing, no artifact
    revision moves, and no MCP tool — this one included — can approve a
    proposal. Applying one is a separate program: an operator runs `vulfi-mcp
    review approve` at a shell, is shown the original bytes, the definitions
    already in the database, the proposed change and its expected effect, and
    types the decision out; the change is then revalidated against the
    *current* artifact revision before it is applied, checkpointed, saved and
    recorded. Each proposal is answered on its own: one that names a
    candidate this revision does not hold, quotes evidence that candidate
    does not carry, sits at an address that is not the candidate's, asks for
    something already defined, or is about a backend this build cannot write
    back to is refused with that reason and is not stored, while the rest of
    the request still stands. A target nothing has prepared is refused
    outright rather than prepared to hold a proposal.
    """
    return propose_recovery(path, analysis_id, proposals)


@tool(title="Read stored VulFi findings")
def vulfi_findings(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb whose managed database holds the"
        " rows. The same file always resolves to the same managed database.",
    ],
    binary_path: Annotated[
        str | None,
        "The original binary, when 'path' is a saved .i64/.idb. External"
        " backends' rows belong to the original binary's SHA-256 namespace,"
        " so a database-only target cannot be joined to them until these"
        " bytes are supplied and proved against the input digest the database"
        " itself records. An unrelated binary is refused, never guessed at.",
    ] = None,
    offset: Annotated[int, "Zero-based index of the first row to return."] = 0,
    limit: Annotated[int, "Rows to return; 1 to 200."] = 100,
) -> FindingsPage:
    """Read the VulFi findings already stored for a target: no rule is
    evaluated, no stored row is rewritten, and no database is analyzed or
    created. Returns one page of rows across every scope of every backend in
    one stable order (verified address space, then location, then finding ID).
    Two backends never share an address space, so a reader is never shown one
    backend's address as if it were another's. Also returned are the target's
    triage counts per backend and in aggregate — counting findings, not
    deduplicated vulnerabilities — how many rows a later partial or failed
    scan did not observe again and were therefore kept as stale, and which
    stores answered. A store that is absent, or that could not be joined
    because source identity does not verify, is reported unavailable with the
    reason, never as zero rows. A target no vulfi_scan has ever run against
    has no managed database and therefore no store: that too is reported as
    unavailable with a reason, not as a target without findings. Only
    vulfi_scan and vulfi_prepare create anything.
    """
    # Refused before a database is even looked for, so an out-of-range page
    # never costs a workspace lookup to say no.
    validate_page(offset, limit)
    return _public_findings(path, binary_path, offset, limit)


@tool(title="Assess one VulFi finding")
def vulfi_triage(
    path: Annotated[
        str,
        "Path to the binary or saved .i64/.idb whose managed database holds the"
        " finding.",
    ],
    finding_id: Annotated[
        str,
        "Exact id of the stored finding, as vulfi_scan or vulfi_findings"
        " reported it. Its backend prefix decides which store is updated. An"
        " id no store holds is refused.",
    ],
    status: Annotated[
        str,
        "One of 'Not Checked', 'False Positive', 'Suspicious', 'Vulnerable'.",
    ],
    rationale: Annotated[
        str,
        "Why this status was chosen. Stored verbatim; it may not be empty.",
    ],
    binary_path: Annotated[
        str | None,
        "The original binary, when 'path' is a saved .i64/.idb and the finding"
        " belongs to an external backend. The same proof vulfi_findings wants,"
        " for the same reason: an external row is identified by the original"
        " binary's SHA-256, and an unrelated binary is refused.",
    ] = None,
) -> TriageResult:
    """Record an assessment of one stored VulFi finding, by its exact id. The
    status, the rationale and the id are all checked before any database is
    opened, and a refused update writes nothing at all. An accepted one is
    committed to the store that authored the row — the managed IDB for an IDA
    finding, the catalog for a Ghidra or radare2 one — and survives reopening
    it; it returns the finding exactly as that store committed it, its
    assessment revision, and the target's triage counts across every store
    that answered. Assessing a target with no such store is refused outright:
    there is no id it could hold, and no database is analyzed or created to
    establish that. An unlinked finding updates only the store that authored it. A
    reviewer-linked pair, addressed by either finding id, is journaled
    and is not reported synchronized until the IDB save is confirmed. A
    missing catalog refuses that edit and does not write the IDB.
    """
    return _public_triage(path, finding_id, status, rationale, binary_path)



def _replay_startup() -> None:
    """Finish pending linked events before the server accepts a connection.

    A restarted process has no target argument. Each pending event names the
    IDB it was mirroring; replay opens that database and finalizes or
    conflicts from the revision actually saved. A missing catalog is not an
    error: there is nothing to replay.
    """
    import json
    import sqlite3

    from vulfi_mcp.catalog import CatalogError, catalog_path

    store = catalog_path()
    if not store.is_file():
        return
    connection = None
    try:
        connection = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
        rows = connection.execute(
            "SELECT e.payload, l.proof, l.target_key, t.managed_idb_id"
            " FROM sync_events e"
            " JOIN links l ON l.link_id = e.link_id"
            " JOIN targets t ON t.target_key = l.target_key"
            " WHERE e.state = 'pending'"
        ).fetchall()
    except sqlite3.Error:
        return
    finally:
        if connection is not None:
            connection.close()
    seen: set[str] = set()
    for payload, proof_text, target_key, stored_id in rows:
        try:
            body = json.loads(payload)
            proof = json.loads(proof_text) if isinstance(proof_text, str) else {}
        except json.JSONDecodeError:
            continue
        if not isinstance(body, dict):
            continue
        if not isinstance(proof, dict):
            proof = {}
        event_proof = body.get("proof") if isinstance(body.get("proof"), dict) else {}
        idb = body.get("idb_path") or proof.get("idb_path")
        if not isinstance(idb, str) or idb in seen:
            continue
        seen.add(idb)
        idb_id = event_proof.get("managed_idb_id") or proof.get("managed_idb_id")
        if not isinstance(idb_id, str) or not idb_id:
            idb_id = stored_id if isinstance(stored_id, str) and stored_id else None
        if not isinstance(idb_id, str) or not idb_id:
            idb_id = _managed_id_from_database(idb)
        if not isinstance(idb_id, str) or not idb_id:
            raise CatalogError(
                f"{idb} is an IDA database, so its original bytes are unknown:"
                " a managed_idb_id from its netnode is required to identify it"
            )
        if isinstance(stored_id, str) and stored_id and stored_id != idb_id:
            raise CatalogError(
                f"target {target_key} is managed database {stored_id},"
                f" not {idb_id}"
            )
        if not isinstance(stored_id, str) or not stored_id:
            _bind_managed_id(str(target_key), idb_id)
        replay_linked_updates(idb, idb_id)



def _managed_id_from_database(idb: str) -> str | None:
    """The netnode id of ``idb``, when the event itself did not carry one."""
    from vulfi_mcp.ida_adapter import findings_ida

    page = findings_ida(idb, 0, 1)
    health = page.get("store_health")
    if not isinstance(health, dict):
        return None
    ida = health.get("ida")
    if not isinstance(ida, dict):
        return None
    value = ida.get("managed_idb_id")
    return value if isinstance(value, str) and value else None


def _bind_managed_id(target_key: str, managed_idb_id: str) -> None:
    """Record the event's database id on the target that already owns the link.

    A catalog opened from the original binary does not always store this id.
    Startup has the id, from the link proof, and has to open that same target
    by it. Writing a second target would replay nothing and leave the crash
    window open.
    """
    import sqlite3

    from vulfi_mcp.catalog import catalog_path

    connection = sqlite3.connect(catalog_path())
    try:
        connection.execute(
            "UPDATE targets SET managed_idb_id = ? WHERE target_key = ?"
            " AND managed_idb_id IS NULL",
            (managed_idb_id, target_key),
        )
        connection.commit()
    finally:
        connection.close()


def _committed_finding(
    path: str, binary_path: str | None, finding_id: str
) -> dict | None:
    """The row ``finding_id`` names, read from its store, not from a page window."""
    from pathlib import Path as _Path

    from vulfi_mcp.ida_adapter import IDB_SUFFIXES, existing_managed_idb
    from vulfi_mcp.prepare import _verified_catalog

    if finding_id.startswith("ida:"):
        named = _Path(path)
        idb = existing_managed_idb(path)
        if idb is None and named.suffix.lower() in IDB_SUFFIXES and named.is_file():
            idb = str(named)
        if idb is None:
            return None
        found, _scopes = _ida_index(idb)
        return found.get(finding_id)
    catalog, _reason = _verified_catalog(path, binary_path)
    if catalog is None:
        return None
    try:
        return catalog.external_finding(finding_id)
    finally:
        catalog.close()

_LINK_RANK = {
    "unlinked": 0,
    "synchronized": 1,
    "pending": 2,
    "paused": 3,
    "conflict": 4,
    "unavailable": 5,
}



_ROLLBACK = "the save before this one left a database it cannot read"


def _retry_ida(call):
    """One retry after IDA 9.4 puts a bad pack back to the previous generation."""
    try:
        return call()
    except Exception as failed:
        if _ROLLBACK not in str(failed):
            raise
        return call()


def _ordinal(finding_id: str) -> int | None:
    tail = finding_id.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else None


def _joined_writer(path: str, binary_path: str | None):
    """The catalog a linked read may update, or ``None`` when it may not join."""
    return _retry_ida(lambda: _open_joined_writer(path, binary_path))


def _open_joined_writer(path: str, binary_path: str | None):
    from vulfi_mcp.catalog import catalog_path
    from vulfi_mcp.prepare import _verified_catalog

    if not catalog_path().is_file():
        return None
    opened, _reason = _verified_catalog(path, binary_path, writable=False)
    if opened is None:
        return None
    opened.close()
    writer, _reason = _verified_catalog(path, binary_path, writable=True)
    return writer


def _ida_index(idb_path: str) -> tuple[dict[str, dict], list[dict]]:
    """Every stored IDA row, keyed by id, plus the scope summaries."""
    from vulfi_mcp.ida_adapter import invoke_ida

    found: dict[str, dict] = {}
    scopes: list[dict] = []
    offset = 0
    total = None
    while True:
        window = _retry_ida(lambda: invoke_ida(
            idb_path, "findings_page", {"offset": offset, "limit": 200}
        ))
        if not scopes:
            raw = window.get("scopes")
            if isinstance(raw, list):
                scopes = [item for item in raw if isinstance(item, dict)]
        rows = window.get("findings")
        page = [item for item in rows if isinstance(item, dict)] if isinstance(rows, list) else []
        for row in page:
            identifier = row.get("id")
            if isinstance(identifier, str):
                found[identifier] = row
        if total is None:
            try:
                total = int(window.get("target_total") or 0)
            except (TypeError, ValueError):
                total = len(page)
        offset += len(page)
        if not page or offset >= total:
            break
    return found, scopes


def _pause_reason(catalog, link: dict, ida_rows: dict[str, dict], scopes: list[dict]) -> str | None:
    """Why this link must pause, or ``None`` when the stale bit is not that fact."""
    from vulfi_mcp.operator import _partial_stale

    proof = link.get("proof") if isinstance(link.get("proof"), dict) else {}
    external_id = str(link["external_finding_id"])
    ida_id = str(link["ida_finding_id"])
    identity = catalog.external_identity(external_id)
    held = catalog.external_finding(external_id)
    if identity is None or held is None:
        return "the external member is gone; the link is paused rather than attached to a similar row"
    if str(held.get("rule_digest") or "") != str(proof.get("rule_digest") or ""):
        return "the external member's rule digest changed; the link is paused"
    ordinal = _ordinal(external_id)
    occurrence = held.get("occurrence")
    if (
        ordinal is not None
        and isinstance(occurrence, int)
        and not isinstance(occurrence, bool)
        and occurrence != ordinal
    ):
        return "the external member's occurrence ordinal changed; the link is paused"
    if _partial_stale(identity):
        return (
            "a partial scan saw other rows and did not reconfirm the external"
            " member; the link is paused"
        )
    ida_row = ida_rows.get(ida_id)
    if ida_rows and ida_row is None:
        return "the IDA member is gone; the link is paused rather than attached to a similar row"
    if ida_row is not None:
        if str(ida_row.get("rule_digest") or "") != str(proof.get("rule_digest") or ""):
            return "the IDA member's rule digest changed; the link is paused"
        ida_ordinal = _ordinal(ida_id)
        ida_occurrence = ida_row.get("occurrence")
        if (
            ida_ordinal is not None
            and isinstance(ida_occurrence, int)
            and not isinstance(ida_occurrence, bool)
            and ida_occurrence != ida_ordinal
        ):
            return "the IDA member's occurrence ordinal changed; the link is paused"
        if ida_row.get("stale") and _ida_not_reconfirmed(ida_row, scopes):
            return (
                "a partial scan saw other IDA rows and did not reconfirm this"
                " member; the link is paused"
            )
    return None


def _ida_not_reconfirmed(row: dict, scopes: list[dict]) -> bool:
    """True only when this stale IDA row was missed by a scan that saw others."""
    source = row.get("source")
    for scope in scopes:
        if scope.get("scope") != source:
            continue
        observed = scope.get("observed")
        if isinstance(observed, bool) or not isinstance(observed, int):
            observed = 0
        return scope.get("coverage") == "partial" and observed > 0
    return False


def _refresh_links(catalog, path: str) -> None:
    from vulfi_mcp.ida_adapter import existing_managed_idb

    idb = existing_managed_idb(path)
    ida_rows: dict[str, dict] = {}
    scopes: list[dict] = []
    if idb is not None:
        ida_rows, scopes = _ida_index(idb)
    for link in catalog.links():
        state = str(link.get("sync_state") or "")
        if state in ("pending", "paused"):
            continue
        reason = _pause_reason(catalog, link, ida_rows, scopes)
        if reason is not None:
            catalog.pause_link(str(link["link_id"]), reason)
            continue
        if state == "conflict":
            continue
        confirmed = catalog.last_confirmed_ida_revision(str(link["link_id"]))
        ida_row = ida_rows.get(str(link["ida_finding_id"]))
        if confirmed is None or ida_row is None:
            continue
        current = ida_row.get("triage_revision")
        if isinstance(current, bool) or not isinstance(current, int):
            continue
        if current != confirmed:
            catalog.mark_link_conflict(
                str(link["link_id"]),
                f"IDA triage revision {current} is not the confirmed {confirmed}",
            )


def _replay_joined(path: str, binary_path: str | None) -> None:
    writer = _joined_writer(path, binary_path)
    if writer is None:
        return
    try:
        writer.replay_pending(_mirror_journal_event)
        _refresh_links(writer, path)
    finally:
        writer.close()


def _scope_health(path: str, binary_path: str | None) -> dict:
    from vulfi_mcp.catalog import CatalogError
    from vulfi_mcp.ida_adapter import existing_managed_idb, invoke_ida
    from vulfi_mcp.prepare import _verified_catalog

    health: dict = {}
    idb = existing_managed_idb(path)
    if idb is not None:
        window = _retry_ida(lambda: invoke_ida(idb, "findings_page", {"offset": 0, "limit": 1}))
        raw = window.get("scopes")
        health["ida"] = {
            "available": True,
            "scopes": [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else [],
        }
    try:
        catalog, _reason = _verified_catalog(path, binary_path)
    except CatalogError:
        return health
    if catalog is None:
        return health
    try:
        grouped: dict[str, list] = {}
        for scope in catalog.external_scopes():
            backend = str(scope.get("backend") or "")
            if not backend:
                continue
            grouped.setdefault(backend, []).append(
                {
                    "state": scope.get("state"),
                    "coverage": scope.get("coverage"),
                    "reason": scope.get("reason"),
                    "scope": scope.get("scope"),
                    "total": scope.get("total"),
                    "stale_total": scope.get("stale_total"),
                }
            )
        for backend, scopes in grouped.items():
            health[backend] = {"scopes": scopes}
    finally:
        catalog.close()
    return health


def _link_views(path: str, binary_path: str | None) -> list[dict]:
    from vulfi_mcp.catalog import CatalogError
    from vulfi_mcp.prepare import _verified_catalog

    try:
        catalog, _reason = _verified_catalog(path, binary_path)
    except CatalogError:
        return []
    if catalog is None:
        return []
    try:
        views = []
        for link in catalog.links():
            views.append(
                {
                    "link_id": link["link_id"],
                    "sync_state": link["sync_state"],
                    "link_revision": link["link_revision"],
                    "last_confirmed_revision": link.get("last_confirmed_revision"),
                    "ida_finding_id": link["ida_finding_id"],
                    "external_finding_id": link["external_finding_id"],
                    "status": link.get("status"),
                    "rationale": link.get("rationale"),
                    "assessed_at": link.get("updated_at"),
                    "chosen_source": link.get("chosen_source"),
                }
            )
        return views
    finally:
        catalog.close()


def _page_sync(links: list[dict], catalog_available: bool) -> str:
    if not catalog_available:
        return "unavailable"
    if not links:
        return "unlinked"
    return max(links, key=lambda item: _LINK_RANK.get(str(item.get("sync_state")), 0))[
        "sync_state"
    ]


def _annotate_page(
    page: dict, path: str, binary_path: str | None, *, catalog_available: bool
) -> FindingsPage:
    links = _link_views(path, binary_path) if catalog_available else []
    page["loaded"] = int(page.get("page_total") or 0)
    page["links"] = links
    page["scope_health"] = _scope_health(path, binary_path)
    page["sync_state"] = _page_sync(links, catalog_available)
    return page


def _ida_only_page(path: str, offset: int, limit: int, reason: str) -> FindingsPage:
    """IDA rows only. The catalog could not be identified, so it is not zero."""
    from pathlib import Path as _Path

    from vulfi_mcp.ida_adapter import (
        IDB_SUFFIXES,
        existing_managed_idb,
        findings_ida,
        unscanned_findings_page,
    )

    named = _Path(path)
    idb = existing_managed_idb(path)
    if idb is None and named.suffix.lower() in IDB_SUFFIXES and named.is_file():
        # The caller named the managed database itself, not the binary it
        # was analyzed from. That file is the store; do not look for a copy
        # of a copy.
        idb = str(named)
    if idb is None:
        page = dict(unscanned_findings_page(path, offset, limit))
    else:
        page = dict(_retry_ida(lambda: findings_ida(idb, offset, limit, path=path)))
    health = page.get("store_health")
    if not isinstance(health, dict):
        health = {}
    health = dict(health)
    health["catalog"] = {"available": False, "reason": reason}
    page["store_health"] = health
    page["target_total_complete"] = False
    # Drop a joined backend the IDA page does not have. A missing catalog is
    # not a ghidra table of zeroes.
    counts = page.get("status_counts")
    if isinstance(counts, dict):
        page["status_counts"] = {
            name: table for name, table in counts.items() if name in ("ida", "aggregate")
        }
        if "ida" in page["status_counts"] and "aggregate" not in page["status_counts"]:
            page["status_counts"]["aggregate"] = dict(page["status_counts"]["ida"])
    return _annotate_page(page, path, None, catalog_available=False)


def _public_findings(
    path: str, binary_path: str | None, offset: int, limit: int
) -> FindingsPage:
    """Replay, pause or conflict, then page. A missing store stays unavailable."""
    from pathlib import Path as _Path

    from vulfi_mcp.catalog import CatalogError
    from vulfi_mcp.ida_adapter import IDB_SUFFIXES

    # An IDB path alone is not permission to join the original-binary catalog.
    # binary_path is how this request proves those bytes.
    if binary_path is None and _Path(path).suffix.lower() in IDB_SUFFIXES:
        return _ida_only_page(
            path,
            offset,
            limit,
            "this request names a database and not the original binary;"
            " supply binary_path to prove the bytes before external rows"
            " or link state can be joined",
        )
    try:
        _replay_joined(path, binary_path)
        page = dict(findings_across_backends(path, binary_path, offset, limit))
    except CatalogError as refused:
        return _ida_only_page(path, offset, limit, str(refused))
    catalog_health = {}
    store_health = page.get("store_health")
    if isinstance(store_health, dict) and isinstance(store_health.get("catalog"), dict):
        catalog_health = store_health["catalog"]
    catalog_available = bool(catalog_health.get("available"))
    return _annotate_page(page, path, binary_path, catalog_available=catalog_available)


def _ida_link_id(path: str, finding_id: str) -> str | None:
    from vulfi_mcp.ida_adapter import existing_managed_idb

    if not finding_id.startswith("ida:"):
        return None
    idb = existing_managed_idb(path)
    if idb is None:
        return None
    rows, _scopes = _ida_index(idb)
    row = rows.get(finding_id)
    link_id = row.get("link_id") if isinstance(row, dict) else None
    return link_id if isinstance(link_id, str) and link_id else None


def _public_triage(
    path: str,
    finding_id: str,
    status: str,
    rationale: str,
    binary_path: str | None,
) -> TriageResult:
    """Journal a linked edit; leave an unlinked finding on its own authority."""
    from vulfi_mcp.catalog import CatalogError, catalog_path
    from vulfi_mcp.prepare import _verified_catalog

    link = None
    if catalog_path().is_file():
        catalog, _reason = _retry_ida(lambda: _verified_catalog(path, binary_path, writable=False))
        if catalog is not None:
            try:
                link = catalog.link_for_finding(finding_id)
            finally:
                catalog.close()
    if link is None:
        if _ida_link_id(path, finding_id):
            raise CatalogError(
                "the SQLite catalog is unavailable; a linked edit is refused"
                " and nothing was written to the IDB"
            )
        result = triage_across_backends(
            path, finding_id, status, rationale, binary_path
        )
        result["findings"] = [result["finding"]]
        return result
    if link.get("sync_state") == "paused":
        raise CatalogError(
            f"link {link['link_id']} is paused; a linked edit is refused"
            " until it is reviewed again. Nothing was written"
        )
    finished = _retry_ida(lambda: apply_linked_update(
        path,
        str(link["link_id"]),
        int(link["link_revision"]),
        status,
        rationale,
    ))
    page = _public_findings(path, binary_path, 0, 200)
    requested = _committed_finding(path, binary_path, finding_id)
    partner_id = (
        link["external_finding_id"]
        if finding_id == link["ida_finding_id"]
        else link["ida_finding_id"]
    )
    partner = _committed_finding(path, binary_path, str(partner_id))
    both = [row for row in (requested, partner) if row is not None]
    if requested is None:
        raise CatalogError(
            f"finding {finding_id} was updated and cannot be read back"
        )
    return {
        "path": page["path"],
        "idb_path": page["idb_path"],
        "finding": requested,
        "triage_revision": int(requested["triage_revision"]),
        "target_total": page["target_total"],
        "target_total_complete": page["target_total_complete"],
        "status_counts": page["status_counts"],
        "store_health": page["store_health"],
        "sync_state": str(finished.get("sync_state") or page["sync_state"]),
        "warnings": list(page.get("warnings") or []),
        "findings": both,
        "scope_health": page["scope_health"],
        "links": page["links"],
        "loaded": page["loaded"],
    }


def apply_linked_update(
    path: str,
    link_id: str,
    expected_link_revision: int,
    status: str,
    rationale: str,
) -> dict[str, object]:
    """Journal one linked decision, mirror it, and confirm only a real save.

    SQLite is written first. A missing catalog refuses before the IDB is
    opened. A failed save stays pending and is never ``synchronized``.
    """
    from vulfi_mcp.catalog import CatalogError, catalog_path, open_catalog
    from vulfi_mcp.ida_adapter import mirror_linked_ida

    if not catalog_path().is_file():
        raise CatalogError(
            "the SQLite catalog is unavailable; a linked edit is refused"
            " and nothing was written to the IDB"
        )
    try:
        catalog = open_catalog(path)
    except Exception as failed:
        raise CatalogError(
            "the SQLite catalog is unavailable; a linked edit is refused"
            " and nothing was written to the IDB"
        ) from failed
    try:
        started = catalog.begin_linked_update(
            link_id, expected_link_revision, status, rationale
        )
        payload = started["payload"]
        if not isinstance(payload, dict):
            started["confirmed"] = False
            started["sync_state"] = "pending"
            started["reason"] = "the pending event has no payload"
            return started
        decision = payload.get("decision")
        try:
            mirrored = mirror_linked_ida(
                str(payload["idb_path"]),
                str(payload["ida_finding_id"]),
                str(started["event_id"]),
                int(payload["expected_ida_revision"]),
                dict(decision) if isinstance(decision, dict) else {},
            )
        except (OSError, ValueError) as failed:
            started["confirmed"] = False
            started["sync_state"] = "pending"
            started["reason"] = str(failed)
            return started
        if mirrored.get("conflict"):
            conflicted = catalog.mark_link_conflict(
                str(started["link_id"]),
                str(mirrored.get("reason") or "unexpected IDB revision"),
            )
            catalog.close_link_event(str(started["event_id"]))
            conflicted["event_id"] = started["event_id"]
            conflicted["sync_state"] = "conflict"
            conflicted["confirmed"] = False
            return conflicted
        if not (mirrored.get("applied") or mirrored.get("already")) or not mirrored.get(
            "saved"
        ):
            started["confirmed"] = False
            started["sync_state"] = "pending"
            started["reason"] = str(mirrored.get("reason") or "the IDB was not saved")
            return started
        observed = mirrored.get("triage_revision")
        if isinstance(observed, bool) or not isinstance(observed, int):
            observed = int(payload["intended_ida_revision"])
        confirmed = catalog.confirm_linked_update(str(started["event_id"]), observed)
        if confirmed.get("sync_state") != "synchronized":
            confirmed["confirmed"] = False
        return confirmed
    finally:
        catalog.close()


def replay_linked_updates(
    path: str, managed_idb_id: str | None = None
) -> list[dict[str, object]]:
    """Finish pending linked creates and updates in a new process."""
    from vulfi_mcp.catalog import open_catalog

    with open_catalog(path, managed_idb_id) as catalog:
        return catalog.replay_pending(_mirror_journal_event)


def _mirror_journal_event(event: dict[str, object]) -> dict[str, object]:
    from vulfi_mcp.ida_adapter import mirror_linked_ida

    payload = event.get("payload")
    if not isinstance(payload, dict):
        return {
            "applied": False,
            "already": False,
            "conflict": False,
            "reason": "event has no payload",
        }
    decision = payload.get("decision")
    try:
        return mirror_linked_ida(
            str(payload["idb_path"]),
            str(payload["ida_finding_id"]),
            str(event["event_id"]),
            int(payload["expected_ida_revision"]),
            dict(decision) if isinstance(decision, dict) else {},
        )
    except (OSError, ValueError) as failed:
        return {
            "applied": False,
            "already": False,
            "conflict": False,
            "saved": False,
            "reason": str(failed),
        }


def main() -> None:
    """Serve the seven tools over stdio, or run an operator command.

    With no arguments this is the MCP server and stdout is its transport.
    ``review`` and ``link`` are the operator's own commands. Neither is an
    MCP tool: each asks a person before it changes a managed analysis.
    """
    if not sys.argv[1:]:
        _replay_startup()
        serve_stdio()
        return
    command = sys.argv[1]
    if command == "review":
        from vulfi_mcp.operator import main as review

        raise SystemExit(review(sys.argv[2:]))
    if command == "link":
        from vulfi_mcp.operator import link_main

        raise SystemExit(link_main(sys.argv[2:]))
    if command == "resolve":
        from vulfi_mcp.operator import resolve_main

        raise SystemExit(resolve_main(sys.argv[2:]))
    raise SystemExit(
        f"vulfi-mcp: {command!r} is not a command. Run 'vulfi-mcp' with no"
        " arguments to serve MCP over stdio, 'vulfi-mcp review --help' to"
        " review stored recovery proposals, 'vulfi-mcp link --help' to"
        " review a finding link, or 'vulfi-mcp resolve --help' to choose"
        " the assessment that wins a conflict."
    )
