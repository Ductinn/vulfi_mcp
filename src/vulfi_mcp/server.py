"""The public MCP entry point: seven VulFi tools beside the six stock IDA ones.

Importing this module registers the VulFi tools on the process-wide server the
official ``ida-mcp`` package already owns, so one stdio connection serves the
six stock IDA tools and these seven together. There is no second MCP server
and no fork of the official one.

What this milestone implements is the IDA backend and nothing else. A caller
may pass the parameters the full design reserves — ``backend`` and
``binary_path`` — and each of them is answered honestly: an unimplemented
capability is refused by name, never served as an empty success that reads
like "nothing found". The external Ghidra/radare2 providers and
reviewer-linked triage are not built here, and nothing below pretends
otherwise.

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
from vulfi_mcp.ida_adapter import (
    NO_DATABASE_REASON,
    existing_managed_idb,
    findings_ida,
    scan_ida,
    triage_ida,
    unscanned_findings_page,
)
from vulfi_mcp.ida_runtime import (
    CUSTOM_SCOPE_PREFIX,
    DEFAULT_SCOPE,
    UnknownFindingError,
    validate_page,
    validate_rationale,
    validate_scan_name,
    validate_status,
)
from vulfi_mcp.prepare import (
    ProposalResult,
    ensure_prepared,
    prepare_target,
    preparation_page,
    propose_recovery,
    resolve_backend,
)
from vulfi_mcp.rules import Rule, load_stock_rules, rule_template, validate_rules

__all__ = [
    "main",
    "vulfi_findings",
    "vulfi_prepare",
    "vulfi_preparation",
    "vulfi_propose_recovery",
    "vulfi_rule_template",
    "vulfi_scan",
    "vulfi_triage",
]


def _require_no_external_store(binary_path: object, where: str) -> None:
    """Refuse to aggregate a findings store this build never writes."""
    if binary_path is None:
        return
    raise ValueError(
        f"binary_path={binary_path!r} asks {where} to aggregate an external"
        " findings store with the managed IDB, and that store is not"
        " implemented in this build. The managed IDB's own rows are the only"
        " rows that exist; omit binary_path to read them."
    )


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
        "Analysis backend: 'ida' or 'auto'. The 'ghidra' and 'r2' providers"
        " this design names are not implemented in this build and are refused"
        " by name rather than quietly served by IDA.",
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
    in the managed IDB's own record. Rules are validated in full before any
    database is created or opened. The target is then prepared — hidden
    functions, undefined strings, structure fields and pointer tables
    recovered where the evidence justifies it — unless a recorded preparation
    revision already matches this request, in which case it is reused and
    nothing is applied again. IDA then extracts call-site evidence from that
    prepared analysis and every `mark_if` branch is evaluated outside IDA by a
    restricted interpreter. The result reports the preparation revision it
    read, per-rule coverage (evaluated, unsupported or failed with a reason),
    the first page of the scope's stored rows, triage counts across the whole
    target, and store health — an unsupported rule is never reported as a
    clean negative. Rescanning a scope preserves earlier assessments by exact
    finding ID. This build implements the IDA backend only.
    """
    resolve_backend(backend)
    scope, selected = _scope_and_rules(rules, scan_name)
    # Only now may a database exist: no malformed rule and no malformed scan
    # name can be the reason a managed IDB or its netnode was ever created.
    prepared = ensure_prepared(path, backend=backend, analysis_id=analysis_id)
    result = scan_ida(prepared["idb_path"], selected, scope, path=path)
    # What the rows were read out of, named on the rows themselves: a scan of
    # a prepared analysis that did not say which one would leave a reader
    # unable to tell it from a scan of the raw auto-analysis.
    result["analysis_id"] = prepared["analysis_id"]
    result["preparation_revision"] = prepared["preparation_revision"]
    result["warnings"] = [*result["warnings"], *prepared["warnings"]]
    return result


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
        "Analysis backend: 'ida' or 'auto'. The 'ghidra' and 'r2' providers"
        " this design names are not implemented in this build and are refused"
        " by name; nothing falls back to IDA in their place.",
    ] = "auto",
    passes: Annotated[
        list[str] | None,
        "Passes to run, from 'functions', 'strings', 'structures' and"
        " 'pointer_tables'. Omit or pass null to run all four in dependency"
        " order. A nonempty subset runs only those and reports which stages"
        " its missing prerequisites cost. An empty list is an error.",
    ] = None,
) -> PreparationResult:
    """Recover what a managed IDA analysis can justify before it is scanned:
    functions in executable bytes nothing references, strings in mapped bytes
    and in the instructions that assemble them, structure layouts proven from
    consistent sized accesses, and pointer tables every slot of which carries
    a relocation. Every recovery carries the bytes, instructions, accesses or
    relocation records it rests on, and anything that cannot be justified
    stays a candidate with the reason — `state` is `applied` only where the
    managed database really changed. Coverage is reported per address range:
    `partial` is the ordinary answer on a real image and means some range was
    not reached, not that the pass failed. Candidates are stored in the
    preparation catalog and paged by vulfi_preparation; only the first page
    is returned here. Re-running an unchanged target reuses the recorded
    revision and applies nothing, which `reused` reports. Passes and backend
    are validated before any database or catalog is created.
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
        "Reserved for aggregating an external findings store with the managed"
        " IDB. That store is not implemented in this build, so any value is"
        " refused rather than silently ignored.",
    ] = None,
    offset: Annotated[int, "Zero-based index of the first row to return."] = 0,
    limit: Annotated[int, "Rows to return; 1 to 200."] = 100,
) -> FindingsPage:
    """Read the VulFi findings already stored for a target: no rule is
    evaluated, no stored row is rewritten, and no database is analyzed or
    created. Returns one page of rows across every scope of the IDA backend in
    one stable order (address space, then location, then finding ID), together
    with the target's triage counts, how many rows a later partial scan did not
    observe again, and which stores answered — a store that is absent is
    reported unavailable, never as zero rows. A target no vulfi_scan has ever
    run against has no managed database and therefore no store: that is
    reported as an unavailable IDA store with a reason, not as a target
    without findings. Only vulfi_scan creates a database.
    """
    _require_no_external_store(binary_path, "vulfi_findings")
    # Refused before a database is even looked for, so an out-of-range page
    # never costs a workspace lookup to say no.
    validate_page(offset, limit)
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        return unscanned_findings_page(path, offset, limit)
    return findings_ida(idb_path, offset, limit, path=path)


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
        " reported it. An id the record does not hold is refused.",
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
        "Reserved for mirroring the assessment into an external findings"
        " store. That store is not implemented in this build, so any value is"
        " refused rather than silently ignored.",
    ] = None,
) -> TriageResult:
    """Record an assessment of one stored VulFi finding, by its exact id. The
    status, the rationale and the id are all checked before any database is
    opened, and a refused update writes nothing at all. An accepted one is
    committed to the managed IDB and survives reopening it; it returns the
    finding exactly as the store committed it, its assessment revision, and the
    target's triage counts. Assessing a target no vulfi_scan has run against is
    refused outright: there is no store, so there is no id it could hold, and
    no database is analyzed or created to establish that. Assessments in this
    build are unlinked: they update the IDA row's own authority and nothing
    else.
    """
    _require_no_external_store(binary_path, "vulfi_triage")
    # Refused before a database can exist, for the same reason vulfi_findings
    # checks its page window first.
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding_id must be a non-empty string")
    validate_status(status)
    validate_rationale(rationale)
    idb_path = existing_managed_idb(path)
    if idb_path is None:
        raise UnknownFindingError(
            f"no stored finding carries the id {finding_id!r}:"
            f" {NO_DATABASE_REASON}. Nothing was written"
        )
    return triage_ida(idb_path, finding_id, status, rationale, path=path)


def main() -> None:
    """Serve the seven tools over stdio, or run the operator review command.

    With no arguments this is the MCP server and stdout is its transport.
    With ``review`` it is the operator's own command, which is deliberately
    *not* reachable through MCP: it is the only path that applies a proposal,
    and it asks a person first.
    """
    if not sys.argv[1:]:
        serve_stdio()
        return
    if sys.argv[1] != "review":
        raise SystemExit(
            f"vulfi-mcp: {sys.argv[1]!r} is not a command. Run 'vulfi-mcp'"
            " with no arguments to serve MCP over stdio, or 'vulfi-mcp review"
            " --help' to review stored recovery proposals."
        )
    # Imported here, not at module scope: serving MCP must not need the
    # review path, and the review path must not register MCP tools it will
    # never serve.
    from vulfi_mcp.operator import main as review

    raise SystemExit(review(sys.argv[2:]))
