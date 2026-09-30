"""The public MCP entry point: four VulFi tools beside the six stock IDA ones.

Importing this module registers the VulFi tools on the process-wide server the
official ``ida-mcp`` package already owns, so one stdio connection serves the
six stock IDA tools and these four together. There is no second MCP server and
no fork of the official one.

What this milestone implements is the IDA backend and nothing else. A caller
may pass the parameters the full design reserves — ``backend``,
``analysis_id`` and ``binary_path`` — and every one of them is answered
honestly: an unimplemented capability is refused by name, never served as an
empty success that reads like "nothing found". Preparation, the external
Ghidra/radare2 providers and reviewer-linked triage are not built here, and
nothing below pretends otherwise.

Two rules shape the order of every tool body. Untrusted input is validated
first, so a malformed rule, scan name, page window or assessment can never be
the reason a managed IDB or its netnode came into existence. And stdout is the
MCP transport: this module writes nothing to it.
"""

# Deliberately not `from __future__ import annotations`. The official `@tool`
# decorator wraps each function with `functools.wraps`, and the schema
# generator then resolves that wrapper's annotations against *its* module
# globals, where this module's names do not exist. Real annotation objects,
# evaluated here at definition time, are the ones that survive that wrapping.

from typing import Annotated, Final

from ida_mcp.mcp import serve_stdio, tool

from vulfi_mcp.contracts import FindingsPage, JsonValue, ScanResult, TriageResult
from vulfi_mcp.ida_adapter import (
    ensure_managed_idb,
    findings_ida,
    scan_ida,
    triage_ida,
)
from vulfi_mcp.ida_runtime import (
    CUSTOM_SCOPE_PREFIX,
    DEFAULT_SCOPE,
    validate_page,
    validate_rationale,
    validate_scan_name,
    validate_status,
)
from vulfi_mcp.rules import Rule, load_stock_rules, rule_template, validate_rules

__all__ = [
    "main",
    "vulfi_findings",
    "vulfi_rule_template",
    "vulfi_scan",
    "vulfi_triage",
]

#: The backend selectors this build can actually honour. ``auto`` resolves to
#: IDA because IDA is the only backend here; Plan 2 is what gives ``auto``
#: something to choose between.
IDA_BACKENDS: Final[tuple[str, str]] = ("auto", "ida")


def _require_ida_backend(backend: object) -> None:
    """Refuse a backend this build does not have, rather than answer for it."""
    if backend in IDA_BACKENDS:
        return
    raise ValueError(
        f"backend={backend!r} is not implemented in this build: it runs the IDA"
        " backend only, so 'ida' and 'auto' are the accepted values. The Ghidra"
        " and radare2 providers do not exist yet, so nothing was scanned and"
        " nothing was stored — this is an incomplete capability, not an empty"
        " result."
    )


def _require_no_preparation(analysis_id: object) -> None:
    """Refuse to reuse a preparation revision no preparation pass produced."""
    if analysis_id is None:
        return
    raise ValueError(
        f"analysis_id={analysis_id!r} names a preparation revision, and"
        " preparation is not implemented in this build: nothing has been"
        " prepared, so there is no revision to reuse and no coverage to report."
        " Omit analysis_id to scan the target exactly as IDA analyzed it."
    )


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
        "Analysis backend: 'ida' or 'auto'. Reserved for the Ghidra and"
        " radare2 providers, which this build does not implement and refuses"
        " by name.",
    ] = "auto",
    analysis_id: Annotated[
        str | None,
        "Reserved for a preparation revision to reuse. Preparation is not"
        " implemented in this build, so any value is refused rather than"
        " silently ignored.",
    ] = None,
) -> ScanResult:
    """Scan a binary or IDA database for VulFi rule matches and store the rows
    in the managed IDB's own record. Rules are validated in full before any
    database is created or opened; IDA then extracts call-site evidence and
    every `mark_if` branch is evaluated outside IDA by a restricted
    interpreter. The result reports per-rule coverage (evaluated, unsupported
    or failed with a reason), the first page of the scope's stored rows, triage
    counts across the whole target, and store health — an unsupported rule is
    never reported as a clean negative. Rescanning a scope preserves earlier
    assessments by exact finding ID. This build implements the IDA backend
    only.
    """
    _require_ida_backend(backend)
    _require_no_preparation(analysis_id)
    scope, selected = _scope_and_rules(rules, scan_name)
    # Only now may a database exist: no malformed rule and no malformed scan
    # name can be the reason a managed IDB or its netnode was ever created.
    idb_path = ensure_managed_idb(path)
    return scan_ida(idb_path, selected, scope, path=path)


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
    evaluated and no stored row is rewritten. Returns one page of rows across
    every scope of the IDA backend in one stable order (address space, then
    location, then finding ID), together with the target's triage counts, how
    many rows a later partial scan did not observe again, and which stores
    answered — a store that is absent is reported unavailable, never as zero
    rows. Reading a target that was never scanned is not cheap: the rows live
    in the target's managed IDA database, so the first call for such a target
    analyzes the binary in full before returning an empty page. Once that
    database exists this is a read, and cheaper than vulfi_scan.
    """
    _require_no_external_store(binary_path, "vulfi_findings")
    # Refused before a database can exist, so an out-of-range page never
    # analyzes a binary just to say no.
    validate_page(offset, limit)
    idb_path = ensure_managed_idb(path)
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
    target's triage counts. Assessments in this build are unlinked: they update
    the IDA row's own authority and nothing else.
    """
    _require_no_external_store(binary_path, "vulfi_triage")
    # Refused before a database can exist, for the same reason vulfi_findings
    # checks its page window first.
    if not isinstance(finding_id, str) or not finding_id:
        raise ValueError("finding_id must be a non-empty string")
    validate_status(status)
    validate_rationale(rationale)
    idb_path = ensure_managed_idb(path)
    return triage_ida(idb_path, finding_id, status, rationale, path=path)


def main() -> None:
    """Serve the stock IDA tools and these four over stdio, until EOF."""
    serve_stdio()
