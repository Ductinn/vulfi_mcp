"""The Ghidra backend: evidence a typed GhidraMCP session can justify.

This adapter owns three things and nothing else: the fixed set of tools it may
ask a Ghidra provider for, the pinned schema each of those tools had when this
code was written, and the rules for turning the provider's *structured*
answers into the shapes the rest of this server already understands —
:class:`~vulfi_mcp.contracts.PassResult`,
:class:`~vulfi_mcp.contracts.Candidate` and
:class:`~vulfi_mcp.contracts.RuleEvidence`. Everything a provider says is data;
nothing it says is an instruction, and nothing it prints as prose becomes a
fact.

The one rule that decides what this module will and will not claim: **a
structural fact may only come from structured output whose addresses can be
cited.** High P-code varnodes, cross-reference records, the memory map and
mapped bytes qualify. Decompiled C does not, and this module never asks for
it: a rule whose branch needs a fact only the pseudocode shows is reported
``unsupported`` with the fact named.

What was measured against GhidraMCP 6.0.0 on Ghidra 12.1.2, and what each
measurement forced:

``import_file`` is GUI-only
    The headless server answers ``{"error": "Import requires GUI mode
    (PluginTool not available)"}``. ``load_program`` is the headless import
    and is what this adapter uses; ``import_file`` is not in the allowlist
    because it cannot work on the server this adapter supports.

``dry_run`` is advertised and not honoured
    ``create_function`` declares a ``dry_run`` argument, and a call carrying
    ``dry_run=true`` **created the function anyway** (the next call reported
    "Function already exists"). No write below is guarded by it; every write
    is guarded by this adapter's own checks, before the call.

``create_function`` will split a function that is already there
    Asked for an address inside an existing function, GhidraMCP created a
    second function at it and shortened the first. The overlap check is
    therefore ours and runs before the call, which is the whole of
    ``test_conflicting_write_not_applied``.

``create_project`` destroys an existing project of the same name
    Re-creating a project emptied it (``file_count`` 1 to 0). The managed
    project is always *opened* first and only created when opening fails.

Every reply is a success
    The bridge returns a tool's failure as ordinary text — ``{"error": ...}``
    or ``{"success": false, ...}`` — with ``isError`` false. Each reply is
    parsed and checked here; an error document is a failure, never an empty
    result.

Every tool declares an ``outputSchema``, and it is always the same
    The bridge's handlers return ``str``, so each tool advertises
    ``{"result": {"type": "string"}}``. The schema gate therefore has a
    declared output shape to fingerprint, unlike a provider that declares
    none — but that shape carries no structure, and the real payload is a
    JSON (or plain-text) document inside that string. Every parse below is
    written as if the text will be wrong, because nothing in the protocol
    says it will not be.

No tool reports a relocation record, and none reports control-flow edges
    ``pointer_tables`` is therefore ``unavailable`` here: an address-shaped
    integer and a relocated pointer look identical through this surface, and
    the difference is the whole of the evidence. ``structures`` is
    ``unavailable`` for the same kind of reason: nothing in this build reports
    sized operand cross-references at byte granularity, so no layout can be
    proven. Neither is claimed because a tool with a promising name exists.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from vulfi_mcp.contracts import (
    AddressGap,
    AddressRange,
    Candidate,
    PassResult,
    RuleEvidence,
)
from vulfi_mcp.ida_adapter import data_dir
from vulfi_mcp.ida_runtime import (
    ADDRESS_SPACE_IMAGE,
    MAX_PREPARE_WARNINGS,
    MAX_STRING_BYTES,
    MIN_STRING_CHARS,
    OperationError,
    UnavailableEvidenceError,
    evaluate_rule,
    validate_proposal,
)
from vulfi_mcp.providers.client import (
    ProviderError,
    ProviderSession,
    ProviderUnavailableError,
    checked_call,
    provider_session,
    rule_contexts,
)
from vulfi_mcp.providers.config import ProviderConfig, load_provider_config
from vulfi_mcp.rules import Rule

__all__ = [
    "ALLOWLIST",
    "BACKEND",
    "GhidraUnavailableError",
    "PINNED_SCHEMAS",
    "PreparedPass",
    "ProviderBusyError",
    "apply_ghidra_review",
    "evidence_ghidra",
    "prepare_ghidra",
]

#: The backend these results are authored by.
BACKEND: Final = "ghidra"

#: Every tool this adapter may ask a Ghidra provider for, and the complete
#: list of them. It is a constant on purpose: an installation cannot widen it,
#: a caller cannot name a tool, and :func:`provider_session` fails closed, so
#: anything missing from here is simply not callable. Nothing that runs a
#: script, a command or a Ghidra analyzer-script is here, and the
#: raw-execution names are refused by the client regardless.
#:
#: Four tools the plan named are deliberately absent, each for a measured
#: reason. ``import_file`` needs the GUI plugin and the headless server
#: refuses it (``load_program`` is the headless import, and is here).
#: ``analyze_dataflow`` anchors on a *named* variable, and the varnodes that
#: decide a constant argument — ``unique`` temporaries holding a COPY of an
#: immediate — have no name to anchor on, so it cannot corroborate the fact
#: that matters. ``get_metadata`` answers in plain text with exactly what
#: ``list_open_programs`` already answers as JSON, so allowlisting it would
#: widen the surface in exchange for a more fragile parse. ``add_struct_field``
#: adds one field at a time to a type that already exists, and the only layout
#: this adapter ever writes is a whole approved one through ``create_struct``;
#: an allowlisted tool nothing calls is surface for nothing.
ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        # project and program lifecycle: the managed project has to survive
        # being saved, released and reopened by a later session
        "get_project_info",
        "open_project",
        "create_project",
        "load_program",
        "load_program_from_project",
        "list_open_programs",
        "close_program",
        "save_program",
        # analysis
        "run_analysis",
        "analysis_status",
        # reads, every one of which answers with addresses
        "list_segments",
        "list_functions",
        "list_strings",
        "read_memory",
        "get_xrefs_to",
        "get_function_pcode",
        "analyze_control_flow",
        # the only writes, each one checked here before it is sent
        "create_function",
        "create_struct",
    }
)

#: The schema each allowlisted tool advertised when this adapter was written,
#: as :func:`vulfi_mcp.providers.client.tool_fingerprint` digests it (name,
#: input schema, output schema; never the description).
#:
#: These are deliberately exact. A provider whose tool no longer matches the
#: contract this code was written against does not quietly answer in a new
#: shape — that capability becomes unavailable and says so. Re-pinning is a
#: deliberate act, done after reading what changed.
#:
#: Measured against GhidraMCP 6.0.0 on Ghidra 12.1.2, over the bridge's stdio
#: MCP server (``ghidra-mcp-bridge`` 6.0.0, whose own virtualenv carries the
#: 1.x MCP SDK it pins and which therefore reports ``serverInfo.version``
#: 1.30.0), reached from *this* project's pinned ``mcp==2.2.0`` client at
#: protocol 2025-11-25.
PINNED_SCHEMAS: Final[dict[str, str]] = {
    "analysis_status": (
        "c897bebdd1513dd28ecb0fbcbb162006a1031e05298958368763d84242a6b24d"
    ),
    "analyze_control_flow": (
        "ed568524c793d5ce00d3e0b425fd42a1325d02ac56bc68b681a44bde24020016"
    ),
    "close_program": (
        "5cd49d3565ef4ddecd09cb33cebce2aaf40f74b1e17da92eb028352f9fd41db1"
    ),
    "create_function": (
        "047a790dec9ebefaffaf580d8f652cc455b43710d8c61f0467bbfadfe9769cb1"
    ),
    "create_project": (
        "e243271f2edf72d7d7755c2ee510dcb7a27ed015b6123979817804a1e81bdde6"
    ),
    "create_struct": (
        "65015216fccfb2a37c388a3e05ac23bd5bc6ea8ae635b01f217c930e21eea4bd"
    ),
    "get_function_pcode": (
        "d14a26a02f6e70e6fdbf1b5a74f7583b24ba245803653f9c7ca5d32ba669fa73"
    ),
    "get_project_info": (
        "eddfda1d22fc3ba95fa110a7152248d9cbee72322f43d0f0045a2745d2a152c5"
    ),
    "get_xrefs_to": (
        "5bc505d408efad46e24971746a0b34264f016e9afe1d7cea1e96a6235efdf4a1"
    ),
    "list_functions": (
        "793dfc75294c28e6333d147bd8048aa6797c3e0e9a082809229968fddf7ad03e"
    ),
    "list_open_programs": (
        "3a6a6ad11be1ebefd69ab7b39c63fced42c44e04e2b95a705edcbed75e174fd4"
    ),
    "list_segments": (
        "8dabb5f3ddd80728d1f1881740aa36d9edb16b3698da18790c51d351a8029412"
    ),
    "list_strings": (
        "dc7971f78dcacea884fa3b23dc61e350230bdbf0ffbc8a58f0a47a4552cd4588"
    ),
    "load_program": (
        "f237e8c304bc2851f0eff934fcc65033cc80c00ed62caa40513cf4c13db1550a"
    ),
    "load_program_from_project": (
        "849a539a9ec258bfb74e7dbec2ae59a2c9e5dba540ee54d9a5592b3433bea9b7"
    ),
    "open_project": (
        "ba65c2fea80b5f5af46d91e3ab9072236d8c60a033929ed1eadc789bada62d1b"
    ),
    "read_memory": (
        "f5d9bb2410b18734f048d82c30048395d02f8ca9e823441a267835ad2509b051"
    ),
    "run_analysis": (
        "e3c6c61ab38b1090276f97cf3fe3ed921b13c9f8c097a57ce2af3bb724b16644"
    ),
    "save_program": (
        "434e01f60701ef3b505d48e0bd9d21edcdca71d0ae00d2d1951818db311b3865"
    ),
}

#: The four passes this project names. Two of them have no evidence source on
#: this provider, and say so.
PASS_NAMES: Final[tuple[str, ...]] = (
    "strings",
    "functions",
    "structures",
    "pointer_tables",
)

#: Bytes one pass may read out of the provider's memory map.
MAX_PASS_READ_BYTES: Final = 256 * 1024
#: Bytes one ``read_memory`` call asks for.
READ_CHUNK: Final = 4096
#: Functions whose extent one pass measures.
MAX_FUNCTION_EXTENTS: Final = 512
#: Candidates one pass reports.
MAX_PASS_CANDIDATES: Final = 256
#: Pages of ``list_strings`` one pass reads.
MAX_STRING_PAGES: Final = 64
#: Rows one ``list_strings`` page asks for.
STRING_PAGE: Final = 200
#: Pages of ``get_xrefs_to`` one lookup reads.
MAX_XREF_PAGES: Final = 16
#: Rows one ``get_xrefs_to`` page asks for.
XREF_PAGE: Final = 200
#: Pages of ``list_segments`` one session reads, and the rows per page. Every
#: pass's coverage denominator comes out of this listing, so it is paged
#: rather than capped.
MAX_SEGMENT_PAGES: Final = 16
SEGMENT_PAGE: Final = 512
#: Call sites one rule's evidence covers.
MAX_RULE_CALL_SITES: Final = 128
#: Steps taken while deciding what defines one varnode.
MAX_VARNODE_DEPTH: Final = 16

#: Reference kinds that are a call site with recoverable arguments. A
#: ``COMPUTED_CALL_TERMINATOR`` — the indirect jump inside a PLT thunk — is
#: not one: it has no argument list of its own, and the real call sites are
#: the ones that reach the thunk.
CALL_REFERENCES: Final[frozenset[str]] = frozenset(
    {"UNCONDITIONAL_CALL", "CONDITIONAL_CALL", "COMPUTED_CALL", "CALL"}
)

#: Encodings this adapter decodes out of mapped bytes, widest run first.
_ENCODINGS: Final[tuple[tuple[str, int, str], ...]] = (
    ("utf-16be", 2, "utf-16-be"),
    ("utf-16le", 2, "utf-16-le"),
    ("ascii", 1, "ascii"),
)

#: Why a pass that has no typed evidence source says so, per pass.
_NO_SOURCE: Final[dict[str, str]] = {
    "structures": (
        "this Ghidra build exposes no typed tool that reports sized operand"
        " cross-references at byte granularity, so no field offset or width"
        " can be proven from it; a structure described from anything less"
        " would be a guess with a type name on it"
    ),
    "pointer_tables": (
        "this Ghidra build exposes no typed tool that reports relocation"
        " records, and through the tools it does expose a relocated pointer"
        " and an address-shaped integer are identical; telling them apart is"
        " the whole of the evidence a pointer table rests on"
    ),
}

_FUNCTION_LINE: Final = re.compile(r"\A(?P<name>.+?) at (?P<address>[0-9A-Fa-f]+)\Z")
_SEGMENT_LINE: Final = re.compile(
    r"\A(?P<name>[^:]+): (?P<start>[0-9A-Fa-f]+) - (?P<end>[0-9A-Fa-f]+)\Z"
)
_STRING_LINE: Final = re.compile(r'\A(?P<address>[0-9A-Fa-f]+): ".*"\Z', re.DOTALL)
_XREF_LINE: Final = re.compile(
    r"\AFrom (?P<source>.+?)(?: in (?P<function>[^\[]+?))?"
    r" \[(?P<kind>[A-Z_]+)\]\Z"
)

#: The width a proposed field maps to, in the spelling Ghidra's type tools
#: take. Any other width is refused rather than approximated.
_FIELD_TYPES: Final[dict[int, str]] = {1: "byte", 2: "word", 4: "dword", 8: "qword"}


class PreparedPass(PassResult):
    """One pass result, with the rows it names and the base it read them at.

    :class:`~vulfi_mcp.contracts.PassResult` carries ``candidate_ids``;
    nothing downstream can do anything with an id whose row it does not have,
    so the rows travel with the pass that found them, exactly as the catalog's
    own pass payload carries them. ``image_base`` is here because Ghidra
    rebases a position-independent image and every address in this result is
    in *its* space, not the file's.
    """

    candidates: list[Candidate]
    image_base: int


class GhidraUnavailableError(ProviderError):
    """The Ghidra provider is not configured, or cannot hold this target.

    Separate from a failed pass on purpose: a pass that ran and could not
    finish is a result with coverage on it, while this is "there is no
    provider to ask", which the routing layer reports as unavailable rather
    than as a clean zero.
    """


class ProviderBusyError(GhidraUnavailableError):
    """Something else is driving this provider, and it is a shared process.

    GhidraMCP is one JVM with one *current* program. Another client that has
    loaded a different binary, or an analysis still running in it, makes this
    target unanalysable right now — which is unavailability, not a result. It
    is a subclass of :class:`GhidraUnavailableError` so every caller that
    already re-raises unavailability re-raises this too, instead of writing it
    down as a rule that failed.
    """


# --------------------------------------------------------------------------
# the public surface
# --------------------------------------------------------------------------


async def prepare_ghidra(
    target: str, passes: tuple[str, ...]
) -> tuple[PassResult, ...]:
    """Run the requested preparation passes against the Ghidra provider.

    Each pass declares its own coverage from what it measured. Two of the four
    are ``unavailable`` on this provider and say which typed capability is
    missing; the two that can be justified read the provider's memory map, its
    cross-references and its function list, and write only where this adapter
    has already checked that the write does not land on something that is
    already there.
    """
    wanted = _requested(passes)
    config = _config()
    async with provider_session(
        config, target, allowlist=_allowlist(config)
    ) as session:
        program = await _open_program(session, config, target)
        try:
            record = _load_record(session.binary_sha256)
            results: list[PassResult] = []
            for name in PASS_NAMES:
                if name not in wanted:
                    continue
                results.append(await _run_pass(session, program, record, name))
            saved, save_reason = await _save(session)
            # Only a run that really changed the program moves the revision. A
            # pass that reports a definition an earlier run already made has
            # applied nothing *now*, and a revision that moved without a
            # change would stale every proposal written against the last one.
            if program.mutated and saved:
                record["revision"] = int(record["revision"]) + 1
            if saved:
                _store_record(session.binary_sha256, record)
            revision = int(record["revision"])
            for entry in results:
                entry["artifact_revision"] = revision if saved else None
                if not saved:
                    _degrade(entry, save_reason)
            return tuple(results)
        finally:
            await _release(session, program)


async def evidence_ghidra(
    target: str, rule: Rule, rule_index: int
) -> RuleEvidence:
    """Establish, for one rule, the facts this provider can actually prove.

    Facts, never a verdict: :func:`vulfi_mcp.ida_runtime.evaluate_rule` stays
    the only thing that turns them into a priority, so a second backend cannot
    reach a different conclusion from the same evidence. Whether the facts are
    *enough* is decided by that same evaluator, run here as a probe over the
    contexts this built — a rule whose branch asks for something no fact here
    states comes back ``unsupported`` with the missing fact named, rather than
    answered ``False``.
    """
    config = _config()
    try:
        async with provider_session(
            config, target, allowlist=_allowlist(config)
        ) as session:
            program = await _open_program(session, config, target)
            try:
                return await _rule_evidence(session, program, rule, rule_index)
            finally:
                await _release(session, program)
    except GhidraUnavailableError:
        # "There is no provider to ask" is unavailability, not a rule this
        # backend tried and could not finish, and the routing layer has to be
        # able to tell the two apart.
        raise
    except ProviderError as refused:
        return _evidence(rule_index, [], [], "failed", str(refused))


async def apply_ghidra_review(
    target: str, proposal: dict[str, object], expected_revision: int
) -> dict[str, object]:
    """Apply one operator-approved proposal, or say exactly why nothing was.

    A refusal is a result rather than an exception, for the same reason the
    IDA path makes it one: the catalog already holds an approval against this
    proposal and has to be able to record what became of it. The one thing
    this never returns is a revision it did not move — the revision rises only
    when the write landed *and* the provider saved the project.
    """
    body = validate_proposal(proposal)
    expected = _whole(expected_revision, "expected_revision")
    config = _config()
    async with provider_session(
        config, target, allowlist=_allowlist(config)
    ) as session:
        program = await _open_program(session, config, target)
        try:
            record = _load_record(session.binary_sha256)
            revision = int(record["revision"])
            if program.mutated:
                # The project held no analysed program, so opening it changed
                # the artifact before this approval was ever considered. That
                # is a new revision, and this approval was not made against
                # it — the comparison below is what says so.
                opened, _ = await _save(session)
                if opened:
                    revision += 1
                    record["revision"] = revision
                    _store_record(session.binary_sha256, record)
            report: dict[str, object] = {
                "backend": BACKEND,
                "mutated": False,
                "applied": False,
                "stale": False,
                "revision": revision,
                "previous_revision": revision,
                "expected_revision": expected,
                "effect": _effect(body),
                "site": None,
                "reason": None,
            }
            if revision != expected:
                report["stale"] = True
                report["reason"] = (
                    f"this approval was made against revision {expected} and"
                    f" the managed Ghidra project now carries revision"
                    f" {revision}, so the evidence it rests on is not the"
                    " evidence it would be applied to; nothing was applied"
                )
                return report
            await _apply(session, program, body, report)
            if not report["mutated"]:
                return report
            saved, save_reason = await _save(session)
            if not saved:
                report["applied"] = False
                report["reason"] = (
                    f"the change was applied to the open program and the"
                    f" provider could not save it ({save_reason}), so no"
                    " revision was approved and the next session reopens the"
                    " project as it was before"
                )
                return report
            record["revision"] = revision + 1
            _store_record(session.binary_sha256, record)
            report.update(applied=True, revision=revision + 1)
            return report
        finally:
            await _release(session, program)


# --------------------------------------------------------------------------
# configuration, identity and the managed record
# --------------------------------------------------------------------------


def _config() -> ProviderConfig:
    config = load_provider_config().get(BACKEND)
    if config is None:
        raise GhidraUnavailableError(
            "no Ghidra provider is configured; this server reaches Ghidra only"
            " through the operator's provider configuration, and an"
            " unconfigured backend is unavailable rather than absent"
        )
    return config


def _allowlist(config: ProviderConfig) -> frozenset[str]:
    """This adapter's tools, plus the attestation tool the operator named.

    The attestation tool is called by the client itself, through the same
    allowlist, so a configuration that names one and an adapter that does not
    declare it would refuse its own identity check.
    """
    if config.attest is None:
        return ALLOWLIST
    return ALLOWLIST | {config.attest.tool}


def _managed_root(sha256: str) -> Path:
    return data_dir() / BACKEND / sha256


def _load_record(sha256: str) -> dict[str, Any]:
    """What this adapter remembers about one binary's managed project.

    Every key it writes is read back. ``project`` in particular: it is the
    only witness that a managed project exists when the workspace is mapped
    somewhere this host cannot see, and a loader that dropped it turned the
    second half of the create-project guard into dead code that the next
    ``_store_record`` then erased from disk.
    """
    empty: dict[str, Any] = {
        "binary_sha256": sha256,
        "revision": 0,
        "defined": [],
        "project": None,
    }
    path = _managed_root(sha256) / "record.json"
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(stored, dict):
        return empty
    revision = stored.get("revision")
    defined = stored.get("defined")
    project = stored.get("project")
    return {
        "binary_sha256": sha256,
        "revision": revision if isinstance(revision, int) and revision >= 0 else 0,
        "defined": [item for item in defined if isinstance(item, int) and item >= 0]
        if isinstance(defined, list)
        else [],
        "project": project if isinstance(project, str) and project else None,
    }


def _store_record(sha256: str, record: Mapping[str, Any]) -> None:
    root = _managed_root(sha256)
    root.mkdir(parents=True, exist_ok=True)
    (root / "record.json").write_text(
        json.dumps(dict(record), sort_keys=True), encoding="utf-8"
    )


def _project(config: ProviderConfig, sha256: str) -> tuple[str, str]:
    """Where the managed project lives on the provider's side, and its name.

    The directory is this server's own managed workspace, translated through
    the operator's path map — the same map that says which bytes are which.
    An installation that never mapped the workspace is told so, rather than
    having a path invented for it.
    """
    local = _managed_root(sha256)
    local.mkdir(parents=True, exist_ok=True)
    try:
        remote = config.remote_path(str(local))
    except KeyError:
        raise GhidraUnavailableError(
            f"the operator's binary map does not say where {local} — this"
            " server's managed Ghidra workspace — is on the provider's side,"
            " so there is nowhere to keep a project that both ends agree on"
        ) from None
    return remote, f"vulfi-{sha256[:16]}"


# --------------------------------------------------------------------------
# one checked call, and the two shapes a reply comes back in
# --------------------------------------------------------------------------


async def _call(session: ProviderSession, tool: str, **arguments: Any) -> str:
    """One allowlisted call, as text, or a failure — never as nothing.

    **This is the only place a reply is judged to have succeeded**, and every
    reply passes through it, the JSON ones and the plain-text ones alike. The
    bridge answers a refused operation with ``isError`` false and an error
    document in the body, so a parser downstream that is handed that body
    reads no rows out of it and returns an empty list — and "the program moved
    out from under us" becomes "we looked and there was nothing", which is the
    one inversion this adapter exists to prevent.

    The invariant is flat and lives here rather than in each parser: *a read
    that did not succeed never becomes an empty collection.* ``_call_json``
    only has to parse what this already accepted.
    """
    pinned = PINNED_SCHEMAS.get(tool)
    if not pinned:
        raise GhidraUnavailableError(
            f"the {tool!r} tool has no pinned schema in this adapter, so there"
            " is nothing to check the provider's contract against"
        )
    reply = await checked_call(session, tool, dict(arguments), pinned)
    structured = reply.get("structured")
    if isinstance(structured, dict) and isinstance(structured.get("result"), str):
        text = structured["result"]
    else:
        blocks = reply.get("text")
        if not isinstance(blocks, list) or not all(
            isinstance(item, str) for item in blocks
        ):
            raise ProviderUnavailableError(
                f"the ghidra provider's {tool!r} reply carried neither a result"
                " string nor text blocks, so there is nothing in it to read"
            )
        text = "\n".join(blocks)
    _refuse_failures(tool, text)
    return text


def _refuse_failures(tool: str, text: str) -> None:
    """Raise when ``text`` is this provider's way of spelling a failure."""
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return
    try:
        document = json.loads(stripped)
    except ValueError:
        return
    if not isinstance(document, dict):
        return
    failure = document.get("error")
    if failure is None and document.get("success") is not False:
        return
    described = f"the ghidra provider refused {tool!r}: {failure or document}"
    if _is_contention(str(failure or document)):
        raise ProviderBusyError(described)
    raise ProviderUnavailableError(described)


async def _call_json(
    session: ProviderSession, tool: str, **arguments: Any
) -> dict[str, Any]:
    """One call whose reply is a JSON object, already known to have succeeded."""
    raw = await _call(session, tool, **arguments)
    try:
        document = json.loads(raw)
    except ValueError:
        raise ProviderUnavailableError(
            f"the ghidra provider's {tool!r} reply is not the JSON document"
            f" this adapter was written against: {raw[:200]!r}"
        ) from None
    if not isinstance(document, dict):
        raise ProviderUnavailableError(
            f"the ghidra provider's {tool!r} reply is a"
            f" {type(document).__name__}, not an object"
        )
    return document


#: The family of things this provider says when it has no program to answer
#: about, or when something else is using it. A *family*, deliberately spelled
#: as one pattern rather than a list of literals: the server source carries a
#: dozen wordings of "no program", and a set that has to enumerate them is a
#: set that is one wording out of date. It is only ever a hint about *how* to
#: report a failure this adapter has already refused to treat as a result —
#: whether the provider is busy (skip) or broken (fail). Whether a foreign
#: program is loaded is asked of :func:`_foreign_programs`, not of prose.
_CONTENTION: Final = re.compile(
    # "no program(s)" — but not "the project has no program files", which is
    # this provider's way of saying a program is not in a project yet, and is
    # an ordinary branch rather than contention.
    r"no programs?\b(?! files)"
    r"|program (?:is )?not (?:loaded|open)"
    r"|not currently open"
    r"|timed out|timeout"
    r"|file is closed|closedexception"
    r"|is being analy[sz]ed|another analysis",
    re.IGNORECASE,
)


def _is_contention(message: str) -> bool:
    return _CONTENTION.search(message) is not None


# --------------------------------------------------------------------------
# opening, saving and releasing the managed program
# --------------------------------------------------------------------------


class _Program:
    """One open program, and everything about it this session measured."""

    __slots__ = (
        "base",
        "mutated",
        "name",
        "project",
        "remote",
        "segment_cap",
        "segments",
    )

    def __init__(
        self,
        *,
        name: str,
        project: str,
        remote: str,
        base: int,
        segments: list[dict[str, Any]],
        segment_cap: str | None,
        mutated: bool,
    ) -> None:
        self.name = name
        self.project = project
        self.remote = remote
        self.base = base
        self.segments = segments
        #: Why the block listing is incomplete, when it is. Every pass's
        #: coverage is measured over ``segments``, so a pass that ran against a
        #: cut-short listing may not report ``complete``.
        self.segment_cap = segment_cap
        #: Whether this session has written anything to the open program.
        self.mutated = mutated


async def _open_program(
    session: ProviderSession, config: ProviderConfig, target: str
) -> _Program:
    """Open the managed project and the program in it, analysing it once.

    Two refusals come before anything that could destroy somebody else's work,
    and the order is the point.

    First, **a foreign program is refused before the project is touched at
    all**. A failed ``open_project`` closes whatever program the JVM was
    holding, so a check that runs after it has nothing left to see: this
    adapter would have evicted another client's program and then reported a
    clean run. The question is asked of the provider's state —
    ``list_open_programs`` says how many and which — never of its prose.

    Second, the project is opened before it is created, and created **only**
    when nothing says one is already there: ``create_project`` on a name that
    already exists empties it, so treating every ``open_project`` failure as
    "it does not exist yet" would turn a stale lock or a transient refusal
    into the loss of every earlier revision.
    """
    foreign = await _foreign_programs(session)
    if foreign:
        raise ProviderBusyError(
            f"the ghidra provider is holding {foreign} open, which this session"
            " did not open and may not close or evict; it works against"
            f" exactly one program and this target is {session.remote_path}"
        )
    parent, name = _project(config, session.binary_sha256)
    path = f"{parent}/{name}.gpr"
    record = _load_record(session.binary_sha256)
    # By path, every time, and never by name: the project name is derived
    # from the binary's digest, so two managed workspaces holding the same
    # bytes name their projects identically. Trusting the name would reopen
    # the program out of whichever of them happened to be current.
    try:
        await _call_json(session, "open_project", path=path)
    except ProviderUnavailableError as refused:
        existing = _existing_project(session.binary_sha256, name, record)
        if existing is not None:
            raise ProviderUnavailableError(
                f"the ghidra provider could not open the managed project at"
                f" {path} ({refused}), and {existing}. Creating it again would"
                " empty it and take every earlier revision with it, so nothing"
                " was created and nothing was opened"
            ) from None
        await _call_json(session, "create_project", parentDir=parent, name=name)
        record["project"] = name
        _store_record(session.binary_sha256, record)
    info = await _call_json(session, "get_project_info")
    if info.get("project_name") != name:
        raise ProviderUnavailableError(
            f"the ghidra provider has project {info.get('project_name')!r} open"
            f" where this target's managed project is {name!r} at {path}"
        )
    program = await _load(session)
    base, title = await _identity(session)
    status = await _call_json(session, "analysis_status", program=title)
    analysed = False
    if not status.get("analyzed"):
        # The first analysis is itself a change to the managed artifact: it is
        # what puts the functions, strings and data in it that every later
        # result rests on, so the revision this session reports has to move.
        await _call_json(session, "run_analysis")
        analysed = True
    segments, segment_cap = await _segments(session)
    return _Program(
        name=title,
        project=name,
        remote=program,
        base=base,
        segments=segments,
        segment_cap=segment_cap,
        mutated=analysed,
    )


def _existing_project(sha256: str, name: str, record: Mapping[str, Any]) -> str | None:
    """Why this adapter believes a managed project is already there, or ``None``.

    Two independent witnesses, because either one can be absent. The project
    directory *on this host* answers whenever the operator mapped the managed
    workspace to itself, which is the ordinary co-located case — but
    :func:`_project` translates that root through the operator's binary map,
    so for a genuinely remote workspace the ``.gpr`` never exists here. The
    second witness covers exactly that case: this adapter's own record of
    having created the project, which :func:`_load_record` carries forward
    precisely so this check can fire when the filesystem cannot answer.
    """
    local = _managed_root(sha256)
    if (local / f"{name}.gpr").exists() or (local / f"{name}.rep").is_dir():
        return f"{local / f'{name}.gpr'} is on this host"
    if record.get("project") == name:
        return (
            "this server's own record of this binary says it created that"
            " project already"
        )
    return None


async def _foreign_programs(session: ProviderSession) -> list[str]:
    """Every program this provider holds that is not the operator's target.

    Asked of the provider's state rather than of its prose, and asked before
    anything that could evict one. ``list_open_programs`` is the only typed
    answer to "whose JVM is this right now", and it is the primary signal for
    every busy refusal below.
    """
    open_now = await _call_json(session, "list_open_programs")
    programs = open_now.get("programs")
    if not isinstance(programs, list):
        raise ProviderUnavailableError(
            "the ghidra provider's open-program listing is not a list, so"
            " there is no way to tell whose program it is holding"
        )
    held: list[str] = []
    for entry in programs:
        if not isinstance(entry, dict):
            raise ProviderUnavailableError(
                "the ghidra provider's open-program listing holds an entry"
                " that is not an object"
            )
        if entry.get("executable_path") != session.remote_path:
            held.append(str(entry.get("executable_path") or entry.get("name")))
    return held


async def _load(session: ProviderSession) -> str:
    """Get *this* program open, from the project when it is already in it.

    A provider holding somebody else's program is refused rather than tidied
    up: GhidraMCP is one process with one current program, and closing a
    program this session did not open would discard another client's unsaved
    analysis. The refusal names what is open, which is what lets a caller —
    and this project's live tests — tell "the provider is busy" from "the
    adapter is wrong".
    """
    remote = session.remote_path
    stem = Path(remote).name
    foreign = await _foreign_programs(session)
    if foreign:
        raise ProviderBusyError(
            f"the ghidra provider is holding {foreign} open, which this"
            f" session did not open and may not close; it works against"
            f" exactly one program and this target is {remote}"
        )
    open_now = await _call_json(session, "list_open_programs")
    programs = open_now.get("programs")
    mine: str | None = None
    for entry in programs if isinstance(programs, list) else []:
        if isinstance(entry, dict) and entry.get("executable_path") == remote:
            mine = str(entry.get("path") or f"/{stem}")
            break
    if mine is not None:
        return mine
    try:
        loaded = await _call_json(session, "load_program_from_project", path=f"/{stem}")
    except ProviderError:
        # Not in the project yet — the ordinary first-run branch. A provider
        # that is really unusable fails again on the import below, loudly and
        # with its own words, rather than being guessed at from this one.
        loaded = await _call_json(session, "load_program", file=remote)
    path = loaded.get("path")
    return str(path) if isinstance(path, str) else f"/{stem}"


async def _identity(session: ProviderSession) -> tuple[int, str]:
    """The image base and program name the provider says it opened.

    Checked, not taken: the provider must be holding the file the operator
    mapped. A provider analysing something else is a provider whose addresses
    mean nothing here.
    """
    open_now = await _call_json(session, "list_open_programs")
    programs = open_now.get("programs")
    if not isinstance(programs, list) or len(programs) != 1:
        raise ProviderBusyError(
            "the ghidra provider has"
            f" {len(programs) if isinstance(programs, list) else 'no'} programs"
            " open; this adapter works against exactly one, so that an address"
            " it is given cannot be read out of a different binary"
        )
    entry = programs[0]
    if not isinstance(entry, dict):
        raise ProviderUnavailableError(
            "the ghidra provider's open-program listing is not an object"
        )
    opened = entry.get("executable_path")
    if opened != session.remote_path:
        raise ProviderBusyError(
            f"the ghidra provider has {opened!r} open where the operator's map"
            f" says this target is {session.remote_path!r}; nothing was read"
            " from it"
        )
    base = _address(entry.get("image_base"))
    if base is None:
        raise ProviderUnavailableError(
            f"the ghidra provider reports image_base={entry.get('image_base')!r},"
            " which is not an address, so no result of this session could be"
            " placed in the image"
        )
    return base, str(entry.get("name") or Path(session.remote_path).name)


async def _save(session: ProviderSession) -> tuple[bool, str]:
    """Save the open program; report a failed save rather than raising."""
    try:
        await _call_json(session, "save_program")
    except ProviderError as refused:
        return False, str(refused)
    return True, ""


async def _release(session: ProviderSession, program: _Program) -> None:
    """Close the program so the next session has to reopen it from the project.

    Deliberate: durability that is only ever observed inside the session that
    wrote it is not durability. Closing here means every later request reads
    the project back off disk, which is the thing that would break first.
    """
    try:
        await _call_json(session, "close_program", name=program.name)
    except ProviderError:
        # Nothing here depends on the close succeeding: the save already
        # happened, and a provider that will not release a program is the
        # next session's problem to report, not a reason to fail this one.
        return


# --------------------------------------------------------------------------
# the provider's own listings, parsed into shapes with addresses in them
# --------------------------------------------------------------------------


def _address(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or "::" in text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _hex(address: int) -> str:
    return f"0x{address:x}"


async def _segments(session: ProviderSession) -> tuple[list[dict[str, Any]], str | None]:
    """Every memory block with a numeric address, as half-open ranges.

    Ghidra's listing is inclusive at both ends and spells an overlay block
    with a ``space::offset`` address that has no place in the image's own
    address space. Those are left out here and named in a warning by the pass
    that wanted them, rather than being folded into an address that is not
    theirs.

    Paged, and the second return value says when the paging ran out. This one
    matters more than the other bounded reads: **every pass computes its
    coverage over these blocks**, so a listing silently cut short shrinks the
    denominator and lets a pass report ``complete`` over blocks it never saw.
    """
    blocks: list[dict[str, Any]] = []
    for page in range(MAX_SEGMENT_PAGES):
        text = await _call(
            session, "list_segments", limit=SEGMENT_PAGE, offset=page * SEGMENT_PAGE
        )
        lines = [line for line in text.splitlines() if line.strip()]
        for line in lines:
            match = _SEGMENT_LINE.match(line.strip())
            if match is None:
                continue
            start = _address(match["start"])
            end = _address(match["end"])
            if start is None or end is None or end < start:
                continue
            blocks.append({"name": match["name"], "start": start, "end": end + 1})
        if len(lines) < SEGMENT_PAGE:
            return blocks, None
    return blocks, (
        f"the provider's memory-block listing did not end within"
        f" {MAX_SEGMENT_PAGES * SEGMENT_PAGE} blocks, so every coverage below"
        " is measured over part of the image rather than over all of it"
    )


async def _functions(session: ProviderSession) -> list[dict[str, Any]]:
    """Every function the provider currently defines, by entry address."""
    found: dict[int, str] = {}
    for line in (await _call(session, "list_functions")).splitlines():
        match = _FUNCTION_LINE.match(line.strip())
        if match is None:
            continue
        entry = _address(match["address"])
        if entry is None:
            continue
        found.setdefault(entry, match["name"])
    return [
        {"entry": entry, "name": name} for entry, name in sorted(found.items())
    ]


class _Extents:
    """How far each known function reaches, and which of those were measured.

    An extent this pass could not measure — the budget ran out, or
    ``analyze_control_flow`` refused — is **not** evidence that the function
    is short. Every such entry is still given a span, running to the next
    known entry (or the end of its block), and is recorded as unmeasured, so
    an address inside it is treated as owned and never written over. The
    alternative, leaving it out of the map, is what let a write land inside a
    function this adapter exists to protect.
    """

    __slots__ = ("measured", "spans", "truncated")

    def __init__(
        self,
        spans: dict[int, int],
        measured: set[int],
        truncated: str | None,
    ) -> None:
        self.spans = spans
        self.measured = measured
        self.truncated = truncated

    def owner(self, address: int) -> tuple[int, int, bool] | None:
        """The function whose body holds ``address``: entry, end, measured."""
        for entry, end in self.spans.items():
            if entry < address < end:
                return entry, end, entry in self.measured
        return None


async def _extents(
    session: ProviderSession,
    entries: Sequence[int],
    blocks: Sequence[Mapping[str, Any]],
) -> _Extents:
    """How far each function reaches, measured one function at a time.

    ``list_functions`` reports entries and nothing else, so the only typed
    source for a function's extent is ``analyze_control_flow``, which is asked
    by address — never by name, because two distinct functions here really are
    both called ``printf`` and the name lookup answers for neither.
    """
    ordered = sorted(entries)
    spans: dict[int, int] = {}
    measured: set[int] = set()
    budget = set(ordered[:MAX_FUNCTION_EXTENTS])
    for index, entry in enumerate(ordered):
        if entry in budget:
            flow: dict[str, Any] | None
            try:
                flow = await _call_json(
                    session, "analyze_control_flow", function_name=_hex(entry)
                )
            except GhidraUnavailableError:
                raise
            except ProviderError:
                flow = None
            if flow is not None:
                start = _address(flow.get("entry_point"))
                size = flow.get("size_bytes")
                if (
                    start == entry
                    and isinstance(size, int)
                    and not isinstance(size, bool)
                ):
                    spans[entry] = entry + max(size, 1)
                    measured.add(entry)
                    continue
        spans[entry] = _conservative_end(entry, ordered, index, blocks)
    truncated = None
    if len(ordered) > len(measured):
        truncated = (
            f"this provider defines {len(ordered)} functions and this pass"
            f" measured the extent of {len(measured)}; the rest are treated as"
            " reaching to the next known entry, so an address inside one of"
            " them is described and never defined"
        )
    return _Extents(spans, measured, truncated)


def _conservative_end(
    entry: int,
    ordered: Sequence[int],
    index: int,
    blocks: Sequence[Mapping[str, Any]],
) -> int:
    """Where an unmeasured function might still reach: the widest it could be."""
    limits = [
        int(block["end"])
        for block in blocks
        if int(block["start"]) <= entry < int(block["end"])
    ]
    if index + 1 < len(ordered):
        limits.append(ordered[index + 1])
    return min(limits) if limits else entry + 1


async def _read(
    session: ProviderSession, start: int, length: int
) -> bytes:
    """Mapped bytes at one address, as the provider reads them."""
    document = await _call_json(
        session, "read_memory", address=_hex(start), length=int(length)
    )
    raw = document.get("hex")
    if not isinstance(raw, str):
        raise ProviderUnavailableError(
            "the ghidra provider's read_memory reply carries no 'hex' field,"
            " so there are no bytes in it to use as evidence"
        )
    try:
        return bytes.fromhex(raw)
    except ValueError:
        raise ProviderUnavailableError(
            f"the ghidra provider's read_memory reply is not hexadecimal:"
            f" {raw[:80]!r}"
        ) from None


async def _xrefs(
    session: ProviderSession, address: int
) -> tuple[list[dict[str, Any]], str | None]:
    """Everything the provider says refers to one address, and what was cut off.

    A reference whose source is a name rather than an address — Ghidra spells
    an external entry point ``From Entry Point`` — is kept with ``address``
    ``None`` rather than dropped. It is still the provider saying something
    reaches here, and the difference between the two forms decides whether a
    write is allowed, so it has to survive into the evidence.

    The listing is paged, and the second return value is non-``None`` when the
    page budget ran out: a bounded read that is not reported as bounded reads
    as "there is nothing more", which is the one thing this project never
    says.
    """
    rows: list[dict[str, Any]] = []
    for page in range(MAX_XREF_PAGES):
        text = await _call(
            session,
            "get_xrefs_to",
            address=_hex(address),
            limit=XREF_PAGE,
            offset=page * XREF_PAGE,
        )
        lines = [line for line in text.splitlines() if line.strip()]
        for line in lines:
            match = _XREF_LINE.match(line.strip())
            if match is None:
                continue
            rows.append(
                {
                    "address": _address(match["source"]),
                    "source": match["source"],
                    "function": match["function"],
                    "kind": match["kind"],
                }
            )
        if len(lines) < XREF_PAGE:
            return rows, None
    return rows, (
        f"the provider's reference listing for {address:#x} did not end within"
        f" {MAX_XREF_PAGES * XREF_PAGE} rows, so what reaches that address is"
        " described from a part of it rather than from all of it"
    )


async def _defined_strings(
    session: ProviderSession,
) -> tuple[set[int], str | None]:
    """The addresses the provider already holds a string at, and what was cut off.

    A capped listing matters here in a specific way: this pass reports what
    the provider *left behind*, so a string it does hold but that fell past
    the cap would be reported as recovered. The cap is therefore named rather
    than left to be inferred from the candidate list.
    """
    defined: set[int] = set()
    for page in range(MAX_STRING_PAGES):
        text = await _call(
            session, "list_strings", offset=page * STRING_PAGE, limit=STRING_PAGE
        )
        lines = [line for line in text.splitlines() if line.strip()]
        for line in lines:
            match = _STRING_LINE.match(line.strip())
            if match is None:
                continue
            address = _address(match["address"])
            if address is not None:
                defined.add(address)
        if len(lines) < STRING_PAGE:
            return defined, None
    return defined, (
        f"the provider's string listing did not end within"
        f" {MAX_STRING_PAGES * STRING_PAGE} rows, so a run this pass reports as"
        " left behind may be one the provider already holds past that cap"
    )


async def _function_pcode(session: ProviderSession, entry: int) -> dict[str, Any]:
    """One function's high P-code, as the provider produced it.

    A module-level function rather than a method so that a test can put a
    changed document in its place and prove that a shape this adapter was not
    written against produces no fact at all.
    """
    return await _call_json(
        session,
        "get_function_pcode",
        function_address=_hex(entry),
        granularity="high",
    )


# --------------------------------------------------------------------------
# the passes
# --------------------------------------------------------------------------


async def _run_pass(
    session: ProviderSession,
    program: _Program,
    record: dict[str, Any],
    name: str,
) -> PreparedPass:
    reason = _NO_SOURCE.get(name)
    if reason is not None:
        return _pass_result(program, name, [], [], [reason])
    try:
        if name == "strings":
            return await _strings_pass(session, program)
        return await _functions_pass(session, program, record)
    except GhidraUnavailableError:
        # Something else is driving this provider, or there is none. Neither is
        # a pass that ran and found little, and recording it as one would turn
        # "we could not look" into "we looked and there was nothing".
        raise
    except ProviderError as refused:
        return _pass_result(
            program,
            name,
            [],
            [],
            [f"the {name!r} pass could not finish: {refused}"],
        )


async def _strings_pass(
    session: ProviderSession, program: _Program
) -> PreparedPass:
    """Recover text out of mapped bytes, and say which of it was already there.

    The evidence is the bytes, at an address, in an encoding — never a
    listing's own opinion. The provider's string listing is read only to
    separate what it already holds from what it left behind.
    """
    defined, capped = await _defined_strings(session)
    entries = {row["entry"] for row in await _functions(session)}
    ranges: list[AddressRange] = []
    candidates: list[Candidate] = []
    warnings: list[str] = [capped] if capped else []
    budget = MAX_PASS_READ_BYTES
    for block in program.segments:
        if any(block["start"] <= entry < block["end"] for entry in entries):
            # A block holding code is not swept for text, and is named here
            # rather than left out: a pass that summarises only the ranges it
            # chose to visit can report `complete` over an image it covered
            # half of.
            ranges.append(
                _unreached(
                    block,
                    "raw_bytes",
                    "this block holds code the provider already defines, so"
                    " this pass did not read it for text",
                )
            )
            continue
        entry_range = _range(block, "raw_bytes")
        read, failure = await _sweep(session, block, entry_range, budget)
        budget -= len(read)
        ranges.append(entry_range)
        if failure is not None:
            warnings.append(failure)
            continue
        for found in _runs(read, block["start"]):
            if len(candidates) >= MAX_PASS_CANDIDATES:
                _stop(entry_range, found["start"], block, "too many candidates")
                warnings.append(
                    f"this pass reported {MAX_PASS_CANDIDATES} strings and"
                    f" stopped in {block['name']}; the rest of it is unvisited"
                )
                break
            if found["start"] in defined:
                continue
            candidates.append(_string_candidate(block, found))
    return _pass_result(program, "strings", ranges, candidates, warnings)


async def _functions_pass(
    session: ProviderSession, program: _Program, record: dict[str, Any]
) -> PreparedPass:
    """Define the entry points a pointer and the mapped bytes justify.

    Every candidate here rests on two things the provider stated: a reference
    record naming the address, and the bytes at it. A candidate that falls
    inside a function the provider already defines is described and never
    written, because ``create_function`` at such an address splits the
    function that was there — measured on this build, not assumed.
    """
    functions = await _functions(session)
    entries = {row["entry"]: row["name"] for row in functions}
    extents = await _extents(session, sorted(entries), program.segments)
    warnings: list[str] = [extents.truncated] if extents.truncated else []
    ranges: list[AddressRange] = []
    candidates: list[Candidate] = []
    examined: dict[int, int] = {}
    budget = MAX_PASS_READ_BYTES

    slots: dict[int, int] = {}
    for block in program.segments:
        if any(block["start"] <= entry < block["end"] for entry in entries):
            continue
        entry_range = _range(block, "raw_bytes")
        read, failure = await _sweep(session, block, entry_range, budget)
        budget -= len(read)
        ranges.append(entry_range)
        if failure is not None:
            warnings.append(failure)
            continue
        for offset in range(0, max(len(read) - 7, 0), 8):
            value = int.from_bytes(read[offset : offset + 8], "little")
            slot = block["start"] + offset
            if value == slot or _block_of(program, value) is None:
                # A slot holding its own address is the loader's own
                # bookkeeping, not a pointer at code.
                continue
            slots.setdefault(value, slot)

    defined_here = set(record["defined"])
    for target in sorted(slots):
        if len(candidates) >= MAX_PASS_CANDIDATES:
            warnings.append(
                f"this pass reported {MAX_PASS_CANDIDATES} entries and stopped"
            )
            break
        if target in entries and target not in defined_here:
            continue
        records, capped = await _xrefs(session, target)
        if capped is not None and capped not in warnings:
            warnings.append(capped)
        referenced = [
            row["address"]
            for row in records
            if row["address"] is not None and row["address"] != target
        ]
        named = sorted(
            {str(row["source"]) for row in records if row["address"] is None}
        )
        if slots[target] not in referenced and not named:
            # The provider does not agree that anything refers to this
            # address, so the only thing backing it is this adapter's own
            # reading of eight bytes. That is not a reference.
            continue
        try:
            raw = await _read(session, target, 16)
        except ProviderError as refused:
            warnings.append(f"the bytes at {target:#x} could not be read: {refused}")
            continue
        examined[target] = len(raw)
        owner = extents.owner(target)
        candidates.append(
            await _function_candidate(
                session,
                program,
                record,
                target=target,
                slot=slots[target],
                referenced=referenced,
                named=named,
                raw=raw,
                owner=owner,
                owner_name=entries.get(owner[0]) if owner else None,
                already=target in entries,
            )
        )

    ranges.extend(_code_ranges(program, extents, examined, entries))
    return _pass_result(program, "functions", ranges, candidates, warnings)


async def _function_candidate(
    session: ProviderSession,
    program: _Program,
    record: dict[str, Any],
    *,
    target: int,
    slot: int,
    referenced: list[int],
    named: list[str],
    raw: bytes,
    owner: tuple[int, int, bool] | None,
    owner_name: str | None,
    already: bool,
) -> Candidate:
    """One entry a pointer names, defined only when nothing is already there."""
    block = _block_of(program, target)
    evidence: dict[str, Any] = {
        "stage": "code_scan",
        "method": "an address held in a mapped pointer slot, with the"
        " provider's own reference record behind it",
        "segment": block["name"] if block else None,
        "slot": slot,
        "referenced_from": sorted(referenced),
        "referenced_by": named,
        "bytes": raw.hex(),
        "already_defined": already,
        "owner": {
            "entry": owner[0],
            "end": owner[1],
            "name": owner_name,
            "measured": owner[2],
        }
        if owner
        else None,
    }
    row: Candidate = {
        "candidate_id": f"ghidra:function:{target:08x}",
        "kind": "function",
        "backend": BACKEND,
        "address_space": ADDRESS_SPACE_IMAGE,
        "address": target,
        "evidence": evidence,
        "confidence": 0.9 if owner is None and slot in referenced else 0.4,
        "state": "candidate",
        "reason": None,
    }
    if already:
        row["state"] = "applied"
        row["reason"] = (
            "this entry is already defined in the managed project, by an"
            " earlier run of this pass"
        )
        return row
    if owner is not None and owner[2]:
        row["reason"] = (
            f"{target:#x} is inside {owner_name or 'a function'} at"
            f" {owner[0]:#x}..{owner[1]:#x}, which this provider already"
            " defines; defining a function there would split it, so this"
            " stays a candidate"
        )
        return row
    if owner is not None:
        row["reason"] = (
            f"{target:#x} falls inside {owner_name or 'a function'} at"
            f" {owner[0]:#x}, whose extent this pass could not measure, so"
            f" {owner[0]:#x}..{owner[1]:#x} is the widest it could reach. An"
            " unmeasured extent is not evidence that the address is outside"
            " it, so this stays a candidate"
        )
        return row
    if slot not in referenced:
        row["reason"] = (
            f"the provider records {named or 'no'} reference to {target:#x}"
            f" and none from the slot at {slot:#x} that holds it, so the only"
            " thing tying the two together is this adapter's own reading of"
            " eight bytes; that is described, never defined"
        )
        return row
    try:
        await _call_json(session, "create_function", address=_hex(target))
    except ProviderError as refused:
        row["reason"] = f"the provider refused to define this entry: {refused}"
        return row
    if target not in {item["entry"] for item in await _functions(session)}:
        row["reason"] = (
            "the provider reported this entry defined and does not list a"
            " function at it, so nothing is claimed"
        )
        return row
    row["state"] = "applied"
    evidence["already_defined"] = True
    program.mutated = True
    if target not in record["defined"]:
        record["defined"] = sorted({*record["defined"], target})
    return row


def _string_candidate(block: Mapping[str, Any], found: Mapping[str, Any]) -> Candidate:
    return {
        "candidate_id": f"ghidra:string:{found['encoding']}:{found['start']:08x}",
        "kind": "string",
        "backend": BACKEND,
        "address_space": ADDRESS_SPACE_IMAGE,
        "address": int(found["start"]),
        "evidence": {
            "stage": "raw_bytes",
            "method": "mapped bytes decoded in place",
            "segment": block["name"],
            "encoding": found["encoding"],
            "start": found["start"],
            "end": found["end"],
            "bytes": bytes(found["raw"]).hex(),
            "text": found["text"],
        },
        "confidence": 0.8,
        "state": "candidate",
        "reason": (
            "this provider's allowlisted tools include no typed writer that"
            " defines a string, so the run is described at its address and"
            " never written into the managed project"
        ),
    }


async def _sweep(
    session: ProviderSession,
    block: Mapping[str, Any],
    entry: AddressRange,
    budget: int,
) -> tuple[bytes, str | None]:
    """Read one block, inside the pass's byte budget, and say where it stopped."""
    read = bytearray()
    cursor = int(block["start"])
    end = int(block["end"])
    while cursor < end:
        if budget - len(read) <= 0:
            _stop(entry, cursor, block, "this pass's read budget ran out")
            return bytes(read), None
        want = min(READ_CHUNK, end - cursor, budget - len(read))
        try:
            chunk = await _read(session, cursor, want)
        except ProviderError as refused:
            if not read:
                entry["coverage"] = "unavailable"
                entry["unvisited"] = [{"start": cursor, "end": end}]
                entry["reason"] = f"this range could not be read: {refused}"
                return bytes(read), (
                    f"{block['name']} at {cursor:#x} could not be read: {refused}"
                )
            _stop(entry, cursor, block, f"the provider stopped reading: {refused}")
            return bytes(read), None
        if not chunk:
            _stop(entry, cursor, block, "the provider returned no bytes")
            return bytes(read), None
        read.extend(chunk)
        cursor += len(chunk)
    return bytes(read), None


def _runs(raw: bytes, base: int) -> list[dict[str, Any]]:
    """Every NUL-terminated run in ``raw`` that decodes as one of the encodings.

    One linear pass per encoding. Each terminator closes a stretch, and the
    run reported is the *longest text suffix* of that stretch — which is what
    puts a string that follows binary noise, with no separator between them,
    at its own address rather than losing it to the noise in front of it.

    Widest encoding first, and each run claims its bytes, so a UTF-16LE string
    is not also reported as the ASCII run its low bytes happen to form.
    """
    taken = bytearray(len(raw))
    found: list[dict[str, Any]] = []
    for name, width, codec in _ENCODINGS:
        opened = 0
        cursor = 0
        while cursor + width <= len(raw):
            if raw[cursor : cursor + width] != b"\x00" * width:
                cursor += width
                continue
            start = _text_start(raw, opened, cursor, width, codec)
            opened = cursor + width
            cursor += width
            if (cursor - width - start) // width < MIN_STRING_CHARS:
                continue
            if any(taken[start:cursor]):
                continue
            found.append(
                {
                    "encoding": name,
                    "start": base + start,
                    "end": base + cursor,
                    "raw": raw[start:cursor],
                    "text": raw[start : cursor - width].decode(codec),
                }
            )
            for index in range(start, cursor):
                taken[index] = 1
    return sorted(found, key=lambda item: item["start"])


def _text_start(raw: bytes, low: int, high: int, width: int, codec: str) -> int:
    """The first byte of the longest text run ending at ``high``.

    Walked backwards one character at a time, so the cost is the length of the
    run rather than the length of the region it sits in.
    """
    first = high
    while first - width >= low and high - first < MAX_STRING_BYTES:
        try:
            character = raw[first - width : first].decode(codec)
        except ValueError:
            break
        if not _is_text(character):
            break
        first -= width
    return first


def _is_text(text: str) -> bool:
    """Whether a decoded run is text a reviewer would call a string.

    Every code point has to be printable ASCII (tab and newline included). A
    wide run is otherwise far too easy to find: decode any ten bytes of a
    relocation table as UTF-16 and five printable code points come out of it
    more often than not, which buries the strings a reviewer is looking for
    under the image's own binary structure. Restricting the decode to Latin
    text is what the compiler emits for source literals, and it is a shape
    rather than a guess.
    """
    return bool(text) and all(
        character in "\t\n" or (character.isascii() and character.isprintable())
        for character in text
    )


def _block_of(program: _Program, address: int) -> dict[str, Any] | None:
    for block in program.segments:
        if block["start"] <= address < block["end"]:
            return block
    return None


def _code_ranges(
    program: _Program,
    extents: _Extents,
    examined: Mapping[int, int],
    entries: Mapping[int, str],
) -> list[AddressRange]:
    """What the functions pass did with each block that holds code.

    A block is code here because the provider defines a function in it, or
    because this pass examined an entry in it — not because of a permission
    bit, which this provider's listing does not carry.
    """
    ranges: list[AddressRange] = []
    for block in program.segments:
        inside = [
            (entry, extents.spans.get(entry, entry + 1))
            for entry in entries
            if block["start"] <= entry < block["end"]
        ]
        looked = [
            (entry, entry + length)
            for entry, length in examined.items()
            if block["start"] <= entry < block["end"]
        ]
        if not inside and not looked:
            continue
        entry_range = _range(block, "code_scan")
        gaps = _gaps(block, [*inside, *looked])
        if gaps:
            entry_range["coverage"] = "partial"
            entry_range["unvisited"] = gaps
            entry_range["reason"] = (
                "entries in this range are recovered from pointer slots read"
                " elsewhere in the image; the bytes between known functions"
                " were not swept, because this provider exposes no typed"
                " linear-disassembly tool to sweep them with"
            )
        ranges.append(entry_range)
    return ranges


def _gaps(
    block: Mapping[str, Any], spans: Sequence[tuple[int, int]]
) -> list[AddressGap]:
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        low = max(start, int(block["start"]))
        high = min(end, int(block["end"]))
        if high <= low:
            continue
        if merged and low <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    gaps: list[AddressGap] = []
    cursor = int(block["start"])
    for low, high in merged:
        if cursor < low:
            gaps.append({"start": cursor, "end": low})
        cursor = high
    if cursor < int(block["end"]):
        gaps.append({"start": cursor, "end": int(block["end"])})
    return gaps


def _range(block: Mapping[str, Any], stage: str) -> AddressRange:
    return {
        "name": str(block["name"]),
        "stage": stage,
        "start": int(block["start"]),
        "end": int(block["end"]),
        "coverage": "complete",
        "unvisited": [],
        "reason": None,
    }


def _unreached(block: Mapping[str, Any], stage: str, reason: str) -> AddressRange:
    """A range the pass never started, named rather than left out.

    The same shape the IDA side uses for the same reason: "the pass found
    nothing here" and "the pass never got here" are different answers, and
    only one of them is evidence.
    """
    entry = _range(block, stage)
    entry["coverage"] = "partial"
    entry["unvisited"] = [{"start": int(block["start"]), "end": int(block["end"])}]
    entry["reason"] = reason
    return entry


def _stop(
    entry: AddressRange, cursor: int, block: Mapping[str, Any], reason: str
) -> None:
    entry["coverage"] = "partial"
    entry["reason"] = reason
    if cursor < int(block["end"]):
        entry["unvisited"] = [{"start": cursor, "end": int(block["end"])}]


def _pass_result(
    program: _Program,
    name: str,
    ranges: list[AddressRange],
    candidates: list[Candidate],
    warnings: list[str],
) -> PreparedPass:
    states = {item["coverage"] for item in ranges}
    if not states or states == {"unavailable"}:
        coverage = "unavailable"
    elif states == {"complete"}:
        coverage = "complete"
    else:
        coverage = "partial"
    if program.segment_cap is not None:
        # The ranges below are every block this session could see, and it could
        # not see them all. A pass cannot be complete over a denominator that
        # was itself cut short.
        warnings = [program.segment_cap, *warnings]
        if coverage == "complete":
            coverage = "partial"
    return {
        "pass": name,
        "backend": BACKEND,
        "ranges": ranges,
        "coverage": coverage,
        "applied_ids": [
            row["candidate_id"] for row in candidates if row["state"] == "applied"
        ],
        "candidate_ids": [row["candidate_id"] for row in candidates],
        "warnings": warnings[:MAX_PREPARE_WARNINGS],
        "artifact_revision": None,
        "candidates": candidates,
        "image_base": program.base,
    }


def _degrade(entry: PassResult, reason: str) -> None:
    """A pass whose project was never saved describes a result nothing holds."""
    if entry["coverage"] == "complete":
        entry["coverage"] = "partial"
    entry["warnings"] = [
        *entry["warnings"],
        f"the provider could not save this project ({reason}), so nothing this"
        " pass did is durable and the next session reads the project as it was",
    ][:MAX_PREPARE_WARNINGS]


def _requested(passes: object) -> tuple[str, ...]:
    if isinstance(passes, str) or not isinstance(passes, Iterable):
        raise GhidraUnavailableError(
            f"passes must be a sequence of pass names, got {passes!r}"
        )
    wanted = tuple(str(name) for name in passes) or PASS_NAMES
    unknown = sorted(set(wanted) - set(PASS_NAMES))
    if unknown:
        raise GhidraUnavailableError(
            f"{unknown} is not a pass this server runs; the passes are"
            f" {', '.join(PASS_NAMES)}"
        )
    return wanted


# --------------------------------------------------------------------------
# rule evidence
# --------------------------------------------------------------------------


def _unreachable_site(entry: int, reason: str) -> AddressRange:
    """One address a rule's evidence could not read, named with why.

    A bounded read, a reference with no address, and a call-site budget that
    ran out are all the same thing to a reader of the result: somewhere this
    rule did not look. Each one gets a range rather than silence.
    """
    return {
        "name": f"{entry:#x}",
        "stage": "instructions",
        "start": entry,
        "end": entry + 1,
        "coverage": "unavailable",
        "unvisited": [{"start": entry, "end": entry + 1}],
        "reason": reason,
    }


async def _rule_evidence(
    session: ProviderSession, program: _Program, rule: Rule, rule_index: int
) -> RuleEvidence:
    functions = await _functions(session)
    wanted = _wanted_names(rule)
    targets = [row for row in functions if _normalize(row["name"]) in wanted]
    if not targets:
        return _evidence(
            rule_index,
            [],
            [],
            "evaluated",
            None,
        )
    entries = sorted({row["entry"] for row in functions})
    names = {row["entry"]: row["name"] for row in functions}
    sites: list[dict[str, Any]] = []
    ranges: list[AddressRange] = []
    for row in targets:
        references, capped = await _xrefs(session, row["entry"])
        if capped is not None:
            ranges.append(_unreachable_site(row["entry"], capped))
        for reference in references:
            if reference["kind"] not in CALL_REFERENCES:
                continue
            if reference["address"] is None:
                # Ghidra spells some reference sources as a name rather than
                # an address (``From Entry Point``, and anything in a space
                # with no numeric address in this program's). A call site with
                # no address is one nothing here can read instructions at, so
                # it is named and never resolved.
                ranges.append(
                    _unreachable_site(
                        row["entry"],
                        f"the provider reports a {reference['kind']} reference"
                        f" to {row['entry']:#x} from {reference['source']!r},"
                        " which is not an address in this program's space, so"
                        " no call site could be read at it",
                    )
                )
                continue
            if len(sites) >= MAX_RULE_CALL_SITES:
                ranges.append(
                    _unreachable_site(
                        row["entry"],
                        f"this rule reached {MAX_RULE_CALL_SITES} call sites and"
                        " stopped; the references past that one were not read",
                    )
                )
                break
            owner = _containing(entries, reference["address"])
            if owner is None or _normalize(names.get(owner, "")) in wanted:
                continue
            sites.append(
                {
                    "address": reference["address"],
                    "owner": owner,
                    "name": reference["function"] or names.get(owner, "?"),
                    "target": row["entry"],
                }
            )
    if not sites:
        return _evidence(
            rule_index,
            [],
            ranges,
            "evaluated" if not ranges else "failed",
            None
            if not ranges
            else "; ".join(str(item["reason"]) for item in ranges[:4]),
        )

    contexts: list[dict[str, Any]] = []
    unresolved: list[str] = []
    documents: dict[int, dict[str, Any]] = {}
    for site in sorted(sites, key=lambda item: item["address"]):
        entry_range = {
            "name": site["name"],
            "stage": "instructions",
            "start": site["address"],
            "end": site["address"] + 1,
            "coverage": "complete",
            "unvisited": [],
            "reason": None,
        }
        try:
            if site["owner"] not in documents:
                documents[site["owner"]] = await _function_pcode(
                    session, site["owner"]
                )
            facts = await _call_facts(
                session, program, documents[site["owner"]], site
            )
        except ProviderError as refused:
            entry_range["coverage"] = "unavailable"
            entry_range["unvisited"] = [
                {"start": site["address"], "end": site["address"] + 1}
            ]
            entry_range["reason"] = str(refused)
            ranges.append(entry_range)
            unresolved.append(str(refused))
            continue
        if facts is None:
            entry_range["coverage"] = "unavailable"
            entry_range["unvisited"] = [
                {"start": site["address"], "end": site["address"] + 1}
            ]
            entry_range["reason"] = (
                "the provider's P-code for this function holds no call"
                f" operation at {site['address']:#x} reaching"
                f" {site['target']:#x}"
            )
            ranges.append(entry_range)
            unresolved.append(str(entry_range["reason"]))
            continue
        ranges.append(entry_range)
        contexts.append(facts)
    if unresolved and not contexts:
        return _evidence(rule_index, [], ranges, "failed", "; ".join(unresolved[:4]))
    missing = _probe(rule, rule_index, contexts, ranges)
    if missing is not None:
        return missing
    return _evidence(rule_index, contexts, ranges, "evaluated", None)


def _probe(
    rule: Rule,
    rule_index: int,
    contexts: list[dict[str, Any]],
    ranges: list[AddressRange],
) -> RuleEvidence | None:
    """Ask the shared evaluator whether these facts are enough for this rule.

    The verdict is thrown away — evidence carries facts, not conclusions — but
    the *question* is the only honest way to know which fact a rule's branches
    actually need, and it is asked with the same code that will later answer
    the rule for real.
    """
    probe = _evidence(rule_index, contexts, ranges, "evaluated", None)
    try:
        built = rule_contexts(probe)
    except ProviderError as refused:
        return _evidence(rule_index, [], ranges, "failed", str(refused))
    for context in built:
        try:
            evaluate_rule(rule, context)
        except UnavailableEvidenceError as missing:
            fact = getattr(missing, "fact", None) or "a fact"
            return _evidence(
                rule_index,
                [],
                ranges,
                "unsupported",
                f"rule {rule['name']!r} needs the {fact!r} fact at a call site"
                " this backend reached, and nothing typed in this Ghidra build"
                " states it: it is visible in the decompiled C, and reading a"
                " structural fact out of decompiled text is exactly what this"
                " adapter refuses to do",
            )
        except OperationError as refused:
            return _evidence(rule_index, [], ranges, "failed", str(refused))
    return None


def _evidence(
    rule_index: int,
    contexts: list[dict[str, Any]],
    ranges: list[AddressRange],
    state: str,
    reason: str | None,
) -> RuleEvidence:
    return {
        "backend": BACKEND,
        "rule_index": rule_index,
        "contexts": contexts,
        "ranges": ranges,
        "state": state,
        "reason": reason,
    }


def _wanted_names(rule: Rule) -> set[str]:
    return {_normalize(name) for name in rule["function_names"]}


def _normalize(name: str) -> str:
    """One function name as upstream VulFi compares them.

    ``utils.prep_func_name`` strips a leading ``.`` or ``_`` and compares
    case-insensitively; Ghidra additionally spells a PLT thunk ``name`` and an
    import ``name``, both of which are the same function to a rule.
    """
    text = name.strip()
    if text[:1] in (".", "_"):
        text = text[1:]
    if text.endswith("@plt"):
        text = text[: -len("@plt")]
    return text.lower()


def _containing(entries: Sequence[int], address: int) -> int | None:
    owner: int | None = None
    for entry in entries:
        if entry > address:
            break
        owner = entry
    return owner


# --------------------------------------------------------------------------
# facts, out of high P-code and nothing else
# --------------------------------------------------------------------------


def _operations(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every P-code operation in one function, in the order it was reported."""
    blocks = document.get("basic_blocks")
    if not isinstance(blocks, list):
        raise ProviderUnavailableError(
            "the ghidra provider's P-code document carries no 'basic_blocks'"
            " list, which is the shape this adapter was written against; no"
            " fact is taken from a document it cannot read"
        )
    operations: list[dict[str, Any]] = []
    for block in blocks:
        if not isinstance(block, dict) or not isinstance(block.get("pcodes"), list):
            raise ProviderUnavailableError(
                "the ghidra provider's P-code document holds a block with no"
                " 'pcodes' list"
            )
        for operation in block["pcodes"]:
            if not isinstance(operation, dict):
                raise ProviderUnavailableError(
                    "the ghidra provider's P-code document holds an operation"
                    " that is not an object"
                )
            operations.append(operation)
    return operations


def _varnode(raw: object) -> tuple[str, int, int] | None:
    if not isinstance(raw, dict):
        return None
    space = raw.get("space")
    offset = _address(raw.get("offset"))
    size = raw.get("size")
    if not isinstance(space, str) or offset is None:
        return None
    if isinstance(size, bool) or not isinstance(size, int):
        return None
    return space, offset, size


#: Operations that pass a value through unchanged. A constant that reaches a
#: call through one of these is still that constant.
_TRANSPARENT: Final[frozenset[str]] = frozenset(
    {"COPY", "CAST", "INT_ZEXT", "INT_SEXT"}
)

#: Operations that add their inputs. The decompiler materialises the address
#: of a literal as ``PTRSUB(const 0, const addr)``, so refusing to fold these
#: would report every ``printf("literal")`` as a non-constant format — a High
#: finding on a call site that has none.
_ADDITIVE: Final[frozenset[str]] = frozenset({"PTRSUB", "INT_ADD"})

#: Operations whose output is never a compile-time constant, whatever their
#: inputs look like.
_OPAQUE: Final[frozenset[str]] = frozenset(
    {
        "CALL",
        "CALLIND",
        "CALLOTHER",
        "LOAD",
        "INDIRECT",
        "MULTIEQUAL",
        "PTRADD",
        "NEW",
    }
)


def _constant_value(
    operations: Sequence[Mapping[str, Any]],
    node: tuple[str, int, int],
    depth: int = 0,
) -> tuple[bool | None, int | None]:
    """Whether ``node`` is a constant, and its value when it is one.

    ``None`` means "this adapter cannot tell", which becomes an absent fact
    rather than a ``False``: a predicate that needs it then refuses to answer
    instead of reporting a call site as safe because the evidence ran out.

    Decided over the whole SSA body the provider reported, and conservatively
    where the body is ambiguous: this reply identifies a varnode by space,
    offset and size, which two distinct SSA values can share, so a node whose
    definitions disagree has no answer here.
    """
    space, _, _ = node
    if space == "const":
        return True, node[1]
    if depth >= MAX_VARNODE_DEPTH:
        return None, None
    definitions = [
        operation
        for operation in operations
        if _varnode(operation.get("output")) == node
    ]
    if not definitions:
        # Nothing in this function defines it. A register or stack slot with
        # no definition is an incoming argument, which is not a constant;
        # anything else is simply unknown.
        return (False, None) if space in {"register", "stack"} else (None, None)
    answers: set[bool] = set()
    values: set[int] = set()
    for operation in definitions:
        mnemonic = operation.get("mnemonic")
        if mnemonic in _OPAQUE:
            answers.add(False)
            continue
        if mnemonic not in _TRANSPARENT and mnemonic not in _ADDITIVE:
            return None, None
        inputs = operation.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            return None, None
        sources = (
            [_varnode(inputs[0])]
            if mnemonic in _TRANSPARENT
            else [_varnode(item) for item in inputs]
        )
        if any(item is None for item in sources):
            return None, None
        total = 0
        for source in sources:
            assert source is not None  # narrowed by the check above
            answer, value = _constant_value(operations, source, depth + 1)
            if answer is None:
                return None, None
            if not answer:
                answers.add(False)
                break
            if value is None:
                total = -1
                break
            total += value
        else:
            answers.add(True)
            if total >= 0:
                values.add(total)
    if answers == {True}:
        return True, values.pop() if len(values) == 1 else None
    if answers == {False}:
        return False, None
    return None, None


async def _call_facts(
    session: ProviderSession,
    program: _Program,
    document: Mapping[str, Any],
    site: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Every fact one call site states, out of the function's own P-code."""
    operations = _operations(document)
    call = _call_operation(operations, site)
    if call is None:
        return None
    inputs = call.get("inputs")
    arguments = [_varnode(item) for item in list(inputs)[1:]]
    params: list[dict[str, Any]] = []
    for node in arguments:
        if node is None:
            params.append({})
            continue
        params.append(await _param_facts(session, program, operations, node))
    facts: dict[str, Any] = {"params": params}
    checked = _return_checked(operations, call)
    if checked is not None:
        facts["call"] = checked
    return facts


def _call_operation(
    operations: Sequence[Mapping[str, Any]], site: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    for operation in operations:
        if operation.get("mnemonic") != "CALL":
            continue
        sequence = operation.get("seq")
        if not isinstance(sequence, dict):
            continue
        if _address(sequence.get("address")) != site["address"]:
            continue
        inputs = operation.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            continue
        target = _varnode(inputs[0])
        if target is not None and target[1] == site["target"]:
            return operation
    return None


async def _param_facts(
    session: ProviderSession,
    program: _Program,
    operations: Sequence[Mapping[str, Any]],
    node: tuple[str, int, int],
) -> dict[str, Any]:
    """One argument's facts: only the ones this P-code really states."""
    constant, value = _constant_value(operations, node)
    facts: dict[str, Any] = {}
    if constant is None:
        return facts
    facts["constant"] = constant
    if node[0] == "const":
        # A literal operand, which is the only thing this build lets this
        # adapter call a number: a constant that arrived through a temporary
        # is an address the compiler materialised, not an immediate.
        facts["const_number"] = True
        facts["number"] = node[1]
    if not constant or value is None:
        return facts
    text = await _string_at(session, program, value)
    if text is not None:
        facts["string"] = text
    return facts


async def _string_at(
    session: ProviderSession, program: _Program, value: int
) -> str | None:
    """The text a constant argument points at, or ``""`` when it points at none.

    ``None`` is different again: the address is mapped and the bytes could not
    be read, so nothing is stated about it at all.
    """
    if _block_of(program, value) is None:
        return ""
    try:
        raw = await _read(session, value, min(READ_CHUNK, MAX_STRING_BYTES))
    except ProviderError:
        return None
    end = raw.find(b"\x00")
    if end < 0:
        return None
    try:
        text = raw[:end].decode("ascii")
    except ValueError:
        return ""
    return text if _is_text(text) else ""


def _return_checked(
    operations: Sequence[Mapping[str, Any]], call: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Whether this call's result reaches a comparison, when that is provable.

    ``False`` only when the call has no result at all, which the P-code states
    outright. A result that no comparison was found for is left unstated: this
    walk follows the operations the provider reported and nothing says it saw
    all of them, so "not checked" would be a claim about what is absent.

    And nothing is stated at all when the varnode cannot be told apart from
    another. This reply identifies a varnode by space, offset and size, which
    two distinct SSA values share whenever two calls return in the same
    register — and a comparison on the second one would otherwise be credited
    to the first, which is a check on a call that was never checked. The same
    ambiguity :func:`_constant_value` already refuses is refused here.
    """
    output = _varnode(call.get("output"))
    if output is None:
        return {"return_checked": False, "return_check_values": []}
    if not _uniquely_defined(operations, output):
        return None
    reached = {output}
    values: list[int | float] = []
    for _ in range(MAX_VARNODE_DEPTH):
        grown = False
        for operation in operations:
            inputs = [_varnode(item) for item in operation.get("inputs") or []]
            if not any(node in reached for node in inputs if node is not None):
                continue
            mnemonic = str(operation.get("mnemonic"))
            if mnemonic.startswith(("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS",
                                    "INT_SLESS", "INT_CARRY", "INT_SBORROW",
                                    "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
                                    "FLOAT_LESS")):
                for node in inputs:
                    if node is not None and node[0] == "const":
                        values.append(node[1])
                return {
                    "return_checked": True,
                    "return_check_values": sorted(set(values)),
                }
            if mnemonic in _TRANSPARENT or mnemonic in {"MULTIEQUAL", "INDIRECT"}:
                successor = _varnode(operation.get("output"))
                if successor is None:
                    continue
                if not _uniquely_defined(operations, successor):
                    # The value moved into something two definitions share, so
                    # from here on a comparison cannot be attributed to this
                    # call rather than to the other one.
                    return None
                if successor not in reached:
                    reached.add(successor)
                    grown = True
        if not grown:
            break
    return None


def _uniquely_defined(
    operations: Sequence[Mapping[str, Any]], node: tuple[str, int, int]
) -> bool:
    """Whether exactly one reported operation produces this varnode."""
    return (
        sum(1 for item in operations if _varnode(item.get("output")) == node) == 1
    )


# --------------------------------------------------------------------------
# applying one approved proposal
# --------------------------------------------------------------------------


async def _apply(
    session: ProviderSession,
    program: _Program,
    body: Mapping[str, Any],
    report: dict[str, object],
) -> None:
    kind = str(body["kind"])
    if kind == "function_boundary":
        await _apply_boundary(session, program, body, report)
        return
    if kind == "structure_field":
        await _apply_layout(session, body, report)
        return
    report["reason"] = (
        f"a {kind!r} proposal needs a typed writer this adapter does not"
        " allowlist on the Ghidra provider; the only changes it applies are a"
        " function boundary and a structure layout, and nothing was applied"
    )


async def _apply_boundary(
    session: ProviderSession,
    program: _Program,
    body: Mapping[str, Any],
    report: dict[str, object],
) -> None:
    entry = int(body["start"])
    functions = await _functions(session)
    entries = {row["entry"]: row["name"] for row in functions}
    extents = await _extents(session, sorted(entries), program.segments)
    report["site"] = {"entry": entry, "end": int(body["end"])}
    if entry in entries:
        report["reason"] = (
            f"this provider already defines {entries[entry]!r} at {entry:#x},"
            " so there is nothing to define and nothing was applied"
        )
        return
    owner = extents.owner(entry)
    if owner is not None and owner[2]:
        report["reason"] = (
            f"{entry:#x} is inside {entries.get(owner[0], 'a function')!r} at"
            f" {owner[0]:#x}..{owner[1]:#x}; this provider's create_function"
            " would split that function rather than refuse, so this adapter"
            " refuses instead and nothing was applied"
        )
        return
    if owner is not None:
        report["reason"] = (
            f"{entry:#x} falls inside {entries.get(owner[0], 'a function')!r}"
            f" at {owner[0]:#x}, whose extent this session could not measure"
            f" ({extents.truncated}), so {owner[0]:#x}..{owner[1]:#x} is the"
            " widest it could reach. An unmeasured extent is not evidence that"
            " the address is outside it; nothing was applied"
        )
        return
    try:
        await _call_json(session, "create_function", address=_hex(entry))
    except ProviderError as refused:
        report["reason"] = f"the provider refused to define this entry: {refused}"
        return
    if entry not in {row["entry"] for row in await _functions(session)}:
        report["reason"] = (
            "the provider reported this entry defined and does not list a"
            " function at it, so nothing is claimed"
        )
        return
    report["mutated"] = True


async def _apply_layout(
    session: ProviderSession, body: Mapping[str, Any], report: dict[str, object]
) -> None:
    value = body["value"]
    name = str(value["type_name"])
    fields = list(value["fields"])
    report["site"] = {"type_name": name, "fields": len(fields)}
    try:
        spelled = [
            {
                "name": str(field["name"]),
                "type": _FIELD_TYPES[int(field["width"])],
                # The offset the operator approved, not the one a width
                # sequence happens to imply. A validated layout covers its
                # bytes from zero with no gap and no overlap, so these two
                # agree today — and if a future layout ever lets them differ,
                # dropping the offset would write a structure nobody approved.
                "offset": int(field["offset"]),
            }
            for field in fields
        ]
    except KeyError as missing:
        report["reason"] = (
            f"this layout has a field this adapter cannot spell for the"
            f" provider ({missing}); a field needs an offset, a name, and one"
            f" of the widths {sorted(_FIELD_TYPES)}"
        )
        return
    answer = await _call(
        session, "create_struct", name=name, fields=json.dumps(spelled)
    )
    if "already exists" in answer:
        report["reason"] = (
            f"this provider already holds a type called {name!r}"
            f" ({answer.strip()}), and this adapter never replaces one;"
            " nothing was applied"
        )
        return
    if "Successfully created" not in answer:
        report["reason"] = (
            f"the provider did not report creating {name!r}: {answer.strip()[:200]}"
        )
        return
    report["mutated"] = True


def _effect(body: Mapping[str, Any]) -> str:
    kind = str(body["kind"])
    start = int(body["start"])
    end = int(body["end"])
    return f"{kind} over {start:#x}..{end:#x} in the managed Ghidra project"


def _whole(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GhidraUnavailableError(f"{what} must be an integer >= 0, got {value!r}")
    return value
