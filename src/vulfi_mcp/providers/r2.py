"""The radare2 backend: evidence a pinned r2mcp session can justify.

This adapter owns three things and nothing else: the fixed set of tools it may
ask an r2mcp provider for, the pinned schema each of those tools had when this
code was written, and the rules for turning the provider's answers into the
shapes the rest of this server already understands —
:class:`~vulfi_mcp.contracts.PassResult`,
:class:`~vulfi_mcp.contracts.Candidate` and
:class:`~vulfi_mcp.contracts.RuleEvidence`. Everything a provider says is data;
nothing it says is an instruction, and nothing it prints as prose becomes a
fact.

The one rule that decides what this module will and will not claim: **a
structural fact may only come from output whose own shape carries the fact.**
A cross-reference record with a ``[CALL:--x]`` kind field qualifies. A
hexdump of bytes at an address qualifies. Decompiled C does not, and neither
do radare2's own inline type-matching comments — this module asks for
neither, and a rule whose branch needs a fact only they show is reported
``unsupported`` with the fact named.

What was measured against ``radareorg/radare2-mcp`` 1.8.8 on radare2 6.2.2,
over a real stdio session at protocol 2025-06-18, and what each measurement
forced:

The advertised tool list is two pages, not one
    ``tools/list`` pages at exactly 32 entries per page
    (``handle_list_tools``'s ``page_size``). A client that reads one page sees
    32 tools; this server has 42, and ``hexdump``, ``search``,
    ``lookup_address``, ``lookup_export`` and ``lookup_symbol`` are all on
    page two. :func:`vulfi_mcp.providers.client.provider_session` follows the
    cursor, so this adapter can pin a page-two tool; a reviewer who counted 32
    was counting a page.

No tool declares an ``outputSchema``
    All 42 advertise ``None``, so the schema gate fingerprints a name and an
    input schema and *nothing about the reply*. Every reply is therefore
    parsed here as if it will be wrong, and every parse is anchored on an
    address this adapter already knew or can check against a range the
    provider itself reported.

``open_file`` is read-only, and that is checked rather than assumed
    ``r2_open_file`` calls ``r_core_file_open (core, filepath, R_PERM_RX, 0)``,
    and the kernel agrees: while a session holds the fixture open,
    ``/proc/<pid>/fdinfo`` reports access mode ``O_RDONLY`` for it. The
    operator's own file is therefore handed to the server directly, and the
    suite still re-hashes it afterwards, because a measurement of this build
    is not a promise about the next one.

Nothing survives a session
    This build advertises no project, no save and no restore: there is no tool
    whose name or schema offers one. Each session therefore reopens and
    re-analyses, which is why :func:`prepare_r2` and :func:`evidence_r2` each
    do their own ``open_file`` and ``analyze``.

A failure arrives as a success
    ``disassemble_function`` at an address with no function answers
    ``<log>[ERROR] Cannot find function at 0x...</log>`` with ``isError``
    false, and ``xrefs_to`` at an unmapped address answers with an empty
    string — indistinguishable, on its own, from "nothing refers here". Every
    address this module asks about is one the provider already named, so an
    empty answer is read as an answer about a real place.

``hexdump`` will dump an address that is not mapped
    ``hexdump`` at ``0x900000`` in a 16 KiB image returns 32 bytes of ``ff``
    and no error. Reads here are therefore bounded to the ranges
    ``list_sections`` itself reports, and each dumped line's address is
    checked against the address that was asked for.

The string tools throw the address away
    ``list_strings`` runs ``izqq`` and ``list_all_strings`` runs ``izzzqq`` —
    radare2's doubly-quiet form, which prints the text and nothing else, where
    ``izq`` would have printed ``vaddr len size string``. A string with no
    address cannot be a :class:`~vulfi_mcp.contracts.Candidate`, so neither
    tool is allowlisted and the strings pass recovers text from mapped bytes
    instead, where the address is the one it read at.

``list_functions`` truncates without saying so
    It defaults to ``max_length`` 50, computes a ``next_cursor``, and then
    frees it: the reply is a short list with no marker on it. This adapter
    asks for the count first and compares, so a truncated listing becomes
    partial coverage rather than a shorter image.

radare2's own argument annotations are wrong, in exactly the tempting way
    For the fixture's one ``strcpy`` whose source really is a literal,
    ``disassemble_function`` and ``decompile_function`` both annotate the call
    ``char *strcpy("", "vulfi-constant")`` — and the first argument is not
    ``""``, it is ``obj.g_buffer``, which the image proves. That line is why
    no ``param`` fact is ever taken from this provider: the text that would
    have supplied it is demonstrably false.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from vulfi_mcp.contracts import (
    AddressGap,
    AddressRange,
    Candidate,
    PassResult,
    RuleEvidence,
)
from vulfi_mcp.ida_runtime import (
    ADDRESS_SPACE_IMAGE,
    MAX_PREPARE_WARNINGS,
    MAX_STRING_BYTES,
    MIN_STRING_CHARS,
    OperationError,
    UnavailableEvidenceError,
    evaluate_rule,
)
from vulfi_mcp.providers.client import (
    ProviderError,
    ProviderSession,
    checked_call,
    provider_session,
    rule_contexts,
)
from vulfi_mcp.providers.config import ProviderConfig, load_provider_config
from vulfi_mcp.rules import Rule

__all__ = [
    "ALLOWLIST",
    "ANALYSIS_LEVEL",
    "BACKEND",
    "PASS_NAMES",
    "PINNED_SCHEMAS",
    "PreparedPass",
    "R2UnavailableError",
    "evidence_r2",
    "prepare_r2",
]

#: The backend these results are authored by.
BACKEND: Final = "r2"

#: Every tool this adapter may ask an r2mcp provider for, and the complete
#: list of them. It is a constant on purpose: an installation cannot widen it,
#: a caller cannot name a tool, and :func:`provider_session` fails closed, so
#: anything missing from here is simply not callable.
#:
#: Eleven of the provider's forty-two, each for a fact this module cites.
#: What is deliberately *not* here, and why — the list matters as much as the
#: one above it, because every one of these was reachable and refused:
#:
#: ``decompile_function``
#:     Pseudocode. It is the single thing this adapter exists to not read:
#:     its argument annotations are provably wrong on the project's own
#:     fixture (see the module docstring), and a rule that needs an argument
#:     fact is answered ``unsupported`` rather than from this.
#: ``disassemble``
#:     An instruction listing starting anywhere, with no measured extent and
#:     no kind field. ``disassemble_function`` already gives the one fact a
#:     listing here is used for — radare2's own measured function size — so
#:     this would be surface bought for nothing.
#: ``list_strings``, ``list_all_strings``
#:     ``izqq`` and ``izzzqq``: text with the address removed. A string
#:     candidate is an address, an encoding and the bytes; two of the three
#:     are missing here, and ``hexdump`` over a named section supplies all
#:     three.
#: ``calculate``
#:     ``r_num_math`` over an operator-supplied expression — flag names,
#:     ``$`` variables and arithmetic. An expression evaluator is the escape
#:     class this project refuses on principle, and every address this module
#:     sends is already an integer it computed itself.
#: ``search``
#:     A whole-image scan whose hit list is its own invention of where a
#:     thing starts. Bounded reads over ranges ``list_sections`` reported are
#:     citable; a hit is not.
#: ``rename_function``, ``rename_flag``, ``set_comment``,
#: ``set_function_prototype``, ``use_decompiler``
#:     Mutations. Nothing in this build persists one — there is no project and
#:     no save — so a write here changes a process that is about to exit.
#:     This adapter has no apply entry point at all, and these are how it
#:     stays that way.
#: ``list_files``
#:     A directory lister. It reads the filesystem, not the image.
#: ``run_command``, ``run_javascript``, ``run_script``, ``sql``
#:     Raw execution. Mode-gated off by this build, and refused by
#:     :data:`~vulfi_mcp.providers.config.FORBIDDEN_TOOLS` whatever a build
#:     decides.
#: ``get_pid``, ``list_threads``, ``dump_registers``, ``memory_map_here``,
#: ``list_heap_allocations``, ``list_memory_maps``
#:     Live-process tools. There is no process.
#: ``list_imports``, ``list_exports``, ``list_libraries``, ``list_classes``,
#: ``list_methods``, ``list_functions_tree``, ``list_entrypoints``,
#: ``show_function_details``, ``get_current_address``,
#: ``get_function_prototype``, ``list_decompilers``, ``lookup_symbol``,
#: ``lookup_export``
#:     Nothing below cites them. ``list_symbols`` already carries every
#:     symbol's address and size in one reply, and ``show_function_details``
#:     and ``get_current_address`` answer about a seek position this adapter
#:     never sets.
ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "analyze",
        "close_file",
        "disassemble_function",
        "hexdump",
        "list_functions",
        "list_sections",
        "list_symbols",
        "lookup_address",
        "open_file",
        "show_info",
        "xrefs_to",
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
#: Measured against ``radareorg/radare2-mcp`` 1.8.8 built on radare2 6.2.2,
#: over stdio at protocol 2025-06-18, from this project's pinned ``mcp==2.2.0``
#: client.
PINNED_SCHEMAS: Final[dict[str, str]] = {
    "analyze": "9c01aa49fa2784a8f5f6d76bfa9a32ecaa9562b94897bf59126d3594a0a50626",
    "close_file": "e5f8049ac320664af7153e3e49a5eb57a3e21d086be4043e4ad88211dec8dc05",
    "disassemble_function": (
        "30bdd15c48fd9e7f0bdbb925608a448a06d81ec46bb94280a330bad59ff6df97"
    ),
    "hexdump": "4282988776cb977c85a65847ff8295ea5217c09e4868c0b0f35c38a5d03d132d",
    "list_functions": (
        "8b0ac47b6ed9ca120466646e517c85e8c74fdf9308c12788c5b4419959ba2660"
    ),
    "list_sections": (
        "5766377a0a7979a79308f929910566ae443fbb879b6e33e22cfdf802525e28a9"
    ),
    "list_symbols": (
        "90095d7fa75074dcb4dcecc1a63d6907649609b50003b4ebf183c34d4d211646"
    ),
    "lookup_address": (
        "473bbdf28e9a8f06e652d19a1f4381609d236ec9f89a0a65f8400e7b9658a99d"
    ),
    "open_file": "29f61b661dc8c2c0eaf48c2bcdee4b994124e1af26b778e4a28f63d36c9213cd",
    "show_info": "dd731ea8bb9e23e41c51d4f8dea3f076d7d2a0c2af1f35d665dbf1d6d9f25c9f",
    "xrefs_to": "8157dbd5f3cb17e0584026a5986ea7a53d136b039395ac241aecd7f00e94b282",
}

#: The four passes this project names. Two of them have no evidence source on
#: this provider, and say so.
PASS_NAMES: Final[tuple[str, ...]] = (
    "strings",
    "functions",
    "structures",
    "pointer_tables",
)

#: The analysis depth every session asks for. Fixed here rather than taken
#: from a caller so two runs of the same binary are the same analysis, and
#: recorded in each pass's warnings when the provider says it stopped early.
ANALYSIS_LEVEL: Final = 2

#: Bytes one pass may read out of the provider's address space.
MAX_PASS_READ_BYTES: Final = 256 * 1024
#: Bytes one ``hexdump`` call asks for.
READ_CHUNK: Final = 4096
#: Functions whose extent one pass measures, one call each.
MAX_FUNCTION_EXTENTS: Final = 512
#: Candidates one pass reports.
MAX_PASS_CANDIDATES: Final = 256
#: Call sites one rule's evidence covers.
MAX_RULE_CALL_SITES: Final = 128
#: Functions walked while answering ``reachable_from`` for one call site. The
#: same budget IDA's scanner charges, and with the same consequence: a walk
#: that runs out does not report a short list, it reports nothing, because a
#: caller graph that was never finished is not evidence about who calls what.
MAX_CALLERS: Final = 512

#: Cross-reference kinds radare2's ``axt`` prints for a call. ``CODE`` is a
#: jump and ``DATA``/``STRN`` are reads; none of them is a call site with an
#: argument list, and a rule asks about call sites.
CALL_REFERENCES: Final[frozenset[str]] = frozenset({"CALL"})

#: Encodings this adapter decodes out of mapped bytes, widest run first.
_ENCODINGS: Final[tuple[tuple[str, int, str], ...]] = (
    ("utf-16be", 2, "utf-16-be"),
    ("utf-16le", 2, "utf-16-le"),
    ("ascii", 1, "ascii"),
)

#: Why a pass that has no evidence source on this provider says so, per pass.
_NO_SOURCE: Final[dict[str, str]] = {
    "structures": (
        "radare2-mcp 1.8.8 exposes no tool that reports an operand's width at"
        " the byte it reads, so no field offset or width can be proven from"
        " it; the only thing that describes a layout here is the decompiler's"
        " prose, and a structure named from that is a guess with a type name"
        " on it"
    ),
    "pointer_tables": (
        "radare2-mcp 1.8.8 exposes no tool that reports relocation records —"
        " there is no listing of r2's own `ir` — and through the tools it does"
        " expose a relocated pointer and an address-shaped integer read out of"
        " `hexdump` are identical; telling them apart is the whole of the"
        " evidence a pointer table rests on"
    ),
}

#: Why the strings pass does not sweep a range that holds code.
_CODE_NOT_SWEPT: Final = (
    "this range holds code the provider's analysis already defines, so this"
    " pass did not read it for text"
)

_FUNCTION_ROW: Final = re.compile(r"\A(?P<address>0x[0-9A-Fa-f]+)\s+(?P<name>\S.*)\Z")
_SYMBOL_ROW: Final = re.compile(
    r"\A(?P<address>0x[0-9A-Fa-f]+)\s+(?P<size>\d+)\s+(?P<name>\S.*)\Z"
)
_XREF_ROW: Final = re.compile(
    r"\A(?P<owner>\S+)\s+(?P<address>0x[0-9A-Fa-f]+)\s+"
    r"\[(?P<kind>[A-Z]+):(?P<perm>[-rwx]+)\]\s*(?P<text>.*)\Z"
)
#: radare2's ``pdf`` signature line: the function's measured size in bytes,
#: then its prototype. This is the one extent this provider states.
_EXTENT_ROW: Final = re.compile(r"\A(?P<size>\d+):\s+\S")
_HEX_LINE: Final = re.compile(r"\A(?P<address>0x[0-9A-Fa-f]+)\s\s(?P<rest>.*)\Z")
_SECTION_HEADER: Final = re.compile(r"\Anth\s+paddr\b")
#: radare2 name prefixes that are its own bookkeeping rather than a symbol's
#: own name. Stripped before a rule's function names are compared.
_PREFIXES: Final[tuple[str, ...]] = ("sym.imp.", "sym.", "imp.", "fcn.", "loc.")


class PreparedPass(PassResult):
    """One pass result, with the rows it names and the base it read them at.

    :class:`~vulfi_mcp.contracts.PassResult` carries ``candidate_ids``;
    nothing downstream can do anything with an id whose row it does not have,
    so the rows travel with the pass that found them. ``image_base`` is here
    because radare2 chooses where it maps a PIE image, and every address below
    is in that space.
    """

    candidates: list[Candidate]
    image_base: int


class R2UnavailableError(ProviderError):
    """The radare2 provider is not configured, or cannot hold this target."""


# --------------------------------------------------------------------------
# the public surface
# --------------------------------------------------------------------------


async def prepare_r2(target: str, passes: tuple[str, ...]) -> tuple[PassResult, ...]:
    """Run the requested preparation passes against the radare2 provider.

    One session, opened and analysed from scratch, because this provider keeps
    nothing between sessions. The session is released on the way out, and the
    operator's file is never written: every allowlisted tool reads.
    """
    wanted = _requested(passes)
    config = _config()
    async with provider_session(config, target, allowlist=ALLOWLIST) as session:
        image = await _open(session)
        try:
            results: list[PassResult] = []
            for name in wanted:
                results.append(await _run_pass(session, image, name))
            return tuple(results)
        finally:
            await _release(session)


async def evidence_r2(target: str, rule: Rule, rule_index: int) -> RuleEvidence:
    """Establish, for one rule, the facts this provider can actually prove.

    Which, on radare2, is one fact: the names of the functions a call site is
    reached from, out of ``axt`` cross-reference records whose own kind field
    says they are calls. Argument recovery is not among them, so a rule whose
    branch indexes ``param`` comes back ``unsupported`` naming what was
    missing — never ``False``, and never a priority read out of pseudocode.
    """
    try:
        config = _config()
    except R2UnavailableError as refused:
        return _evidence(rule_index, [], [], "failed", str(refused))
    try:
        async with provider_session(config, target, allowlist=ALLOWLIST) as session:
            image = await _open(session)
            try:
                return await _rule_evidence(session, image, rule, rule_index)
            finally:
                await _release(session)
    except ProviderError as refused:
        return _evidence(rule_index, [], [], "failed", str(refused))


# --------------------------------------------------------------------------
# configuration, and the one open session
# --------------------------------------------------------------------------


def _config() -> ProviderConfig:
    config = load_provider_config().get(BACKEND)
    if config is None:
        raise R2UnavailableError(
            "no radare2 provider is configured; add an [r2] table to the"
            " operator's providers.toml to make this backend available"
        )
    return config


class _Image:
    """One open binary, and everything about it this session measured."""

    __slots__ = ("base", "bits", "format", "sections", "warnings")

    def __init__(
        self,
        base: int,
        bits: int,
        format_name: str,
        sections: list[dict[str, Any]],
        warnings: list[str],
    ) -> None:
        self.base = base
        self.bits = bits
        self.format = format_name
        self.sections = sections
        self.warnings = warnings


async def _open(session: ProviderSession) -> _Image:
    """Open and analyse the operator's file, or say why neither happened."""
    opened = await _call(session, "open_file", file_path=session.remote_path)
    if "opened successfully" not in opened.lower():
        raise R2UnavailableError(
            f"the radare2 provider did not open {session.remote_path}:"
            f" {opened.strip()[:200]!r}"
        )
    warnings: list[str] = []
    analysed = await _call(session, "analyze", level=ANALYSIS_LEVEL)
    headline = analysed.splitlines()[0] if analysed.strip() else ""
    if headline.startswith("Analysis stopped"):
        warnings.append(
            f"the provider's analysis did not finish ({headline}), so every"
            " function and cross-reference below is what a stopped analysis"
            " had found"
        )
    elif not headline.startswith(
        ("Analysis completed", "File was already analyzed")
    ):
        raise R2UnavailableError(
            f"the radare2 provider did not analyse {session.remote_path}:"
            f" {headline[:200]!r}"
        )
    info = _info(await _call(session, "show_info"))
    listing = await _call(session, "list_sections")
    sections = _sections(listing)
    unmapped = _unmapped_sections(listing)
    if unmapped:
        warnings.append(
            "the provider reports "
            + ", ".join(unmapped[:8])
            + f" ({len(unmapped)} sections) with no address in this image's"
            " space, so no pass below covers them: they are in the file and"
            " not in the address space these results describe"
        )
    if not sections:
        raise R2UnavailableError(
            "the radare2 provider reports no mapped section for"
            f" {session.remote_path}, so there is no address range to read"
        )
    return _Image(
        _whole(info.get("baddr"), 0),
        _whole(info.get("bits"), 0),
        str(info.get("format") or "unknown"),
        sections,
        warnings,
    )


async def _release(session: ProviderSession) -> None:
    """Close the file so nothing is left open on a shared server.

    A failure here is not a failure of the evidence that was already read, and
    the process this adapter launched is about to exit anyway, so it is
    swallowed rather than raised over a result that is already correct.
    """
    try:
        await _call(session, "close_file")
    except ProviderError:
        return


# --------------------------------------------------------------------------
# one checked call
# --------------------------------------------------------------------------


async def _call(session: ProviderSession, tool: str, **arguments: Any) -> str:
    """One allowlisted call, returned as the text the provider produced."""
    reply = await checked_call(session, tool, dict(arguments), PINNED_SCHEMAS[tool])
    blocks = reply.get("text")
    if not isinstance(blocks, list):
        raise R2UnavailableError(
            f"the radare2 provider's {tool!r} reply carries no text blocks"
        )
    return "\n".join(str(block) for block in blocks)


def _rows(text: str) -> list[str]:
    """Every non-empty line of a reply, with radare2's own log removed.

    ``analyze`` and ``disassemble_function`` wrap radare2's log in ``<log>``
    and print it inside the same text block as the answer. It is the
    provider's prose about itself, so it never reaches a parse.
    """
    rows: list[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "<log>":
            inside = True
            continue
        if stripped == "</log>":
            inside = False
            continue
        if inside or not stripped:
            continue
        rows.append(line.rstrip())
    return rows


# --------------------------------------------------------------------------
# the provider's own listings, parsed into shapes with addresses in them
# --------------------------------------------------------------------------


def _whole(value: object, fallback: int) -> int:
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return fallback
    return fallback


def _info(text: str) -> dict[str, str]:
    """``show_info``'s leading ``key value`` table, and nothing after it."""
    fields: dict[str, str] = {}
    for line in _rows(text):
        parts = line.split(None, 1)
        if len(parts) != 2 or line.startswith("0x"):
            continue
        key, value = parts[0], parts[1].strip()
        if key not in fields:
            fields[key] = value
    return fields


def _sections(text: str) -> list[dict[str, Any]]:
    """Every mapped section, as half-open ranges in the provider's space.

    ``list_sections`` runs ``iS;iSS`` and prints two tables with the same
    header: sections, then segments. Only the first is read — the second
    describes the same bytes a second time, and a range reported twice would
    be a range this pass claims to have covered twice.

    A section with no virtual address is not in the address space at all
    (``.symtab``, ``.strtab``, ``.comment``). It is dropped here and named in
    the pass's warnings rather than reported as a range nothing read.
    """
    blocks: list[dict[str, Any]] = []
    headers = 0
    for line in _rows(text):
        if _SECTION_HEADER.match(line.strip()):
            headers += 1
            if headers > 1:
                break
            continue
        fields = line.split()
        if len(fields) < 9 or not fields[0].isdigit():
            continue
        try:
            start = int(fields[3], 0)
            size = int(fields[4], 0)
        except ValueError:
            continue
        if start <= 0 or size <= 0 or "r" not in fields[5]:
            continue
        blocks.append(
            {
                "name": fields[8],
                "start": start,
                "end": start + size,
                "perm": fields[5],
                "type": fields[7],
                "executable": "x" in fields[5],
            }
        )
    return sorted(blocks, key=lambda block: block["start"])


def _unmapped_sections(text: str) -> list[str]:
    """Section names the provider reports with no address in this space."""
    names: list[str] = []
    headers = 0
    for line in _rows(text):
        if _SECTION_HEADER.match(line.strip()):
            headers += 1
            if headers > 1:
                break
            continue
        fields = line.split()
        if len(fields) < 9 or not fields[0].isdigit():
            continue
        if _whole(fields[3], 0) == 0 and _whole(fields[4], 0) > 0:
            names.append(fields[8])
    return names


async def _functions(
    session: ProviderSession,
) -> tuple[list[dict[str, Any]], str | None]:
    """Every function the provider defines, and whether the listing was whole.

    ``list_functions`` pages at ``max_length`` and throws its own
    ``next_cursor`` away, so a truncated reply looks exactly like a complete
    one. The count is asked for first, by the same tool, and a listing that
    does not match it is reported short rather than read as the whole image.
    """
    declared = _rows(await _call(session, "list_functions", count=True))
    expected: int | None = None
    if len(declared) == 1 and declared[0].strip().isdigit():
        expected = int(declared[0].strip())
    rows: list[dict[str, Any]] = []
    for line in _rows(await _call(session, "list_functions", max_length=-1)):
        matched = _FUNCTION_ROW.match(line.strip())
        if matched is None:
            continue
        rows.append(
            {
                "entry": int(matched["address"], 16),
                "name": matched["name"].strip(),
            }
        )
    rows.sort(key=lambda row: row["entry"])
    if expected is None:
        return rows, (
            "the provider did not answer how many functions it has, so this"
            " listing cannot be checked for truncation"
        )
    if len(rows) != expected:
        return rows, (
            f"the provider reports {expected} functions and listed"
            f" {len(rows)}; this run read the ones it listed and nothing is"
            " claimed about the rest"
        )
    return rows, None


async def _symbols(session: ProviderSession) -> dict[int, dict[str, Any]]:
    """Every symbol with an address and a size, keyed by address.

    An import with no local implementation is spelled ``0xffffffffffffffff``
    here; it is not an address in this image and is dropped.
    """
    symbols: dict[int, dict[str, Any]] = {}
    for line in _rows(await _call(session, "list_symbols")):
        matched = _SYMBOL_ROW.match(line.strip())
        if matched is None:
            continue
        address = int(matched["address"], 16)
        if address == 0 or address == 0xFFFFFFFFFFFFFFFF:
            continue
        symbols.setdefault(
            address, {"size": int(matched["size"]), "name": matched["name"].strip()}
        )
    return symbols


async def _extent(session: ProviderSession, entry: int) -> int | None:
    """How far one function reaches, as radare2's own listing measured it.

    ``pdf``'s signature line carries the size radare2 assigned the function.
    An address with no function answers with a logged error and no signature
    line, and that is reported as an unmeasured extent — never as zero.
    """
    try:
        listing = await _call(session, "disassemble_function", address=_hex(entry))
    except ProviderError:
        return None
    for line in _rows(listing):
        matched = _EXTENT_ROW.match(line.strip())
        if matched is not None:
            size = int(matched["size"])
            return entry + size if size > 0 else None
    return None


async def _xrefs(session: ProviderSession, address: int) -> list[dict[str, Any]]:
    """Everything the provider says refers to one address.

    Each row carries its own kind — ``[CALL:--x]``, ``[DATA:r--]`` — and that
    field, not the instruction text beside it, is what decides whether a row
    is a call site.
    """
    rows: list[dict[str, Any]] = []
    for line in _rows(await _call(session, "xrefs_to", address=_hex(address))):
        matched = _XREF_ROW.match(line.strip())
        if matched is None:
            continue
        rows.append(
            {
                "owner": matched["owner"],
                "address": int(matched["address"], 16),
                "kind": matched["kind"],
                "text": matched["text"].strip(),
            }
        )
    return rows


async def _read(session: ProviderSession, start: int, length: int) -> bytes:
    """Mapped bytes at one address, exactly as the provider dumped them.

    Each line's own address is checked against where it should be. ``hexdump``
    will dump an address that is not mapped, so a reply whose first line is
    somewhere else is read as the end of what could be read, not as bytes from
    the address that was asked for.
    """
    if length <= 0:
        return b""
    text = await _call(session, "hexdump", address=_hex(start), size=str(length))
    read = bytearray()
    for line in _rows(text):
        if line.lstrip().startswith("- offset -"):
            continue
        matched = _HEX_LINE.match(line.rstrip())
        if matched is None:
            break
        if int(matched["address"], 16) != start + len(read):
            break
        wanted = min(16, length - len(read))
        field = matched["rest"][: wanted * 2 + (wanted + 1) // 2].replace(" ", "")
        if len(field) != wanted * 2:
            break
        try:
            read.extend(bytes.fromhex(field))
        except ValueError:
            break
        if len(read) >= length:
            break
    return bytes(read)


async def _flag_at(session: ProviderSession, address: int) -> str | None:
    """The name the provider already holds at exactly this address, if any.

    ``fd`` answers with the nearest flag and a ``+ delta`` when the address is
    inside one rather than at it. Only an exact hit is reported, because
    "there is a string eight bytes before this" is not a fact about this
    address.
    """
    try:
        answer = _rows(await _call(session, "lookup_address", address=_hex(address)))
    except ProviderError:
        return None
    if not answer:
        return None
    name = answer[0].strip()
    return None if not name or "+" in name else name


def _hex(address: int) -> str:
    return f"0x{address:x}"


# --------------------------------------------------------------------------
# the passes
# --------------------------------------------------------------------------


async def _run_pass(
    session: ProviderSession, image: _Image, name: str
) -> PreparedPass:
    reason = _NO_SOURCE.get(name)
    if reason is not None:
        return _pass_result(
            image,
            name,
            [
                _unavailable(block, "raw_bytes", reason)
                for block in image.sections
            ],
            [],
            list(image.warnings),
        )
    if name == "strings":
        return await _strings_pass(session, image)
    return await _functions_pass(session, image)


async def _strings_pass(session: ProviderSession, image: _Image) -> PreparedPass:
    """Recover text out of mapped bytes, at the address they were read at.

    The evidence is the bytes, at an address, in an encoding — never a
    listing's own opinion, because this provider's string listing has no
    address in it at all. ``lookup_address`` is asked afterwards, per
    candidate, only to record whether radare2 already holds a string there.
    """
    ranges: list[AddressRange] = []
    candidates: list[Candidate] = []
    warnings = list(image.warnings)
    budget = MAX_PASS_READ_BYTES
    for block in image.sections:
        if block["executable"]:
            ranges.append(_unreached(block, "raw_bytes", _CODE_NOT_SWEPT))
            continue
        entry_range = _range(block, "raw_bytes")
        read, failure = await _sweep(session, block, entry_range, budget)
        budget -= len(read)
        ranges.append(entry_range)
        if failure is not None:
            warnings.append(failure)
            continue
        for found in _runs(read, int(block["start"])):
            if len(candidates) >= MAX_PASS_CANDIDATES:
                _stop(
                    entry_range,
                    int(found["start"]),
                    block,
                    f"this pass reported {MAX_PASS_CANDIDATES} strings and"
                    " stopped here",
                )
                warnings.append(
                    f"this pass reported {MAX_PASS_CANDIDATES} strings and"
                    f" stopped inside {block['name']}; what is past"
                    f" {found['start']:#x} was not examined"
                )
                break
            flag = await _flag_at(session, int(found["start"]))
            candidates.append(_string_candidate(block, found, flag))
    return _pass_result(image, "strings", ranges, candidates, warnings)


async def _functions_pass(session: ProviderSession, image: _Image) -> PreparedPass:
    """Report the function entries this provider's analysis actually defines.

    Each entry is a candidate, never an applied change: there is no tool in
    this build that writes one anywhere that survives the session. The extent
    beside it is radare2's own measurement, and an entry whose extent could
    not be measured carries none rather than a guessed one — which is also why
    it closes no gap in the coverage below.
    """
    rows, truncated = await _functions(session)
    symbols = await _symbols(session)
    warnings = list(image.warnings)
    if truncated is not None:
        warnings.append(truncated)
    extents: dict[int, int] = {}
    measured = 0
    unmeasured: list[int] = []
    for row in rows:
        entry = int(row["entry"])
        if measured >= MAX_FUNCTION_EXTENTS:
            unmeasured.append(entry)
            continue
        measured += 1
        end = await _extent(session, entry)
        if end is None:
            unmeasured.append(entry)
            continue
        extents[entry] = end
    if unmeasured:
        warnings.append(
            f"{len(unmeasured)} of {len(rows)} function entries have no"
            " measured extent here (the provider's listing carried no size"
            f" line for them, first at {unmeasured[0]:#x}), so the bytes they"
            " cover are reported unvisited rather than assumed"
        )

    candidates: list[Candidate] = []
    for row in rows:
        if len(candidates) >= MAX_PASS_CANDIDATES:
            warnings.append(
                f"this pass reported {MAX_PASS_CANDIDATES} functions and"
                " stopped; the entries past that one were not described"
            )
            break
        entry = int(row["entry"])
        block = _block_of(image, entry)
        if block is None:
            continue
        references = await _xrefs(session, entry)
        candidates.append(
            _function_candidate(block, row, extents.get(entry), symbols, references)
        )
    ranges = _code_ranges(image, extents, truncated is not None or bool(unmeasured))
    return _pass_result(image, "functions", ranges, candidates, warnings)


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
            _stop(
                entry,
                cursor,
                block,
                "the provider returned no bytes this range could be read from",
            )
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
    """The first byte of the longest text run ending at ``high``."""
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
    under the image's own binary structure.
    """
    return bool(text) and all(
        character in "\t\n" or (character.isascii() and character.isprintable())
        for character in text
    )


def _string_candidate(
    block: Mapping[str, Any], found: Mapping[str, Any], flag: str | None
) -> Candidate:
    return {
        "candidate_id": f"r2:string:{found['encoding']}:{found['start']:08x}",
        "kind": "string",
        "backend": BACKEND,
        "address_space": ADDRESS_SPACE_IMAGE,
        "address": int(found["start"]),
        "evidence": {
            "stage": "raw_bytes",
            "method": "bytes read with hexdump and decoded in place",
            "section": block["name"],
            "encoding": found["encoding"],
            "start": int(found["start"]),
            "end": int(found["end"]),
            "bytes": bytes(found["raw"]).hex(),
            "text": found["text"],
            "provider_flag": flag,
        },
        "confidence": 0.8,
        "state": "candidate",
        "reason": (
            "this provider has no tool that defines a string anywhere that"
            " outlives the session, so the run is described at the address it"
            " was read from and nothing is written"
        ),
    }


def _function_candidate(
    block: Mapping[str, Any],
    row: Mapping[str, Any],
    end: int | None,
    symbols: Mapping[int, Mapping[str, Any]],
    references: Sequence[Mapping[str, Any]],
) -> Candidate:
    entry = int(row["entry"])
    symbol = symbols.get(entry)
    calls = [item for item in references if item["kind"] in CALL_REFERENCES]
    return {
        "candidate_id": f"r2:function:{entry:08x}",
        "kind": "function",
        "backend": BACKEND,
        "address_space": ADDRESS_SPACE_IMAGE,
        "address": entry,
        "evidence": {
            "stage": "code_scan",
            "method": "function entry defined by the provider's own analysis",
            "section": block["name"],
            "name": str(row["name"]),
            "start": entry,
            "end": end,
            "extent_measured": end is not None,
            "symbol": None if symbol is None else str(symbol["name"]),
            "symbol_size": None if symbol is None else int(symbol["size"]),
            "call_references": len(calls),
            "reference_kinds": sorted({str(item["kind"]) for item in references}),
        },
        "confidence": 0.9 if symbol is not None else 0.6,
        "state": "candidate",
        "reason": (
            "this provider has no tool that writes a function boundary"
            " anywhere that outlives the session, so the entry is described"
            " and nothing is written"
        ),
    }


def _block_of(image: _Image, address: int) -> dict[str, Any] | None:
    for block in image.sections:
        if block["start"] <= address < block["end"]:
            return block
    return None


def _code_ranges(
    image: _Image, extents: Mapping[int, int], bounded: bool
) -> list[AddressRange]:
    """What the functions pass measured in each range that holds code.

    Only a measured extent closes bytes. Everything else is named in
    ``unvisited``: radare2's analysis is not a linear sweep, and the bytes
    between the functions it found are bytes nothing here looked at.
    """
    ranges: list[AddressRange] = []
    for block in image.sections:
        if not block["executable"]:
            continue
        entry_range = _range(block, "code_scan")
        spans = [
            (entry, end)
            for entry, end in extents.items()
            if block["start"] <= entry < block["end"]
        ]
        gaps = _gaps(block, spans)
        if gaps:
            entry_range["coverage"] = "partial"
            entry_range["unvisited"] = gaps
            entry_range["reason"] = (
                "the entries here are the ones the provider's own analysis"
                " defines, with the extent its listing measured; the bytes"
                " between them were not swept, because this build exposes no"
                " linear-disassembly tool to sweep them with"
                + (
                    " and this run did not measure every entry it was told"
                    " about"
                    if bounded
                    else ""
                )
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

    "The pass found nothing here" and "the pass never got here" are different
    answers, and only one of them is evidence.
    """
    entry = _range(block, stage)
    entry["coverage"] = "partial"
    entry["unvisited"] = [{"start": int(block["start"]), "end": int(block["end"])}]
    entry["reason"] = reason
    return entry


def _unavailable(block: Mapping[str, Any], stage: str, reason: str) -> AddressRange:
    """A range this provider cannot answer about at all."""
    entry = _range(block, stage)
    entry["coverage"] = "unavailable"
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
    image: _Image,
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
    return {
        "pass": name,
        "backend": BACKEND,
        "ranges": ranges,
        "coverage": coverage,
        "applied_ids": [],
        "candidate_ids": [row["candidate_id"] for row in candidates],
        "warnings": warnings[:MAX_PREPARE_WARNINGS],
        "artifact_revision": None,
        "candidates": candidates,
        "image_base": image.base,
    }


def _requested(passes: object) -> tuple[str, ...]:
    if isinstance(passes, str) or not isinstance(passes, Iterable):
        raise R2UnavailableError(
            f"passes must be a sequence of pass names, got {passes!r}"
        )
    wanted = tuple(str(name) for name in passes) or PASS_NAMES
    unknown = sorted(set(wanted) - set(PASS_NAMES))
    if unknown:
        raise R2UnavailableError(
            f"{unknown} is not a pass this server runs; the passes are"
            f" {', '.join(PASS_NAMES)}"
        )
    return wanted


# --------------------------------------------------------------------------
# rule evidence
# --------------------------------------------------------------------------


async def _rule_evidence(
    session: ProviderSession, image: _Image, rule: Rule, rule_index: int
) -> RuleEvidence:
    rows, truncated = await _functions(session)
    wanted = _wanted_names(rule)
    targets = [row for row in rows if _normalize(str(row["name"])) in wanted]
    if not targets:
        return _evidence(rule_index, [], [], "evaluated", None)
    names = {int(row["entry"]): str(row["name"]) for row in rows}
    by_name: dict[str, int] = {}
    for entry, name in names.items():
        by_name.setdefault(name, entry)

    sites: list[dict[str, Any]] = []
    ranges: list[AddressRange] = []
    for row in targets:
        for reference in await _xrefs(session, int(row["entry"])):
            if reference["kind"] not in CALL_REFERENCES:
                continue
            owner = str(reference["owner"])
            if owner not in by_name:
                # radare2 spells a reference from outside any function
                # ``(nofunc)``. A call site with no containing function is one
                # no caller graph can be walked from, so it is named here and
                # never answered for.
                ranges.append(
                    _site_range(
                        int(reference["address"]),
                        owner,
                        "unavailable",
                        "the provider reports this call site inside"
                        f" {owner!r}, which it lists as no function, so the"
                        " functions it is reached from cannot be walked",
                    )
                )
                continue
            if _normalize(owner) in wanted:
                continue
            if len(sites) >= MAX_RULE_CALL_SITES:
                ranges.append(
                    _site_range(
                        int(reference["address"]),
                        owner,
                        "unavailable",
                        f"this rule reached {MAX_RULE_CALL_SITES} call sites"
                        " and stopped; the references past this one were not"
                        " read",
                    )
                )
                break
            sites.append(
                {
                    "address": int(reference["address"]),
                    "owner": by_name[owner],
                    "name": owner,
                }
            )
    if not sites:
        failed = [item for item in ranges if item["coverage"] == "unavailable"]
        return _evidence(
            rule_index,
            [],
            ranges,
            "failed" if failed else "evaluated",
            "; ".join(str(item["reason"]) for item in failed[:4]) or None,
        )

    callers: dict[int, list[str] | None] = {}
    contexts: list[dict[str, Any]] = []
    for site in sorted(sites, key=lambda item: item["address"]):
        owner = int(site["owner"])
        if owner not in callers:
            callers[owner] = await _reachable_from(session, owner, names, by_name)
        reached = callers[owner]
        entry_range = _site_range(
            int(site["address"]), str(site["name"]), "complete", None
        )
        facts: dict[str, Any] = {"call": {}}
        if reached is None:
            entry_range["coverage"] = "partial"
            entry_range["unvisited"] = [
                {"start": int(site["address"]), "end": int(site["address"]) + 1}
            ]
            entry_range["reason"] = (
                "the caller graph above this call site is larger than the"
                f" {MAX_CALLERS} functions this pass walks, so which functions"
                " it is reached from was not established"
            )
        else:
            facts["call"]["reachable_from_names"] = reached
        ranges.append(entry_range)
        contexts.append(facts)

    if truncated is not None:
        return _evidence(
            rule_index,
            [],
            ranges,
            "failed",
            f"{truncated}: a rule evaluated over a function listing that is"
            " not the whole image would be answered over part of it",
        )
    missing = _probe(rule, rule_index, contexts, ranges)
    if missing is not None:
        return missing
    return _evidence(rule_index, contexts, ranges, "evaluated", None)


async def _reachable_from(
    session: ProviderSession,
    entry: int,
    names: Mapping[int, str],
    by_name: Mapping[str, int],
) -> list[str] | None:
    """Every function one call site is reached from, or ``None`` when unknown.

    The same walk IDA's scanner does, over the only cross-reference records
    this provider states: breadth-first from the containing function, over
    ``axt`` rows whose kind field says ``CALL``. A walk that exceeds its
    budget returns ``None`` — a caller graph that was never finished is not
    evidence about who calls what, and a rule that asks is told the fact is
    unavailable rather than handed a short list.
    """
    reached: list[str] = []
    seen = {entry}
    pending = [entry]
    while pending:
        if len(seen) > MAX_CALLERS:
            return None
        current = pending.pop(0)
        name = names.get(current)
        if name and name not in reached:
            reached.append(_bare(name))
        for reference in await _xrefs(session, current):
            if reference["kind"] not in CALL_REFERENCES:
                continue
            caller = by_name.get(str(reference["owner"]))
            if caller is None or caller in seen:
                continue
            seen.add(caller)
            pending.append(caller)
    return reached


def _site_range(
    address: int, name: str, coverage: str, reason: str | None
) -> AddressRange:
    return {
        "name": name,
        "stage": "instructions",
        "start": address,
        "end": address + 1,
        "coverage": coverage,
        "unvisited": (
            [] if coverage == "complete" else [{"start": address, "end": address + 1}]
        ),
        "reason": reason,
    }


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
            source = getattr(missing, "source", None) or "one of its branches"
            return _evidence(
                rule_index,
                [],
                ranges,
                "unsupported",
                f"rule {rule['name']!r} needs the {fact!r} fact at a call site"
                f" this backend reached, asked for by {source!r}, and"
                " radare2-mcp 1.8.8 states no per-argument fact at any call"
                " site: the only output that shows an argument is decompiled"
                " text and radare2's own inline type-matching annotations,"
                " which are prose about the code rather than facts out of it"
                " — and which this project measured naming an argument the"
                " image contradicts. Reading a structural fact out of that is"
                " exactly what this adapter refuses to do",
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


def _bare(name: str) -> str:
    """One radare2 name with its own bookkeeping prefix removed."""
    text = name.strip()
    for prefix in _PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix) :]
    return text


def _normalize(name: str) -> str:
    """One function name as upstream VulFi compares them.

    ``utils.prep_func_name`` strips a leading ``.`` or ``_`` and compares
    case-insensitively. radare2 additionally spells an import's PLT stub
    ``sym.imp.name`` and a discovered function ``fcn.address``, and the first
    of those is the same function to a rule.
    """
    text = _bare(name)
    if text[:1] in (".", "_"):
        text = text[1:]
    return text.lower()
