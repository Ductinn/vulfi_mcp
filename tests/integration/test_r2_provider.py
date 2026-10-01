"""Live coverage of the radare2 provider adapter against a real r2mcp server.

Every test here drives a real ``radareorg/radare2-mcp`` 1.8.8 binary over a
real MCP stdio session, through
:func:`vulfi_mcp.providers.client.provider_session` and its schema gate.
Nothing is mocked: the provider opens the compiled fixture, analyses it, and
answers with its own listings, cross-references and mapped bytes.

The prerequisite is a built r2mcp *and* a radare2 it can load, so the gate
below performs a real MCP handshake rather than looking at a file name. It is
an **autouse fixture**, not a ``pytest_runtest_setup`` hook: that hook is only
honoured from a conftest or a plugin, and a copy of it in a test module is
simply never called. An ordinary contributor run skips with the exact missing
prerequisite and the command that rebuilds it; a run with
``VULFI_REQUIRE_LIVE=1`` turns that skip into a failure.

Every address an assertion names is derived from the compiled ELF — its
section headers and its own symbol table — plus the image base the provider
itself reports, never from the result being checked.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import struct
import subprocess
from collections.abc import Awaitable
from functools import lru_cache
from pathlib import Path
from typing import Any, TypeVar

import pytest
from conftest import CC_FLAGS, FIXTURES, missing_prerequisite
from vulfi_mcp.contracts import PassResult
from vulfi_mcp.ida_runtime import evaluate_rule
from vulfi_mcp.providers import rule_contexts
from vulfi_mcp.providers.config import FORBIDDEN_TOOLS
from vulfi_mcp.providers.r2 import (
    ALLOWLIST,
    BACKEND,
    PINNED_SCHEMAS,
    evidence_r2,
    prepare_r2,
)
from vulfi_mcp.rules import Rule, load_stock_rules

T = TypeVar("T")

#: Where the r2mcp executable is, when the operator did not say.
DEFAULT_R2MCP = "/tmp/vulfi-providers/r2mcp/src/r2mcp"

#: Where the radare2 this server loads is installed, when the operator did not
#: say. ``$PREFIX/lib`` has to be on ``LD_LIBRARY_PATH`` and ``$PREFIX/bin`` on
#: ``PATH`` for the plugins r2mcp opens.
DEFAULT_R2_PREFIX = "/tmp/vulfi-providers/r2"

R2MCP_ENV = "VULFI_R2MCP"
R2_PREFIX_ENV = "VULFI_R2_PREFIX"

#: How to build what this file needs, named in the skip reason so the missing
#: prerequisite is actionable rather than merely reported.
BUILD_HINT = (
    "build it with the commands in"
    " .superpowers/sdd/2026-09-29-vulfi-mcp-fallback/task-3-report.md"
    " (/tmp is cleared by a reboot)"
)

ALL_PASSES = ("strings", "functions", "structures", "pointer_tables")

#: Exactly what the provider's own analysis is asked for. The adapter decides
#: the level; this is only here so a failure message can quote it.
SERVER_NAME = "Radare2 MCP Connector"
SERVER_VERSION = "1.8.8"

#: Mutating tools this build advertises. The allowlist must hold none of them:
#: nothing in this adapter writes, and nothing it could write would survive,
#: because r2mcp exposes no project to save one into.
MUTATING_TOOLS = frozenset(
    {
        "rename_function",
        "rename_flag",
        "set_comment",
        "set_function_prototype",
        "use_decompiler",
    }
)


# --------------------------------------------------------------------------
# the live prerequisite
# --------------------------------------------------------------------------


def r2mcp_path() -> Path:
    return Path(os.environ.get(R2MCP_ENV) or DEFAULT_R2MCP)


def r2_prefix() -> Path:
    return Path(os.environ.get(R2_PREFIX_ENV) or DEFAULT_R2_PREFIX)


def provider_env() -> dict[str, str]:
    """The environment the server needs, as the operator's config will carry it."""
    prefix = r2_prefix()
    return {
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(prefix / "lib"),
    }


@lru_cache(maxsize=1)
def _missing_r2_prerequisite() -> str | None:
    """Why the live r2 provider cannot run here, or ``None`` when it can.

    The handshake is real. A built executable that cannot find ``libr_core``
    is a missing prerequisite that only a started session can see, and a gate
    that stopped at ``is_file()`` would let that fail as if the adapter were
    wrong.
    """
    if shutil.which("gcc") is None:
        return "gcc is not installed, so vulfi_calls.c cannot be built"
    server = r2mcp_path()
    if not server.is_file() or not os.access(server, os.X_OK):
        return (
            f"the r2mcp server is not at {server} (set {R2MCP_ENV} to the"
            f" executable, or {BUILD_HINT})"
        )
    library = r2_prefix() / "lib"
    if not library.is_dir():
        return (
            f"radare2 is not installed at {r2_prefix()} (set {R2_PREFIX_ENV}"
            f" to its prefix, or {BUILD_HINT})"
        )
    try:
        name, version = asyncio.run(_handshake())
    except Exception as refused:  # noqa: BLE001 - every failure is the same gate
        return (
            f"the r2mcp server at {server} did not answer an MCP handshake"
            f" ({type(refused).__name__}: {refused}); {BUILD_HINT}"
        )
    if name != SERVER_NAME:
        return f"the server at {server} calls itself {name!r}, not {SERVER_NAME!r}"
    if version != SERVER_VERSION:
        return (
            f"the server at {server} is version {version!r}, and this adapter"
            f" pins its tool schemas against {SERVER_VERSION!r}"
        )
    return None


async def _handshake() -> tuple[str, str]:
    """Open one real session and return the server's own name and version."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(
        command=str(r2mcp_path()), args=[], env=provider_env()
    )
    with open(os.devnull, "a", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=None) as session:
                initialized = await session.initialize()
                info = initialized.server_info
                return info.name, info.version


@pytest.fixture(autouse=True)
def live_r2_provider() -> None:
    """Skip, or fail under ``VULFI_REQUIRE_LIVE=1``, when r2mcp is absent."""
    reason = _missing_r2_prerequisite()
    if reason is not None:
        missing_prerequisite(reason)


def live(awaitable: Awaitable[T]) -> T:
    return asyncio.run(awaitable)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def compiled_calls_binary(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_calls.c`` into ``tmp_path``.

    The fixture holds three ``strcpy`` call sites — one with a string literal
    source, two with a variable one — which is exactly the shape that makes a
    pseudocode-derived answer look right and be wrong.
    """
    compiler = shutil.which("gcc")
    if compiler is None:  # pragma: no cover - the gate above already refused
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / "vulfi_calls"
    completed = subprocess.run(
        [str(compiler), *CC_FLAGS, "-o", str(binary), str(FIXTURES / "vulfi_calls.c")],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_calls.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@pytest.fixture
def r2_config(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Write the operator's provider configuration and point the loader at it.

    This is the operator's half of the contract and nothing else: the
    executable, the environment radare2 needs, and the directory whose bytes
    mean the same thing on both sides. No test argument names a tool.
    """
    config = tmp_path / "providers.toml"
    environment = provider_env()
    config.write_text(
        "\n".join(
            (
                "[r2]",
                'transport = "stdio"',
                f'command = "{r2mcp_path()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "r2mcp.err"}"',
                "",
                "[r2.env]",
                f'PATH = "{environment["PATH"]}"',
                f'LD_LIBRARY_PATH = "{environment["LD_LIBRARY_PATH"]}"',
                f'HOME = "{tmp_path / "r2-home"}"',
                "",
                "[[r2.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
                "[[r2.binaries]]",
                f'local = "{managed_data_dir}"',
                f'remote = "{managed_data_dir}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "r2-home").mkdir(exist_ok=True)
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


# --------------------------------------------------------------------------
# reading the image, so assertions name addresses the ELF proves
# --------------------------------------------------------------------------


def elf_sections(binary: Path) -> dict[str, tuple[int, int, int]]:
    """Section name to ``(virtual address, size, file offset)``."""
    raw = binary.read_bytes()
    # e_shoff at 0x28, then e_shentsize at 0x3a, e_shnum at 0x3c, e_shstrndx
    # at 0x3e: ten bytes of e_flags/e_ehsize/e_phentsize/e_phnum in between.
    shoff, shentsize, shnum, shstrndx = struct.unpack_from("<Q10xHHH", raw, 0x28)
    headers = [
        struct.unpack_from("<IIQQQQIIQQ", raw, shoff + index * shentsize)
        for index in range(shnum)
    ]
    strtab = headers[shstrndx][4]
    sections: dict[str, tuple[int, int, int]] = {}
    for name_offset, _, _, addr, offset, size, *_ in headers:
        end = raw.index(b"\x00", strtab + name_offset)
        name = raw[strtab + name_offset : end].decode("ascii")
        if name:
            sections[name] = (addr, size, offset)
    return sections


def elf_symbols(binary: Path) -> dict[str, tuple[int, int]]:
    """Symbol name to ``(virtual address, size)``, out of ``.symtab``."""
    raw = binary.read_bytes()
    sections = elf_sections(binary)
    _, symsize, symoff = sections[".symtab"]
    _, _, stroff = sections[".strtab"]
    symbols: dict[str, tuple[int, int]] = {}
    for offset in range(symoff, symoff + symsize, 24):
        # Elf64_Sym: name, info, other, shndx, value, size.
        name_offset, _, _, _, value, size = struct.unpack_from(
            "<IBBHQQ", raw, offset
        )
        if not name_offset:
            continue
        end = raw.index(b"\x00", stroff + name_offset)
        name = raw[stroff + name_offset : end].decode("ascii")
        if name and name not in symbols:
            symbols[name] = (value, size)
    return symbols


def section_bytes(binary: Path, name: str) -> bytes:
    _, size, offset = elf_sections(binary)[name]
    return binary.read_bytes()[offset : offset + size]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# small readers over the results, so a failure explains itself
# --------------------------------------------------------------------------


def one_pass(results: tuple[PassResult, ...], name: str) -> dict[str, Any]:
    matches = [entry for entry in results if entry["pass"] == name]
    assert matches, f"no {name!r} pass in {[entry['pass'] for entry in results]}"
    return dict(matches[0])


def candidates(results: tuple[PassResult, ...], name: str) -> list[dict[str, Any]]:
    return list(one_pass(results, name).get("candidates", []))


def at_address(
    rows: list[dict[str, Any]], address: int, what: str
) -> dict[str, Any]:
    matches = [row for row in rows if row["address"] == address]
    assert matches, (
        f"no {what} at {address:#x}; the pass reported "
        f"{sorted(hex(row['address']) for row in rows if row['address'] is not None)}"
    )
    return matches[0]


def image_base(results: tuple[PassResult, ...]) -> int:
    bases = {entry["image_base"] for entry in results if "image_base" in entry}
    assert len(bases) == 1, f"the passes disagree about the image base: {bases}"
    return bases.pop()


def ranges_by_name(entry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): dict(item) for item in entry["ranges"]}


def stock_rule(function: str) -> tuple[int, Rule]:
    for index, rule in enumerate(load_stock_rules()):
        if function in rule["function_names"]:
            return index, rule
    raise AssertionError(f"no stock rule names {function!r}")


#: A rule whose only fact is one this provider really establishes: the names
#: of the functions a call site is reached from, out of ``axt`` cross-reference
#: records. It exists so the suite proves the adapter answers what it can as
#: well as refusing what it cannot.
REACHABILITY_RULE: Rule = {
    "name": "r2 reachability probe",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {
        "High": "function_call.reachable_from('copy_wrapper')",
        "Medium": "False",
        "Low": "False",
    },
}


# --------------------------------------------------------------------------
# the tests
# --------------------------------------------------------------------------


def test_r2_analysis_reopens_in_second_request(
    compiled_calls_binary: Path, r2_config: Path, managed_data_dir: Path
) -> None:
    """Two separate sessions, the same addresses, and an untouched binary.

    r2mcp keeps nothing between stdio sessions — it advertises no project and
    no save — so the adapter reopens and re-analyses every time. The claim
    under test is that this costs nothing in fidelity: the string and the
    function the first session proves are proven again by the second, at the
    addresses the ELF itself gives, and the operator's file is byte-identical
    afterwards.
    """
    before = digest(compiled_calls_binary)
    sections = elf_sections(compiled_calls_binary)
    symbols = elf_symbols(compiled_calls_binary)

    first = live(prepare_r2(str(compiled_calls_binary), ("strings", "functions")))
    base = image_base(first)

    rodata_address, _, _ = sections[".rodata"]
    literal = b"vulfi-constant\x00"
    offset = section_bytes(compiled_calls_binary, ".rodata").index(literal)
    string_address = base + rodata_address + offset

    found = at_address(candidates(first, "strings"), string_address, "string candidate")
    assert found["kind"] == "string"
    assert found["backend"] == BACKEND
    assert found["state"] == "candidate"
    assert found["evidence"]["encoding"] == "ascii"
    assert found["evidence"]["text"] == "vulfi-constant"
    assert found["evidence"]["bytes"] == literal.hex()
    assert found["evidence"]["end"] == string_address + len(literal)

    entry, size = symbols["copy_constant"]
    function = at_address(
        candidates(first, "functions"), base + entry, "function candidate"
    )
    assert function["kind"] == "function"
    assert function["state"] == "candidate", "nothing may be written back"
    assert function["evidence"]["end"] == base + entry + size, function["evidence"]

    # A second request, a second process, a second analysis.
    index, _ = stock_rule("strcpy")
    second = live(
        evidence_r2(str(compiled_calls_binary), REACHABILITY_RULE, index)
    )
    assert second["state"] == "evaluated", second["reason"]
    sites = sorted(item["start"] for item in second["ranges"])
    expected = []
    for owner in ("copy_from_argument", "copy_from_environment", "copy_constant"):
        start, length = symbols[owner]
        expected.append((base + start, base + start + length))
    assert len(sites) == len(expected), second["ranges"]
    for site, (low, high) in zip(sites, expected, strict=True):
        assert low <= site < high, (
            f"call site {site:#x} is not inside {low:#x}..{high:#x}"
        )

    contexts = rule_contexts(second)
    assert len(contexts) == len(expected)
    verdicts = [evaluate_rule(REACHABILITY_RULE, context) for context in contexts]
    assert verdicts == ["High", None, None], verdicts

    assert digest(compiled_calls_binary) == before, "the operator's binary was written"


def test_no_structural_args_from_pseudocode(
    compiled_calls_binary: Path, r2_config: Path, managed_data_dir: Path
) -> None:
    """A named dangerous call, no argument facts, and no verdict invented.

    ``decompile_function`` will happily print ``strcpy("", "vulfi-constant")``
    for the one call site whose source really is a literal — and its first
    argument is not ``""`` at all, it is ``obj.g_buffer``. Nothing in r2mcp's
    typed surface states whether an argument is a constant, so the only honest
    answer for a rule that asks is ``unsupported`` naming the missing fact:
    not ``High``, not ``Info``, and not a clean negative.
    """
    index, rule = stock_rule("strcpy")
    assert "param[1].is_constant()" in rule["mark_if"]["High"], rule["mark_if"]

    evidence = live(evidence_r2(str(compiled_calls_binary), rule, index))

    assert evidence["state"] == "unsupported", evidence
    assert evidence["contexts"] == [], "an unsupported rule carries no facts"
    reason = evidence["reason"] or ""
    # The missing fact is the argument list itself, and the reason names both
    # it and the expression that asked for it.
    assert "'params'" in reason, reason
    assert "param[1]" in reason, reason
    assert evidence["rule_index"] == index
    assert evidence["backend"] == BACKEND

    # The sites were still reached: the gap is the fact, not the search.
    assert evidence["ranges"], "the call sites this rule reached must be named"
    assert all(item["stage"] == "instructions" for item in evidence["ranges"])

    # No pseudocode tool is even reachable from this adapter.
    assert "decompile_function" not in ALLOWLIST
    assert "disassemble" not in ALLOWLIST

    # And nothing downstream can turn this into a finding.
    assert rule_contexts(evidence) == ()


def test_unsafe_writes_are_unavailable(
    compiled_calls_binary: Path, r2_config: Path, managed_data_dir: Path
) -> None:
    """Candidate-only verdicts, no mutation tool, and no raw execution."""
    import vulfi_mcp.providers.r2 as adapter

    assert not [name for name in dir(adapter) if name.startswith("apply")]

    assert ALLOWLIST.isdisjoint(FORBIDDEN_TOOLS)
    assert ALLOWLIST.isdisjoint(MUTATING_TOOLS)
    assert "calculate" not in ALLOWLIST, "an expression evaluator is an escape"
    assert set(PINNED_SCHEMAS) == set(ALLOWLIST)

    results = live(prepare_r2(str(compiled_calls_binary), ALL_PASSES))
    assert {entry["pass"] for entry in results} == set(ALL_PASSES)
    for entry in results:
        assert entry["applied_ids"] == [], entry["pass"]
        assert entry["artifact_revision"] is None
        for row in entry.get("candidates", []):
            assert row["state"] == "candidate", row
            assert row["reason"], "a candidate nothing applied must say why"

    for name in ("structures", "pointer_tables"):
        entry = one_pass(results, name)
        assert entry["coverage"] == "unavailable", entry
        assert entry["candidate_ids"] == []
        assert entry["ranges"], f"{name} must name the ranges it cannot answer for"
        for item in entry["ranges"]:
            assert item["coverage"] == "unavailable"
            assert item["reason"]


def test_bounded_reads_say_what_they_left_behind(
    compiled_calls_binary: Path, r2_config: Path, managed_data_dir: Path
) -> None:
    """No pass reports ``complete`` over a range it never swept."""
    results = live(prepare_r2(str(compiled_calls_binary), ("strings", "functions")))
    base = image_base(results)
    sections = elf_sections(compiled_calls_binary)

    strings = one_pass(results, "strings")
    reported = ranges_by_name(strings)
    for name in (".rodata", ".text", ".data"):
        assert name in reported, sorted(reported)
    assert reported[".rodata"]["coverage"] == "complete", reported[".rodata"]
    assert reported[".text"]["coverage"] != "complete", reported[".text"]
    assert reported[".text"]["reason"], reported[".text"]

    for name, item in reported.items():
        address, size, _ = sections[name]
        assert item["start"] == base + address
        assert item["end"] == base + address + size
        if item["coverage"] == "complete":
            assert item["unvisited"] == []
        else:
            assert item["unvisited"], item
            assert item["reason"], item

    functions = one_pass(results, "functions")
    code = ranges_by_name(functions)[".text"]
    assert code["coverage"] == "partial", code
    assert code["reason"], code
    covered = [
        (gap["start"], gap["end"]) for gap in code["unvisited"]
    ]
    assert covered == sorted(covered), covered
    assert all(low < high for low, high in covered), covered


def test_a_drifted_tool_schema_takes_only_that_capability_down(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A re-pinned fingerprint fails loudly rather than answering differently."""
    import vulfi_mcp.providers.r2 as adapter

    drifted = dict(PINNED_SCHEMAS)
    drifted["xrefs_to"] = "0" * 64
    monkeypatch.setattr(adapter, "PINNED_SCHEMAS", drifted)

    index, rule = stock_rule("strcpy")
    evidence = live(evidence_r2(str(compiled_calls_binary), rule, index))
    assert evidence["state"] == "failed", evidence
    assert "xrefs_to" in (evidence["reason"] or ""), evidence["reason"]
    assert evidence["contexts"] == []


# --------------------------------------------------------------------------
# the four invariants fix round 1 is about. r2mcp declares no ``outputSchema``
# for any tool, so the pin attests the call and nothing about the reply: this
# adapter is the only thing between a format drift and a clean result.
# --------------------------------------------------------------------------


def test_an_unrecognised_row_fails_the_capability(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant A: a row the parser does not recognise is not an absence.

    A drifted listing must take the capability down. The failure mode this
    closes is the quiet one: ``xrefs_to`` rows that no longer parse become an
    empty reference list, the rule gets ``evaluated`` with no call sites, and
    a real target reads as clean.
    """
    import vulfi_mcp.providers.r2 as adapter

    never = re.compile(r"\A(?!)")
    index, _ = stock_rule("strcpy")

    # The section table first, because a drift there is what makes every later
    # pass summarise the rows that happened to survive as if they were the
    # image. ``_open`` must refuse instead.
    real_section_row = adapter._SECTION_ROW
    monkeypatch.setattr(adapter, "_SECTION_ROW", never)
    with pytest.raises(adapter.R2FormatError) as refused:
        live(prepare_r2(str(compiled_calls_binary), ("strings",)))
    assert "list_sections" in str(refused.value), refused.value
    monkeypatch.setattr(adapter, "_SECTION_ROW", real_section_row)

    # And the cross-reference rows: an unreadable row is not "no references".
    monkeypatch.setattr(adapter, "_XREF_ROW", never)
    evidence = live(evidence_r2(str(compiled_calls_binary), REACHABILITY_RULE, index))
    assert evidence["state"] == "failed", evidence
    assert "xrefs_to" in (evidence["reason"] or ""), evidence["reason"]
    assert evidence["contexts"] == []


def test_a_truncated_listing_blocks_complete_coverage(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant B: a bounded read forces partial coverage, whatever the shape.

    Geometry is not the test. A section whose measured extents happen to cover
    it may not stay ``complete`` once the pass has proved it left rows behind,
    and the extents of rows past the cap may not close gaps whose candidates
    were never reported.
    """
    import vulfi_mcp.providers.r2 as adapter

    whole = live(prepare_r2(str(compiled_calls_binary), ("functions",)))
    entries = sorted(
        row["address"] for row in candidates(whole, "functions")
    )
    assert len(entries) > 2, entries
    covered = ranges_by_name(one_pass(whole, "functions"))
    assert any(item["coverage"] == "complete" for item in covered.values()), covered

    monkeypatch.setattr(adapter, "MAX_PASS_CANDIDATES", 2)
    short = live(prepare_r2(str(compiled_calls_binary), ("functions",)))
    entry = one_pass(short, "functions")
    reported = sorted(row["address"] for row in candidates(short, "functions"))
    assert 0 < len(reported) <= 2, reported
    assert entry["coverage"] == "partial", entry["coverage"]
    assert all(item["coverage"] != "complete" for item in entry["ranges"]), (
        entry["ranges"]
    )
    assert all(item["reason"] for item in entry["ranges"]), entry["ranges"]
    # contracts.py says a partial range names the rest in ``unvisited``; a
    # range the pass vetoed is no exception.
    assert all(item["unvisited"] for item in entry["ranges"]), entry["ranges"]
    left_out = [item for item in entry["warnings"] if "left out" in item]
    assert left_out, entry["warnings"]
    named = re.search(r"first at (0x[0-9a-f]+)", left_out[0])
    assert named is not None, left_out[0]
    first_omitted = int(named.group(1), 16)
    assert all(address < first_omitted for address in reported), (
        first_omitted,
        reported,
    )
    assert first_omitted <= max(entries), (first_omitted, entries)


def test_evidence_without_a_fact_is_never_a_clean_negative(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant C: "I could not tell" is ``unsupported``, not ``False``."""
    import vulfi_mcp.providers.r2 as adapter

    index, _ = stock_rule("strcpy")
    symbols = elf_symbols(compiled_calls_binary)

    # A rule that follows wrappers asks for something no structural evidence
    # here can establish: this adapter only ever follows direct references.
    wrapped: Rule = {**REACHABILITY_RULE, "wrappers": True}
    evidence = live(evidence_r2(str(compiled_calls_binary), wrapped, index))
    assert evidence["state"] == "unsupported", evidence
    assert "wrapper" in (evidence["reason"] or "").lower(), evidence["reason"]

    # A rule whose functions are not in the listing is not a clean zero: the
    # listing covers what radare2 recognised, not every executable byte.
    absent: Rule = {**REACHABILITY_RULE, "function_names": ["gets"]}
    evidence = live(evidence_r2(str(compiled_calls_binary), absent, index))
    assert evidence["state"] == "unsupported", evidence
    assert "gets" in (evidence["reason"] or ""), evidence["reason"]

    # An unresolved caller inside the reachability walk — radare2 spells one
    # ``(nofunc)`` — leaves the fact unestablished rather than short.
    owner = symbols["copy_from_argument"][0]
    real_xrefs = adapter._xrefs

    async def with_unresolved_caller(session: Any, address: int) -> list[Any]:
        rows = await real_xrefs(session, address)
        if address == owner:
            rows.append(
                {
                    "owner": "(nofunc)",
                    "address": owner - 0x50,
                    "kind": "CALL",
                    "text": "call sym.copy_from_argument",
                }
            )
        return rows

    monkeypatch.setattr(adapter, "_xrefs", with_unresolved_caller)
    evidence = live(
        evidence_r2(str(compiled_calls_binary), REACHABILITY_RULE, index)
    )
    assert evidence["state"] == "unsupported", evidence
    assert "reachable_from_names" in (evidence["reason"] or ""), evidence["reason"]
    assert evidence["contexts"] == []


def test_one_capability_failure_keeps_the_other_passes(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant D: unavailable and failed are different, and per pass."""
    import vulfi_mcp.providers.r2 as adapter

    drifted = dict(PINNED_SCHEMAS)
    drifted["list_symbols"] = "0" * 64
    monkeypatch.setattr(adapter, "PINNED_SCHEMAS", drifted)

    results = live(prepare_r2(str(compiled_calls_binary), ("strings", "functions")))
    assert {entry["pass"] for entry in results} == {"strings", "functions"}
    assert candidates(results, "strings"), "a working pass must survive"
    broken = one_pass(results, "functions")
    assert broken["coverage"] == "unavailable", broken
    assert broken["candidate_ids"] == []
    assert any(
        "list_symbols" in str(item["reason"]) for item in broken["ranges"]
    ), broken["ranges"]

    # A backend that is not configured at all is unavailable, not a rule that
    # was tried and failed: Task 4 routes on that difference.
    empty = tmp_path / "no-providers.toml"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(empty))
    index, rule = stock_rule("strcpy")
    with pytest.raises(adapter.R2UnavailableError):
        live(evidence_r2(str(compiled_calls_binary), rule, index))


def test_a_drifted_scalar_is_refused_like_a_drifted_row(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant A, for scalars: a reply that is one value is still a reply.

    ``image_base`` is in every ``PassResult`` as the space its addresses are
    in. A ``baddr`` this adapter cannot read used to fall back to ``0`` — on a
    non-PIE image that publishes an address space nothing is in, with no
    warning anywhere. It must refuse exactly as an unreadable row does.
    """
    import vulfi_mcp.providers.r2 as adapter

    real_call = adapter._call

    async def drifted(session: Any, tool: str, **arguments: Any) -> str:
        text = await real_call(session, tool, **arguments)
        if tool == "show_info":
            return re.sub(r"(?m)^baddr\s+\S+$", "baddr    notanumber", text)
        return text

    monkeypatch.setattr(adapter, "_call", drifted)
    with pytest.raises(adapter.R2FormatError) as refused:
        live(prepare_r2(str(compiled_calls_binary), ("strings",)))
    assert "baddr" in str(refused.value), refused.value


def test_a_session_that_never_opened_is_unavailable_not_failed(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invariant D: *unavailable* is about the session, not about the rule.

    A server that exits the moment it is launched never answered a call, so
    there is no extraction that failed — and Plan 3 routes on that difference.
    Both entry points must say the same thing about it.
    """
    import vulfi_mcp.providers.r2 as adapter

    dead = tmp_path / "dead-providers.toml"
    dead.write_text(
        "\n".join(
            (
                "[r2]",
                'transport = "stdio"',
                'command = "/bin/true"',
                "args = []",
                "",
                "[[r2.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(dead))
    index, rule = stock_rule("strcpy")
    with pytest.raises(adapter.R2UnavailableError):
        live(evidence_r2(str(compiled_calls_binary), rule, index))
    with pytest.raises(adapter.R2UnavailableError):
        live(prepare_r2(str(compiled_calls_binary), ("strings",)))


def test_a_target_with_no_call_reference_says_where_it_looked(
    compiled_calls_binary: Path, r2_config: Path, managed_data_dir: Path
) -> None:
    """A real empty answer is still an answer about a place, and names it.

    ``main`` is in the listing and nothing *calls* it — the entry point
    reaches it through a data reference. That is a true negative, and it stays
    ``evaluated``; what it may not do is arrive with no statement of where the
    backend looked.
    """
    index, _ = stock_rule("strcpy")
    rule: Rule = {**REACHABILITY_RULE, "function_names": ["main"]}
    evidence = live(evidence_r2(str(compiled_calls_binary), rule, index))
    assert evidence["state"] == "evaluated", evidence
    assert evidence["contexts"] == []
    assert evidence["ranges"], "the target this rule searched must be named"
    entry = elf_symbols(compiled_calls_binary)["main"][0]
    assert any(item["start"] == entry for item in evidence["ranges"]), (
        evidence["ranges"]
    )
    assert all(item["reason"] for item in evidence["ranges"]), evidence["ranges"]


def test_a_lookup_that_could_not_be_made_is_not_a_missing_flag(
    compiled_calls_binary: Path,
    r2_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last place a failure could pass for an absence.

    ``lookup_address`` only corroborates — the candidate's claim is the bytes
    the pass read at that address — so losing it must not take the pass down.
    What it must also not do is turn every candidate into "radare2 holds no
    flag here", which is what returning ``None`` on a refusal did.
    """
    import vulfi_mcp.providers.r2 as adapter

    whole = candidates(
        live(prepare_r2(str(compiled_calls_binary), ("strings",))), "strings"
    )
    assert any(row["evidence"]["provider_flag"] for row in whole), whole
    assert all(row["evidence"]["provider_flag_checked"] for row in whole)

    drifted = dict(PINNED_SCHEMAS)
    drifted["lookup_address"] = "0" * 64
    monkeypatch.setattr(adapter, "PINNED_SCHEMAS", drifted)
    results = live(prepare_r2(str(compiled_calls_binary), ("strings",)))
    rows = candidates(results, "strings")
    assert len(rows) == len(whole), "the bytes are still the evidence"
    assert all(not row["evidence"]["provider_flag_checked"] for row in rows)
    assert all(row["evidence"]["provider_flag_unavailable"] for row in rows)
    assert any(
        "lookup_address" in warning
        for warning in one_pass(results, "strings")["warnings"]
    ), one_pass(results, "strings")["warnings"]


def test_the_adapter_allowlist_is_a_constant_no_caller_can_widen() -> None:
    """The tool surface is the adapter's, and it holds no escape."""
    assert BACKEND == "r2"
    assert isinstance(ALLOWLIST, frozenset)
    assert ALLOWLIST, "an empty allowlist would make every capability missing"
    assert ALLOWLIST.isdisjoint({"run_command", "run_javascript", "run_script", "sql"})
    assert all(
        isinstance(value, str) and len(value) == 64
        for value in PINNED_SCHEMAS.values()
    )
