"""Live coverage of the Ghidra provider adapter against a real GhidraMCP server.

Every test here drives a real headless GhidraMCP 6.0.0 server over a real MCP
stdio session, through :func:`vulfi_mcp.providers.client.provider_session` and
its schema gate. Nothing is mocked: the provider imports the compiled fixture,
analyses it, answers with its own P-code and its own cross-references, and
keeps a project on disk that the next session has to reopen.

The prerequisite is a *running server*, not an installed package, and it is a
single JVM holding one current program. Two things follow, and both are
handled here rather than hoped for. The gate lives in ``tests/conftest.py``,
because ``pytest_runtest_setup`` only fires from a conftest or a plugin and
one defined in a test module is never called at all. And every test in this
file takes an exclusive lock on that server first, so a second pytest process
waits instead of pulling the current program out from under this one; a
provider that is busy anyway — another client's program loaded, an analysis
still running — is reported as a missing prerequisite rather than as a failed
assertion, because "something else is using it" is not a result about this
adapter. An ordinary contributor run skips with the exact thing that is
missing; a run with ``VULFI_REQUIRE_LIVE=1`` turns that skip into a failure.

Every address an assertion names is derived from the compiled ELF — section
headers and the symbol table — plus the image base the provider itself
reports, never from the result being checked.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import shutil
import struct
import subprocess
import time
from collections.abc import Awaitable, Iterator
from pathlib import Path
from typing import Any, TypeVar

import pytest
from conftest import (
    FIXTURES,
    GHIDRA_START_HINT,
    ghidra_bridge,
    ghidra_url,
    missing_prerequisite,
)
from vulfi_mcp.contracts import PassResult
from vulfi_mcp.ida_runtime import evaluate_rule
from vulfi_mcp.providers import rule_contexts
from vulfi_mcp.providers.ghidra import (
    ALLOWLIST,
    BACKEND,
    ProviderBusyError,
    apply_ghidra_review,
    evidence_ghidra,
    prepare_ghidra,
)
from vulfi_mcp.rules import Rule, load_stock_rules

#: Exactly the flags this fixture needs: every call survives as its own call
#: site, and the pointers in ``.vulfi_fb_ptrs`` really carry relocations.
CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline", "-fPIE", "-pie")

ALL_PASSES = ("strings", "functions", "structures", "pointer_tables")

#: Where the exclusive lock on the shared provider lives. Beside the bridge,
#: so every checkout driving the same server contends on the same file.
PROVIDER_LOCK = Path(ghidra_bridge()).parent.parent / "vulfi-provider.lock"

#: How long to wait for another process to let go of that server.
LOCK_TIMEOUT = 300.0

T = TypeVar("T")


# --------------------------------------------------------------------------
# the shared single-JVM provider
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def provider_lock(request: pytest.FixtureRequest) -> Iterator[None]:
    """Hold the one GhidraMCP server for the duration of one test.

    GhidraMCP is a single JVM with a single *current* program, so two test
    processes driving it do not merely slow each other down — they move each
    other's program. An advisory lock makes that serial for every cooperating
    runner; a runner that will not wait is reported, not raced.
    """
    if request.node.get_closest_marker("requires_ghidra") is None:
        yield
        return
    PROVIDER_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(PROVIDER_LOCK, os.O_CREAT | os.O_RDWR, 0o666)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    missing_prerequisite(
                        "another process has held the GhidraMCP server at"
                        f" {ghidra_url()} for more than {LOCK_TIMEOUT:.0f}s"
                        f" ({PROVIDER_LOCK}); this adapter needs it to itself"
                    )
                time.sleep(0.5)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)


def live(awaitable: Awaitable[T]) -> T:
    """Run one adapter call, turning "the provider is busy" into a skip.

    The adapter reports a shared JVM holding somebody else's program, or an
    analysis that timed out under contention, as
    :class:`~vulfi_mcp.providers.ghidra.ProviderBusyError`. That is a statement
    about the provider, not about this adapter, so it becomes the same missing
    prerequisite a dead server does — and under ``VULFI_REQUIRE_LIVE=1`` it
    still fails rather than hiding.
    """
    try:
        return asyncio.run(awaitable)  # type: ignore[arg-type]
    except ProviderBusyError as busy:
        missing_prerequisite(
            f"the GhidraMCP server at {ghidra_url()} is not available to this"
            f" run: {busy}. {GHIDRA_START_HINT}"
        )
        raise  # pragma: no cover - missing_prerequisite always raises


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def compiled_fallback(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_fallback.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:  # pragma: no cover - the gate above already refused
        missing_prerequisite(
            "gcc is not installed, so vulfi_fallback.c cannot be built"
        )
    binary = tmp_path / "vulfi_fallback"
    command = [
        str(compiler),
        *CC_FLAGS,
        "-o",
        str(binary),
        str(FIXTURES / "vulfi_fallback.c"),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_fallback.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@pytest.fixture
def ghidra_config(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Write the operator's provider configuration, and point the loader at it.

    This is the operator's half of the contract and nothing else: the
    executable, its environment, and the two directories whose bytes mean the
    same thing on both sides. No test argument names a tool, and the adapter's
    allowlist is a constant it owns.
    """
    config = tmp_path / "providers.toml"
    config.write_text(
        "\n".join(
            (
                "[ghidra]",
                'transport = "stdio"',
                f'command = "{ghidra_bridge()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "bridge.err"}"',
                "",
                "[ghidra.env]",
                'PATH = "/usr/bin:/bin"',
                f'HOME = "{tmp_path / "bridge-home"}"',
                f'GHIDRA_MCP_URL = "{ghidra_url()}"',
                'GHIDRA_MCP_LOG_LEVEL = "WARNING"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{managed_data_dir}"',
                f'remote = "{managed_data_dir}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "bridge-home").mkdir(exist_ok=True)
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


# --------------------------------------------------------------------------
# reading the image, so assertions name addresses the ELF proves
# --------------------------------------------------------------------------


def elf_sections(binary: Path) -> dict[str, tuple[int, int]]:
    """Section name to ``(virtual address, size)``, read out of the ELF."""
    raw = binary.read_bytes()
    assert raw[:4] == b"\x7fELF" and raw[4] == 2, "the fixture must be a 64-bit ELF"
    order = "<" if raw[5] == 1 else ">"
    (shoff,) = struct.unpack_from(f"{order}Q", raw, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", raw, 0x3A)
    strtab_off = struct.unpack_from(
        f"{order}Q", raw, shoff + shstrndx * shentsize + 0x18
    )[0]
    sections: dict[str, tuple[int, int]] = {}
    for index in range(shnum):
        base = shoff + index * shentsize
        name_off = struct.unpack_from(f"{order}I", raw, base)[0]
        addr, _, size = struct.unpack_from(f"{order}QQQ", raw, base + 0x10)
        end = raw.index(b"\x00", strtab_off + name_off)
        sections[raw[strtab_off + name_off : end].decode()] = (addr, size)
    return sections


def elf_symbols(binary: Path) -> dict[str, int]:
    """Symbol name to virtual address, read out of the ELF's own symbol table."""
    raw = binary.read_bytes()
    order = "<" if raw[5] == 1 else ">"
    (shoff,) = struct.unpack_from(f"{order}Q", raw, 0x28)
    shentsize, shnum, _ = struct.unpack_from(f"{order}HHH", raw, 0x3A)
    symbols: dict[str, int] = {}
    for index in range(shnum):
        base = shoff + index * shentsize
        name_off, kind = struct.unpack_from(f"{order}II", raw, base)
        if kind != 2:  # SHT_SYMTAB
            continue
        offset, size = struct.unpack_from(f"{order}QQ", raw, base + 0x18)
        link, _ = struct.unpack_from(f"{order}II", raw, base + 0x28)
        entsize = struct.unpack_from(f"{order}Q", raw, base + 0x38)[0]
        strings = struct.unpack_from(
            f"{order}Q", raw, shoff + link * shentsize + 0x18
        )[0]
        for entry in range(size // entsize):
            item = offset + entry * entsize
            (symbol_name,) = struct.unpack_from(f"{order}I", raw, item)
            (value,) = struct.unpack_from(f"{order}Q", raw, item + 8)
            end = raw.index(b"\x00", strings + symbol_name)
            name = raw[strings + symbol_name : end].decode()
            if name:
                symbols[name] = value
    return symbols


def section_bytes(binary: Path, name: str) -> bytes:
    """The raw bytes of one section, as the file holds them."""
    raw = binary.read_bytes()
    order = "<" if raw[5] == 1 else ">"
    (shoff,) = struct.unpack_from(f"{order}Q", raw, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", raw, 0x3A)
    strtab_off = struct.unpack_from(
        f"{order}Q", raw, shoff + shstrndx * shentsize + 0x18
    )[0]
    for index in range(shnum):
        base = shoff + index * shentsize
        name_off = struct.unpack_from(f"{order}I", raw, base)[0]
        end = raw.index(b"\x00", strtab_off + name_off)
        if raw[strtab_off + name_off : end].decode() != name:
            continue
        offset, size = struct.unpack_from(f"{order}QQ", raw, base + 0x18)
        return raw[offset : offset + size]
    raise AssertionError(f"the fixture has no {name!r} section")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# small readers over the results, so a failure explains itself
# --------------------------------------------------------------------------


def _pass(results: tuple[PassResult, ...], name: str) -> dict[str, Any]:
    matches = [entry for entry in results if entry["pass"] == name]
    assert matches, f"no {name!r} pass in {[entry['pass'] for entry in results]}"
    return dict(matches[0])


def _report(results: tuple[PassResult, ...]) -> str:
    lines: list[str] = []
    for entry in results:
        lines.append(
            f"{entry['pass']}: coverage={entry['coverage']}"
            f" applied={len(entry['applied_ids'])}"
            f" candidates={len(entry['candidate_ids'])}"
            f" revision={entry['artifact_revision']}"
        )
        lines += [f"  warning: {text}" for text in entry["warnings"]]
        for item in entry["ranges"]:
            lines.append(
                f"  range {item['name']} {item['start']:#x}-{item['end']:#x}"
                f" {item['coverage']} unvisited={item['unvisited']}"
                f" reason={item['reason']}"
            )
        for row in dict(entry).get("candidates", []):
            lines.append(
                f"  candidate {row['candidate_id']} {row['kind']}"
                f" {row['address']:#x} {row['state']} :: {row['reason']}"
            )
    return "\n".join(lines)


def _candidates(results: tuple[PassResult, ...], name: str) -> list[dict[str, Any]]:
    return list(_pass(results, name).get("candidates", []))


def _at(rows: list[dict[str, Any]], address: int, context: str) -> dict[str, Any]:
    matches = [row for row in rows if row["address"] == address]
    assert len(matches) == 1, (
        f"expected one row at {address:#x}, got"
        f" {[(row['candidate_id'], row['state']) for row in matches]}\n{context}"
    )
    return matches[0]


def _image_base(results: tuple[PassResult, ...]) -> int:
    """The base the provider loaded the image at, as its own ranges report it.

    Taken from the result rather than assumed: Ghidra rebases a PIE, and an
    assertion that hard-coded the rebase would stop testing the adapter and
    start testing the constant.
    """
    bases = {
        int(dict(entry).get("image_base", -1))
        for entry in results
        if dict(entry).get("image_base") is not None
    }
    assert len(bases) == 1 and -1 not in bases, f"one image base, got {bases}"
    return bases.pop()


def _stock(name: str, function: str) -> tuple[int, Rule]:
    """One stock rule, by the function name it matches."""
    for index, rule in enumerate(load_stock_rules()):
        if rule["name"] == name and function in rule["function_names"]:
            return index, rule
    raise AssertionError(f"no stock {name!r} rule naming {function!r}")


# --------------------------------------------------------------------------
# the tests
# --------------------------------------------------------------------------


@pytest.mark.requires_ghidra
def test_ghidra_function_and_string_evidence(
    compiled_fallback: Path, ghidra_config: Path, managed_data_dir: Path
) -> None:
    """An unmarked reachable function and raw strings, proven and persisted.

    The function is proven by what the provider itself reports: a data
    cross-reference from the relocated pointer slot, and the mapped bytes at
    the entry. The strings are proven by mapped bytes alone. Then the project
    is saved, the program released, and a second session has to reopen it and
    find the same artifact — with the operator's binary byte-identical
    throughout.
    """
    before = _digest(compiled_fallback)
    sections = elf_sections(compiled_fallback)
    blob = section_bytes(compiled_fallback, ".vulfi_fb_blob")

    results = live(prepare_ghidra(str(compiled_fallback), ALL_PASSES))
    context = _report(results)
    base = _image_base(results)

    hidden = base + sections[".vulfi_fb_hidden"][0]
    slot = base + sections[".vulfi_fb_ptrs"][0]
    functions = _pass(results, "functions")
    recovered = _at(_candidates(results, "functions"), hidden, context)

    assert recovered["backend"] == BACKEND, context
    assert recovered["kind"] == "function", context
    assert recovered["state"] == "applied", context
    assert recovered["candidate_id"] in functions["applied_ids"], context
    evidence = recovered["evidence"]
    assert slot in evidence["referenced_from"], context
    assert bytes.fromhex(evidence["bytes"]) == section_bytes(
        compiled_fallback, ".vulfi_fb_hidden"
    )[: len(bytes.fromhex(evidence["bytes"]))], context
    assert functions["coverage"] in {"partial", "complete"}, context

    # Both wide runs are in the image and in neither Ghidra's string listing
    # nor its data listing, so the only thing that can produce them is the
    # mapped bytes this pass reads. Each is looked up at the address the ELF
    # puts it at, never by picking whichever row carries the same encoding.
    strings = _candidates(results, "strings")
    for encoding, text in (
        ("utf-16le", "vulfi-fb-utf16le"),
        ("utf-16be", "vulfi-fb-utf16be"),
    ):
        raw = text.encode(encoding) + b"\x00\x00"
        address = base + sections[".vulfi_fb_blob"][0] + blob.index(raw)
        row = _at(strings, address, context)
        assert row["evidence"]["encoding"] == encoding, context
        assert bytes.fromhex(row["evidence"]["bytes"]) == raw, context
        assert row["evidence"]["text"] == text, context
        assert row["evidence"]["segment"] == ".vulfi_fb_blob", context
        assert row["state"] == "candidate", context

    # The ASCII marker in the same section is one Ghidra's own analyzer
    # already typed, so this pass does not report it as something left behind.
    marker = base + sections[".vulfi_fb_blob"][0] + blob.index(b"vulfi-fallback-raw-")
    assert [row for row in strings if row["address"] == marker] == [], context

    # Two of the four passes have no typed evidence source in this build, and
    # say so rather than reporting a clean nothing.
    for name in ("structures", "pointer_tables"):
        entry = _pass(results, name)
        assert entry["coverage"] == "unavailable", context
        assert entry["candidate_ids"] == [] and entry["applied_ids"] == [], context
        assert entry["warnings"], context

    # A second session: the project was saved and the program released, so
    # this one has to reopen both and find the function the first one defined.
    again = live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    reopened = _at(_candidates(again, "functions"), hidden, _report(again))
    assert reopened["state"] == "applied", _report(again)
    assert reopened["evidence"]["already_defined"] is True, _report(again)
    # And it does not move the revision: this session wrote nothing, and a
    # revision that moved anyway would stale every proposal made against the
    # one before it.
    assert _pass(again, "functions")["artifact_revision"] == functions[
        "artifact_revision"
    ], _report(again)

    assert _digest(compiled_fallback) == before, "the operator's binary was written to"


@pytest.mark.requires_ghidra
def test_pcode_supported_rule_vs_pseudocode_only_gap(
    compiled_fallback: Path, ghidra_config: Path, managed_data_dir: Path
) -> None:
    """One rule the P-code answers, one it cannot, and no guessing between.

    The format-string rule needs one fact — is the format argument a constant
    — and high P-code states it as structure: a constant varnode against a
    register defined by a call. The buffer-overflow rule also asks whether
    ``strlen`` took the same buffer first; the decompiled C shows that guard
    and nothing typed in this build states it, so the rule is ``unsupported``
    with a reason rather than answered from text.
    """
    symbols = elf_symbols(compiled_fallback)
    live(prepare_ghidra(str(compiled_fallback), ("functions",)))

    index, printf_rule = _stock("Format String", "printf")
    evidence = live(
        evidence_ghidra(str(compiled_fallback), printf_rule, index)
    )
    assert evidence["backend"] == BACKEND, evidence
    assert evidence["state"] == "evaluated", evidence
    assert evidence["rule_index"] == index, evidence

    base = evidence["ranges"][0]["start"] - (
        evidence["ranges"][0]["start"] % 0x100000
    )
    callers = {item["name"] for item in evidence["ranges"]}
    assert callers == {
        "vulfi_fb_fmt_constant",
        "vulfi_fb_fmt_variable",
        "main",
    }, evidence["ranges"]
    for item in evidence["ranges"]:
        owner = symbols[item["name"]] + base
        assert owner <= item["start"] < item["end"], item

    constants = [
        context
        for context in evidence["contexts"]
        if context["params"][0].get("constant") is True
    ]
    variables = [
        context
        for context in evidence["contexts"]
        if context["params"][0].get("constant") is False
    ]
    assert len(constants) == 2 and len(variables) == 1, evidence["contexts"]
    assert any(
        context["params"][0].get("string") == "vulfi-fallback-constant-format\n"
        for context in constants
    ), evidence["contexts"]

    # The facts really feed the shared evaluator, which is the only thing that
    # turns them into a priority.
    verdicts = [
        evaluate_rule(printf_rule, context) for context in rule_contexts(evidence)
    ]
    assert sorted(str(one) for one in verdicts) == ["High", "None", "None"], verdicts

    # The same binary, a rule whose branch needs a fact nothing here states.
    copy_index, copy_rule = _stock("Buffer Overflow", "strcpy")
    gap = live(evidence_ghidra(str(compiled_fallback), copy_rule, copy_index))
    assert gap["state"] == "unsupported", gap
    assert gap["contexts"] == [], gap
    assert "calls_before" in (gap["reason"] or ""), gap["reason"]
    assert gap["ranges"], gap
    # It still says where it looked: both call sites, inside both callers.
    assert {item["name"] for item in gap["ranges"]} == {
        "vulfi_fb_copy_unguarded",
        "vulfi_fb_copy_guarded",
    }, gap["ranges"]


@pytest.mark.requires_ghidra
def test_a_changed_pcode_shape_cannot_produce_a_positive(
    compiled_fallback: Path,
    ghidra_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drifted schema and drifted payload both end as a refusal, not a fact."""
    from vulfi_mcp.providers import ghidra

    index, printf_rule = _stock("Format String", "printf")
    live(prepare_ghidra(str(compiled_fallback), ("functions",)))

    original = dict(ghidra.PINNED_SCHEMAS)
    drifted_pins = dict(original)
    drifted_pins["get_function_pcode"] = "0" * 64
    monkeypatch.setattr(ghidra, "PINNED_SCHEMAS", drifted_pins)
    drifted = live(evidence_ghidra(str(compiled_fallback), printf_rule, index))
    assert drifted["state"] == "failed", drifted
    assert drifted["contexts"] == [], drifted
    assert "get_function_pcode" in (drifted["reason"] or ""), drifted["reason"]

    monkeypatch.setattr(ghidra, "PINNED_SCHEMAS", original)
    real = ghidra._function_pcode

    async def renamed(session: Any, entry: int) -> Any:
        document = await real(session, entry)
        document["blocks"] = document.pop("basic_blocks")
        return document

    monkeypatch.setattr(ghidra, "_function_pcode", renamed)
    malformed = live(
        evidence_ghidra(str(compiled_fallback), printf_rule, index)
    )
    assert malformed["state"] == "failed", malformed
    assert malformed["contexts"] == [], malformed
    assert "basic_blocks" in (malformed["reason"] or ""), malformed["reason"]


@pytest.mark.requires_ghidra
def test_conflicting_write_not_applied(
    compiled_fallback: Path, ghidra_config: Path, managed_data_dir: Path
) -> None:
    """A pointer into the middle of a function never becomes a function.

    GhidraMCP's own ``create_function`` will happily split an existing
    function at that address — measured, not assumed — so the refusal has to
    be this adapter's, before the call. The candidate stays a candidate, the
    reviewed proposal is refused with the overlap named, no revision moves,
    and the function it would have split is the same size on the next session.
    """
    before = _digest(compiled_fallback)
    symbols = elf_symbols(compiled_fallback)

    results = live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    context = _report(results)
    base = _image_base(results)
    tail = base + symbols["vulfi_fb_tail"]
    owner = base + symbols["vulfi_fb_tail_owner"]

    blocked = _at(_candidates(results, "functions"), tail, context)
    assert blocked["state"] == "candidate", context
    assert blocked["candidate_id"] not in _pass(results, "functions")["applied_ids"]
    assert blocked["evidence"]["owner"]["entry"] == owner, context
    assert "vulfi_fb_tail_owner" in (blocked["reason"] or ""), blocked["reason"]
    owner_end = blocked["evidence"]["owner"]["end"]
    assert owner_end > tail, context

    revision = int(_pass(results, "functions")["artifact_revision"] or 0)
    proposal = {
        "candidate_id": blocked["candidate_id"],
        "kind": "function_boundary",
        "address_space": blocked["address_space"],
        "address": tail,
        "value": {"end": owner_end},
        "evidence": {"referenced_from": blocked["evidence"]["referenced_from"]},
        "rationale": "the relocated pointer names this address",
    }
    refused = live(
        apply_ghidra_review(str(compiled_fallback), proposal, revision)
    )
    assert refused["applied"] is False, refused
    assert refused["mutated"] is False, refused
    assert refused["revision"] == revision, refused
    assert "vulfi_fb_tail_owner" in (refused["reason"] or ""), refused["reason"]

    # Nothing split it: the next session reads the same owner back.
    again = live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    still = _at(_candidates(again, "functions"), tail, _report(again))
    assert still["evidence"]["owner"] == blocked["evidence"]["owner"], _report(again)

    assert _digest(compiled_fallback) == before, "the operator's binary was written to"


@pytest.mark.requires_ghidra
def test_every_block_a_pass_did_not_read_is_named(
    compiled_fallback: Path, ghidra_config: Path, managed_data_dir: Path
) -> None:
    """A pass never summarises itself over ranges nobody put in the result.

    The ``strings`` pass skips a block that holds code. Leaving that block out
    of ``ranges`` let ``coverage`` come back ``complete`` over an image half
    of which was never read, which is the one claim this project's coverage
    vocabulary exists to prevent.
    """
    results = live(prepare_ghidra(str(compiled_fallback), ALL_PASSES))
    context = _report(results)
    entry = _pass(results, "strings")
    named = {item["name"] for item in entry["ranges"]}
    base = _image_base(results)

    # `.text` holds every function in this fixture, so the strings pass does
    # not read it — and has to say so.
    skipped = [item for item in entry["ranges"] if item["name"] == ".text"]
    assert len(skipped) == 1, context
    assert skipped[0]["coverage"] != "complete", context
    assert skipped[0]["unvisited"] == [
        {"start": skipped[0]["start"], "end": skipped[0]["end"]}
    ], context
    assert "code" in (skipped[0]["reason"] or ""), skipped[0]["reason"]
    assert entry["coverage"] != "complete", context

    # And nothing is quietly left out: every block the functions pass named is
    # also named by the strings pass, so neither summarises over a hole.
    assert {item["name"] for item in _pass(results, "functions")["ranges"]} <= named
    assert base > 0, context


@pytest.mark.requires_ghidra
def test_an_unmeasured_extent_is_never_written_over(
    compiled_fallback: Path,
    ghidra_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A function whose extent was not measured still owns its address range.

    With the extent budget at zero nothing is measured, so an address this
    adapter cannot prove is outside a function has to stay a candidate.
    Dropping unmeasured functions out of the map instead made the owner lookup
    answer ``None``, and ``create_function`` then split exactly the function
    this adapter exists to protect — an unmeasured extent is not evidence of
    absence.

    The address that is genuinely outside every span this pass could bound is
    still defined, so the guard is a refusal to guess, not a refusal to work.
    """
    from vulfi_mcp.providers import ghidra

    symbols = elf_symbols(compiled_fallback)
    monkeypatch.setattr(ghidra, "MAX_FUNCTION_EXTENTS", 0)
    results = live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    context = _report(results)
    entry = _pass(results, "functions")
    base = _image_base(results)

    assert entry["warnings"], context
    assert any(
        "measured the extent of 0" in text for text in entry["warnings"]
    ), context

    tail = base + symbols["vulfi_fb_tail"]
    owner = base + symbols["vulfi_fb_tail_owner"]
    blocked = _at(_candidates(results, "functions"), tail, context)
    assert blocked["state"] == "candidate", context
    assert blocked["candidate_id"] not in entry["applied_ids"], context
    assert blocked["evidence"]["owner"]["entry"] == owner, context
    assert blocked["evidence"]["owner"]["measured"] is False, context
    assert "could not measure" in (blocked["reason"] or ""), blocked["reason"]

    # Nothing this pass could not bound was written over, and no candidate was
    # applied inside a span it could not measure.
    for row in _candidates(results, "functions"):
        held = row["evidence"]["owner"]
        assert held is None or row["state"] == "candidate", context

    # And the reviewed path refuses the same address for the same reason.
    report = live(
        apply_ghidra_review(
            str(compiled_fallback),
            {
                "candidate_id": blocked["candidate_id"],
                "kind": "function_boundary",
                "address_space": blocked["address_space"],
                "address": tail,
                "value": {"end": blocked["evidence"]["owner"]["end"]},
                "evidence": {"slot": blocked["evidence"]["slot"]},
                "rationale": "a relocated pointer names this address",
            },
            int(entry["artifact_revision"] or 0),
        )
    )
    assert report["mutated"] is False, report
    assert report["applied"] is False, report
    assert "could not measure" in (report["reason"] or ""), report["reason"]


@pytest.mark.requires_ghidra
def test_an_approved_layout_is_written_once_and_never_twice(
    compiled_fallback: Path, ghidra_config: Path, managed_data_dir: Path
) -> None:
    """The structure writer: the approved offsets, the revision, and staleness.

    The successful-apply branch had no coverage at all, which is how the
    approved field offsets came to be dropped on the way to the provider.
    """
    results = live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    revision = int(_pass(results, "functions")["artifact_revision"] or 0)
    candidate = _candidates(results, "functions")[0]
    layout = {
        "candidate_id": candidate["candidate_id"],
        "kind": "structure_field",
        "address_space": candidate["address_space"],
        "address": candidate["address"],
        "value": {
            "type_name": "VulfiFbRecord",
            "fields": [
                {"offset": 0, "width": 4, "name": "dwCount"},
                {"offset": 4, "width": 4, "name": "dwLimit"},
                {"offset": 8, "width": 8, "name": "qwTotal"},
            ],
        },
        "evidence": {"slot": candidate["evidence"]["slot"]},
        "rationale": "the operator approved this layout after reading the bytes",
    }

    # A decision made against a revision the project has moved past applies
    # nothing at all.
    stale = live(
        apply_ghidra_review(str(compiled_fallback), layout, revision + 7)
    )
    assert stale["stale"] is True, stale
    assert stale["mutated"] is False and stale["applied"] is False, stale
    assert stale["revision"] == revision, stale

    applied = live(apply_ghidra_review(str(compiled_fallback), layout, revision))
    assert applied["mutated"] is True, applied
    assert applied["applied"] is True, applied
    assert applied["revision"] == revision + 1, applied
    assert applied["site"] == {"type_name": "VulfiFbRecord", "fields": 3}, applied

    # The same layout again is refused rather than replacing what is there,
    # and nothing moves.
    twice = live(
        apply_ghidra_review(str(compiled_fallback), layout, revision + 1)
    )
    assert twice["mutated"] is False and twice["applied"] is False, twice
    assert twice["revision"] == revision + 1, twice
    assert "already holds a type" in (twice["reason"] or ""), twice["reason"]


@pytest.mark.requires_ghidra
def test_a_reference_with_no_address_is_named_not_crashed_on(
    compiled_fallback: Path,
    ghidra_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A call-kind reference Ghidra spells as a name is evidence of nothing.

    Ghidra renders some reference sources as a label rather than an address.
    Feeding one to the containing-function lookup compared ``int > None`` and
    raised ``TypeError`` straight past every provider-error handler.
    """
    from vulfi_mcp.providers import ghidra

    live(prepare_ghidra(str(compiled_fallback), ("functions",)))
    index, printf_rule = _stock("Format String", "printf")
    real = ghidra._xrefs

    async def labelled(session: Any, address: int) -> Any:
        rows, capped = await real(session, address)
        return (
            [
                {
                    "address": None,
                    "source": "Entry Point",
                    "function": None,
                    "kind": "UNCONDITIONAL_CALL",
                },
                *rows,
            ],
            capped,
        )

    monkeypatch.setattr(ghidra, "_xrefs", labelled)
    evidence = live(evidence_ghidra(str(compiled_fallback), printf_rule, index))

    assert evidence["state"] in {"evaluated", "unsupported", "failed"}, evidence
    named = [
        item for item in evidence["ranges"] if "Entry Point" in (item["reason"] or "")
    ]
    assert named, evidence["ranges"]
    assert all(item["coverage"] == "unavailable" for item in named), named
    # The real call sites still came through beside it.
    assert len(evidence["contexts"]) == 3, evidence["contexts"]


def test_a_return_value_is_never_credited_to_the_wrong_call() -> None:
    """Two calls returning in one register state nothing about either.

    High P-code names a varnode by space, offset and size, and two calls that
    return in the same register share all three. Walking forward from the
    first call's output therefore reached the comparison that belongs to the
    second, and reported a call as checked that nothing checks.
    """
    from vulfi_mcp.providers import ghidra

    def node(space: str, offset: str, size: int) -> dict[str, Any]:
        return {"space": space, "offset": offset, "size": size}

    first = {
        "mnemonic": "CALL",
        "seq": {"address": "00101000"},
        "inputs": [node("ram", "101100", 8)],
        "output": node("register", "0", 8),
    }
    second = {
        "mnemonic": "CALL",
        "seq": {"address": "00101010"},
        "inputs": [node("ram", "101200", 8)],
        "output": node("register", "0", 8),
    }
    compare = {
        "mnemonic": "INT_NOTEQUAL",
        "seq": {"address": "00101018"},
        "inputs": [node("register", "0", 8), node("const", "ffffffff", 8)],
        "output": node("register", "206", 1),
    }
    operations = [first, second, compare]

    assert ghidra._return_checked(operations, first) is None
    assert ghidra._return_checked(operations, second) is None

    # One call in the same body still answers, so the guard is not a blanket
    # refusal to state the fact.
    alone = [second, compare]
    assert ghidra._return_checked(alone, second) == {
        "return_checked": True,
        "return_check_values": [0xFFFFFFFF],
    }
    # And a call with no result at all is still provably unchecked.
    assert ghidra._return_checked(
        operations, {"mnemonic": "CALL", "seq": {"address": "0"}, "inputs": []}
    ) == {"return_checked": False, "return_check_values": []}


def test_the_adapter_allowlist_is_a_constant_no_caller_can_widen() -> None:
    """The tool surface is the adapter's, and it holds no escape."""
    assert BACKEND == "ghidra"
    assert isinstance(ALLOWLIST, frozenset)
    assert "run_script_inline" not in ALLOWLIST
    assert not {
        name
        for name in ALLOWLIST
        if "script" in name or "command" in name or "eval" in name
    }
    assert set(json.loads(json.dumps(sorted(ALLOWLIST)))) == set(ALLOWLIST)
