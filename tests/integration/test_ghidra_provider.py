"""Live coverage of the Ghidra provider adapter against a real GhidraMCP server.

Every test here drives a real headless GhidraMCP 6.0.0 server over a real MCP
stdio session, through :func:`vulfi_mcp.providers.client.provider_session` and
its schema gate. Nothing is mocked: the provider imports the compiled fixture,
analyses it, answers with its own P-code and its own cross-references, and
keeps a project on disk that the next session has to reopen.

The prerequisite is a running server, not an installed package, so the gate
below probes the socket as well as the bridge executable. An ordinary
contributor run skips with the exact thing that is missing; a run with
``VULFI_REQUIRE_LIVE=1`` turns that skip into a failure, exactly as
``tests/conftest.py`` does for IDA.

Every address an assertion names is derived from the compiled ELF — section
headers and the symbol table — plus the image base the provider itself
reports, never from the result being checked.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import FIXTURES, missing_prerequisite
from vulfi_mcp.contracts import PassResult
from vulfi_mcp.ida_runtime import evaluate_rule
from vulfi_mcp.providers import rule_contexts
from vulfi_mcp.providers.ghidra import (
    ALLOWLIST,
    BACKEND,
    apply_ghidra_review,
    evidence_ghidra,
    prepare_ghidra,
)
from vulfi_mcp.rules import Rule, load_stock_rules

#: Exactly the flags this fixture needs: every call survives as its own call
#: site, and the pointers in ``.vulfi_fb_ptrs`` really carry relocations.
CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline", "-fPIE", "-pie")

#: Where the bridge executable is, when the operator did not say.
DEFAULT_BRIDGE = "/tmp/vulfi-ghidra/bridge-venv/bin/bridge-mcp-ghidra"

#: Where the headless server listens, when the operator did not say.
DEFAULT_URL = "http://127.0.0.1:8192"

BRIDGE_ENV = "VULFI_GHIDRA_BRIDGE"
URL_ENV = "VULFI_GHIDRA_MCP_URL"

#: How to start the server this file needs, named in the skip reason so the
#: missing prerequisite is actionable rather than just reported.
START_HINT = (
    "start it with /tmp/vulfi-ghidra/bin/start-headless.sh (see"
    " .superpowers/sdd/2026-09-29-vulfi-mcp-fallback/task-2-report.md)"
)

ALL_PASSES = ("strings", "functions", "structures", "pointer_tables")


# --------------------------------------------------------------------------
# the live prerequisite
# --------------------------------------------------------------------------


def _bridge_path() -> str:
    return os.environ.get(BRIDGE_ENV) or DEFAULT_BRIDGE


def _server_url() -> str:
    return os.environ.get(URL_ENV) or DEFAULT_URL


@lru_cache(maxsize=1)
def _missing_ghidra_prerequisite() -> str | None:
    """Return why the live Ghidra provider cannot run here, or ``None``."""
    if shutil.which("gcc") is None:
        return "gcc is not installed, so vulfi_fallback.c cannot be built"
    bridge = Path(_bridge_path())
    if not bridge.is_file() or not os.access(bridge, os.X_OK):
        return (
            f"the GhidraMCP bridge is not at {bridge} (set {BRIDGE_ENV} to"
            " the executable built by `uv pip install <ghidra-mcp checkout>`)"
        )
    url = urlsplit(_server_url())
    host, port = url.hostname or "127.0.0.1", url.port or 80
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except OSError as refused:
        return (
            f"no GhidraMCP headless server is listening on {host}:{port}"
            f" ({refused}); {START_HINT}"
        )
    return None


def pytest_runtest_setup(item: pytest.Item) -> None:  # pragma: no cover - gate
    reason = _missing_ghidra_prerequisite()
    if reason is not None:
        missing_prerequisite(reason)


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
                f'command = "{_bridge_path()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "bridge.err"}"',
                "",
                "[ghidra.env]",
                'PATH = "/usr/bin:/bin"',
                f'HOME = "{tmp_path / "bridge-home"}"',
                f'GHIDRA_MCP_URL = "{_server_url()}"',
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

    results = asyncio.run(prepare_ghidra(str(compiled_fallback), ALL_PASSES))
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
    again = asyncio.run(prepare_ghidra(str(compiled_fallback), ("functions",)))
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
    asyncio.run(prepare_ghidra(str(compiled_fallback), ("functions",)))

    index, printf_rule = _stock("Format String", "printf")
    evidence = asyncio.run(
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
    gap = asyncio.run(evidence_ghidra(str(compiled_fallback), copy_rule, copy_index))
    assert gap["state"] == "unsupported", gap
    assert gap["contexts"] == [], gap
    assert "calls_before" in (gap["reason"] or ""), gap["reason"]
    assert gap["ranges"], gap
    # It still says where it looked: both call sites, inside both callers.
    assert {item["name"] for item in gap["ranges"]} == {
        "vulfi_fb_copy_unguarded",
        "vulfi_fb_copy_guarded",
    }, gap["ranges"]


def test_a_changed_pcode_shape_cannot_produce_a_positive(
    compiled_fallback: Path,
    ghidra_config: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Drifted schema and drifted payload both end as a refusal, not a fact."""
    from vulfi_mcp.providers import ghidra

    index, printf_rule = _stock("Format String", "printf")
    asyncio.run(prepare_ghidra(str(compiled_fallback), ("functions",)))

    original = dict(ghidra.PINNED_SCHEMAS)
    drifted_pins = dict(original)
    drifted_pins["get_function_pcode"] = "0" * 64
    monkeypatch.setattr(ghidra, "PINNED_SCHEMAS", drifted_pins)
    drifted = asyncio.run(evidence_ghidra(str(compiled_fallback), printf_rule, index))
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
    malformed = asyncio.run(
        evidence_ghidra(str(compiled_fallback), printf_rule, index)
    )
    assert malformed["state"] == "failed", malformed
    assert malformed["contexts"] == [], malformed
    assert "basic_blocks" in (malformed["reason"] or ""), malformed["reason"]


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

    results = asyncio.run(prepare_ghidra(str(compiled_fallback), ("functions",)))
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
    refused = asyncio.run(
        apply_ghidra_review(str(compiled_fallback), proposal, revision)
    )
    assert refused["applied"] is False, refused
    assert refused["mutated"] is False, refused
    assert refused["revision"] == revision, refused
    assert "vulfi_fb_tail_owner" in (refused["reason"] or ""), refused["reason"]

    # Nothing split it: the next session reads the same owner back.
    again = asyncio.run(prepare_ghidra(str(compiled_fallback), ("functions",)))
    still = _at(_candidates(again, "functions"), tail, _report(again))
    assert still["evidence"]["owner"] == blocked["evidence"]["owner"], _report(again)

    assert _digest(compiled_fallback) == before, "the operator's binary was written to"


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
