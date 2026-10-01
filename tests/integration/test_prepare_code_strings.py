"""Live IDA coverage of the ``functions`` and ``strings`` preparation passes.

Every assertion here is made against a real compiled ELF and a real managed
IDA database. The fixture is built so that IDA's own auto-analysis leaves
exactly the shapes under test behind: two unreferenced functions in an
executable section, three undefined strings in a data section, a relocated
pointer into the middle of an existing function, and a buffer that exists
only in the immediate operands that build it. The baseline those shapes
produce is asserted, not assumed, so a future IDA that recovers them on its
own fails this file loudly instead of passing it vacuously.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest
from conftest import FIXTURES, missing_prerequisite
from vulfi_mcp.ida_adapter import ensure_managed_idb, invoke_ida
from vulfi_mcp.prepare import PASSES, PreparationError, run_ida_passes

#: `tests/conftest.py`'s `durable_or_reported` fixture: hold a body to "the
#: state is intact, or the loss was reported", because IDA 9.4.260714 cannot
#: promise that every pack reopens. Register each managed database with the
#: list it yields.
Tolerance = Callable[[], AbstractContextManager[list[str]]]

SUMMARY = "database_summary"

#: Exactly the flags the plan pins for this fixture.
CC_FLAGS = ("-O0", "-fno-inline", "-fPIE", "-pie")

#: The three encodings the blob section carries, and the offset of each one
#: from the start of that section. The fixture pins them with `.balign 16`.
BLOB_LAYOUT = {
    "ascii": (0x10, "vulfi-plain-ascii-marker", b"vulfi-plain-ascii-marker\x00"),
    "utf-16le": (0x30, "vulfi-utf16le", "vulfi-utf16le\x00".encode("utf-16-le")),
    "utf-16be": (0x50, "vulfi-utf16be", "vulfi-utf16be\x00".encode("utf-16-be")),
}

#: The buffer `vulfi_stack_string` assembles out of immediate operands.
STACK_TEXT = "vulfi-stack-string!!"


@pytest.fixture
def compiled_preparation(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_preparation.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite(
            "gcc is not installed, so vulfi_preparation.c cannot be built"
        )
    binary = tmp_path / "vulfi_preparation"
    command = [
        str(compiler),
        *CC_FLAGS,
        "-o",
        str(binary),
        str(FIXTURES / "vulfi_preparation.c"),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_preparation.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_sections(binary: Path) -> dict[str, tuple[int, int]]:
    """Section name to ``(virtual address, size)``, read out of the ELF itself.

    The point of reading the file is that the addresses the preparation result
    reports are then checked against the image rather than against themselves.
    """
    raw = binary.read_bytes()
    assert raw[:4] == b"\x7fELF" and raw[4] == 2, "the fixture must be a 64-bit ELF"
    little = raw[5] == 1
    order = "<" if little else ">"
    (shoff,) = struct.unpack_from(f"{order}Q", raw, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", raw, 0x3A)
    names_header = shoff + shstrndx * shentsize
    strtab_off = struct.unpack_from(f"{order}Q", raw, names_header + 0x18)[0]
    sections: dict[str, tuple[int, int]] = {}
    for index in range(shnum):
        base = shoff + index * shentsize
        name_off = struct.unpack_from(f"{order}I", raw, base)[0]
        addr, _, size = struct.unpack_from(f"{order}QQQ", raw, base + 0x10)
        end = raw.index(b"\x00", strtab_off + name_off)
        sections[raw[strtab_off + name_off : end].decode()] = (addr, size)
    return sections


def _by_kind(result: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [row for row in result["candidates"] if row["kind"] == kind]


def _pass(result: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [row for row in result["passes"] if row["pass"] == name]
    assert matches, f"no {name!r} pass in {[row['pass'] for row in result['passes']]}"
    return matches[0]


def _at(rows: list[dict[str, Any]], address: int) -> dict[str, Any]:
    matches = [row for row in rows if row["address"] == address]
    assert len(matches) == 1, f"expected one row at {address:#x}, got {matches}"
    return matches[0]


# --------------------------------------------------------------------------
# Host-side refusals: no database is opened, so these need no licensed IDA.
# --------------------------------------------------------------------------


def test_an_unknown_pass_is_refused_by_name(tmp_path: Path) -> None:
    with pytest.raises(PreparationError) as refused:
        run_ida_passes(str(tmp_path / "nothing.i64"), ("functions", "decrypt"))
    assert "decrypt" in str(refused.value)
    assert "functions" in str(refused.value)
    assert not (tmp_path / "nothing.i64").exists()


def test_a_pass_this_build_does_not_implement_is_not_silently_dropped(
    tmp_path: Path,
) -> None:
    # `structures` is a real pass in the design and arrives with Plan 2's
    # Task 3. Accepting it now and running `functions` instead would report a
    # coverage this build never produced.
    with pytest.raises(PreparationError) as refused:
        run_ida_passes(str(tmp_path / "nothing.i64"), ("structures",))
    assert "structures" in str(refused.value)


def test_an_empty_pass_list_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PreparationError):
        run_ida_passes(str(tmp_path / "nothing.i64"), ())


def test_an_unknown_limit_is_refused(tmp_path: Path) -> None:
    with pytest.raises(PreparationError) as refused:
        run_ida_passes(str(tmp_path / "nothing.i64"), PASSES, {"forever": 1})
    assert "forever" in str(refused.value)


# --------------------------------------------------------------------------
# Live preparation.
# --------------------------------------------------------------------------


@pytest.mark.requires_ida
def test_recover_unmarked_function_and_strings(
    compiled_preparation: Path,
    managed_data_dir: Path,
    tmp_path: Path,
    durable_or_reported: Tolerance,
) -> None:
    # Preparation saves the managed database and the summary after it opens
    # what that save wrote; see `durable_or_reported`.
    with durable_or_reported() as produced:
        _assert_preparation_recovers_the_fixture(
            compiled_preparation, tmp_path, produced
        )


def _assert_preparation_recovers_the_fixture(
    binary: Path, tmp_path: Path, produced: list[str]
) -> None:
    sections = elf_sections(binary)
    source_digest = _digest(binary)

    # The "original IDB" of the design: a database the operator supplies and
    # this server may never write to. Preparation runs on the managed copy.
    analyzed = Path(ensure_managed_idb(str(binary)))
    produced.append(str(analyzed))
    supplied = tmp_path / "operator-supplied.i64"
    shutil.copy2(analyzed, supplied)
    supplied_digest = _digest(supplied)

    managed = ensure_managed_idb(str(supplied))
    produced.append(managed)
    assert Path(managed) != supplied

    before = invoke_ida(managed, SUMMARY, {"name_limit": 400})
    assert "vulfi_hidden_add" not in before["function_names"], (
        "the fixture's hidden function must be undefined at baseline;"
        " this IDA found it on its own, so the test below proves nothing"
    )

    result = run_ida_passes(managed, ("functions", "strings"))
    after = invoke_ida(managed, SUMMARY, {"name_limit": 400})

    # Nothing outside the managed workspace moved.
    assert _digest(binary) == source_digest
    assert _digest(supplied) == supplied_digest

    base = result["image_base"]
    hidden_start = base + sections[".vulfi_hidden"][0]
    blob_start = base + sections[".vulfi_blob"][0]

    # -- the function the fixture hid ------------------------------------
    functions = _by_kind(result, "function")
    recovered = _at(functions, hidden_start)
    assert recovered["state"] == "applied"
    assert recovered["backend"] == "ida"
    assert recovered["address_space"] == "image"
    evidence = recovered["evidence"]
    assert evidence["end"] == hidden_start + 10
    assert evidence["entry_evidence"]["kind"] == "symbol"
    assert evidence["entry_evidence"]["symbol"] == "vulfi_hidden_add"
    assert evidence["overlaps"] is None
    assert evidence["segment"] == ".vulfi_hidden"
    decoded = evidence["instructions"]
    assert [item["address"] for item in decoded] == [
        hidden_start,
        hidden_start + 4,
        hidden_start + 6,
        hidden_start + 9,
    ]
    assert decoded[0]["mnemonic"] == "endbr64"
    assert decoded[-1]["mnemonic"].startswith("ret")
    assert sum(item["size"] for item in decoded) == 10
    assert recovered["candidate_id"] in _pass(result, "functions")["applied_ids"]
    assert "vulfi_hidden_add" in after["function_names"]
    assert after["function_count"] == before["function_count"] + 1

    # The second blob carries no symbol and no reference, so nothing says it
    # is an entry point. It is described, and it is not defined.
    unnamed = _at(functions, hidden_start + 0x10)
    assert unnamed["state"] == "candidate"
    assert unnamed["reason"]
    assert unnamed["evidence"]["entry_evidence"]["kind"] == "aligned_gap"
    assert unnamed["candidate_id"] not in _pass(result, "functions")["applied_ids"]

    # -- the strings the fixture hid -------------------------------------
    strings = _by_kind(result, "string")
    for encoding, (offset, text, raw) in BLOB_LAYOUT.items():
        row = _at(
            [item for item in strings if item["evidence"]["encoding"] == encoding],
            blob_start + offset,
        )
        assert row["evidence"]["text"] == text
        assert bytes.fromhex(row["evidence"]["bytes_hex"]) == raw
        assert row["evidence"]["end"] == blob_start + offset + len(raw)
        assert row["evidence"]["segment"] == ".vulfi_blob"
        assert row["evidence"]["stage"] == "raw_bytes"

    strings_pass = _pass(result, "strings")
    applied = set(strings_pass["applied_ids"])
    ascii_row = _at(strings, blob_start + BLOB_LAYOUT["ascii"][0])
    le_row = _at(strings, blob_start + BLOB_LAYOUT["utf-16le"][0])
    be_row = _at(strings, blob_start + BLOB_LAYOUT["utf-16be"][0])
    assert ascii_row["candidate_id"] in applied
    assert le_row["candidate_id"] in applied
    # IDA 9.4 registers no big-endian UTF-16 string type, so these bytes are
    # described exactly and are not defined.
    assert be_row["candidate_id"] not in applied
    assert be_row["state"] == "candidate"
    assert "UTF-16" in (be_row["reason"] or "")

    # -- the string that exists only in instructions ----------------------
    stack = [row for row in strings if row["evidence"]["stage"] == "instructions"]
    assert len(stack) == 1, stack
    built = stack[0]
    assert built["evidence"]["text"] == STACK_TEXT
    quoted = bytes.fromhex(built["evidence"]["bytes_hex"])
    assert quoted == STACK_TEXT.encode() + b"\x00"
    assert built["evidence"]["function_name"] == "vulfi_stack_string"
    writes = built["evidence"]["writes"]
    # 21 bytes cannot leave x86-64 in fewer than three stores of eight.
    assert len(writes) >= 3
    function_start = built["evidence"]["function"]
    for write in writes:
        assert function_start <= write["address"] < built["evidence"]["function_end"]
        assert write["mnemonic"] == "mov"
        # The quoted disassembly is of the instruction the write names, and
        # the value it cites is as wide as the store it cites.
        assert write["text"].split()[0].startswith(write["mnemonic"])
        assert len(bytes.fromhex(write["value"])) == write["size"]
    # Every recovered byte came from one of the cited writes.
    assembled = bytearray()
    for write in sorted(writes, key=lambda item: item["frame_offset"]):
        assembled += bytes.fromhex(write["value"])
    assert assembled.startswith(STACK_TEXT.encode() + b"\x00")

    # -- the run as a whole ----------------------------------------------
    assert result["backend"] == "ida"
    assert [row["pass"] for row in result["passes"]] == ["functions", "strings"]
    assert result["skipped_prerequisites"] == []
    assert result["artifact_revision"] >= 1
    for one in result["passes"]:
        assert one["coverage"] == "complete", one["ranges"]
        assert set(one["applied_ids"]) <= set(one["candidate_ids"])


@pytest.mark.requires_ida
def test_overlap_stays_candidate(
    compiled_preparation: Path, managed_data_dir: Path, durable_or_reported: Tolerance
) -> None:
    with durable_or_reported() as produced:
        _assert_an_overlapping_target_is_not_defined(compiled_preparation, produced)


def _assert_an_overlapping_target_is_not_defined(
    binary: Path, produced: list[str]
) -> None:
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)
    before = invoke_ida(managed, SUMMARY, {"name_limit": 400})
    assert "vulfi_overlap_tail" not in before["function_names"]

    result = run_ida_passes(managed, ("functions",))
    after = invoke_ida(managed, SUMMARY, {"name_limit": 400})

    # `vulfi_pointer_table[1]` points into the middle of `vulfi_tail_owner`.
    # That is a call target overlapping an existing function, and splitting
    # the owner to claim one more function is exactly what must not happen.
    overlapping = [
        row
        for row in _by_kind(result, "function")
        if row["evidence"]["overlaps"] is not None
    ]
    assert len(overlapping) == 1, overlapping
    tail = overlapping[0]
    assert tail["state"] == "candidate"
    assert tail["reason"]
    owner = tail["evidence"]["overlaps"]
    assert owner["name"] == "vulfi_tail_owner"
    assert owner["start"] < tail["address"] < owner["end"]
    assert tail["evidence"]["entry_evidence"]["kind"] == "data_pointer"
    assert tail["candidate_id"] not in _pass(result, "functions")["applied_ids"]

    # The owner kept its boundaries: a split would have created a function at
    # the named tail address, and IDA names a function after the symbol there.
    assert "vulfi_overlap_tail" not in after["function_names"]
    assert "vulfi_tail_owner" in after["function_names"]
    assert after["function_count"] == before["function_count"] + 1


@pytest.mark.requires_ida
def test_budget_and_cancel_are_partial(
    compiled_preparation: Path, managed_data_dir: Path, durable_or_reported: Tolerance
) -> None:
    with durable_or_reported() as produced:
        _assert_a_bounded_pass_names_what_it_missed(compiled_preparation, produced)


def _assert_a_bounded_pass_names_what_it_missed(
    binary: Path, produced: list[str]
) -> None:
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)
    # A byte budget far below the mapped image.
    bounded = run_ida_passes(managed, ("strings",), {"bytes": 64})
    strings = _pass(bounded, "strings")
    assert strings["coverage"] == "partial"
    cut = [row for row in strings["ranges"] if row["unvisited"]]
    assert cut, strings["ranges"]
    for row in cut:
        for gap in row["unvisited"]:
            assert row["start"] <= gap["start"] < gap["end"] <= row["end"]
    # The cut is where the budget ran out, not a blanket "nothing was read":
    # the range it stopped inside names the bytes after the ones it read.
    assert any(row["unvisited"][0]["start"] > row["start"] for row in cut)
    assert any("bytes" in warning for warning in strings["warnings"])
    assert bounded["bounded"] is True

    # A candidate budget: the pass reports the ceiling it hit rather than
    # returning a short list that looks like the whole answer.
    few = run_ida_passes(managed, ("strings",), {"candidates": 1})
    short = _pass(few, "strings")
    assert short["coverage"] == "partial"
    assert len(short["candidate_ids"]) == 1
    assert any("candidates" in warning for warning in short["warnings"])
    assert [row for row in short["ranges"] if row["unvisited"]]


@pytest.mark.requires_ida
def test_a_requested_subset_says_which_prerequisite_it_skipped(
    compiled_preparation: Path, managed_data_dir: Path, durable_or_reported: Tolerance
) -> None:
    with durable_or_reported() as produced:
        _assert_a_subset_names_its_skipped_stage(compiled_preparation, produced)


def _assert_a_subset_names_its_skipped_stage(
    binary: Path, produced: list[str]
) -> None:
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)
    result = run_ida_passes(managed, ("strings",))

    # Raw mapped-byte discovery does not need the function pass, so it ran.
    strings = [row for row in result["candidates"] if row["kind"] == "string"]
    assert [row for row in strings if row["evidence"]["stage"] == "raw_bytes"]
    # Instruction-derived discovery does, and it says so instead of reporting
    # a complete strings pass that never looked at an instruction.
    assert [row for row in strings if row["evidence"]["stage"] == "instructions"] == []
    skipped = result["skipped_prerequisites"]
    assert len(skipped) == 1, skipped
    assert skipped[0]["pass"] == "strings"
    assert skipped[0]["stage"] == "instructions"
    assert skipped[0]["requires"] == "functions"
    assert _pass(result, "strings")["coverage"] == "partial"
    assert any(
        "functions" in warning for warning in _pass(result, "strings")["warnings"]
    )


@pytest.mark.requires_ida
def test_a_branch_target_inside_unrecognized_code_is_not_defined(
    compiled_preparation: Path, managed_data_dir: Path, durable_or_reported: Tolerance
) -> None:
    with durable_or_reported() as produced:
        _assert_an_intra_gap_branch_target_stays_a_candidate(
            compiled_preparation, produced
        )


def _assert_an_intra_gap_branch_target_stays_a_candidate(
    binary: Path, produced: list[str]
) -> None:
    # The fixture's third hidden stretch branches out of itself to an address
    # that is not a function entry, so its own decode refuses; the block its
    # conditional branch targets then decodes cleanly to a return. The only
    # thing reaching that block is a jump from inside the same unrecognized
    # stretch. Defining a function there would split whatever contains it,
    # which is the ordinary-control-flow case the in-function sweep already
    # discounts, so the gap sweep must discount it too.
    sections = elf_sections(binary)
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)
    before = invoke_ida(managed, SUMMARY, {"name_limit": 400})

    result = run_ida_passes(managed, ("functions",))
    after = invoke_ida(managed, SUMMARY, {"name_limit": 400})

    hidden_start = result["image_base"] + sections[".vulfi_hidden"][0]
    hidden_end = hidden_start + sections[".vulfi_hidden"][1]
    reached = [
        row
        for row in _by_kind(result, "function")
        if row["evidence"]["entry_evidence"]["kind"] == "unowned_jump"
    ]
    assert len(reached) == 1, reached
    block = reached[0]
    assert hidden_start < block["address"] < hidden_end
    # The decode succeeded, so the only thing keeping this a candidate is the
    # evidence rule — which is what makes this test fail without it.
    assert block["evidence"]["terminator"] == "return"
    assert block["evidence"]["end"] is not None
    assert block["state"] == "candidate"
    assert block["evidence"]["defined_end"] is None
    assert block["candidate_id"] not in _pass(result, "functions")["applied_ids"]
    sources = block["evidence"]["entry_evidence"]["from"]
    assert sources and all(hidden_start <= source < hidden_end for source in sources)
    assert f"{sources[0]:#x}" in block["reason"]

    # Only `vulfi_hidden_add` was defined.
    assert after["function_count"] == before["function_count"] + 1
