"""Live IDA coverage of the ``structures`` and ``pointer_tables`` passes.

The fixture carries three pointer-shaped ranges that differ only in what
backs them, so a pass that guesses instead of reading evidence cannot pass
this file. ``.vulfi_fnptrs`` has a relocation behind every slot;
``.vulfi_ints`` has none and still points at four real function entries;
``.vulfi_ptrs`` has relocations and one target that is not an entry. The same
idea runs through the structure objects: one layout every access agrees on,
one the accesses contradict, and one that is a stride rather than a set of
distinct fields.

Every address an assertion names is read out of the ELF itself — section
headers, the symbol table, and the ``R_X86_64_RELATIVE`` entries of
``.rela.dyn`` — never out of the result being checked.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
from pathlib import Path
from typing import Any

import pytest
from test_prepare_code_strings import (
    SUMMARY,
    Tolerance,
    _at,
    _by_kind,
    _pass,
    _report,
    compiled_preparation,  # noqa: F401 - the fixture this module runs on
    elf_sections,
)
from vulfi_mcp.ida_adapter import ensure_managed_idb, invoke_ida
from vulfi_mcp.prepare import run_ida_passes

#: ``R_X86_64_RELATIVE``: "store the load address plus this addend here". It
#: is the only relocation the fixture's tables use, and the only one a
#: position-independent executable needs for a pointer into its own image.
R_X86_64_RELATIVE = 8

#: The fixture's structure objects, as the C declares them: the offset and
#: the width of every field, in declaration order.
CONSISTENT_FIELDS = ((0, 4), (4, 4), (8, 8))
STRIDE_FIELDS = ((0, 8), (8, 8), (16, 8), (24, 8))

#: The functions whose instructions are the only evidence those objects have.
ACCESSORS = (
    "vulfi_record_read",
    "vulfi_record_total",
    "vulfi_record_write",
    "vulfi_conflicting_narrow",
    "vulfi_conflicting_wide",
    "vulfi_stride_sum",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


#: Section name to ``(virtual address, file offset, size)``.
Headers = dict[str, tuple[int, int, int]]


def _section_headers(binary: Path) -> tuple[bytes, str, Headers]:
    """Every section header, by name: ``(address, file offset, size)``."""
    raw = binary.read_bytes()
    assert raw[:4] == b"\x7fELF" and raw[4] == 2, "the fixture must be a 64-bit ELF"
    order = "<" if raw[5] == 1 else ">"
    (shoff,) = struct.unpack_from(f"{order}Q", raw, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from(f"{order}HHH", raw, 0x3A)
    (strtab_off,) = struct.unpack_from(
        f"{order}Q", raw, shoff + shstrndx * shentsize + 0x18
    )
    headers: dict[str, tuple[int, int, int]] = {}
    for index in range(shnum):
        base = shoff + index * shentsize
        (name_off,) = struct.unpack_from(f"{order}I", raw, base)
        addr, offset, size = struct.unpack_from(f"{order}QQQ", raw, base + 0x10)
        end = raw.index(b"\x00", strtab_off + name_off)
        headers[raw[strtab_off + name_off : end].decode()] = (addr, offset, size)
    return raw, order, headers


def elf_symbols(binary: Path) -> dict[str, tuple[int, int]]:
    """Symbol name to ``(value, size)``, read out of the ELF's symbol table."""
    raw, order, headers = _section_headers(binary)
    _, offset, size = headers[".symtab"]
    strings = headers[".strtab"][1]
    symbols: dict[str, tuple[int, int]] = {}
    for base in range(offset, offset + size, 24):
        (name_off,) = struct.unpack_from(f"{order}I", raw, base)
        value, length = struct.unpack_from(f"{order}QQ", raw, base + 8)
        end = raw.index(b"\x00", strings + name_off)
        label = raw[strings + name_off : end].decode()
        if label:
            symbols[label] = (value, length)
    return symbols


def elf_relative_relocations(binary: Path) -> dict[int, int]:
    """Virtual address to addend, for every ``R_X86_64_RELATIVE`` in the image."""
    raw, order, headers = _section_headers(binary)
    found: dict[int, int] = {}
    for name, (_, offset, size) in headers.items():
        if not name.startswith(".rela"):
            continue
        for base in range(offset, offset + size, 24):
            where, info, addend = struct.unpack_from(f"{order}QQq", raw, base)
            if info & 0xFFFFFFFF == R_X86_64_RELATIVE:
                found[where] = addend
    return found


def section_bytes(binary: Path, section: str) -> bytes:
    raw, _, headers = _section_headers(binary)
    _, offset, size = headers[section]
    return raw[offset : offset + size]


def _fields(candidate: dict[str, Any]) -> tuple[tuple[int, int], ...]:
    return tuple(
        (field["offset"], field["size"]) for field in candidate["evidence"]["fields"]
    )


def _range(result: dict[str, Any], name: str, segment: str) -> dict[str, Any]:
    matches = [row for row in _pass(result, name)["ranges"] if row["name"] == segment]
    assert len(matches) == 1, f"expected one {segment} range, got {matches}"
    return matches[0]


# --------------------------------------------------------------------------
# Structure fields.
# --------------------------------------------------------------------------


@pytest.mark.requires_ida
def test_consistent_offsets_produce_fields(
    compiled_preparation: Path,  # noqa: F811 - the imported fixture
    managed_data_dir: Path,
    tmp_path: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced:
        _assert_only_a_proven_layout_is_defined(
            compiled_preparation, tmp_path, produced
        )


def _assert_only_a_proven_layout_is_defined(
    binary: Path, tmp_path: Path, produced: list[str]
) -> None:
    symbols = elf_symbols(binary)
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

    result = run_ida_passes(managed, ("structures",))
    assert _digest(binary) == source_digest
    assert _digest(supplied) == supplied_digest

    base = result["image_base"]
    consistent = base + symbols["vulfi_consistent_record"][0]
    conflicting = base + symbols["vulfi_conflicting_record"][0]
    stride = base + symbols["vulfi_stride_table"][0]
    structures = _by_kind(result, "structure")
    applied = set(_pass(result, "structures")["applied_ids"])
    accessors = [
        (base + symbols[name][0], base + symbols[name][0] + symbols[name][1])
        for name in ACCESSORS
    ]

    # The pass's own account of this run, before a single row is read out of
    # it. Every way this pass can return fewer objects than the fixture
    # contains is something it reports — an exhausted budget, an object too
    # big to walk, a range it never started — and asserting on rows alone
    # throws all of that away. `first` and `second` below are attached to the
    # row lookups so a missing object names its own cause.
    first = _report(result, "structures")
    assert _pass(result, "structures")["coverage"] == "complete", first
    assert result["bounded"] is False, first

    # -- the layout every access agrees on --------------------------------
    proven = _at(structures, consistent, first)
    assert proven["state"] == "applied"
    assert proven["backend"] == "ida"
    assert proven["address_space"] == "image"
    evidence = proven["evidence"]
    assert evidence["shape"] == "struct"
    assert evidence["object_size"] == symbols["vulfi_consistent_record"][1] == 16
    assert evidence["conflicts"] == []
    assert evidence["existing_type"] is None
    assert evidence["segment"] == ".bss"
    for field, (_, width) in zip(evidence["fields"], CONSISTENT_FIELDS, strict=True):
        assert field["reads"] + field["writes"] >= len(field["use_sites"]) >= 1
        for site in field["use_sites"]:
            # The instruction cited really is one of the fixture's accessors,
            # really touches this field at this width, and the disassembly
            # quoted is of the mnemonic the site names.
            assert any(start <= site["address"] < end for start, end in accessors), site
            assert site["size"] == width
            assert site["access"] in ("read", "write")
            assert site["text"].split()[0].startswith(site["mnemonic"])
    assert proven["candidate_id"] in applied

    # -- the same offset at two widths ------------------------------------
    contradicted = _at(structures, conflicting, first)
    assert contradicted["state"] == "candidate"
    assert contradicted["evidence"]["existing_type"] is None
    assert [entry["offset"] for entry in contradicted["evidence"]["conflicts"]] == [0]
    assert contradicted["evidence"]["conflicts"][0]["sizes"] == [4, 8]
    assert "4" in contradicted["reason"] and "8" in contradicted["reason"]
    assert contradicted["candidate_id"] not in applied

    # -- one width, repeated: a stride, not a set of distinct fields ------
    array = _at(structures, stride, first)
    assert array["state"] == "applied"
    assert array["evidence"]["shape"] == "array"
    assert array["evidence"]["stride"] == 8
    assert array["evidence"]["field_count"] == 4
    assert _fields(array) == STRIDE_FIELDS
    assert array["evidence"]["object_size"] == symbols["vulfi_stride_table"][1] == 32
    assert array["candidate_id"] in applied

    assert result["artifact_revision"] >= 1

    # -- what the managed database now holds, read back out of it ---------
    again = run_ida_passes(managed, ("structures",))
    second = _report(again, "structures")
    assert _pass(again, "structures")["coverage"] == "complete", second
    assert again["bounded"] is False, second
    assert again["applied_ids"] == [], second
    assert again["artifact_revision"] == result["artifact_revision"], second
    held = _at(_by_kind(again, "structure"), consistent, second)
    assert held["state"] == "candidate"
    existing = held["evidence"]["existing_type"]
    assert existing is not None, held
    assert existing["size"] == 16
    assert [
        (field["offset"], field["size"]) for field in existing["fields"]
    ] == list(CONSISTENT_FIELDS)
    assert existing["name"] in held["reason"]
    held_array = _at(_by_kind(again, "structure"), stride, second)
    assert held_array["state"] == "candidate"
    assert held_array["evidence"]["existing_type"]["size"] == 32
    # The object the accesses contradict was never given a type, so there is
    # still nothing there for a second run to preserve or to overwrite.
    held_conflict = _at(_by_kind(again, "structure"), conflicting, second)
    assert held_conflict["evidence"]["existing_type"] is None
    assert held_conflict["state"] == "candidate"
    assert _digest(binary) == source_digest
    assert _digest(supplied) == supplied_digest


# --------------------------------------------------------------------------
# Pointer tables.
# --------------------------------------------------------------------------


@pytest.mark.requires_ida
def test_relocation_table_not_random_integers(
    compiled_preparation: Path,  # noqa: F811 - the imported fixture
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced:
        _assert_only_relocated_ranges_are_defined(compiled_preparation, produced)


def _assert_only_relocated_ranges_are_defined(
    binary: Path, produced: list[str]
) -> None:
    sections = elf_sections(binary)
    relocations = elf_relative_relocations(binary)
    source_digest = _digest(binary)
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)
    before = invoke_ida(managed, SUMMARY, {"name_limit": 400})

    result = run_ida_passes(managed, ("pointer_tables",))
    assert _digest(binary) == source_digest

    base = result["image_base"]
    tables = _by_kind(result, "pointer_table")
    applied = set(_pass(result, "pointer_tables")["applied_ids"])

    # -- a relocation behind every slot -----------------------------------
    relocated = _at(tables, base + sections[".vulfi_fnptrs"][0])
    assert relocated["state"] == "applied"
    evidence = relocated["evidence"]
    assert evidence["classification"] == "function_pointer_table"
    assert evidence["pointer_width"] == 8
    assert evidence["endianness"] == "little"
    assert evidence["stride"] == 8
    assert evidence["entry_count"] == 3
    assert evidence["segment"] == ".vulfi_fnptrs"
    assert evidence["end"] == base + sections[".vulfi_fnptrs"][0] + 24
    for index, entry in enumerate(evidence["entries"]):
        where = sections[".vulfi_fnptrs"][0] + index * 8
        # The value the pass read is the one this ELF's own relocation puts
        # there, and it cites the relocation record at that very address.
        assert entry["address"] == base + where
        assert entry["value"] == base + relocations[where]
        assert entry["relocated"] is True
        assert entry["relocation"], entry
        assert entry["target_is_function_entry"] is True
        assert entry["target_executable"] is True
    assert relocated["candidate_id"] in applied

    # -- the same shape, with nothing behind it ---------------------------
    integers = _at(tables, base + sections[".vulfi_ints"][0])
    assert integers["state"] == "candidate"
    assert integers["candidate_id"] not in applied
    integer_evidence = integers["evidence"]
    assert integer_evidence["classification"] == "unrelocated_integers"
    assert integer_evidence["pointer_width"] == 8
    assert integer_evidence["stride"] == 8
    assert integer_evidence["entry_count"] == 4
    assert "relocation" in integers["reason"]
    stored = section_bytes(binary, ".vulfi_ints")
    assert sections[".vulfi_ints"][0] not in relocations
    for index, entry in enumerate(integer_evidence["entries"]):
        assert entry["relocated"] is False
        assert entry["relocation"] is None
        assert entry["target_segment"] is not None
        assert entry["target_executable"] is True
        assert entry["value"] == int.from_bytes(
            stored[index * 8 : index * 8 + 8], "little"
        )
    # At least one of those values is the entry of a real function, so the
    # run is not set apart by its targets being obviously wrong. (Only one
    # is asserted: the others are the linker's PLT stubs, whose addresses
    # are this toolchain's business and not this test's.)
    assert any(
        entry["target_is_function_entry"]
        for entry in integer_evidence["entries"]
    )
    # By every measure of shape this pass reports, the two ranges are the
    # same. The relocation record is the only thing that tells them apart,
    # which is what makes one applied and the other a candidate.
    for measure in ("pointer_width", "endianness", "stride"):
        assert integer_evidence[measure] == evidence[measure], measure
    for shaped in (integer_evidence, evidence):
        assert shaped["alignment"] % shaped["pointer_width"] == 0
    assert {entry["relocated"] for entry in evidence["entries"]} == {True}
    assert {entry["relocated"] for entry in integer_evidence["entries"]} == {False}

    # -- relocated, but one target is not an entry ------------------------
    ambiguous = _at(tables, base + sections[".vulfi_ptrs"][0])
    assert ambiguous["state"] == "candidate"
    assert ambiguous["candidate_id"] not in applied
    assert ambiguous["evidence"]["classification"] == "jump_table"
    assert all(entry["relocated"] for entry in ambiguous["evidence"]["entries"])
    inside = [
        entry
        for entry in ambiguous["evidence"]["entries"]
        if not entry["target_is_function_entry"]
    ]
    assert len(inside) == 1, ambiguous["evidence"]["entries"]
    assert f"{inside[0]['value']:#x}" in ambiguous["reason"]

    # -- nothing was applied without a relocation behind all of it --------
    for row in tables:
        if row["candidate_id"] in applied:
            assert row["state"] == "applied"
            assert all(entry["relocated"] for entry in row["evidence"]["entries"])
            assert row["evidence"]["classification"] in (
                "function_pointer_table",
                "data_pointer_array",
            )

    # This pass types data. It never splits, creates or renames a function.
    after = invoke_ida(managed, SUMMARY, {"name_limit": 400})
    assert after["function_count"] == before["function_count"]
    assert after["function_names"] == before["function_names"]


# --------------------------------------------------------------------------
# Alignment and truncation.
# --------------------------------------------------------------------------


@pytest.mark.requires_ida
def test_bad_alignment_and_truncated_range_are_partial(
    compiled_preparation: Path,  # noqa: F811 - the imported fixture
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced:
        _assert_a_ragged_range_is_named_not_skipped(compiled_preparation, produced)


def _assert_a_ragged_range_is_named_not_skipped(
    binary: Path, produced: list[str]
) -> None:
    sections = elf_sections(binary)
    symbols = elf_symbols(binary)
    managed = ensure_managed_idb(str(binary))
    produced.append(managed)

    result = run_ida_passes(managed, ("pointer_tables",))
    base = result["image_base"]
    start, size = sections[".vulfi_ragged"]
    ragged = _range(result, "pointer_tables", ".vulfi_ragged")

    # Seventeen bytes is two whole pointers and one byte that is not one.
    assert size == 17, size
    assert ragged["coverage"] == "partial"
    assert ragged["reason"]
    assert ragged["unvisited"] == [
        {"start": base + start + 16, "end": base + start + size}
    ]
    assert _pass(result, "pointer_tables")["coverage"] == "partial"

    # The relocated pointer four bytes into the grid is named, not skipped: a
    # relocation this pass cannot fold into an aligned table is still a
    # relocation, and dropping it would lose it with no address and no reason.
    misaligned = _at(
        _by_kind(result, "pointer_table"),
        base + symbols["vulfi_misaligned_pointer"][0],
    )
    assert misaligned["state"] == "candidate"
    assert misaligned["evidence"]["classification"] == "misaligned_pointer"
    assert misaligned["evidence"]["alignment"] == 4
    assert misaligned["evidence"]["entries"][0]["relocated"] is True
    assert "align" in misaligned["reason"]
    assert (
        misaligned["candidate_id"]
        not in _pass(result, "pointer_tables")["applied_ids"]
    )

    # The pass says out loud that it inventories candidates rather than
    # promising that every pointer in the image was enumerated.
    assert any(
        "inventory" in warning
        for warning in _pass(result, "pointer_tables")["warnings"]
    )

    # A budget that runs out names the addresses it never reached, exactly as
    # the passes Task 2 shipped do.
    few = run_ida_passes(managed, ("pointer_tables",), {"candidates": 1})
    short = _pass(few, "pointer_tables")
    assert short["coverage"] == "partial"
    assert len(short["candidate_ids"]) == 1
    assert any("candidates" in warning for warning in short["warnings"])
    cut = [row for row in short["ranges"] if row["unvisited"]]
    assert cut, short["ranges"]
    for row in cut:
        for gap in row["unvisited"]:
            assert row["start"] <= gap["start"] < gap["end"] <= row["end"]
    assert few["bounded"] is True
