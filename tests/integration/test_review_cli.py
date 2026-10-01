"""The operator review path, against real IDA and the real `vulfi-mcp review`.

The split this file exists to prove is the whole feature. An agent may store a
proposal through MCP and that changes *nothing*: not the managed database, not
its revision, not what a scan can see. Only the local `vulfi-mcp review`
command — a separate program, run with the operator's own credentials, which
prints the original bytes, the definitions already there, the proposed change
and its expected effect, and then waits for a typed confirmation — can approve
one, and only after revalidating the evidence against the database as it is
*now*.

The fixture below is five candidate-only ranges, one per thing a proposal may
ask for. "Candidate-only" is the point: preparation describes each of them and
deliberately defines none of them, so every definition this file observes
afterwards came from an approval and from nothing else.

  `.vulfi_review_code`   Two unreferenced stretches with no symbol. IDA
                         decodes the bytes and makes no function of either;
                         preparation cannot either, because nothing
                         establishes an entry point. The first calls `strcpy`,
                         so the scanner has a row to find once — and only
                         once — a function exists over it.
  `.vulfi_review_text`   Six printable bytes and a terminator, which is short
                         enough that preparation reports the run and refuses
                         to define a string over it.
  `vulfi_review_object`  A global touched at one offset only, so the accesses
                         cover part of it and its packing is not established.
  `.vulfi_review_ptrs`   Two relocated slots, one pointing at code and one at
                         data: a relocation-backed run whose targets do not
                         agree on what one element is.

A failure here is never tolerated by loosening an assertion. The one tolerated
outcome is `tests/conftest.py`'s `durable_or_reported`, which accepts IDA
9.4's own bad-pack defect *as a reported rollback* and nothing else.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import pytest
from conftest import missing_prerequisite, names_the_rollback
from vulfi_mcp.catalog import Catalog, get_catalog
from vulfi_mcp.ida_adapter import ManagedDatabaseError, ensure_managed_idb, scan_ida
from vulfi_mcp.operator import proposal_briefing, review_proposal
from vulfi_mcp.rules import validate_rules
from vulfi_mcp.server import vulfi_prepare, vulfi_propose_recovery, vulfi_scan

pytestmark = pytest.mark.requires_ida

#: `tests/conftest.py`'s tolerance for IDA 9.4's bad-pack defect.
Tolerance = Callable[[], AbstractContextManager[list[str]]]

CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline", "-fPIE", "-pie")

SCAN_NAME = "reviewflow"
SCOPE = f"custom:{SCAN_NAME}"

#: The marker the short run spells. Six printable characters: long enough for
#: preparation to report it, short enough that it refuses to define it.
MARKER = "VuLfI7"

#: The run in the same section that is long enough for preparation to define
#: it. A proposal to decode those bytes again has to be refused against it.
DEFINED_MARKER = "vulfi-review-defined-marker"

FIXTURE_SOURCE = """\
#include <string.h>

char vulfi_review_destination[64];

/* Two stretches of real code in an executable section, neither referenced by
 * anything and neither carrying a symbol. IDA decodes the bytes and creates
 * no function over either, and preparation may not either: nothing
 * establishes an entry point, so both stay candidates with that reason. The
 * first calls `strcpy`, so a scan has exactly one row to find here once a
 * function exists over it, and none before that. */
__asm__(
    ".section .vulfi_review_code,\\"ax\\",@progbits\\n"
    ".balign 16\\n"
    "  endbr64\\n"
    "  call strcpy@PLT\\n"
    "  ret\\n"
    ".balign 16\\n"
    "  endbr64\\n"
    "  mov %esi,%eax\\n"
    "  sub $0x17,%eax\\n"
    "  ret\\n"
    ".previous\\n");

/* Six printable bytes and a terminator, fenced by bytes that are text in no
 * encoding. Preparation reports the run with its exact addresses and refuses
 * to define a string literal over something this short. */
__asm__(
    ".section .vulfi_review_text,\\"a\\",@progbits\\n"
    ".balign 16\\n"
    "  .byte 0x8f,0x01,0xd3,0x02,0xa7,0x03,0xbe,0x04\\n"
    ".balign 16\\n"
    "  .ascii \\"VuLfI7\\"\\n"
    "  .byte 0x00\\n"
    "  .byte 0x8f,0x01,0xd3,0x02,0xa7,0x03,0xbe,0x04\\n"
    ".balign 16\\n"
    /* Long enough that preparation defines it, which is what a proposal to
     * decode it again has to be refused against. */
    "  .ascii \\"vulfi-review-defined-marker\\"\\n"
    "  .byte 0x00\\n"
    ".previous\\n");

/* A global object two of whose offsets are touched, with four bytes between
 * them that nothing reads or writes. The accesses prove two fields and do
 * not prove how the bytes between them are packed, so preparation describes
 * the object and defines nothing: what the whole layout is, is exactly the
 * kind of inference the design keeps as a proposal. */
struct vulfi_review_record {
    unsigned int  count;   /* +0, touched */
    unsigned int  unseen;  /* +4, deliberately never touched */
    unsigned long total;   /* +8, touched */
};

struct vulfi_review_record vulfi_review_object;
unsigned long vulfi_review_guard;

void vulfi_review_touch(unsigned int value)
{
    vulfi_review_object.count = value;
    vulfi_review_object.total = value + 1u;
}

/* Two relocated slots whose targets disagree about what one element is: the
 * first is a function entry, the second is data. */
__asm__(
    ".section .vulfi_review_ptrs,\\"aw\\",@progbits\\n"
    ".balign 8\\n"
    ".globl vulfi_review_table\\n"
    "vulfi_review_table:\\n"
    "  .quad vulfi_review_touch\\n"
    "  .quad vulfi_review_object\\n"
    ".previous\\n");

extern void *vulfi_review_table[2];

int main(int argc, char **argv)
{
    if (argc > 1)
        strcpy(vulfi_review_destination, argv[1]);
    vulfi_review_touch((unsigned int)argc);
    vulfi_review_guard = (unsigned long)vulfi_review_table[0];
    return (int)vulfi_review_object.count;
}
"""

#: A rule that matches every `strcpy` call site and decides on nothing else:
#: the question here is which call sites exist at all.
COPY_RULE: dict[str, Any] = {
    "name": "Any Copy",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {"High": "True", "Medium": "False", "Low": "False"},
}


@pytest.fixture
def compiled_review(tmp_path: Path) -> Path:
    """Compile the fixture above into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite(
            "gcc is not installed, so the review fixture cannot be built"
        )
    source = tmp_path / "vulfi_review.c"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    binary = tmp_path / "vulfi_review"
    completed = subprocess.run(
        [str(compiler), *CC_FLAGS, "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling the review fixture failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@contextmanager
def _rollback_survives_the_tool_wrapper() -> Iterator[None]:
    """Give the shared bad-pack tolerance back the error the server raised."""
    try:
        yield
    except Exception as wrapped:
        cause = wrapped.__cause__
        if not isinstance(cause, BaseException) or not names_the_rollback(cause):
            raise
        raise cause from wrapped


# -- the real command -------------------------------------------------------


def _review_command() -> str:
    """The installed `vulfi-mcp` console script, or a skip saying it is not."""
    found = shutil.which("vulfi-mcp") or str(
        Path(sys.executable).with_name("vulfi-mcp")
    )
    if not Path(found).is_file():
        missing_prerequisite(
            "the vulfi-mcp console script is not installed, so the operator"
            " review command cannot be exercised"
        )
    return found


def _review(*arguments: str, answer: str | None = None) -> subprocess.CompletedProcess:
    """Run `vulfi-mcp review ...` the way an operator would, in its own process."""
    return subprocess.run(
        [_review_command(), "review", *arguments],
        input="" if answer is None else f"{answer}\n",
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ},
    )


def _result(completed: subprocess.CompletedProcess) -> dict[str, Any]:
    """The JSON document a `--json` run writes, with its stderr on failure."""
    try:
        return json.loads(completed.stdout)
    except ValueError as broken:  # pragma: no cover - only on a CLI regression
        raise AssertionError(
            f"the review command wrote no JSON (exit {completed.returncode}):\n"
            f"stdout: {completed.stdout!r}\nstderr: {completed.stderr!r}"
        ) from broken


# -- reading what preparation recorded, without re-running it ---------------


def _all_candidates(target: str, analysis_id: str) -> list[dict[str, Any]]:
    """Every recorded candidate, read straight out of the catalog."""
    rows: list[dict[str, Any]] = []
    with get_catalog(target) as catalog:
        assert catalog is not None
        while True:
            page = catalog.page_candidates(analysis_id, len(rows), 200)
            rows.extend(page["candidates"])
            if len(rows) >= page["total"] or not page["loaded"]:
                return rows


#: Candidate facts these tests look a row up by that live in its evidence
#: rather than on the row itself.
_EVIDENCE_FACTS = frozenset({"segment", "text", "object_name", "classification"})


def _only(rows: list[dict[str, Any]], **facts: Any) -> dict[str, Any]:
    """Exactly one candidate matching ``facts``, or a failure showing why not."""
    matches = [
        row
        for row in rows
        if all(_fact(row, key) == value for key, value in facts.items())
    ]
    assert len(matches) == 1, (
        f"expected one candidate matching {facts}, got"
        f" {[(row['candidate_id'], row['state'], row['reason']) for row in matches]}"
    )
    return matches[0]


def _fact(row: dict[str, Any], key: str) -> Any:
    """One candidate fact, from the row itself or from its evidence."""
    return row["evidence"].get(key) if key in _EVIDENCE_FACTS else row.get(key)


def _candidate_ranges(target: str, analysis_id: str) -> dict[str, dict[str, Any]]:
    """The five candidate-only ranges the fixture is built out of."""
    rows = _all_candidates(target, analysis_id)
    code = sorted(
        (
            row
            for row in rows
            if row["kind"] == "function"
            and row["evidence"].get("segment") == ".vulfi_review_code"
        ),
        key=lambda row: row["address"],
    )
    assert len(code) == 2, [(row["address"], row["reason"]) for row in code]
    found = {
        "boundary": code[0],
        "name": code[1],
        "string": _only(rows, kind="string", text=MARKER),
        "structure": _only(rows, kind="structure", object_name="vulfi_review_object"),
        "table": _only(rows, kind="pointer_table", classification="mixed_targets"),
    }
    for label, row in found.items():
        # Every premise this file rests on, asserted rather than assumed: a
        # future IDA that recovers one of these unaided would otherwise make
        # the approval it is checked through vacuous.
        assert row["state"] == "candidate", (label, row["state"], row["reason"])
        assert row["reason"], label
        assert row["backend"] == "ida", label
    return found


def _tiling(size: int, known: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """A gapless, aligned layout of ``size`` bytes that keeps ``known``.

    The fields the accesses proved are kept exactly as they were proved, and
    only the bytes between them — the ones preparation refused to guess at —
    are filled in. That is what a proposal is: the evidence, plus the one
    inference a reviewer is being asked to sign.
    """
    held = dict(known)
    fields: list[dict[str, Any]] = []
    offset = 0
    while offset < size:
        width = held.get(offset) or next(
            step
            for step in (8, 4, 2, 1)
            if step <= size - offset
            and offset % step == 0
            and not any(offset < start < offset + step for start in held)
        )
        fields.append({"offset": offset, "width": width, "name": f"slot_{offset:x}"})
        offset += width
    return fields


# --------------------------------------------------------------------------
# A proposal changes nothing until an operator approves it.
# --------------------------------------------------------------------------


def test_proposal_is_inert_until_review(
    compiled_review: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _propose_then_approve_a_boundary(compiled_review)
        finally:
            produced.append(ensure_managed_idb(str(compiled_review)))


def _propose_then_approve_a_boundary(binary: Path) -> None:
    target = str(binary)
    prepared = vulfi_prepare(target)
    analysis_id = prepared["analysis_id"]
    revision = prepared["preparation_revision"]
    ranges = _candidate_ranges(target, analysis_id)
    hidden = ranges["boundary"]
    entry = hidden["address"]
    end = hidden["evidence"]["end"]
    assert end is not None and end > entry

    # Baseline, asserted rather than assumed: the call inside the stretch
    # belongs to no function, so the scanner does not report it.
    idb_path = prepared["idb_path"]
    before = scan_ida(idb_path, validate_rules([COPY_RULE]), SCOPE, path=target)
    assert [row["found_in"] for row in before["findings"]] == ["main"]

    submitted = vulfi_propose_recovery(
        target,
        analysis_id,
        [
            {
                "candidate_id": hidden["candidate_id"],
                "kind": "function_boundary",
                "address_space": "image",
                "address": entry,
                "value": {"end": end},
                "evidence": {
                    "segment": ".vulfi_review_code",
                    "terminator": hidden["evidence"]["terminator"],
                },
                "rationale": "the decoded instructions run to a return",
            }
        ],
    )
    assert submitted["accepted_total"] == 1
    assert submitted["refused_total"] == 0
    stored = submitted["proposals"][0]
    assert stored["accepted"] is True
    assert stored["state"] == "pending"
    assert stored["start"] == entry and stored["end"] == end
    proposal_id = stored["proposal_id"]
    assert proposal_id

    # Inert: the artifact revision has not moved, no function exists over the
    # stretch, and the same scan still finds nothing there.
    assert submitted["preparation_revision"] == revision
    briefing = proposal_briefing(target, proposal_id)
    assert briefing["proposal"]["state"] == "pending"
    assert briefing["site"]["function"] is None
    assert briefing["artifact_revision"] == revision
    still = scan_ida(idb_path, validate_rules([COPY_RULE]), SCOPE, path=target)
    assert [row["found_in"] for row in still["findings"]] == ["main"]

    # An operator who does not confirm changes nothing either, and the
    # evidence they were shown came before the prompt that asked them.
    aborted = _review(
        "approve",
        "--path",
        target,
        "--proposal-id",
        proposal_id,
        "--expected-revision",
        str(revision),
        answer="no",
    )
    assert aborted.returncode == 1, aborted.stderr
    shown = aborted.stdout
    assert shown.index(f"{entry:#x}") < shown.index("Type 'approve'")
    assert "original bytes" in shown
    assert "function_boundary" in shown
    assert proposal_briefing(target, proposal_id)["site"]["function"] is None

    # And the real approval does change it, once, through the one path that may.
    approved = _result(
        _review(
            "approve",
            "--path",
            target,
            "--proposal-id",
            proposal_id,
            "--expected-revision",
            str(revision),
            "--json",
            answer="approve",
        )
    )
    assert approved["confirmed"] is True
    assert approved["state"] == "applied"
    assert approved["applied"] is True
    assert approved["approved_revision"] == revision + 1
    assert approved["expected_revision"] == revision

    # Read back out of a database this process reopened: the function is
    # there, at exactly the boundary the proposal named.
    after = proposal_briefing(target, proposal_id)
    assert after["proposal"]["state"] == "applied"
    assert after["artifact_revision"] == revision + 1
    assert after["site"]["function"] is not None
    assert after["site"]["function"]["start"] == entry

    # And the scan that follows reads that revision and finds the call the
    # recovered function now holds.
    scanned = vulfi_scan(target, rules=[COPY_RULE], scan_name=SCAN_NAME)
    assert scanned["preparation_revision"] == revision + 1
    assert scanned["analysis_id"] == analysis_id
    inside = [
        row
        for row in scanned["findings"]
        if entry <= int(row["address"], 16) < after["site"]["function"]["end"]
    ]
    assert len(inside) == 1, scanned["findings"]
    assert inside[0]["found_in"] == after["site"]["function"]["name"]


# --------------------------------------------------------------------------
# Each permitted kind, each on its own evidence.
# --------------------------------------------------------------------------


def test_each_permitted_kind_applies_only_with_proof(
    compiled_review: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _approve_one_of_each_kind(compiled_review)
        finally:
            produced.append(ensure_managed_idb(str(compiled_review)))


def _approve_one_of_each_kind(binary: Path) -> None:
    target = str(binary)
    source_bytes = binary.read_bytes()
    prepared = vulfi_prepare(target)
    analysis_id = prepared["analysis_id"]
    ranges = _candidate_ranges(target, analysis_id)

    named = ranges["name"]
    text = ranges["string"]
    record = ranges["structure"]
    table = ranges["table"]
    size = record["evidence"]["object_size"]
    assert 4 < size <= 64, record["evidence"]
    proven = [
        (field["offset"], field["size"]) for field in record["evidence"]["fields"]
    ]
    assert len(proven) >= 2, record["evidence"]
    fields = _tiling(size, proven)

    submitted = vulfi_propose_recovery(
        target,
        analysis_id,
        [
            {
                "candidate_id": named["candidate_id"],
                "kind": "name",
                "address_space": "image",
                "address": named["address"],
                "value": {"name": "vulfi_reviewed_entry"},
                "evidence": {"segment": ".vulfi_review_code"},
                "rationale": "the second stretch decodes to a self-contained body",
            },
            {
                "candidate_id": text["candidate_id"],
                "kind": "string_decode",
                "address_space": "image",
                "address": text["address"],
                "value": {"encoding": "ascii", "length": text["evidence"]["length"]},
                "evidence": {
                    "text": MARKER,
                    "bytes_sha256": text["evidence"]["bytes_sha256"],
                },
                "rationale": "six printable bytes and a terminator, fenced by binary",
            },
            {
                "candidate_id": record["candidate_id"],
                "kind": "structure_field",
                "address_space": "image",
                "address": record["address"],
                "value": {"type_name": "vulfi_reviewed_record", "fields": fields},
                "evidence": {"object_size": size, "object_name": "vulfi_review_object"},
                "rationale": "the touched offset anchors a layout of this size",
            },
            {
                "candidate_id": table["candidate_id"],
                "kind": "pointer_table",
                "address_space": "image",
                "address": table["address"],
                "value": {
                    "entry_count": table["evidence"]["entry_count"],
                    "pointer_width": table["evidence"]["pointer_width"],
                },
                "rationale": "every slot carries a relocation record",
                "evidence": {
                    "classification": "mixed_targets",
                    "entry_count": table["evidence"]["entry_count"],
                },
            },
        ],
    )
    assert submitted["accepted_total"] == 4, submitted["proposals"]
    assert submitted["refused_total"] == 0
    assert [row["state"] for row in submitted["proposals"]] == ["pending"] * 4
    by_kind = {row["kind"]: row for row in submitted["proposals"]}

    revision = submitted["preparation_revision"]
    for kind in ("name", "string_decode", "structure_field", "pointer_table"):
        proposal_id = by_kind[kind]["proposal_id"]
        approved = _result(
            _review(
                "approve",
                "--path",
                target,
                "--proposal-id",
                proposal_id,
                "--expected-revision",
                str(revision),
                "--json",
                answer="approve",
            )
        )
        assert approved["confirmed"] is True, approved
        assert approved["state"] == "applied"
        assert approved["approved_revision"] == revision + 1
        revision += 1

    # Every definition, read back out of the managed database afterwards —
    # and nothing else in those ranges touched.
    name_site = proposal_briefing(target, by_kind["name"]["proposal_id"])["site"]
    assert name_site["name"] == "vulfi_reviewed_entry"
    assert name_site["function"] is None, "a name is a name, not a function"

    string_site = proposal_briefing(target, by_kind["string_decode"]["proposal_id"])[
        "site"
    ]
    assert string_site["items"] == [
        {
            "address": text["address"],
            "size": text["evidence"]["length"],
            "is_string": True,
        }
    ]
    # The bytes under it are the ones the evidence named: a definition, not
    # an edit.
    assert string_site["bytes_sha256"] == text["evidence"]["bytes_sha256"]

    record_site = proposal_briefing(target, by_kind["structure_field"]["proposal_id"])[
        "site"
    ]
    assert record_site["existing_type"] is not None
    assert record_site["existing_type"]["size"] == size
    assert [
        (member["offset"], member["size"])
        for member in record_site["existing_type"]["fields"]
    ] == [(field["offset"], field["width"]) for field in fields]

    table_site = proposal_briefing(
        target, by_kind["pointer_table"]["proposal_id"]
    )["site"]
    assert table_site["existing_type"] is not None
    assert table_site["existing_type"]["shape"] == "array"
    assert table_site["existing_type"]["size"] == (
        table["evidence"]["entry_count"] * table["evidence"]["pointer_width"]
    )

    # The operator's own file was never opened for writing by any of this.
    assert binary.read_bytes() == source_bytes


# --------------------------------------------------------------------------
# What a proposal may not be.
# --------------------------------------------------------------------------


def test_scripts_missing_evidence_and_type_conflicts_rejected(
    compiled_review: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _three_invalid_proposals(compiled_review)
        finally:
            produced.append(ensure_managed_idb(str(compiled_review)))


def _three_invalid_proposals(binary: Path) -> None:
    target = str(binary)
    prepared = vulfi_prepare(target)
    analysis_id = prepared["analysis_id"]
    ranges = _candidate_ranges(target, analysis_id)
    hidden = ranges["boundary"]
    defined = _only(
        _all_candidates(target, analysis_id), kind="string", text=DEFINED_MARKER
    )
    assert defined["state"] == "applied", defined["reason"]
    conflicting = defined
    escaped = Path.cwd() / "vulfi-review-escaped"

    submitted = vulfi_propose_recovery(
        target,
        analysis_id,
        [
            # 1. A script where a value belongs.
            {
                "candidate_id": hidden["candidate_id"],
                "kind": "name",
                "address_space": "image",
                "address": hidden["address"],
                "value": {
                    "name": "__import__('os').system('touch vulfi-review-escaped')"
                },
                "evidence": {"segment": ".vulfi_review_code"},
                "rationale": "a name, allegedly",
            },
            # 2. No evidence at all.
            {
                "candidate_id": hidden["candidate_id"],
                "kind": "function_boundary",
                "address_space": "image",
                "address": hidden["address"],
                "value": {"end": hidden["evidence"]["end"]},
                "evidence": {},
                "rationale": "trust me",
            },
            # 3. A definition the managed database already holds.
            {
                "candidate_id": conflicting["candidate_id"],
                "kind": "string_decode",
                "address_space": "image",
                "address": conflicting["address"],
                "value": {
                    "encoding": "ascii",
                    "length": conflicting["evidence"]["length"],
                },
                "evidence": {"text": conflicting["evidence"]["text"]},
                "rationale": "decode it again, differently",
            },
        ],
    )

    assert submitted["accepted_total"] == 0
    assert submitted["refused_total"] == 3
    script, missing, conflict = submitted["proposals"]

    assert script["accepted"] is False
    assert script["proposal_id"] is None
    assert "identifier" in script["reason"]
    assert not escaped.exists(), "a refused proposal ran its own value"

    assert missing["accepted"] is False
    assert "evidence" in missing["reason"]

    assert conflict["accepted"] is False
    assert "already" in conflict["reason"]
    assert str(conflicting["address"]) in conflict["reason"] or (
        f"{conflicting['address']:#x}" in conflict["reason"]
    )

    # Nothing was stored, so there is nothing for an operator to approve.
    with get_catalog(target) as catalog:
        assert catalog is not None
        assert catalog.page_proposals(analysis_id)["total"] == 0

    listed = _result(_review("list", "--path", target, "--json"))
    assert listed["total"] == 0
    assert listed["proposals"] == []


# --------------------------------------------------------------------------
# A refused, stale or unconfirmable approval never reports a durable revision.
# --------------------------------------------------------------------------


def test_stale_and_failed_review_do_not_confirm(
    compiled_review: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _nothing_half_approved_is_reported_as_approved(compiled_review)
        finally:
            produced.append(ensure_managed_idb(str(compiled_review)))


def _refuse_to_save(handle: object, database: object) -> None:
    """Stand in for the adapter's save and fail the way a bad one does."""
    raise ManagedDatabaseError(f"IDA reported no save for {database}: injected")


def _refuse_to_confirm(
    self: Catalog, proposal_id: str, **decision: object
) -> dict[str, object]:
    """Fail exactly the catalog write that follows a successful save."""
    if decision.get("state") == "applied":
        raise OSError("injected: the catalog went away after the save")
    return _real_decide(self, proposal_id, **decision)


_real_decide = Catalog.decide_proposal


def _nothing_half_approved_is_reported_as_approved(binary: Path) -> None:
    target = str(binary)
    prepared = vulfi_prepare(target)
    analysis_id = prepared["analysis_id"]
    ranges = _candidate_ranges(target, analysis_id)
    text = ranges["string"]
    named = ranges["name"]

    submitted = vulfi_propose_recovery(
        target,
        analysis_id,
        [
            {
                "candidate_id": text["candidate_id"],
                "kind": "string_decode",
                "address_space": "image",
                "address": text["address"],
                "value": {"encoding": "ascii", "length": text["evidence"]["length"]},
                "evidence": {"text": MARKER},
                "rationale": "six printable bytes and a terminator",
            },
            {
                "candidate_id": named["candidate_id"],
                "kind": "name",
                "address_space": "image",
                "address": named["address"],
                "value": {"name": "vulfi_reviewed_entry"},
                "evidence": {"segment": ".vulfi_review_code"},
                "rationale": "the stretch decodes to a self-contained body",
            },
        ],
    )
    assert submitted["accepted_total"] == 2
    first, second = (row["proposal_id"] for row in submitted["proposals"])
    revision = submitted["preparation_revision"]

    # One real approval, so the artifact revision moves under the other one.
    done = review_proposal(target, first, "approve", revision, reviewer="tester")
    assert done["approved_revision"] == revision + 1

    # 1. The revision the operator reviewed against is no longer the one the
    #    artifact carries. Nothing is applied and nothing is approved.
    stale = review_proposal(target, second, "approve", revision, reviewer="tester")
    assert stale["confirmed"] is False
    assert stale["applied"] is False
    assert stale["approved_revision"] is None
    assert stale["state"] == "stale"
    assert str(revision) in stale["reason"] and str(revision + 1) in stale["reason"]
    assert proposal_briefing(target, second)["site"]["name"] is None

    # A stale proposal has to be regenerated; it cannot be approved again.
    again = review_proposal(target, second, "approve", revision + 1, reviewer="tester")
    assert again["confirmed"] is False
    assert again["approved_revision"] is None
    assert "stale" in again["reason"]

    # 2. A save the adapter cannot complete. The proposal goes back to
    #    pending, no revision is claimed, and the database is as it was.
    submitted = vulfi_propose_recovery(
        target,
        analysis_id,
        [
            {
                "candidate_id": named["candidate_id"],
                "kind": "name",
                "address_space": "image",
                "address": named["address"],
                "value": {"name": "vulfi_reviewed_again"},
                "evidence": {"segment": ".vulfi_review_code"},
                "rationale": "the stretch decodes to a self-contained body",
            }
        ],
    )
    third = submitted["proposals"][0]["proposal_id"]
    current = submitted["preparation_revision"]

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("vulfi_mcp.ida_adapter._save_session", _refuse_to_save)
        failed = review_proposal(target, third, "approve", current, reviewer="tester")
    assert failed["confirmed"] is False
    assert failed["applied"] is False
    assert failed["approved_revision"] is None
    assert "injected" in failed["reason"]

    pending = proposal_briefing(target, third)
    assert pending["proposal"]["state"] == "pending"
    assert pending["artifact_revision"] == current
    assert pending["site"]["name"] is None

    # 3. The save lands and the catalog cannot record it. That must never be
    #    reported as an approval: the decision stays visible as the
    #    reconciliation anchor it is, and the change is taken back off the
    #    artifact using the checkpoint the apply recorded.
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(Catalog, "decide_proposal", _refuse_to_confirm)
        unconfirmed = review_proposal(
            target, third, "approve", current, reviewer="tester"
        )
    assert unconfirmed["confirmed"] is False
    assert unconfirmed["approved_revision"] is None
    assert unconfirmed["state"] == "approved"
    assert unconfirmed["reconciliation"] is not None
    assert unconfirmed["reconciliation"]["recovered"] is True
    assert "injected" in unconfirmed["reason"]

    reconciled = proposal_briefing(target, third)
    assert reconciled["proposal"]["state"] == "approved"
    assert reconciled["site"]["name"] is None, "the checkpoint was not restored"

    # And an approval of a row already awaiting reconciliation is refused
    # rather than applied a second time.
    retried = review_proposal(
        target, third, "approve", reconciled["artifact_revision"], reviewer="tester"
    )
    assert retried["confirmed"] is False
    assert retried["approved_revision"] is None
    assert "approved" in retried["reason"]
