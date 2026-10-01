"""What an agent may propose, and everything it may not do by proposing it.

Every test here runs on the host without a licensed IDA, because every rule it
pins is decided before a database is opened. That is the point of the split
this file guards: a proposal is *data*. It names a candidate the catalog
already holds, quotes that candidate's own evidence back, proposes one of five
changes in a closed vocabulary, and is stored `pending`. Nothing in this file
can change an analysis artifact, and no MCP tool anywhere can approve one —
only `vulfi-mcp review`, which lives in :mod:`vulfi_mcp.operator` and is
exercised live in `tests/integration/test_review_cli.py`.

The refusals below are the whole security surface of the proposal path, so
each one is checked for the thing it must say, not merely for failing:

* a kind outside the five permitted ones, named with the five;
* executable content — a Python call, a provider command, a shell string —
  refused while it is still JSON, never stored and never run;
* a proposal that cites no evidence, cites a field its candidate does not
  carry, or cites a value its candidate contradicts;
* an address that is not the candidate's own;
* a candidate produced by a backend this build has no safe writer for, which
  is refused with that reason rather than faked.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from vulfi_mcp.catalog import (
    CatalogError,
    ReadOnlyCatalogError,
    catalog_path,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.ida_runtime import (
    MAX_PROPOSALS,
    PROPOSAL_KINDS,
    OperationError,
    validate_proposal,
    validate_proposal_request,
)
from vulfi_mcp.prepare import (
    PreparationError,
    check_proposal_against_candidate,
    propose_recovery,
)

ANALYSIS = "prep-0123456789abcdef0123456789abcdef"

#: One candidate row of each kind, exactly as Tasks 2 and 3's worker produces
#: them: an id, an address, and the evidence the recovery rests on.
FUNCTION_CANDIDATE: dict[str, Any] = {
    "candidate_id": "ida:function:00401000",
    "kind": "function",
    "backend": "ida",
    "address_space": "image",
    "address": 0x401000,
    "evidence": {
        "entry": 0x401000,
        "end": 0x401010,
        "segment": ".vulfi_hidden",
        "entry_evidence": {"kind": "aligned_gap", "from": [], "symbol": None},
        "instruction_count": 4,
    },
    "confidence": 0.4,
    "state": "candidate",
    "reason": "no call, jump, relocated pointer or symbol establishes 0x401000",
}

STRING_CANDIDATE: dict[str, Any] = {
    "candidate_id": "ida:string:ascii:00402000",
    "kind": "string",
    "backend": "ida",
    "address_space": "image",
    "address": 0x402000,
    "evidence": {
        "encoding": "ascii",
        "start": 0x402000,
        "end": 0x402007,
        "length": 7,
        "characters": 6,
        "text": "VuLfI7",
        "bytes_hex": "56754c66493700",
        "bytes_sha256": "a" * 64,
    },
    "confidence": 0.7,
    "state": "candidate",
    "reason": "6 printable characters followed by a terminator happen by chance",
}


def _proposal(**overrides: Any) -> dict[str, Any]:
    """A valid `name` proposal against the function candidate above."""
    body: dict[str, Any] = {
        "candidate_id": FUNCTION_CANDIDATE["candidate_id"],
        "kind": "name",
        "address_space": "image",
        "address": 0x401000,
        "value": {"name": "vulfi_reviewed_entry"},
        "evidence": {"segment": ".vulfi_hidden", "instruction_count": 4},
        "rationale": "the decoded instructions end in a return at this entry",
    }
    body.update(overrides)
    return body


def _refusal(body: object) -> str:
    """Validate one proposal, and return exactly what it was refused for."""
    with pytest.raises(OperationError) as refused:
        validate_proposal(body)
    return str(refused.value)


# -- the closed vocabulary --------------------------------------------------


def test_every_permitted_kind_validates_and_a_sixth_does_not() -> None:
    assert PROPOSAL_KINDS == (
        "name",
        "function_boundary",
        "string_decode",
        "structure_field",
        "pointer_table",
    )

    accepted = {
        "name": {"name": "vulfi_reviewed_entry"},
        "function_boundary": {"end": 0x401010},
        "string_decode": {"encoding": "ascii", "length": 7},
        "structure_field": {
            "type_name": "vulfi_reviewed_record",
            "fields": [
                {"offset": 0, "width": 4, "name": "count"},
                {"offset": 4, "width": 4, "name": "limit"},
                {"offset": 8, "width": 8, "name": "total"},
            ],
        },
        "pointer_table": {"entry_count": 2, "pointer_width": 8},
    }
    assert set(accepted) == set(PROPOSAL_KINDS)
    for kind, value in accepted.items():
        checked = validate_proposal(_proposal(kind=kind, value=value))
        assert checked["kind"] == kind
        # Every kind's address range is a function of its own value, so a
        # reviewer is never shown a range the proposal did not imply.
        assert checked["start"] == 0x401000
        assert checked["end"] > checked["start"]

    assert validate_proposal(_proposal(kind="name"))["end"] == 0x401001
    assert validate_proposal(
        _proposal(kind="string_decode", value={"encoding": "ascii", "length": 7})
    )["end"] == 0x401007
    assert validate_proposal(
        _proposal(kind="pointer_table", value={"entry_count": 2, "pointer_width": 8})
    )["end"] == 0x401010

    refusal = _refusal(_proposal(kind="rename_everything", value={}))
    assert "rename_everything" in refusal
    for kind in PROPOSAL_KINDS:
        assert kind in refusal


def test_executable_content_is_refused_while_it_is_still_data() -> None:
    # A Python expression where an identifier belongs.
    call = _refusal(
        _proposal(value={"name": "__import__('os').system('touch escaped')"})
    )
    assert "name" in call and "identifier" in call

    # A provider command smuggled in beside a legitimate value.
    command = _refusal(
        _proposal(value={"name": "vulfi_ok", "command": "idat -S evil.idc"})
    )
    assert "command" in command
    assert "name" in command, "the refusal must name the keys this kind accepts"

    # A whole script offered as the proposed value.
    script = _refusal(
        _proposal(
            kind="function_boundary",
            value={"end": 0x401010, "script": "import os; os.system('id')"},
        )
    )
    assert "script" in script

    # And a shell string in a field name, where only identifiers go.
    field = _refusal(
        _proposal(
            kind="structure_field",
            value={
                "type_name": "vulfi_reviewed_record",
                "fields": [{"offset": 0, "width": 4, "name": "$(id)"}],
            },
        )
    )
    assert "$(id)" in field and "identifier" in field


def test_a_request_is_bounded_before_one_proposal_is_looked_at() -> None:
    with pytest.raises(OperationError, match="must be a list"):
        validate_proposal_request({"candidate_id": "x"})
    with pytest.raises(OperationError, match="at least one"):
        validate_proposal_request([])
    with pytest.raises(OperationError, match=str(MAX_PROPOSALS)):
        validate_proposal_request([_proposal() for _ in range(MAX_PROPOSALS + 1)])

    # The shape only: each proposal is validated on its own afterwards, so
    # one unacceptable proposal is one unacceptable proposal and not a
    # refusal of the whole request.
    assert validate_proposal_request([_proposal(), {"junk": True}]) == [
        _proposal(),
        {"junk": True},
    ]


def test_a_proposal_without_a_rationale_or_an_address_is_refused() -> None:
    assert "rationale" in _refusal(_proposal(rationale=""))
    assert "rationale" in _refusal(_proposal(rationale="   "))
    assert "address" in _refusal(_proposal(address=-1))
    assert "address" in _refusal(_proposal(address="0x401000"))
    assert "candidate_id" in _refusal(_proposal(candidate_id=""))
    assert "address_space" in _refusal(_proposal(address_space=""))
    assert "evidence" in _refusal(_proposal(evidence={}))
    assert "evidence" in _refusal(_proposal(evidence=["segment"]))


def test_an_encoding_with_no_writer_is_refused_rather_than_half_applied() -> None:
    # The strings pass reports UTF-16BE runs and never defines them, because
    # this IDA registers no big-endian UTF-16 string type. A proposal to
    # define one has to be refused for that reason, not accepted and then
    # discovered to be unapplicable at review time.
    refusal = _refusal(
        _proposal(kind="string_decode", value={"encoding": "utf-16be", "length": 8})
    )
    assert "utf-16be" in refusal
    assert "ascii" in refusal and "utf-16le" in refusal


# -- the proposal has to be about the candidate it names --------------------


def test_a_proposal_must_quote_evidence_its_candidate_really_holds() -> None:
    body = validate_proposal(_proposal())
    check_proposal_against_candidate(body, FUNCTION_CANDIDATE)

    invented = validate_proposal(
        _proposal(evidence={"entry_evidence_kind": "call_xref"})
    )
    with pytest.raises(PreparationError, match="entry_evidence_kind"):
        check_proposal_against_candidate(invented, FUNCTION_CANDIDATE)

    contradicted = validate_proposal(_proposal(evidence={"segment": ".text"}))
    with pytest.raises(PreparationError) as refused:
        check_proposal_against_candidate(contradicted, FUNCTION_CANDIDATE)
    assert ".text" in str(refused.value)
    assert ".vulfi_hidden" in str(refused.value)


def test_a_proposal_must_name_its_candidates_own_address_and_kind() -> None:
    elsewhere = validate_proposal(_proposal(address=0x401008))
    with pytest.raises(PreparationError, match="0x401008"):
        check_proposal_against_candidate(elsewhere, FUNCTION_CANDIDATE)

    other_space = validate_proposal(_proposal(address_space="physical"))
    with pytest.raises(PreparationError, match="physical"):
        check_proposal_against_candidate(other_space, FUNCTION_CANDIDATE)

    mismatched = validate_proposal(
        _proposal(
            kind="string_decode",
            value={"encoding": "ascii", "length": 7},
            evidence={"segment": ".vulfi_hidden"},
        )
    )
    with pytest.raises(PreparationError) as refused:
        check_proposal_against_candidate(mismatched, FUNCTION_CANDIDATE)
    assert "string_decode" in str(refused.value)
    assert "function" in str(refused.value)


def test_a_candidate_this_build_cannot_write_is_refused_not_faked() -> None:
    # Plan 3 brings the external providers. Until one of them can write back
    # safely, a proposal against its candidate is unavailable *by name* — the
    # one outcome that must never happen is a reported apply that no backend
    # performed.
    foreign = dict(FUNCTION_CANDIDATE, backend="ghidra")
    body = validate_proposal(_proposal())
    with pytest.raises(PreparationError) as refused:
        check_proposal_against_candidate(body, foreign)
    assert "ghidra" in str(refused.value)
    assert "nothing was applied" in str(refused.value).lower()


# -- what the catalog does with a decision ----------------------------------


def _catalog_with_candidates(binary: Path) -> None:
    binary.write_bytes(b"\x7fELFproposals")
    with open_catalog(str(binary)) as catalog:
        catalog.record_pass(
            ANALYSIS,
            {
                "pass": "functions",
                "backend": "ida",
                "ranges": [{"start": 0x401000, "end": 0x402000}],
                "coverage": "complete",
                "applied_ids": [],
                "candidates": [FUNCTION_CANDIDATE],
                "warnings": [],
                "artifact_revision": 1,
            },
        )
        catalog.record_pass(
            ANALYSIS,
            {
                "pass": "strings",
                "backend": "ida",
                "ranges": [{"start": 0x402000, "end": 0x403000}],
                "coverage": "complete",
                "applied_ids": [],
                "candidates": [STRING_CANDIDATE],
                "warnings": [],
                "artifact_revision": 1,
            },
        )


def _stored(binary: Path, proposal_id: str) -> dict[str, Any]:
    with get_catalog(str(binary)) as catalog:
        held = catalog.proposal(proposal_id)
    assert held is not None, proposal_id
    return held


def test_the_catalog_stores_a_proposal_pending_with_its_evidence(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _catalog_with_candidates(binary)

    with open_catalog(str(binary)) as catalog:
        stored = catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-1",
            candidate_id=FUNCTION_CANDIDATE["candidate_id"],
            kind="name",
            address_space="image",
            address=0x401000,
            value={"name": "vulfi_reviewed_entry"},
            evidence={"segment": ".vulfi_hidden"},
            rationale="the decoded instructions end in a return",
        )

        # Two concurrent submissions of one change race for this row: the
        # id is derived from the content, so both mint the same one and the
        # pre-check in `propose_recovery` can see nothing before either
        # writes. The loser is owed the duplicate refusal, in this module's
        # vocabulary rather than the database driver's.
        with pytest.raises(CatalogError, match="already recorded") as collided:
            catalog.record_proposal(
                ANALYSIS,
                proposal_id="prop-1",
                candidate_id=FUNCTION_CANDIDATE["candidate_id"],
                kind="name",
                address_space="image",
                address=0x401000,
                value={"name": "vulfi_reviewed_entry"},
                evidence={"segment": ".vulfi_hidden"},
                rationale="the decoded instructions end in a return",
            )
        assert "prop-1" in str(collided.value)
        assert not isinstance(collided.value, sqlite3.Error)

    assert stored["state"] == "pending"
    assert stored["expected_revision"] is None
    assert stored["decided_at"] is None
    assert stored["decided_by"] is None
    # Stored whole: the operator reviews what the agent said, not a summary
    # of it, and the evidence travels with the proposal.
    assert stored["value"] == {"name": "vulfi_reviewed_entry"}
    assert stored["evidence"] == {"segment": ".vulfi_hidden"}
    assert _stored(binary, "prop-1") == stored

    with get_catalog(str(binary)) as catalog:
        page = catalog.page_proposals(ANALYSIS, state="pending", offset=0, limit=10)
    assert page["total"] == 1
    assert page["loaded"] == 1
    assert page["proposals"][0]["proposal_id"] == "prop-1"

    # A read-only catalog may not record or decide anything.
    with get_catalog(str(binary)) as catalog, pytest.raises(ReadOnlyCatalogError):
        catalog.decide_proposal(
            "prop-1", state="rejected", decided_by="operator", reason="no"
        )


def test_a_decision_moves_only_the_ways_the_review_path_allows(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _catalog_with_candidates(binary)

    with open_catalog(str(binary)) as catalog:
        catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-1",
            candidate_id=FUNCTION_CANDIDATE["candidate_id"],
            kind="name",
            address_space="image",
            address=0x401000,
            value={"name": "vulfi_reviewed_entry"},
            evidence={"segment": ".vulfi_hidden"},
            rationale="the decoded instructions end in a return",
        )

        # An agent-authored row is born pending and there is no parameter
        # that could make it anything else: the party who writes a proposal
        # is not the party who decides it, and a caller able to insert an
        # already-decided row would be both.
        with pytest.raises(TypeError, match="state"):
            catalog.record_proposal(
                ANALYSIS,
                proposal_id="prop-2",
                candidate_id=FUNCTION_CANDIDATE["candidate_id"],
                kind="name",
                address_space="image",
                address=0x401000,
                value={"name": "vulfi_second"},
                evidence={"segment": ".vulfi_hidden"},
                rationale="another name",
                state="applied",
            )

        # pending -> applied skips the approval that is the whole control.
        with pytest.raises(CatalogError) as refused:
            catalog.decide_proposal(
                "prop-1", state="applied", decided_by="operator", reason="jump"
            )
        assert "pending" in str(refused.value)
        assert "applied" in str(refused.value)

        approved = catalog.decide_proposal(
            "prop-1",
            state="approved",
            decided_by="operator",
            reason="checked the bytes",
            expected_revision=3,
        )
        assert approved["state"] == "approved"
        assert approved["expected_revision"] == 3
        assert approved["decided_by"] == "operator"
        assert approved["decided_at"]

        applied = catalog.decide_proposal(
            "prop-1", state="applied", decided_by="operator", reason="applied"
        )
        assert applied["state"] == "applied"
        # The revision the operator reviewed against is kept, not overwritten
        # by the state that followed it.
        assert applied["expected_revision"] == 3

        # A decided row is decided: a second decision is refused rather than
        # quietly replacing the first.
        with pytest.raises(CatalogError, match="applied"):
            catalog.decide_proposal(
                "prop-1", state="rejected", decided_by="operator", reason="changed"
            )

    with pytest.raises(CatalogError, match="prop-nothing"):
        with open_catalog(str(binary)) as catalog:
            catalog.decide_proposal(
                "prop-nothing", state="rejected", decided_by="o", reason="x"
            )


def test_a_rerun_that_drops_a_candidate_drops_its_proposals(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _catalog_with_candidates(binary)

    with open_catalog(str(binary)) as catalog:
        catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-function",
            candidate_id=FUNCTION_CANDIDATE["candidate_id"],
            kind="name",
            address_space="image",
            address=0x401000,
            value={"name": "vulfi_reviewed_entry"},
            evidence={"segment": ".vulfi_hidden"},
            rationale="the decoded instructions end in a return",
        )
        catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-string",
            candidate_id=STRING_CANDIDATE["candidate_id"],
            kind="string_decode",
            address_space="image",
            address=0x402000,
            value={"encoding": "ascii", "length": 7},
            evidence={"text": "VuLfI7"},
            rationale="seven bytes, six printable and a terminator",
        )

        # The strings pass runs again and no longer finds its candidate. The
        # decision recorded against it goes with it; the one recorded against
        # the function candidate, which this run did not touch, stays.
        catalog.record_pass(
            ANALYSIS,
            {
                "pass": "strings",
                "backend": "ida",
                "ranges": [{"start": 0x402000, "end": 0x403000}],
                "coverage": "complete",
                "applied_ids": [],
                "candidates": [],
                "warnings": [],
                "artifact_revision": 2,
            },
        )

    with get_catalog(str(binary)) as catalog:
        assert catalog.proposal("prop-string") is None
        assert catalog.proposal("prop-function") is not None
        assert catalog.candidate(ANALYSIS, STRING_CANDIDATE["candidate_id"]) is None
        held = catalog.candidate(ANALYSIS, FUNCTION_CANDIDATE["candidate_id"])
    assert held is not None
    assert held["evidence"] == FUNCTION_CANDIDATE["evidence"]


def test_one_target_cannot_read_another_targets_proposal(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    mine = tmp_path / "mine" / "service"
    theirs = tmp_path / "theirs" / "service"
    mine.parent.mkdir()
    theirs.parent.mkdir()
    _catalog_with_candidates(mine)
    theirs.write_bytes(b"\x7fELFsomebody-else")

    with open_catalog(str(mine)) as catalog:
        catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-1",
            candidate_id=FUNCTION_CANDIDATE["candidate_id"],
            kind="name",
            address_space="image",
            address=0x401000,
            value={"name": "vulfi_reviewed_entry"},
            evidence={"segment": ".vulfi_hidden"},
            rationale="the decoded instructions end in a return",
        )

    with open_catalog(str(theirs)) as catalog:
        assert catalog.proposal("prop-1") is None
        assert catalog.page_proposals()["total"] == 0


# -- nothing is created to answer a proposal --------------------------------


def test_proposing_against_an_unprepared_target_creates_nothing(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    binary.write_bytes(b"\x7fELFnever-prepared")

    with pytest.raises(PreparationError) as refused:
        propose_recovery(str(binary), ANALYSIS, [_proposal()])
    assert "vulfi_prepare" in str(refused.value)

    # Not a database, not a catalog, not a directory: a proposal is a read of
    # an analysis that already exists, and may not manufacture one.
    assert not managed_data_dir.exists() or list(managed_data_dir.rglob("*")) == []
    assert not catalog_path().exists()


def test_a_malformed_request_is_refused_before_anything_is_opened(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    binary.write_bytes(b"\x7fELFnever-prepared")

    with pytest.raises(PreparationError, match="analysis_id"):
        propose_recovery(str(binary), "", [_proposal()])
    with pytest.raises(PreparationError, match="at least one"):
        propose_recovery(str(binary), ANALYSIS, [])
    assert not catalog_path().exists()


def test_the_stored_proposal_column_is_json_the_next_build_can_read(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The catalog is a shared store with a versioned schema, so what one build
    # writes has to be readable by the next one without guessing.
    binary = tmp_path / "service"
    _catalog_with_candidates(binary)
    with open_catalog(str(binary)) as catalog:
        catalog.record_proposal(
            ANALYSIS,
            proposal_id="prop-1",
            candidate_id=FUNCTION_CANDIDATE["candidate_id"],
            kind="name",
            address_space="image",
            address=0x401000,
            value={"name": "vulfi_reviewed_entry"},
            evidence={"segment": ".vulfi_hidden"},
            rationale="the decoded instructions end in a return",
        )

    connection = sqlite3.connect(f"file:{catalog_path()}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT value, rationale, state FROM proposals WHERE proposal_id = ?",
            ("prop-1",),
        ).fetchone()
    finally:
        connection.close()
    held = json.loads(row[0])
    assert held["value"] == {"name": "vulfi_reviewed_entry"}
    assert held["evidence"] == {"segment": ".vulfi_hidden"}
    assert row[1] == "the decoded instructions end in a return"
    assert row[2] == "pending"
