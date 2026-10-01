"""Two worker decisions, at the seam where IDA would be.

Both are about this pass refusing to say something that is not true, and both
are decided before any database state matters, so the IDA side is a scripted
stand-in:

* what proves a gap address is an entry point, when a real ELF symbol names it
  and the only reference to it is a jump from unrecognized code;
* whether a checkpoint recovery that undid nothing may move the artifact
  revision.

The live end-to-end counterparts run in ``tests/integration``.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

from vulfi_mcp import ida_runtime
from vulfi_mcp.ida_runtime import _Preparation, _recover_reviewed_proposal

# --------------------------------------------------------------------------
# A symbol outranks a jump from unrecognized code
# --------------------------------------------------------------------------

SEGMENT: dict[str, Any] = {"name": ".vulfi_hidden"}

#: The gap this stand-in scans, sized so its one aligned address is the one
#: under test and no other seed muddies the rejection count.
GAP_START = 0x401010
GAP_END = 0x401020
ENTRY = 0x401010

#: The unrecognized code that jumps to ``ENTRY``.
JUMP_FROM = 0x401004


class _Xref:
    def __init__(self, frm: int, type_: int, iscode: int = 1) -> None:
        self.frm = frm
        self.type = type_
        self.iscode = iscode


class _Bytes:
    """Only the four byte-level questions these two methods ask."""

    def __init__(self, named: dict[int, str], referred: set[int]) -> None:
        self._named = named
        self._referred = referred

    def get_flags(self, address: int) -> int:
        return address

    def has_name(self, flags: int) -> bool:
        return flags in self._named

    def has_xref(self, flags: int) -> bool:
        return flags in self._referred

    def next_that(self, address: int, end: int, test: Any) -> int:
        for candidate in range(address + 1, end):
            if test(candidate):
                return candidate
        return 0xFFFFFFFF


class _Budget:
    def __init__(self) -> None:
        self.charged: list[str] = []

    def charge(self, name: str) -> None:
        self.charged.append(name)


def _preparation(
    *,
    symbol: str | None,
    refusal: str | None,
    defines: bool = True,
) -> _Preparation:
    """A preparation whose only gap address is reached by an unowned jump."""
    named = {ENTRY: symbol} if symbol else {}
    scan = object.__new__(_Preparation)
    scan._bytes = _Bytes(named, {ENTRY})
    scan._names = SimpleNamespace(get_name=lambda address: named.get(address, ""))
    # The jump's source belongs to no function: that is what makes it unowned.
    scan._funcs = SimpleNamespace(
        get_func=lambda address: (
            SimpleNamespace(start_ea=ENTRY, end_ea=ENTRY + 0x10)
            if address == ENTRY and defines
            else None
        ),
        add_func=lambda entry, end: defines,
    )
    scan._utils = SimpleNamespace(XrefsTo=lambda address: [_Xref(JUMP_FROM, 19)])
    scan._xref = SimpleNamespace(fl_CN=17, fl_CF=18, fl_JN=19, fl_JF=20, dr_O=1)
    scan._api = SimpleNamespace(BADADDR=0xFFFFFFFF)
    scan._budget = _Budget()
    scan._cursor = GAP_START
    scan._candidates = []
    scan._applied = []
    scan._gap_rejections = 0
    scan._decode_function = lambda entry, limit: {  # type: ignore[method-assign]
        "refusal": refusal,
        "end": None if refusal else entry + 0x10,
        "instructions": [],
        "count": 0 if refusal else 4,
        "terminator": None if refusal else "retn",
    }
    return scan


def test_a_symbol_outranks_an_unowned_jump_when_proving_a_gap_entry() -> None:
    # Without the symbol, the jump from unrecognized code is all there is and
    # the entry stays a described candidate — that part is deliberate.
    plain = _preparation(symbol=None, refusal=None)
    evidence = plain._entry_evidence(ENTRY)
    assert evidence is not None
    assert evidence["kind"] == "unowned_jump"
    block = plain._gap_candidate(SEGMENT, ENTRY, GAP_START, GAP_END, evidence)
    assert block is not None
    assert block["state"] == "candidate"

    # With a real ELF symbol on the same address, the symbol is the proof and
    # the function is created. Saying "control flow inside something this pass
    # has not identified" about an address the image itself names is false.
    named = _preparation(symbol="vulfi_hidden_entry", refusal=None)
    evidence = named._entry_evidence(ENTRY)
    assert evidence is not None
    assert evidence["kind"] == "symbol"
    assert evidence["symbol"] == "vulfi_hidden_entry"
    # The jump is still reported; only the proof kind changed.
    assert evidence["unowned_jump_from"] == [JUMP_FROM]
    candidate = named._gap_candidate(SEGMENT, ENTRY, GAP_START, GAP_END, evidence)
    assert candidate is not None
    assert candidate["state"] == "applied"
    assert candidate["reason"] is None
    assert candidate["confidence"] == 0.9
    assert candidate["evidence"]["defined_end"] == ENTRY + 0x10


def test_a_symbol_backed_entry_is_never_counted_as_carrying_no_symbol() -> None:
    # The bytes refuse to decode, so an unproven address would be dropped and
    # counted into a warning that says those addresses "carry no reference or
    # symbol". A symbol-backed address is neither of those things.
    scan = _preparation(symbol="vulfi_hidden_entry", refusal="no return reached")
    scan._scan_gap(SEGMENT, GAP_START, GAP_END)
    assert scan._gap_rejections == 0
    assert len(scan._candidates) == 1
    kept = scan._candidates[0]
    assert kept["state"] == "candidate"
    assert kept["reason"] == "no return reached"
    assert kept["evidence"]["entry_evidence"]["symbol"] == "vulfi_hidden_entry"

    # The same address without a symbol is still dropped and still counted.
    anonymous = _preparation(symbol=None, refusal="no return reached")
    anonymous._scan_gap(SEGMENT, GAP_START, GAP_END)
    assert anonymous._gap_rejections == 1
    assert anonymous._candidates == []


# --------------------------------------------------------------------------
# A recovery that undid nothing moves no revision
# --------------------------------------------------------------------------

CHECKPOINT: dict[str, Any] = {
    "kind": "name",
    "start": 0x401000,
    "end": 0x401001,
    "name": "",
    "function": False,
    "item": False,
    "type": False,
}


@pytest.fixture
def scripted_worker(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The record this worker would read, and the writes it would make."""
    state: dict[str, Any] = {
        "record": {"preparation": {"revision": 7}},
        "writes": 0,
    }

    def _write(record: dict[str, Any]) -> bytes:
        state["writes"] += 1
        return b""

    monkeypatch.setattr(
        ida_runtime, "_read_record", lambda: (state["record"], None)
    )
    monkeypatch.setattr(ida_runtime, "_write_record", _write)
    monkeypatch.setattr(
        ida_runtime, "_proposal_site", lambda start, end: {"start": start}
    )
    monkeypatch.setattr(ida_runtime, "_preparation_report", lambda record: {})
    monkeypatch.setitem(sys.modules, "ida_bytes", SimpleNamespace(DELIT_SIMPLE=0))
    monkeypatch.setitem(sys.modules, "ida_funcs", SimpleNamespace())
    return state


def test_a_recovery_ida_refused_moves_no_revision(
    scripted_worker: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        SimpleNamespace(set_name=lambda *args, **kwargs: False, SN_NOCHECK=0),
    )

    answer = _recover_reviewed_proposal({"checkpoint": dict(CHECKPOINT)})

    assert answer["mutated"] is False
    assert answer["recovered"] is False
    # The revision the artifact still carries, not a new one it did not earn.
    assert answer["revision"] == 7
    assert scripted_worker["record"]["preparation"]["revision"] == 7
    assert scripted_worker["writes"] == 0
    assert "refused to clear the name" in str(answer["reason"])


def test_a_recovery_that_undid_the_change_moves_the_revision_once(
    scripted_worker: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "ida_name",
        SimpleNamespace(set_name=lambda *args, **kwargs: True, SN_NOCHECK=0),
    )

    answer = _recover_reviewed_proposal({"checkpoint": dict(CHECKPOINT)})

    assert answer["mutated"] is True
    assert answer["recovered"] is True
    assert answer["revision"] == 8
    assert scripted_worker["record"]["preparation"]["revision"] == 8
    assert scripted_worker["writes"] == 1
    assert answer["reason"] is None
