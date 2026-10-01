"""Two seams of one scan that decide what a finding may claim, without IDA.

Both are host-only on purpose. The first is the argument slot IDA could not
read: the extractor marks the position absent rather than closing the gap, and
every later layer has to keep it absent — a slot that silently became its
neighbour would move facts between arguments and so change which rule matched.
The second is the one write a scan may make, whose gate decides whether a
pinned prototype lands on the function the rule named or on an unrelated local
one that shares its name.
"""

from __future__ import annotations

from typing import Any

from vulfi_mcp.ida_adapter import _param, _site_priority
from vulfi_mcp.ida_runtime import UNAVAILABLE, Param, _Scanner
from vulfi_mcp.rules import Rule, validate_rules

COPIED_FROM: Rule = validate_rules(
    [
        {
            "name": "Buffer Overflow",
            "function_names": ["strcpy"],
            "wrappers": False,
            "mark_if": {
                "High": "not param[1].is_constant()",
                "Medium": "",
                "Low": "",
            },
        }
    ]
)[0]

#: What `_arguments_disass` puts in a slot whose argument instruction IDA could
#: not attribute or could not decode.
ABSENT: dict[str, Any] = {"kind": "absent"}


def _site(*params: dict[str, Any]) -> dict[str, Any]:
    return {"address": "0x401000", "params": list(params), "call": {}}


def test_an_unreadable_argument_slot_keeps_its_position_and_loses_its_facts() -> None:
    # `get_arg_addrs` answers BADADDR for a slot it cannot attribute, and
    # upstream compacts those away — which renumbers every later argument, so
    # `param[1]` silently becomes `param[2]`'s facts. The slot travels instead.
    scanner = object.__new__(_Scanner)

    assert _Scanner._param_facts(scanner, None, 0x1234, "strcpy") == ABSENT

    # And the facts it carries into evaluation are no facts at all, not false
    # ones: every field stays explicitly unavailable.
    blank = _param(ABSENT)
    assert blank == Param()
    assert all(
        getattr(blank, field) is UNAVAILABLE for field in Param.__dataclass_fields__
    )


def test_an_absent_slot_is_unavailable_evidence_only_where_the_rule_reads_it() -> None:
    # The rule reads `param[1]`. With the hole in slot 0 the fact it needs is
    # still there, and the site evaluates; with the hole in slot 1 the site is
    # unsupported. Compacting the hole away would make both of these the first
    # answer, which is the bug: a High finding reported from the wrong argument.
    assert _site_priority(COPIED_FROM, _site(ABSENT, {"constant": False})) == (
        "High",
        None,
        "evaluated",
    )

    priority, reason, outcome = _site_priority(
        COPIED_FROM, _site({"constant": False}, ABSENT)
    )
    assert (priority, outcome) == (None, "unsupported")
    assert reason and "is_constant" in reason


def test_a_wrapper_site_never_offers_the_pinned_prototype_to_the_wrapper() -> None:
    # `_call_site` passes the wrapper's own name for a wrapper site, so without
    # the rule-named gate a local function colliding with one of the 441 pinned
    # keys would be typed as the library function it shares a name with.
    scanner = object.__new__(_Scanner)
    scanner._typed = set()
    scanner._prototypes = {"strcpy": "char* strcpy(char* dest, char* src);"}
    scanner._applied = []

    assert _Scanner._apply_prototype(scanner, 0x401000, "strcpy", False) is False
    assert scanner._applied == []
    # Refused before the one-offer-per-function record, so the real rule-named
    # call site that comes later is still eligible.
    assert scanner._typed == set()


def test_a_rule_named_callee_without_a_pinned_prototype_is_offered_nothing() -> None:
    scanner = object.__new__(_Scanner)
    scanner._typed = set()
    scanner._prototypes = {"strcpy": "char* strcpy(char* dest, char* src);"}
    scanner._applied = []

    # Rule-named, so the gate lets it reach the table; the table has no entry,
    # so nothing is written and the function is not offered one twice.
    assert _Scanner._apply_prototype(scanner, 0x401000, "parse_config", True) is False
    assert scanner._applied == []
    assert scanner._typed == {0x401000}
