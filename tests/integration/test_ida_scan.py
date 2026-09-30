"""Live IDA coverage of call-site, wrapper, array, and loop evidence.

Every test scans a compiled fixture through a managed IDB, so each fact it
asserts is one IDA actually established. Nothing here stubs a backend: a claim
about a missing fact is a claim about what the real extractor could not
recover.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

import pytest

from conftest import CC_FLAGS, FIXTURES, missing_prerequisite
from vulfi_mcp.contracts import Finding, ScanResult
from vulfi_mcp.ida_adapter import ensure_managed_idb, scan_ida
from vulfi_mcp.rules import Rule, load_stock_rules, validate_rules

pytestmark = pytest.mark.requires_ida

#: `tests/conftest.py`'s `durable_or_reported` fixture: hold a body to "the
#: state is intact, or the loss was reported", because IDA 9.4.260714 cannot
#: promise that every pack reopens. Register each managed database with the
#: list it yields.
Tolerance = Callable[[], AbstractContextManager[list[str]]]

STOCK: tuple[Rule, ...] = load_stock_rules()

ZERO_ARGUMENT_RULE: Rule = validate_rules(
    [
        {
            "name": "Zero Argument Probe",
            "function_names": ["reset_state"],
            "wrappers": False,
            "mark_if": {"High": "False", "Medium": "False", "Low": "False"},
        }
    ]
)[0]


def _stock_rule(first_function: str) -> Rule:
    """The one stock rule whose ``function_names`` start with this name."""
    matches = [rule for rule in STOCK if rule["function_names"][0] == first_function]
    assert len(matches) == 1, f"{first_function}: matched {len(matches)} stock rules"
    return matches[0]


@pytest.fixture
def compiled_shapes(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_shapes.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_shapes.c cannot be built")
    binary = tmp_path / "vulfi_shapes"
    command = [
        str(compiler),
        *CC_FLAGS,
        "-o",
        str(binary),
        str(FIXTURES / "vulfi_shapes.c"),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_shapes.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


def _scan(binary: Path, rules: tuple[Rule, ...], **options: Any) -> ScanResult:
    return scan_ida(
        ensure_managed_idb(str(binary)),
        rules,
        "default",
        path=str(binary),
        **options,
    )


def _for_rule(result: ScanResult, rule_index: int) -> list[Finding]:
    return [row for row in result["findings"] if row["rule_index"] == rule_index]


def test_two_variable_source_calls_are_distinct(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    rule = _stock_rule("strcpy")
    result = _scan(compiled_calls, (rule,))

    assert result["rule_coverage"] == [
        {"rule_index": 0, "backend": "ida", "state": "evaluated", "reason": None}
    ]
    assert result["coverage"] == "complete"
    assert result["scope_total"] == 2

    by_caller = {row["found_in"]: row for row in result["findings"]}
    assert sorted(by_caller) == ["copy_from_argument", "copy_from_environment"]
    first = by_caller["copy_from_argument"]
    second = by_caller["copy_from_environment"]
    assert first["address"] != second["address"]
    assert first["id"] != second["id"]

    for finding in (first, second):
        assert finding["priority"] == "High"
        assert finding["backend"] == "ida"
        # The called function is IDA's own name for it: an ELF import is
        # reached through its `.plt.sec` thunk, which IDA calls `.strcpy`.
        assert finding["function_name"] == ".strcpy"
        assert finding["evidence"]["matched_name"] == ".strcpy"
        assert finding["rule_name"] == rule["name"]
        evidence = finding["evidence"]
        assert evidence["matched_branch"] == "High"
        assert evidence["expression"] == rule["mark_if"]["High"]
        assert evidence["analysis_mode"] == "ctree"
        assert evidence["argument_count"] == 2
        copied_from = evidence["params"][1]
        assert copied_from["constant"] is False
        assert copied_from["calls_before"] == []


def test_wrapper_loop_and_array_fact_detection(
    compiled_shapes: Path, managed_data_dir: Path
) -> None:
    rules = (
        _stock_rule("free"),
        _stock_rule("Array Access"),
        _stock_rule("Loop Check"),
        _stock_rule("strcpy"),
    )
    result = _scan(compiled_shapes, rules)

    # One level of wrapper discovery reports the call to the wrapper, never the
    # wrapped `free` itself.
    wrappers = _for_rule(result, 0)
    assert [row["function_name"] for row in wrappers] == ["release_buffer"]
    assert wrappers[0]["found_in"] == "drop_buffer"
    assert wrappers[0]["priority"] == "Low"
    assert wrappers[0]["evidence"]["wrapper_of"] == ".free"
    assert wrappers[0]["evidence"]["params"][0]["nulled_after_call"] is False

    arrays = [row for row in _for_rule(result, 1) if row["found_in"] == "read_table"]
    assert arrays, "no signed-compared array access was found in read_table"
    assert {row["priority"] for row in arrays} == {"High"}
    assert arrays[0]["evidence"]["params"][1]["sign_compared"] is True
    assert arrays[0]["evidence"]["params"][1]["kind"] == "cot_var"

    loops = [row for row in _for_rule(result, 2) if row["found_in"] == "copy_dynamic"]
    assert [row["priority"] for row in loops] == ["High"]
    counter, bound = loops[0]["evidence"]["params"]
    assert counter["indexed"] is True
    assert bound["constant"] is False
    assert bound["number"] is None

    # `i <= 7` bounds the same loop shape with a literal, so only the weakest
    # branch matches.
    fixed = [row for row in _for_rule(result, 2) if row["found_in"] == "fill_fixed"]
    assert [row["priority"] for row in fixed] == ["Low"]
    assert fixed[0]["evidence"]["params"][1]["number"] == 7

    # `lstrcpya` has a pinned VulFi prototype and no type of its own, but the
    # decompiler recovers its call's arguments unaided, so the scan must leave
    # the managed database alone.
    assert result["scope_health"]["ida"]["applied_prototypes"] == []
    typed = _for_rule(result, 3)
    assert [row["function_name"] for row in typed] == ["lstrcpya"]
    assert typed[0]["evidence"]["argument_count"] == 2


def test_prototype_is_applied_only_when_arguments_cannot_be_recovered(
    compiled_shapes: Path, managed_data_dir: Path, durable_or_reported: Tolerance
) -> None:
    # The one test in this file that saves and then reopens: applying the
    # prototype is a real write, and the second scan opens what it wrote. One
    # spare-backed pack and one reopen; see `durable_or_reported`. Observed
    # failing here on a bad pack in a whole-suite run before it was wrapped.
    with durable_or_reported() as produced:
        _assert_prototype_is_applied_on_demand(compiled_shapes, produced)


def _assert_prototype_is_applied_on_demand(
    compiled_shapes: Path, produced: list[str]
) -> None:
    # Without a decompiler, `get_arg_addrs` cannot read a call to an untyped
    # `lstrcpya` at all. That — and only that — is what earns the one write a
    # scan may make, so the arguments come back on the retry.
    rule = _stock_rule("strcpy")
    produced.append(ensure_managed_idb(str(compiled_shapes)))
    result = _scan(compiled_shapes, (rule,), decompiler="disabled")

    applied = result["scope_health"]["ida"]["applied_prototypes"]
    assert [entry["function"] for entry in applied] == ["lstrcpya"]
    assert applied[0]["prototype"] == (
        "char* lstrcpyA(char* lpString1, char* lpString2);"
    )
    assert applied[0]["address"].startswith("0x")
    # The retry recovered both arguments: the rule is unsupported because a
    # disassembly-only backend cannot establish `is_constant`, not because the
    # arguments are missing.
    reason = result["rule_coverage"][0]["reason"] or ""
    assert "constant" in reason
    assert result["scope_health"]["ida"]["call_sites"] == 1

    # The database now carries that type, so a second scan writes nothing more.
    again = _scan(compiled_shapes, (rule,))
    assert again["scope_health"]["ida"]["applied_prototypes"] == []


def test_verified_zero_arguments_get_info(
    compiled_shapes: Path, managed_data_dir: Path
) -> None:
    result = _scan(compiled_shapes, (ZERO_ARGUMENT_RULE,))

    assert result["rule_coverage"][0]["state"] == "evaluated"
    assert [row["priority"] for row in result["findings"]] == ["Info"]
    finding = result["findings"][0]
    assert finding["function_name"] == "reset_state"
    assert finding["found_in"] == "main"
    assert finding["evidence"]["argument_count"] == 0
    assert finding["evidence"]["params"] == []
    assert finding["evidence"]["matched_branch"] is None


def test_decompiler_unavailable_is_partial(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    # `decompiler="disabled"` runs the real disassembly-only extractor, the
    # same branch IDA takes when `init_hexrays_plugin()` is false. Nothing here
    # is stubbed: the facts below are the ones that path actually recovered.
    rule = _stock_rule("strcpy")
    result = _scan(compiled_calls, (rule,), decompiler="disabled")

    health = result["scope_health"]["ida"]
    assert health["analysis_mode"] == "disassembly"
    assert health["decompiler_available"] is True
    assert result["coverage"] == "partial"

    coverage = result["rule_coverage"][0]
    assert coverage["state"] == "unsupported"
    assert "2 of 3 call sites" in (coverage["reason"] or "")
    assert "constant" in (coverage["reason"] or "")

    # The two variable-source sites lost their facts, not their arguments: the
    # arguments were recovered, so this is neither an `Info` finding nor a
    # clean negative.
    assert health["call_sites"] == 3
    assert health["unsupported_sites"] == 2
    assert health["evaluated_sites"] == 1
    assert result["findings"] == []
