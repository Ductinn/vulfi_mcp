"""Behavior tests for the restricted VulFi rule expression interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from vulfi_mcp import ida_runtime, rules
from vulfi_mcp.ida_runtime import (
    MAX_COMPREHENSION_ITERATIONS,
    MAX_EXPRESSION_LENGTH,
    MAX_EXPRESSION_NODES,
    UNAVAILABLE,
    ExpressionBudgetError,
    ExpressionError,
    ExpressionEvaluationError,
    FunctionCall,
    InvalidExpressionError,
    Param,
    RuleContext,
    UnavailableEvidenceError,
    evaluate_rule,
    validate_expression,
)

# Verbatim stock expressions (Accenture/VulFi @0bb7fdf8) exercised below.
STOCK_STRCPY_HIGH = (
    "not param[1].is_constant() and not param[1].used_in_call_before(['strlen'])"
)
STOCK_FORMAT_MEDIUM = (
    "any([not param[i+1].is_constant()"
    " for i in range(len(param[1].string_value().split('%')))"
    " if param[1].string_value().split('%')[i].startswith('s')])"
)
STOCK_OBJC_HIGH = (
    "('appendformat:' in param[1].string_value().lower() and not param[2].is_constant())"
    " or ('stringwithformat:' in param[1].string_value().lower()"
    " and not param[2].is_constant())"
)


def make_rule(**branches: str) -> dict[str, Any]:
    mark_if = {"High": "False", "Medium": "False", "Low": "False"}
    mark_if.update(branches)
    return {
        "name": "Test Rule",
        "function_names": ["strcpy"],
        "wrappers": False,
        "mark_if": mark_if,
    }


def make_context(*params: Param, call: FunctionCall | None = None) -> RuleContext:
    return RuleContext(params=params, call=call or FunctionCall())


def test_priority_and_bounded_comprehensions() -> None:
    strcpy = make_rule(High=STOCK_STRCPY_HIGH, Low="not param[1].is_constant()")
    dest = Param(constant=False)

    unmeasured = make_context(dest, Param(constant=False, calls_before=()))
    measured = make_context(dest, Param(constant=False, calls_before=("strlen",)))
    constant = make_context(dest, Param(constant=True))

    assert evaluate_rule(strcpy, unmeasured) == "High"
    # High fails on the strlen guard, Medium is "False": the Low branch decides.
    assert evaluate_rule(strcpy, measured) == "Low"
    assert evaluate_rule(strcpy, constant) is None

    # "%s-%d-%s".split("%") == ["", "s-", "d-", "s"]: parts 1 and 3 start with "s",
    # so the comprehension inspects param[2] and param[4] only.
    fmt = make_rule(Medium=STOCK_FORMAT_MEDIUM)
    format_string = Param(constant=True, string="%s-%d-%s")
    variadic = make_context(
        dest,
        format_string,
        Param(constant=True),
        Param(constant=False),
        Param(constant=False),
    )
    all_constant = make_context(
        dest,
        format_string,
        Param(constant=True),
        Param(constant=False),
        Param(constant=True),
    )
    assert evaluate_rule(fmt, variadic) == "Medium"
    assert evaluate_rule(fmt, all_constant) is None

    # A hostile format string cannot buy unbounded iteration.
    huge = Param(constant=True, string="%s" * (MAX_COMPREHENSION_ITERATIONS + 1))
    with pytest.raises(ExpressionBudgetError, match="iterat"):
        evaluate_rule(fmt, make_context(dest, huge))


def test_all_stock_expressions_validate() -> None:
    stock = rules.load_stock_rules()
    assert len(stock) == 24

    branches = 0
    for rule in stock:
        for priority in rules.PRIORITIES:
            assert validate_expression(rule["mark_if"][priority]) is None
            branches += 1
    assert branches == 72

    # Validation alone is not enough: every stock rule must also run to a verdict
    # when the backend supplies every fact.
    facts = Param(
        constant=False,
        string="%s-%d-%s",
        number=0,
        const_number=False,
        size_bytes=8,
        indexed=True,
        sign_compared=True,
        nulled_after_call=False,
        calls_before=("strlen",),
        calls_after=("free",),
    )
    context = RuleContext(
        params=tuple(facts for _ in range(10)),
        call=FunctionCall(
            return_checked=True,
            return_check_values=(0,),
            reachable_from_names=("main",),
        ),
    )
    for rule in stock:
        assert evaluate_rule(rule, context) in {"High", "Medium", "Low", None}


REJECTED = InvalidExpressionError
OVER_BUDGET = ExpressionBudgetError


@pytest.mark.parametrize(
    ("expression", "message", "error"),
    [
        pytest.param(
            "__import__('os').system('id')", "__import__", REJECTED, id="import-dunder"
        ),
        pytest.param("import os", "could not be parsed", REJECTED, id="import-statement"),
        pytest.param("param_count = 1", "could not be parsed", REJECTED, id="assignment"),
        pytest.param(
            "param[0].__class__", "attribute access", REJECTED, id="dunder-attribute"
        ),
        pytest.param(
            "param[0].is_constant.__globals__",
            "attribute access",
            REJECTED,
            id="attribute-chain",
        ),
        pytest.param("param[0].__class__()", "dunder", REJECTED, id="dunder-call"),
        pytest.param(
            "open('/etc/passwd')", "unknown name 'open'", REJECTED, id="arbitrary-call"
        ),
        pytest.param("(lambda: 1)()", "lambda", REJECTED, id="lambda"),
        pytest.param("self", "unknown name 'self'", REJECTED, id="upstream-self-binding"),
        pytest.param(
            "param.append(1)", "unknown method 'append'", REJECTED, id="mutation"
        ),
        pytest.param(
            "[x for x in range(3) if (y := x)]",
            "assignment expression",
            REJECTED,
            id="walrus",
        ),
        pytest.param("f'{param_count}'", "f-string", REJECTED, id="f-string"),
        pytest.param("2 ** 64", "operator", REJECTED, id="power-operator"),
        pytest.param("param[0:2]", "slice", REJECTED, id="slice"),
        pytest.param("any(i for i in range(3))", "generator", REJECTED, id="generator"),
        pytest.param("{'a': 1}", "dict literal", REJECTED, id="dict-literal"),
        pytest.param("param[0].is_constant(1)", "is_constant", REJECTED, id="wrong-arity"),
        pytest.param(
            "[i for param in range(3)]", "shadow", REJECTED, id="comprehension-shadowing"
        ),
        pytest.param(
            "any([not param[0].is_constant() for i in range(" + "1+" * 400 + "1)])",
            "budget",
            OVER_BUDGET,
            id="over-budget-comprehension",
        ),
    ],
)
def test_rejects_python_escape_before_ida(
    expression: str, message: str, error: type[ExpressionError]
) -> None:
    with pytest.raises(error, match=message):
        validate_expression(expression)

    # evaluate_rule refuses the same expressions, with or without facts.
    with pytest.raises(error, match=message):
        evaluate_rule(make_rule(High=expression), make_context(Param()))


def test_verified_empty_argument_list_is_not_an_unavailable_fact() -> None:
    empty = RuleContext(params=(), call=FunctionCall())

    assert evaluate_rule(make_rule(High="param_count == 0"), empty) == "High"
    assert evaluate_rule(make_rule(High="param_count > 2"), empty) is None

    with pytest.raises(UnavailableEvidenceError) as excinfo:
        evaluate_rule(make_rule(High="not param[0].is_constant()"), empty)
    assert excinfo.value.param_index == 0
    assert "0 recovered argument" in str(excinfo.value)


def test_unavailable_arguments_never_evaluate_as_a_clean_negative() -> None:
    blind = RuleContext(params=UNAVAILABLE, call=FunctionCall())

    for expression in ("param_count == 0", "not param[0].is_constant()", "len(param)"):
        with pytest.raises(UnavailableEvidenceError, match="argument recovery"):
            evaluate_rule(make_rule(High=expression), blind)


def test_missing_facts_raise_instead_of_defaulting_to_false() -> None:
    with pytest.raises(UnavailableEvidenceError) as param_fact:
        evaluate_rule(
            make_rule(High="not param[0].is_constant()"), make_context(Param())
        )
    assert param_fact.value.fact == "constant"
    assert "param[0].is_constant()" in str(param_fact.value)

    with pytest.raises(UnavailableEvidenceError) as call_fact:
        evaluate_rule(
            make_rule(High="not function_call.return_value_checked()"),
            make_context(Param(), call=FunctionCall()),
        )
    assert call_fact.value.fact == "return_checked"

    # A checked return value is still not enough to answer the valued form.
    with pytest.raises(UnavailableEvidenceError) as valued:
        evaluate_rule(
            make_rule(High="not function_call.return_value_checked(param_count - 2)"),
            make_context(Param(), Param(), Param(), call=FunctionCall(return_checked=True)),
        )
    assert valued.value.fact == "return_check_values"


def test_literal_and_blank_branches_never_match_and_need_no_facts() -> None:
    blind = RuleContext(params=UNAVAILABLE, call=FunctionCall())

    assert evaluate_rule(make_rule(High="True"), blind) == "High"
    assert evaluate_rule(make_rule(High="False", Medium="", Low=""), blind) is None
    assert validate_expression("") is None
    assert validate_expression("   ") is None


def test_string_and_membership_operations_match_stock_semantics() -> None:
    objc = make_rule(High=STOCK_OBJC_HIGH)
    matched = make_context(
        Param(), Param(string="AppendFormat:withArgs"), Param(constant=False)
    )
    other = make_context(
        Param(), Param(string="lowercaseString"), Param(constant=False)
    )
    assert evaluate_rule(objc, matched) == "High"
    assert evaluate_rule(objc, other) is None

    numeric = make_rule(High="param[1].number_value() in [0, 1] or param[0].used_as_index()")
    assert evaluate_rule(numeric, make_context(Param(indexed=False), Param(number=1))) == "High"
    assert evaluate_rule(numeric, make_context(Param(indexed=True), Param(number=7))) == "High"
    assert evaluate_rule(numeric, make_context(Param(indexed=False), Param(number=7))) is None
    assert evaluate_rule(numeric, make_context(Param(indexed=False), Param(number=None))) is None


def test_function_name_matching_follows_upstream_variants() -> None:
    used = make_rule(High="param[0].used_in_call_before(['strlen'])")

    assert evaluate_rule(used, make_context(Param(calls_before=("_strlen",)))) == "High"
    assert evaluate_rule(used, make_context(Param(calls_before=(".strlen",)))) == "High"
    assert evaluate_rule(used, make_context(Param(calls_before=("strlen_0",)))) is None

    reachable = make_rule(High="function_call.reachable_from('main')")
    assert (
        evaluate_rule(
            reachable,
            make_context(Param(), call=FunctionCall(reachable_from_names=("_main",))),
        )
        == "High"
    )


def test_bad_predicate_arguments_are_a_failure_not_missing_evidence() -> None:
    # Task 4 maps UnavailableEvidenceError to "unsupported"; a malformed rule is
    # a failure instead, so the argument check must run before the fact lookup.
    wrong_type = make_rule(High="param[0].used_in_call_before('strlen')")

    with pytest.raises(ExpressionEvaluationError, match="list of function name"):
        evaluate_rule(wrong_type, make_context(Param()))
    with pytest.raises(ExpressionEvaluationError, match="list of function name"):
        evaluate_rule(wrong_type, make_context(Param(calls_before=("strlen",))))


def test_expression_budgets_are_pinned() -> None:
    assert MAX_EXPRESSION_LENGTH == 2000
    assert MAX_EXPRESSION_NODES == 500
    assert MAX_COMPREHENSION_ITERATIONS == 1000

    with pytest.raises(ExpressionBudgetError, match="character"):
        validate_expression("'" + "a" * MAX_EXPRESSION_LENGTH + "'")
    with pytest.raises(ExpressionBudgetError, match="node"):
        # A flat list: dense in nodes, cheap in characters and nesting.
        validate_expression("[" + "1," * MAX_EXPRESSION_NODES + "]")

    over_budget = make_rule(
        High=f"any([not param[0].is_constant() for i in range({MAX_COMPREHENSION_ITERATIONS + 1})])"
    )
    with pytest.raises(ExpressionBudgetError, match="iterat"):
        evaluate_rule(over_budget, make_context(Param(constant=True)))

    inside_budget = make_rule(
        High=f"any([not param[0].is_constant() for i in range({MAX_COMPREHENSION_ITERATIONS})])"
    )
    assert evaluate_rule(inside_budget, make_context(Param(constant=False))) == "High"


def test_branch_order_matches_the_rules_module() -> None:
    assert ida_runtime.PRIORITIES == rules.PRIORITIES


def test_rule_template_publishes_exactly_the_interpreted_surface() -> None:
    # rule_template() tells agents these are the only accepted calls; keep that true.
    language = rules.rule_template()["expression_language"]
    published = {
        key: {entry.split("(")[0] for entry in language[key]}
        for key in ("param_methods", "function_call_methods", "string_methods")
    }

    assert published["param_methods"] == set(ida_runtime._METHODS[Param])
    assert published["function_call_methods"] == set(ida_runtime._METHODS[FunctionCall])
    assert published["string_methods"] == set(ida_runtime._METHODS[str])
    assert set(language["builtins"]) == set(ida_runtime._BUILTIN_ARITIES)


def test_stock_rules_stay_well_inside_the_expression_budgets() -> None:
    longest = max(
        (
            rule["mark_if"][priority]
            for rule in rules.load_stock_rules()
            for priority in rules.PRIORITIES
        ),
        key=len,
    )
    assert len(longest) * 4 < MAX_EXPRESSION_LENGTH


def test_invalid_rule_expressions_are_rejected_with_a_rule_index() -> None:
    bad = make_rule(Medium="param[0].__class__")

    with pytest.raises(ValueError, match=r"rules\[0\]: mark_if\['Medium'\]"):
        rules.validate_rules([bad])


def test_module_runs_standalone_without_the_package_or_ida(tmp_path: Path) -> None:
    """The worker installs this file's source under its own module name.

    The child mirrors ``ida_nexus.RemoteModule``: it registers a bare
    ``types.ModuleType`` in ``sys.modules`` and execs the compiled source into
    it, with the package and every IDA module made unimportable.
    """
    module_path = Path(ida_runtime.__file__)
    child = """
import sys
import types

BLOCKED = (
    "vulfi_mcp", "ida_domain", "ida_nexus", "ida_mcp",
    "idaapi", "idc", "idautils", "ida_hexrays", "ida_ua",
)


class Blocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ImportError("blocked for this test: " + fullname)
        return None


sys.meta_path.insert(0, Blocker())
try:
    import vulfi_mcp
except ImportError:
    pass
else:
    raise AssertionError("the package must not be importable in this child")

with open(sys.argv[1], encoding="utf-8") as handle:
    source = handle.read()
module = types.ModuleType("vulfi_ida_runtime")
module.__file__ = sys.argv[1]
sys.modules["vulfi_ida_runtime"] = module
exec(compile(source, sys.argv[1], "exec"), module.__dict__)

assert not [name for name in sys.modules if name.split(".")[0] in BLOCKED]

module.validate_expression("not param[0].is_constant()")
rule = {
    "name": "standalone",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {"High": "not param[0].is_constant()", "Medium": "False", "Low": ""},
}
context = module.RuleContext(
    params=(module.Param(constant=False),), call=module.FunctionCall()
)
assert module.evaluate_rule(rule, context) == "High"
print("standalone ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", child, str(module_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "standalone ok"
