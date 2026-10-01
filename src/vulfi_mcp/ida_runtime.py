"""Restricted, IDA-free core that evaluates VulFi ``mark_if`` expressions.

Upstream VulFi (Accenture/VulFi commit ``0bb7fdf8``) evaluated every ``mark_if``
branch with :func:`eval`. Agent-authored rules are untrusted input here, so this
module parses each branch into an abstract syntax tree and interprets only a
whitelist of nodes, names, operators, builtins, and receiver methods. There is
no :func:`eval` and no :func:`exec` anywhere.

This file is shipped to the IDA worker **by path**
(``ida_nexus.RemoteModule("<path>/ida_runtime.py", codec="json")``) and executes
as a standalone module inside another interpreter, where
:func:`run` is its single entry point. It therefore imports nothing from the
:mod:`vulfi_mcp` package at runtime, uses no relative imports, and imports
nothing from IDA at module load; IDA APIs are imported inside worker
functions only. Rules arrive as plain JSON-native dictionaries.

Nothing here may depend on the module being registered in ``sys.modules``: a
loader that only executes the source would break ``@dataclass(slots=True)``,
which is why the fact types below are plain frozen dataclasses.

:class:`Param` and :class:`FunctionCall` are pure fact carriers: each predicate
answers from facts a backend verified and supplied. A fact that was not supplied
is :data:`UNAVAILABLE` and raises :class:`UnavailableEvidenceError` rather than
answering ``False``, so a backend that cannot recover an argument is reported as
``unsupported``/``partial`` instead of as a clean negative.

The worker half below :func:`run` is the other side of that contract: it
reproduces upstream's IDA evidence extraction and reports each predicate as a
JSON fact, leaving a fact it could not establish out of the payload entirely.
Rule evaluation itself stays on the host.

The last section owns the managed IDB's own authority: one versioned JSON
record in netnode ``vulfi_mcp.v2``, read, modified and written inside a single
worker operation so a finding, its assessment and its freshness never have to
be assembled from two round trips.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import operator
import time
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, TypeAlias, TypeVar

if TYPE_CHECKING:  # pragma: no cover - the worker never imports the package.
    from vulfi_mcp.rules import Rule

__all__ = [
    "MAX_ANALYSIS_ID_LENGTH",
    "MAX_COMPREHENSION_ITERATIONS",
    "MAX_EXPRESSION_DEPTH",
    "MAX_EXPRESSION_LENGTH",
    "MAX_EXPRESSION_NODES",
    "MAX_PAGE_LIMIT",
    "MAX_PREPARE_WARNINGS",
    "MAX_PROPOSALS",
    "MAX_PROPOSAL_EVIDENCE_FACTS",
    "MAX_PROPOSAL_FIELDS",
    "MAX_PROPOSAL_NAME_LENGTH",
    "MAX_PROPOSED_TABLE_ENTRIES",
    "MAX_RATIONALE_LENGTH",
    "MAX_SCAN_NAME_LENGTH",
    "MIN_DEFINED_STRING_CHARS",
    "MIN_STRING_CHARS",
    "NETNODE_BLOB_INDEX",
    "NETNODE_BLOB_TAG",
    "NETNODE_NAME",
    "PREPARE_CONTRACT",
    "PREPARE_COVERAGES",
    "PREPARE_LIMITS",
    "PREPARE_PASSES",
    "PRIORITIES",
    "PROPOSAL_ENCODINGS",
    "PROPOSAL_KINDS",
    "PROPOSAL_STATES",
    "SCHEMA_VERSION",
    "TRIAGE_STATUSES",
    "UNAVAILABLE",
    "BranchPriority",
    "ExpressionBudgetError",
    "ExpressionError",
    "ExpressionEvaluationError",
    "FunctionCall",
    "InvalidExpressionError",
    "OperationError",
    "Param",
    "RuleContext",
    "SchemaVersionError",
    "Unavailable",
    "UnavailableEvidenceError",
    "UnknownFindingError",
    "UnknownOperationError",
    "capability_fingerprint",
    "evaluate_rule",
    "finding_order",
    "proposal_payload",
    "run",
    "utc_now",
    "validate_analysis_id",
    "validate_expression",
    "validate_page",
    "validate_prepare_limits",
    "validate_prepare_passes",
    "validate_proposal",
    "validate_proposal_request",
    "validate_rationale",
    "validate_scan_name",
    "validate_scope",
    "validate_status",
]

BranchPriority: TypeAlias = Literal["High", "Medium", "Low"]

#: ``mark_if`` branches, evaluated in this order. Kept in step with
#: ``vulfi_mcp.rules.PRIORITIES``, which this standalone module cannot import.
PRIORITIES: Final[tuple[BranchPriority, BranchPriority, BranchPriority]] = (
    "High",
    "Medium",
    "Low",
)

#: Longest accepted branch, in characters. The longest stock expression is 359.
MAX_EXPRESSION_LENGTH: Final = 2000
#: Largest accepted syntax tree, in interpreted nodes. The largest stock
#: expression uses 66 of them.
MAX_EXPRESSION_NODES: Final = 500
#: Deepest accepted nesting, in interpreted nodes from the branch's root. The
#: deepest stock expression nests 9 of them. The character and node budgets do
#: not bound this: ``'not ' * 498 + 'True'`` is inside both and would recurse
#: the interpreter past Python's own frame limit, which aborts a scan instead
#: of refusing a rule.
MAX_EXPRESSION_DEPTH: Final = 50
#: Most elements one branch may touch: every ``range()`` it builds, every item a
#: comprehension or ``any()`` iterates, and every element an ``in`` scan
#: compares are charged to this one budget.
MAX_COMPREHENSION_ITERATIONS: Final = 1000


class ExpressionError(ValueError):
    """A rule expression is rejected or cannot be evaluated."""


class InvalidExpressionError(ExpressionError):
    """The expression uses syntax, a name, or a method outside the whitelist."""


class ExpressionBudgetError(ExpressionError):
    """The expression exceeds the size or iteration budget."""


class ExpressionEvaluationError(ExpressionError):
    """A whitelisted expression cannot be evaluated over the supplied values."""


class UnavailableEvidenceError(Exception):
    """A fact the expression needs was never supplied by the backend.

    This is not a negative result: callers map it to ``unsupported`` rule
    coverage or ``partial`` scan coverage. ``fact`` names the missing
    :class:`Param`/:class:`FunctionCall` field (``"params"`` when argument
    recovery itself is unavailable), ``source`` is the expression fragment that
    needed it, and ``param_index`` is set when the argument could not be located.
    """

    def __init__(
        self,
        message: str,
        *,
        fact: str,
        source: str | None = None,
        param_index: int | None = None,
    ) -> None:
        super().__init__(f"{source}: {message}" if source else message)
        self.fact = fact
        self.source = source
        self.param_index = param_index

    def locate(self, source: str) -> None:
        """Attach the expression fragment that asked for the missing fact."""
        if self.source is None:
            self.source = source
            self.args = (f"{source}: {self.args[0]}",)


class Unavailable:
    """Type of :data:`UNAVAILABLE`; compare with ``is``, never for truth."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNAVAILABLE"

    def __bool__(self) -> bool:
        raise TypeError("UNAVAILABLE has no truth value; test it with 'is UNAVAILABLE'")


#: An explicitly absent fact: the backend never established this value.
UNAVAILABLE: Final[Unavailable] = Unavailable()

BoolFact: TypeAlias = bool | Unavailable
StringFact: TypeAlias = str | Unavailable
NumberFact: TypeAlias = int | float | None | Unavailable
SizeFact: TypeAlias = int | Unavailable
NamesFact: TypeAlias = tuple[str, ...] | Unavailable
ValuesFact: TypeAlias = tuple[int | float, ...] | Unavailable

_FactValue = TypeVar("_FactValue")


def _fact(value: _FactValue | Unavailable, name: str) -> _FactValue:
    """Return a supplied fact, or refuse to answer when it was never supplied."""
    if isinstance(value, Unavailable):
        raise UnavailableEvidenceError(f"the {name!r} fact is unavailable", fact=name)
    return value


def _spellings(name: str) -> tuple[str, str, str]:
    """Upstream ``utils.prep_func_name``: a name, and its ``.`` and ``_`` forms."""
    base = name[1:] if name[:1] in (".", "_") else name
    return (base, f".{base}", f"_{base}")


def _name_spellings(wanted: object, method: str) -> set[str]:
    """Expand rule-supplied names the way upstream ``utils.prep_func_name`` does."""
    if not isinstance(wanted, (list, tuple)) or not all(
        isinstance(name, str) for name in wanted
    ):
        raise ExpressionEvaluationError(
            f"{method}() expects a list of function name strings"
        )
    spellings: set[str] = set()
    for name in wanted:
        spellings.update(_spellings(name))
    return spellings


@dataclass(frozen=True)
class Param:
    """One recovered call argument, carrying only facts a backend verified.

    Every field defaults to :data:`UNAVAILABLE`, so a predicate whose fact was
    never established raises :class:`UnavailableEvidenceError` instead of
    answering ``False``. Field names are the evidence; the methods are the
    upstream VulFi predicate surface that rules call.
    """

    #: ``is_constant()``: the argument is a literal or only ever assigned one.
    constant: BoolFact = UNAVAILABLE
    #: ``string_value()``: the referenced string literal, ``""`` when there is none.
    string: StringFact = UNAVAILABLE
    #: ``number_value()``: the immediate value, ``None`` when it is not a number.
    number: NumberFact = UNAVAILABLE
    #: ``is_const_number()``: the argument is a numeric literal.
    const_number: BoolFact = UNAVAILABLE
    #: ``size()``: width in bytes of the backing variable; an unmeasured width
    #: stays :data:`UNAVAILABLE` rather than becoming a number-less answer.
    size_bytes: SizeFact = UNAVAILABLE
    #: ``used_as_index()``: the argument indexes memory in the caller.
    indexed: BoolFact = UNAVAILABLE
    #: ``is_sign_compared()``: the argument reaches a signed comparison.
    sign_compared: BoolFact = UNAVAILABLE
    #: ``set_to_null_after_call()``: the argument is nulled right after the call.
    nulled_after_call: BoolFact = UNAVAILABLE
    #: ``used_in_call_before()``: callees taking this argument before the call.
    calls_before: NamesFact = UNAVAILABLE
    #: ``used_in_call_after()``: callees taking this argument after the call.
    calls_after: NamesFact = UNAVAILABLE

    def size(self) -> int:
        return _fact(self.size_bytes, "size_bytes")

    def used_as_index(self) -> bool:
        return _fact(self.indexed, "indexed")

    def is_constant(self) -> bool:
        return _fact(self.constant, "constant")

    def is_const_number(self) -> bool:
        return _fact(self.const_number, "const_number")

    def is_sign_compared(self) -> bool:
        return _fact(self.sign_compared, "sign_compared")

    def set_to_null_after_call(self) -> bool:
        return _fact(self.nulled_after_call, "nulled_after_call")

    def string_value(self) -> str:
        return _fact(self.string, "string")

    def number_value(self) -> int | float | None:
        return _fact(self.number, "number")

    def used_in_call_before(self, function_list: object) -> bool:
        wanted = _name_spellings(function_list, "used_in_call_before")
        return any(name in wanted for name in _fact(self.calls_before, "calls_before"))

    def used_in_call_after(self, function_list: object) -> bool:
        wanted = _name_spellings(function_list, "used_in_call_after")
        return any(name in wanted for name in _fact(self.calls_after, "calls_after"))


@dataclass(frozen=True)
class FunctionCall:
    """The matched call site itself, carrying only verified facts."""

    #: ``return_value_checked()``: the return value reaches a comparison.
    return_checked: BoolFact = UNAVAILABLE
    #: ``return_value_checked(value)``: the constants it is compared against.
    return_check_values: ValuesFact = UNAVAILABLE
    #: ``reachable_from()``: names of the functions this call site is reached from.
    reachable_from_names: NamesFact = UNAVAILABLE

    def return_value_checked(self, check_val: object = None) -> bool:
        if check_val is None:
            return _fact(self.return_checked, "return_checked")
        if isinstance(check_val, bool) or not isinstance(check_val, (int, float)):
            raise ExpressionEvaluationError(
                "return_value_checked() expects a number or no argument"
            )
        values = _fact(self.return_check_values, "return_check_values")
        return any(value == check_val for value in values)

    def reachable_from(self, function_name: object) -> bool:
        wanted = _name_spellings([function_name], "reachable_from")
        observed = _fact(self.reachable_from_names, "reachable_from_names")
        return any(name in wanted for name in observed)


@dataclass(frozen=True)
class RuleContext:
    """Everything one rule may ask about one call site.

    ``params`` is a tuple only when the backend verified the argument list: an
    empty tuple means a call site with no arguments, while :data:`UNAVAILABLE`
    means argument recovery failed and every ``param`` use raises
    :class:`UnavailableEvidenceError`.
    """

    params: tuple[Param, ...] | Unavailable = UNAVAILABLE
    call: FunctionCall = field(default_factory=FunctionCall)


def _string_lower(value: str) -> str:
    return value.lower()


def _string_split(value: str, separator: object = None) -> list[str]:
    if separator is None:
        return value.split()
    if not isinstance(separator, str) or not separator:
        raise ExpressionEvaluationError("split() expects a non-empty separator string")
    return value.split(separator)


def _string_startswith(value: str, prefix: object) -> bool:
    if not isinstance(prefix, str):
        raise ExpressionEvaluationError("startswith() expects a string prefix")
    return value.startswith(prefix)


#: Static value kinds, used to reject a method call on the wrong receiver before
#: any IDB is opened. Every name is also the phrase used in the error message.
_PARAM: Final = "a call argument"
_CALL: Final = "the function call"
_STR: Final = "a string"
_INT: Final = "an integer"
_NUMBER: Final = "a number"
_BOOL: Final = "a boolean"
_NONE: Final = "None"
_PARAMS: Final = "the argument list"
_STR_LIST: Final = "a list of strings"
_INT_LIST: Final = "a list of integers"
_LIST: Final = "a list"
_UNKNOWN: Final = "an unknown value"


@dataclass(frozen=True)
class _MethodSpec:
    call: Callable[..., object]
    min_args: int
    max_args: int
    result: str


_METHODS: Final[dict[type, dict[str, _MethodSpec]]] = {
    Param: {
        "size": _MethodSpec(Param.size, 0, 0, _INT),
        "used_as_index": _MethodSpec(Param.used_as_index, 0, 0, _BOOL),
        "is_constant": _MethodSpec(Param.is_constant, 0, 0, _BOOL),
        "is_const_number": _MethodSpec(Param.is_const_number, 0, 0, _BOOL),
        "is_sign_compared": _MethodSpec(Param.is_sign_compared, 0, 0, _BOOL),
        "set_to_null_after_call": _MethodSpec(
            Param.set_to_null_after_call, 0, 0, _BOOL
        ),
        "string_value": _MethodSpec(Param.string_value, 0, 0, _STR),
        "number_value": _MethodSpec(Param.number_value, 0, 0, _NUMBER),
        "used_in_call_before": _MethodSpec(Param.used_in_call_before, 1, 1, _BOOL),
        "used_in_call_after": _MethodSpec(Param.used_in_call_after, 1, 1, _BOOL),
    },
    FunctionCall: {
        "reachable_from": _MethodSpec(FunctionCall.reachable_from, 1, 1, _BOOL),
        "return_value_checked": _MethodSpec(
            FunctionCall.return_value_checked, 0, 1, _BOOL
        ),
    },
    str: {
        "lower": _MethodSpec(_string_lower, 0, 0, _STR),
        "split": _MethodSpec(_string_split, 0, 1, _STR_LIST),
        "startswith": _MethodSpec(_string_startswith, 1, 1, _BOOL),
    },
}

#: Receiver kinds that carry methods, mapped to their table in ``_METHODS``.
_RECEIVER_TYPES: Final[dict[str, type]] = {
    _PARAM: Param,
    _CALL: FunctionCall,
    _STR: str,
}
#: Kind of one element of an indexable or iterable kind.
_ELEMENT_KINDS: Final[dict[str, str]] = {
    _PARAMS: _PARAM,
    _STR_LIST: _STR,
    _INT_LIST: _INT,
}
#: Kind of a list built out of elements of a given kind.
_LIST_KINDS: Final[dict[str, str]] = {_STR: _STR_LIST, _INT: _INT_LIST}
_BUILTIN_RESULTS: Final[dict[str, str]] = {
    "any": _BOOL,
    "len": _INT,
    "range": _INT_LIST,
}


def _merged_arities() -> dict[str, tuple[int, int]]:
    merged: dict[str, tuple[int, int]] = {}
    for table in _METHODS.values():
        for name, spec in table.items():
            low, high = merged.get(name, (spec.min_args, spec.max_args))
            merged[name] = (min(low, spec.min_args), max(high, spec.max_args))
    return merged


def _merged_results() -> dict[str, str]:
    merged: dict[str, str] = {}
    for table in _METHODS.values():
        for name, spec in table.items():
            agreed = merged.get(name, spec.result) == spec.result
            merged[name] = spec.result if agreed else _UNKNOWN
    return merged


_METHOD_ARITIES: Final[dict[str, tuple[int, int]]] = _merged_arities()
_METHOD_RESULTS: Final[dict[str, str]] = _merged_results()
_BUILTIN_ARITIES: Final[dict[str, tuple[int, int]]] = {
    "any": (1, 1),
    "len": (1, 1),
    "range": (1, 3),
}
_BOUND_NAMES: Final[frozenset[str]] = frozenset({"param", "param_count", "function_call"})

_BOOL_OPS: Final = (ast.And, ast.Or)
_UNARY_OPS: Final = (ast.Not, ast.USub, ast.UAdd)
_BIN_OPS: Final = (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)
_COMPARE_OPS: Final = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
)
#: Ordering comparisons, applied once both operands are known comparable.
_ORDER_OPS: Final[dict[type, Callable[[Any, Any], bool]]] = {
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}
_LITERAL_TYPES: Final = (str, int, float, bool, type(None))
_CONTAINER_TYPES: Final = (list, tuple, range)

_NODE_LABELS: Final[dict[type, str]] = {
    ast.Attribute: "attribute access",
    ast.Await: "await",
    ast.Dict: "dict literal",
    ast.DictComp: "dict comprehension",
    ast.FormattedValue: "f-string",
    ast.GeneratorExp: "generator expression",
    ast.IfExp: "conditional expression",
    ast.JoinedStr: "f-string",
    ast.Lambda: "lambda",
    ast.NamedExpr: "assignment expression",
    ast.Set: "set literal",
    ast.SetComp: "set comprehension",
    ast.Slice: "slice",
    ast.Starred: "argument unpacking",
    ast.Tuple: "tuple literal",
    ast.Yield: "yield",
}


def _label(node: ast.AST) -> str:
    return _NODE_LABELS.get(type(node), type(node).__name__)


def _source(node: ast.AST) -> str:
    text = ast.unparse(node)
    return text if len(text) <= 60 else f"{text[:57]}..."


def validate_expression(expression: str) -> None:
    """Statically accept or reject one ``mark_if`` branch, without any facts.

    An empty or blank branch is a valid branch that never matches. Anything
    outside the whitelist raises :class:`InvalidExpressionError`, and an
    oversized branch raises :class:`ExpressionBudgetError`; both name the
    offending construct. Callers add their own framing, such as a rule index.
    """
    _prepare(expression)


def evaluate_rule(rule: Rule, context: RuleContext) -> BranchPriority | None:
    """Return the first ``mark_if`` branch that matches, or ``None`` if none do.

    Branches are evaluated in :data:`PRIORITIES` order. ``None`` means every
    branch was fully evaluated and none matched; it is never an extraction
    failure. A fact the backend never supplied raises
    :class:`UnavailableEvidenceError`, and a rejected or over-budget expression
    raises :class:`ExpressionError`.
    """
    mark_if = rule["mark_if"]
    for priority in PRIORITIES:
        tree = _prepare(mark_if[priority])
        if tree is None:
            continue
        if _Interpreter(context).evaluate(tree):
            return priority
    return None


def _prepare(expression: object) -> ast.Expression | None:
    """Return the checked syntax tree, or ``None`` for a blank branch."""
    if not isinstance(expression, str):
        raise InvalidExpressionError(
            f"expression must be a string, got {type(expression).__name__}"
        )
    if not expression.strip():
        return None
    return _compile(expression)


@lru_cache(maxsize=256)
def _compile(expression: str) -> ast.Expression:
    """Parse and whitelist-check one non-blank expression, memoized by source."""
    if len(expression) > MAX_EXPRESSION_LENGTH:
        raise ExpressionBudgetError(
            f"expression is {len(expression)} characters,"
            f" over the {MAX_EXPRESSION_LENGTH} character budget"
        )
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as error:
        raise InvalidExpressionError(
            f"expression could not be parsed as a single expression: {error.msg}"
        ) from None
    _Validator().check(tree, {})
    return tree


def _element_kind(node: ast.expr, bound: dict[str, str], depth: int = 0) -> str:
    """Static kind of one element of ``node``, or ``_UNKNOWN``."""
    return _ELEMENT_KINDS.get(_infer_kind(node, bound, depth), _UNKNOWN)


def _list_kind(element: str) -> str:
    """Static kind of a list whose elements are all of kind ``element``."""
    return _LIST_KINDS.get(element, _LIST)


def _infer_kind(node: ast.expr, bound: dict[str, str], depth: int = 0) -> str:
    """Infer what kind of value an expression produces, without any facts.

    Receivers in this language are a closed set, so an unmistakable kind lets
    :class:`_Validator` reject a method call on the wrong receiver before any
    IDB is opened. Anything not inferable is ``_UNKNOWN`` and stays permissive.

    This recursion runs *before* :meth:`_Validator.check` descends into the
    receiver, so it carries its own copy of the nesting budget: without one, a
    deeply nested receiver raises a bare ``RecursionError`` out of validation,
    where every other refusal is a rule-indexed :class:`ExpressionError`.
    """
    if depth > MAX_EXPRESSION_DEPTH:
        # The same refusal `_Validator.check` raises, and for the same reason
        # it quotes no source: unparsing an over-deep subtree recurses too.
        raise ExpressionBudgetError(
            f"expression is over the {MAX_EXPRESSION_DEPTH} nesting level budget"
        )
    depth += 1
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool):
            return _BOOL
        if isinstance(value, str):
            return _STR
        if isinstance(value, int):
            return _INT
        if isinstance(value, float):
            return _NUMBER
        return _NONE
    if isinstance(node, ast.Name):
        if node.id == "param":
            return _PARAMS
        if node.id == "param_count":
            return _INT
        if node.id == "function_call":
            return _CALL
        return bound.get(node.id, _UNKNOWN)
    if isinstance(node, ast.Subscript):
        return _element_kind(node.value, bound, depth)
    if isinstance(node, ast.List):
        kinds = {_infer_kind(element, bound, depth) for element in node.elts}
        return _list_kind(kinds.pop()) if len(kinds) == 1 else _LIST
    if isinstance(node, ast.ListComp):
        inner = dict(bound)
        for generator in node.generators:
            if isinstance(generator.target, ast.Name):
                inner[generator.target.id] = _element_kind(
                    generator.iter, bound, depth
                )
        return _list_kind(_infer_kind(node.elt, inner, depth))
    if isinstance(node, (ast.BoolOp, ast.Compare)):
        return _BOOL
    if isinstance(node, ast.UnaryOp):
        return _BOOL if isinstance(node.op, ast.Not) else _NUMBER
    if isinstance(node, ast.BinOp):
        return _NUMBER
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return _BUILTIN_RESULTS.get(func.id, _UNKNOWN)
        if isinstance(func, ast.Attribute):
            table = _METHODS.get(
                _RECEIVER_TYPES.get(_infer_kind(func.value, bound, depth))
            )
            if table is not None and func.attr in table:
                return table[func.attr].result
            return _METHOD_RESULTS.get(func.attr, _UNKNOWN)
    return _UNKNOWN


class _Validator:
    """Walks one parsed branch and rejects everything outside the whitelist."""

    __slots__ = ("_depth", "_nodes")

    def __init__(self) -> None:
        self._nodes = 0
        self._depth = 0

    def check(self, node: ast.AST, bound: dict[str, str]) -> None:
        """One node and everything under it, inside every size budget.

        Depth is charged here rather than in :class:`_Interpreter` because the
        interpreter recurses once, sometimes twice, per nested node: a branch
        deep enough to exhaust Python's frame limit must be refused while it is
        still JSON, before any database has been created or opened.
        """
        self._count()
        self._depth += 1
        if self._depth > MAX_EXPRESSION_DEPTH:
            raise ExpressionBudgetError(
                # No `_source(node)` here: unparsing an over-deep subtree is
                # itself recursive, so the refusal would raise the very error
                # it exists to prevent.
                f"expression is over the {MAX_EXPRESSION_DEPTH} nesting"
                " level budget"
            )
        try:
            self._walk(node, bound)
        finally:
            self._depth -= 1

    def _walk(self, node: ast.AST, bound: dict[str, str]) -> None:
        if isinstance(node, ast.Expression):
            self.check(node.body, bound)
        elif isinstance(node, ast.BoolOp):
            self._check_op(node.op, _BOOL_OPS, node)
            for value in node.values:
                self.check(value, bound)
        elif isinstance(node, ast.UnaryOp):
            self._check_op(node.op, _UNARY_OPS, node)
            self.check(node.operand, bound)
        elif isinstance(node, ast.BinOp):
            self._check_op(node.op, _BIN_OPS, node)
            self.check(node.left, bound)
            self.check(node.right, bound)
        elif isinstance(node, ast.Compare):
            for op in node.ops:
                self._check_op(op, _COMPARE_OPS, node)
            self.check(node.left, bound)
            for comparator in node.comparators:
                self.check(comparator, bound)
        elif isinstance(node, ast.Constant):
            if not isinstance(node.value, _LITERAL_TYPES):
                _reject(f"the {type(node.value).__name__} literal", node)
        elif isinstance(node, ast.Name):
            self._check_name(node, bound)
        elif isinstance(node, ast.List):
            self._check_load(node)
            for element in node.elts:
                self.check(element, bound)
        elif isinstance(node, ast.Subscript):
            self._check_load(node)
            self.check(node.value, bound)
            self.check(node.slice, bound)
        elif isinstance(node, ast.ListComp):
            self._check_comprehension(node, bound)
        elif isinstance(node, ast.Call):
            self._check_call(node, bound)
        else:
            _reject(_label(node), node)

    def _count(self) -> None:
        self._nodes += 1
        if self._nodes > MAX_EXPRESSION_NODES:
            raise ExpressionBudgetError(
                f"expression is over the {MAX_EXPRESSION_NODES} node budget"
            )

    def _check_op(self, op: ast.AST, allowed: tuple[type, ...], node: ast.AST) -> None:
        if not isinstance(op, allowed):
            raise InvalidExpressionError(
                f"unsupported operator {type(op).__name__!r} in: {_source(node)}"
            )

    def _check_load(self, node: ast.Name | ast.List | ast.Subscript) -> None:
        if not isinstance(node.ctx, ast.Load):
            _reject("assignment to", node)

    def _check_name(self, node: ast.Name, bound: dict[str, str]) -> None:
        self._check_load(node)
        if node.id not in bound and node.id not in _BOUND_NAMES:
            raise InvalidExpressionError(
                f"unknown name {node.id!r}; only"
                f" {', '.join(sorted(_BOUND_NAMES))} are bound"
            )

    def _check_comprehension(self, node: ast.ListComp, bound: dict[str, str]) -> None:
        if len(node.generators) != 1:
            _reject("a comprehension with more than one 'for' clause", node)
        generator = node.generators[0]
        if generator.is_async:
            _reject("an async comprehension", node)
        target = generator.target
        if not isinstance(target, ast.Name):
            _reject("a comprehension target that is not a plain name", node)
        if target.id in _BOUND_NAMES:
            raise InvalidExpressionError(
                f"a comprehension target may not shadow {target.id!r}: {_source(node)}"
            )
        self.check(generator.iter, bound)
        inner = {**bound, target.id: _element_kind(generator.iter, bound)}
        for condition in generator.ifs:
            self.check(condition, inner)
        self.check(node.elt, inner)

    def _check_call(self, node: ast.Call, bound: dict[str, str]) -> None:
        if node.keywords:
            _reject("a keyword argument", node)
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                _reject("argument unpacking", node)
        func = node.func
        self._count()
        if isinstance(func, ast.Name):
            if func.id not in _BUILTIN_ARITIES:
                raise InvalidExpressionError(
                    f"unknown name {func.id!r}; only"
                    f" {', '.join(sorted(_BUILTIN_ARITIES))} may be called"
                )
            self._check_arity(func.id, _BUILTIN_ARITIES[func.id], node)
        elif isinstance(func, ast.Attribute):
            if func.attr.startswith("__"):
                _reject(f"dunder access {func.attr!r}", node)
            if func.attr not in _METHOD_ARITIES:
                raise InvalidExpressionError(
                    f"unknown method {func.attr!r} in: {_source(node)}"
                )
            receiver = _infer_kind(func.value, bound)
            table = _METHODS.get(_RECEIVER_TYPES.get(receiver))
            spec = table.get(func.attr) if table is not None else None
            if spec is None and receiver != _UNKNOWN:
                raise InvalidExpressionError(
                    f"{func.attr}() is not a method of {receiver}: {_source(node)}"
                )
            arity = (
                (spec.min_args, spec.max_args)
                if spec is not None
                else _METHOD_ARITIES[func.attr]
            )
            self._check_arity(func.attr, arity, node)
            self.check(func.value, bound)
        else:
            _reject(f"a call of {_label(func)}", node)
        for argument in node.args:
            self.check(argument, bound)

    def _check_arity(
        self, name: str, arity: tuple[int, int], node: ast.Call
    ) -> None:
        low, high = arity
        if not low <= len(node.args) <= high:
            expected = f"{low}" if low == high else f"{low} to {high}"
            raise InvalidExpressionError(
                f"{name}() takes {expected} argument(s),"
                f" got {len(node.args)}: {_source(node)}"
            )


def _reject(description: str, node: ast.AST) -> NoReturn:
    raise InvalidExpressionError(f"{description} is not allowed: {_source(node)}")


class _Interpreter:
    """Evaluates one already-whitelisted branch against one call site."""

    __slots__ = ("_context", "_names", "_iterations")

    def __init__(self, context: RuleContext) -> None:
        self._context = context
        self._names: dict[str, object] = {}
        self._iterations = 0

    def evaluate(self, tree: ast.Expression) -> bool:
        return self._truth(self._eval(tree.body), tree.body)

    def _charge(self, items: int = 1) -> None:
        """Charge scanned or built elements to this branch's iteration budget."""
        self._iterations += items
        if self._iterations > MAX_COMPREHENSION_ITERATIONS:
            raise ExpressionBudgetError(
                f"expression is over the {MAX_COMPREHENSION_ITERATIONS}"
                f" iteration budget"
            )

    def _eval(self, node: ast.expr) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self._name(node)
        if isinstance(node, ast.BoolOp):
            return self._bool_op(node)
        if isinstance(node, ast.UnaryOp):
            return self._unary_op(node)
        if isinstance(node, ast.Compare):
            return self._compare(node)
        if isinstance(node, ast.Call):
            return self._call(node)
        if isinstance(node, ast.Subscript):
            return self._subscript(node)
        if isinstance(node, ast.BinOp):
            return self._bin_op(node)
        if isinstance(node, ast.List):
            return [self._eval(element) for element in node.elts]
        if isinstance(node, ast.ListComp):
            return self._comprehension(node)
        raise InvalidExpressionError(f"{_label(node)} is not allowed: {_source(node)}")

    def _truth(self, value: object, node: ast.expr) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float, str, list, tuple, range)):
            return bool(value)
        raise ExpressionEvaluationError(f"{_source(node)} has no truth value")

    def _number(self, value: object, node: ast.expr) -> int | float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ExpressionEvaluationError(f"{_source(node)} is not a number")
        return value

    def _index(self, value: object, node: ast.expr) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExpressionEvaluationError(f"{_source(node)} is not an integer index")
        return value

    def _name(self, node: ast.Name) -> object:
        if node.id in self._names:
            return self._names[node.id]
        if node.id == "param":
            return self._params(node)
        if node.id == "param_count":
            return len(self._params(node))
        if node.id == "function_call":
            return self._context.call
        raise InvalidExpressionError(f"unknown name {node.id!r}")

    def _params(self, node: ast.expr) -> tuple[Param, ...]:
        params = self._context.params
        if isinstance(params, Unavailable):
            raise UnavailableEvidenceError(
                "argument recovery is unavailable at this call site",
                fact="params",
                source=_source(node),
            )
        return params

    def _bool_op(self, node: ast.BoolOp) -> bool:
        if isinstance(node.op, ast.And):
            return all(self._truth(self._eval(value), value) for value in node.values)
        return any(self._truth(self._eval(value), value) for value in node.values)

    def _unary_op(self, node: ast.UnaryOp) -> object:
        if isinstance(node.op, ast.Not):
            return not self._truth(self._eval(node.operand), node.operand)
        value = self._number(self._eval(node.operand), node.operand)
        return -value if isinstance(node.op, ast.USub) else +value

    def _bin_op(self, node: ast.BinOp) -> int | float:
        left = self._number(self._eval(node.left), node.left)
        right = self._number(self._eval(node.right), node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if right == 0:
            raise ExpressionEvaluationError(f"division by zero in: {_source(node)}")
        return left // right if isinstance(node.op, ast.FloorDiv) else left % right

    def _compare(self, node: ast.Compare) -> bool:
        left_node: ast.expr = node.left
        left = self._eval(left_node)
        for op, right_node in zip(node.ops, node.comparators):
            right = self._eval(right_node)
            if not self._compare_pair(op, left, right, left_node, right_node):
                return False
            left, left_node = right, right_node
        return True

    def _compare_pair(
        self,
        op: ast.cmpop,
        left: object,
        right: object,
        left_node: ast.expr,
        right_node: ast.expr,
    ) -> bool:
        if isinstance(op, ast.Eq):
            return bool(left == right)
        if isinstance(op, ast.NotEq):
            return bool(left != right)
        if isinstance(op, (ast.In, ast.NotIn)):
            found = self._contains(left, right, left_node, right_node)
            return found if isinstance(op, ast.In) else not found
        if not (isinstance(left, str) and isinstance(right, str)):
            left = self._number(left, left_node)
            right = self._number(right, right_node)
        return _ORDER_OPS[type(op)](left, right)

    def _contains(
        self,
        item: object,
        container: object,
        item_node: ast.expr,
        container_node: ast.expr,
    ) -> bool:
        if isinstance(container, str):
            if not isinstance(item, str):
                raise ExpressionEvaluationError(
                    f"{_source(item_node)} is not a string, so it cannot be looked for"
                    f" in {_source(container_node)}"
                )
            return item in container
        if isinstance(container, _CONTAINER_TYPES):
            for element in container:
                self._charge()
                if item == element:
                    return True
            return False
        raise ExpressionEvaluationError(
            f"{_source(container_node)} is not a string or list"
        )

    def _subscript(self, node: ast.Subscript) -> object:
        index = self._index(self._eval(node.slice), node.slice)
        if isinstance(node.value, ast.Name) and node.value.id == "param":
            return self._argument(index, node)
        container = self._eval(node.value)
        if not isinstance(container, _CONTAINER_TYPES):
            raise ExpressionEvaluationError(
                f"{_source(node.value)} is not a list and cannot be indexed"
            )
        if not -len(container) <= index < len(container):
            raise ExpressionEvaluationError(
                f"index {index} is out of range for the {len(container)} item(s)"
                f" in: {_source(node)}"
            )
        return container[index]

    def _argument(self, index: int, node: ast.Subscript) -> Param:
        params = self._params(node)
        if index < 0:
            raise ExpressionEvaluationError(
                f"param is indexed from zero, so {index} is never an argument"
                f" in: {_source(node)}"
            )
        if index >= len(params):
            raise UnavailableEvidenceError(
                f"argument {index} is not available: this call site has"
                f" {len(params)} recovered argument(s)",
                fact="params",
                source=_source(node),
                param_index=index,
            )
        return params[index]

    def _call(self, node: ast.Call) -> object:
        func = node.func
        if isinstance(func, ast.Name):
            return self._builtin(func.id, node)
        if not isinstance(func, ast.Attribute):  # guaranteed by _Validator
            _reject(f"a call of {_label(func)}", node)
        receiver = self._eval(func.value)
        table = _METHODS.get(type(receiver))
        if table is None or func.attr not in table:
            raise ExpressionEvaluationError(
                f"{_source(func.value)} has no method {func.attr!r}"
            )
        spec = table[func.attr]
        arguments = [self._eval(argument) for argument in node.args]
        if not spec.min_args <= len(arguments) <= spec.max_args:
            raise ExpressionEvaluationError(
                f"{func.attr}() does not take {len(arguments)} argument(s)"
                f" on {type(receiver).__name__}"
            )
        try:
            return spec.call(receiver, *arguments)
        except UnavailableEvidenceError as error:
            error.locate(_source(node))
            raise

    def _builtin(self, name: str, node: ast.Call) -> object:
        arguments = [self._eval(argument) for argument in node.args]
        if name == "len":
            value = arguments[0]
            if isinstance(value, (str, list, tuple, range)):
                return len(value)
            raise ExpressionEvaluationError(
                f"len() expects a string or list: {_source(node)}"
            )
        if name == "any":
            values = arguments[0]
            if not isinstance(values, _CONTAINER_TYPES):
                raise ExpressionEvaluationError(
                    f"any() expects a list: {_source(node)}"
                )
            for value in values:
                self._charge()
                if self._truth(value, node):
                    return True
            return False
        bounds = [
            self._index(value, argument)
            for value, argument in zip(arguments, node.args)
        ]
        if len(bounds) == 3 and bounds[2] == 0:
            raise ExpressionEvaluationError("range() step must not be zero")
        span = range(*bounds)
        self._charge(len(span))
        return span

    def _comprehension(self, node: ast.ListComp) -> list[object]:
        generator = node.generators[0]
        iterable = self._eval(generator.iter)
        if not isinstance(iterable, _CONTAINER_TYPES):
            raise ExpressionEvaluationError(
                f"a comprehension can only iterate a list or range:"
                f" {_source(generator.iter)}"
            )
        target = generator.target
        if not isinstance(target, ast.Name):
            _reject("a comprehension target that is not a plain name", node)
        name = target.id
        shadowed = name in self._names
        previous = self._names.get(name)
        results: list[object] = []
        try:
            for item in iterable:
                self._charge()
                self._names[name] = item
                if all(
                    self._truth(self._eval(condition), condition)
                    for condition in generator.ifs
                ):
                    results.append(self._eval(node.elt))
        finally:
            if shadowed:
                self._names[name] = previous
            else:
                self._names.pop(name, None)
        return results


# ---------------------------------------------------------------------------
# Worker entry point.
#
# Everything below runs inside the IDA process, reached through the single
# ``run`` function that ``vulfi_mcp.ida_adapter`` binds with
# ``RemoteModule(..., codec="json")``. IDA is imported inside the operation
# bodies only, so this module still imports standalone on a host without IDA.
# ---------------------------------------------------------------------------


class OperationError(ValueError):
    """A worker operation was rejected before it touched the database.

    It derives from :class:`ValueError` because every rejection below is a
    rejected argument, and because the host raises the same class for the
    checks it runs before it opens a database at all.
    """


class UnknownOperationError(OperationError):
    """No operation is registered under the requested name."""


class SchemaVersionError(OperationError):
    """The stored record is a schema version this build must not overwrite."""


class UnknownFindingError(OperationError):
    """No stored finding carries the requested ID."""


def run(operation: str, payload: dict[str, object]) -> dict[str, object]:
    """Dispatch one named operation against the database this worker has open.

    ``payload`` and the returned dictionary are JSON-native throughout: the
    adapter normalizes both, and the ``json`` codec carries nothing else.

    Every result carries its ``operation`` and a ``mutated`` flag. ``mutated``
    is the only signal the adapter has that the IDB must be saved, so an
    operation that writes to the database MUST report ``True``.
    """
    if not isinstance(operation, str):
        raise OperationError(
            f"operation must be a string, got {type(operation).__name__}"
        )
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise OperationError(
            f"{operation}: payload must be a JSON object,"
            f" got {type(payload).__name__}"
        )
    handler = _OPERATIONS.get(operation)
    if handler is None:
        known = ", ".join(sorted(_OPERATIONS))
        raise UnknownOperationError(
            f"unknown IDA operation: {operation!r}; known operations: {known}"
        )
    result = handler(payload)
    result["operation"] = operation
    result.setdefault("mutated", False)
    return result


def _database_summary(payload: dict[str, object]) -> dict[str, object]:
    """Report what IDA loaded and what its analysis found.

    ``name_limit`` caps how many function names travel back; the count is
    always exact and ``names_truncated`` says whether the list is complete.
    """
    import ida_funcs
    import ida_hexrays
    import ida_loader
    import ida_nalt
    import idautils

    limit = _int_option(payload, "name_limit", 100)
    names: list[str] = []
    total = 0
    for address in idautils.Functions():
        total += 1
        if len(names) < limit:
            names.append(ida_funcs.get_func_name(address))
    digest = ida_nalt.retrieve_input_file_sha256()
    return {
        "mutated": False,
        "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
        "input_file": ida_nalt.get_root_filename(),
        "input_sha256": digest.hex() if digest else None,
        "function_count": total,
        "function_names": names,
        "names_truncated": total > len(names),
        "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
    }


def _int_option(payload: dict[str, object], name: str, default: int) -> int:
    """Read one optional non-negative integer option out of a payload."""
    value = payload.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OperationError(f"{name} must be a non-negative integer, got {value!r}")
    return value


# ---------------------------------------------------------------------------
# Scan operation: what one IDA database can say about one set of rules.
#
# This mirrors Accenture/VulFi ``0bb7fdf8``'s ``VulFiScanner``: the same name
# matching, the same call xrefs, the same argument extraction, the same
# one-level wrapper discovery, and the same array/loop pseudo-rules. Upstream
# answered a ``Param``/``FunctionCall`` predicate from a live ctree while it
# evaluated a rule, and answered ``False`` whenever the decompiler was absent
# or the lookup failed. This worker answers every predicate once, up front, as
# a plain JSON fact, and simply omits a fact it could not establish; the host
# then reports that rule ``unsupported`` where upstream invented a negative.
# ---------------------------------------------------------------------------

#: ``function_names`` values that select a pseudo-rule instead of call xrefs.
ARRAY_RULE_NAME: Final = "Array Access"
LOOP_RULE_NAME: Final = "Loop Check"

#: Ceilings on one scan's work. A payload may lower a bound, never raise one,
#: and a scan that hits a bound says so instead of truncating in silence.
SCAN_LIMITS: Final[dict[str, int]] = {
    #: Functions decompiled for the array and loop pseudo-rules.
    "functions": 5000,
    #: Call sites recorded for one rule.
    "sites": 2000,
    #: ctree items examined in one function; a larger ctree is not analyzed.
    "tree_items": 60000,
    #: Call sites followed out of one wrapper, one level deep as upstream.
    "wrappers": 64,
    #: Functions walked to answer ``reachable_from``.
    "callers": 512,
    #: Callee names recorded for one argument.
    "names": 64,
    #: String references indexed for the disassembly-only string search.
    "strings": 20000,
}

#: Most warnings one scan result carries back.
MAX_SCAN_WARNINGS: Final = 64

#: Decompiled functions kept alive at once. Their ctree items are only valid
#: while the ``cfunc_t`` that owns them is, so the caches are only ever
#: dropped between call sites and between functions.
_CFUNC_CACHE: Final = 256

_MISSING: Final = object()


class _Unestablished(Exception):
    """IDA did not establish this fact, so the scan reports it as absent."""


class _Scanner:
    """One pass of VulFi evidence extraction over the open database."""

    def __init__(self, payload: dict[str, object]) -> None:
        import ida_funcs
        import ida_hexrays
        import ida_ida
        import ida_loader
        import ida_nalt
        import ida_segment
        import ida_typeinf
        import ida_ua
        import idaapi
        import idautils
        import idc

        self._funcs = ida_funcs
        self._hx = ida_hexrays
        self._loader = ida_loader
        self._nalt = ida_nalt
        self._segment = ida_segment
        self._typeinf = ida_typeinf
        self._ua = ida_ua
        self._api = idaapi
        self._utils = idautils
        self._idc = idc

        self._rules = _scan_rules(payload)
        self._prototypes = _scan_prototypes(payload)
        self._limits = _scan_limits(payload)
        requested = payload.get("decompiler", "auto")
        if requested not in ("auto", "disabled"):
            raise OperationError(
                f"decompiler must be 'auto' or 'disabled', got {requested!r}"
            )
        self._requested = requested
        self._available = bool(ida_hexrays.init_hexrays_plugin())
        #: The one switch upstream flips when ``init_hexrays_plugin`` is false.
        self._hexrays = self._available and requested == "auto"
        self._ptr_size = 8 if ida_ida.inf_is_64bit() else 4
        self._endian = "big" if ida_ida.inf_is_be() else "little"
        self._image_base = idaapi.get_imagebase()
        self._functions: list[int] = []
        self._code_functions: list[int] = []
        self._applied: list[dict[str, object]] = []
        #: Functions a pinned prototype has already been offered to.
        self._typed: set[int] = set()
        self._warnings: list[str] = []
        self._bounded = False
        self._cfuncs: dict[int, Any] = {}
        self._trees: dict[int, Any] = {}
        self._op_names: dict[int, str] | None = None
        self._strings: dict[int, list[tuple[int, str]]] | None = None

    # -- entry point ------------------------------------------------------

    def run(self) -> dict[str, object]:
        self._collect_functions()
        records: list[dict[str, object]] = []
        for rule in self._rules:
            names = rule["function_names"]
            if names == [ARRAY_RULE_NAME]:
                records.append(self._pseudo_record(rule, "array"))
            elif names == [LOOP_RULE_NAME]:
                records.append(self._pseudo_record(rule, "loop"))
            else:
                records.append(self._call_record(rule))
        digest = self._nalt.retrieve_input_file_sha256()
        return {
            "mutated": bool(self._applied),
            "analysis_mode": "ctree" if self._hexrays else "disassembly",
            "decompiler_available": self._available,
            "decompiler_requested": self._requested,
            "idb_path": self._loader.get_path(self._loader.PATH_TYPE_IDB),
            "input_file": self._nalt.get_root_filename(),
            "input_sha256": digest.hex() if digest else None,
            "image_base": hex(self._image_base),
            "function_count": len(self._functions),
            "code_function_count": len(self._code_functions),
            "applied_prototypes": self._applied,
            "rules": records,
            "warnings": self._warnings,
            "bounded": self._bounded,
        }

    # -- discovery --------------------------------------------------------

    def _collect_functions(self) -> None:
        """Every function and import, the way upstream gathers them.

        ``_code_functions`` drops the ``extern`` segment, whose entries IDA
        lists as functions but which hold no code to decompile: a pseudo-rule
        that skipped them would otherwise have to report missing evidence for
        every imported symbol in the binary.
        """
        seen: set[int] = set()
        for segment_ea in self._utils.Segments():
            segment = self._segment.getseg(segment_ea)
            if segment is None:
                continue
            is_code = segment.type == self._idc.SEG_CODE
            for ea in self._utils.Functions(segment.start_ea, segment.end_ea):
                if ea in seen:
                    continue
                seen.add(ea)
                self._functions.append(ea)
                if is_code:
                    self._code_functions.append(ea)

        def collect(ea: int, _name: str, _ordinal: int) -> bool:
            if ea not in seen:
                seen.add(ea)
                self._functions.append(ea)
            return True

        for index in range(self._api.get_import_module_qty()):
            self._api.enum_import_names(index, collect)

    def _apply_prototype(self, ea: int, name: str, rule_named: bool) -> bool:
        """Type a rule-named function VulFi ships a prototype for, once.

        Upstream applied a prototype to every function it recognized, up
        front. This runs only after argument recovery for a call to ``ea``
        actually failed, which is the only state in which a missing prototype
        is what the recovery lacked: a function IDA already types, and one the
        decompiler recovered arguments for on its own, are never rewritten. It
        is the only write this operation makes, it happens in the managed
        database alone, and every application is reported back as
        ``applied_prototypes``.

        ``rule_named`` is what makes "rule-named" true rather than assumed. A
        wrapper site would otherwise offer the pinned prototype to the
        *wrapper*, which the rule never named: a local function whose name
        happens to collide with one of the pinned keys would be typed as the
        library function it shares a name with, and every fact later extracted
        from calls to it would be read through the wrong prototype.
        """
        if not rule_named or not name or ea in self._typed:
            return False
        self._typed.add(ea)
        prototype = self._prototypes.get(name.lower())
        if prototype is None:
            return False
        try:
            if self._idc.get_type(ea):
                return False
            applied = bool(self._idc.SetType(ea, prototype))
            if applied:
                self._api.auto_wait()
        except Exception as error:
            self._warn(f"{name}: SetType: {type(error).__name__}: {error}")
            return False
        if not applied:
            self._warn(f"{name}: IDA did not accept the pinned prototype")
            return False
        self._forget_decompilations()
        self._applied.append(
            {"function": name, "address": hex(ea), "prototype": prototype}
        )
        return True

    def _forget_decompilations(self) -> None:
        """Drop every cached ctree: a new prototype changes what they say."""
        for entry in self._cfuncs:
            # No decompiler, or nothing cached for that function.
            with suppress(Exception):
                self._hx.mark_cfunc_dirty(entry)
        self._cfuncs.clear()
        self._trees.clear()

    def _wanted_names(self, rule: dict[str, Any]) -> set[str]:
        """The spellings upstream matches a function name against."""
        names: set[str] = set()
        for name in rule["function_names"]:
            for spelling in _spellings(name):
                names.add(self._pretty(spelling))
        return names

    def _call_record(self, rule: dict[str, Any]) -> dict[str, object]:
        """``find_xrefs_by_name``: every call to a named function, in order."""
        wanted = self._wanted_names(rule)
        sites: list[dict[str, object]] = []
        notes: list[str] = []
        truncated = False
        if rule["wrappers"] and not self._hexrays:
            # `_wrapper_sites` needs a ctree and has none, so half of what this
            # rule asked for cannot run. Said here, the rule reads `unsupported`
            # and the scan `partial`; left unsaid, "no wrapper was found" and
            # "wrapper discovery never ran" would be the same answer.
            notes.append(
                "wrapper discovery needs the decompiler, which this scan did"
                " not use, so only direct call sites were examined"
            )
        seen: set[tuple[int, str]] = set()
        for ea in self._functions:
            if truncated:
                break
            name = self._func_name(ea)
            if not name:
                continue
            if name not in wanted:
                name = name.lower()
                if name not in wanted:
                    continue
            for xref in self._utils.XrefsTo(ea):
                if len(sites) >= self._limits["sites"]:
                    truncated = True
                    self._bounded = True
                    notes.append(
                        f"stopped at the {self._limits['sites']} call site scan budget"
                    )
                    break
                holder = self._func_name(xref.frm)
                if not holder or holder.lower() in wanted:
                    continue
                if not self._is_call(xref.frm):
                    continue
                key = (xref.frm, name)
                if key in seen:
                    continue
                self._trim()
                wrappers = (
                    self._wrapper_sites(xref.frm, name) if rule["wrappers"] else []
                )
                if not wrappers:
                    seen.add(key)
                    sites.append(self._call_site(xref.frm, name, name, ea))
                    continue
                # Upstream emits the wrapped call right before its wrappers and
                # never reports it: it only decides whether the wrappers are
                # worth looking at.
                sites.append(
                    self._call_site(
                        xref.frm,
                        name,
                        name,
                        ea,
                        display=f"{name} (wrapped:{len(wrappers)})",
                        gate=True,
                        wrapped=len(wrappers),
                    )
                )
                sites.extend(wrappers)
        return {
            "rule_index": rule["index"],
            "kind": "calls",
            "sites": sites,
            "truncated": truncated,
            "notes": notes,
        }

    def _is_call(self, ea: int) -> bool:
        """Upstream's instruction test: a call, or a jump to a fixed target."""
        insn = self._ua.insn_t()
        if self._ua.decode_insn(insn, ea) == self._idc.BADADDR:
            return False
        feature = insn.get_canon_feature()
        if feature & 0x2 == 0x2:
            return True
        return feature & 0xFFF == 0x100 and insn.Op1.type in (
            self._idc.o_near,
            self._idc.o_far,
        )

    def _wrapper_sites(
        self, call_ea: int, callee_name: str
    ) -> list[dict[str, object]]:
        """``get_wrapper_xrefs``: one level, and only with a decompiler.

        A containing function is a wrapper when every argument of the call
        comes from one of its own arguments; its own call sites are then what
        the rule looks at. Upstream has no architecture-agnostic way to decide
        this without a ctree, and neither does this.
        """
        if not self._hexrays:
            return []
        cfunc = self._decompile(call_ea)
        if cfunc is None:
            return []
        items = self._tree(cfunc)
        if items is None:
            return []
        wrapper_ea = cfunc.entry_ea
        for item in items:
            if item.ea != call_ea or item.op != self._hx.cot_call:
                continue
            call = item.to_specific_type
            if self._callee_name(call) != callee_name.lower():
                continue
            try:
                if not self._only_argument_vars(cfunc, call):
                    continue
            except Exception as error:
                self._warn(
                    f"{self._func_name(cfunc.entry_ea)}: wrapper detection"
                    f" failed: {type(error).__name__}: {error}"
                )
                return []
            name = self._func_name(wrapper_ea)
            sites: list[dict[str, object]] = []
            for xref in self._utils.XrefsTo(wrapper_ea):
                if len(sites) >= self._limits["wrappers"]:
                    self._bounded = True
                    self._warn(
                        f"{name}: stopped at the {self._limits['wrappers']} wrapper"
                        " call site budget"
                    )
                    break
                sites.append(
                    self._call_site(
                        xref.frm,
                        name,
                        callee_name,
                        wrapper_ea,
                        display=f"{name} ({callee_name} wrapper)",
                        wrapper_of=callee_name,
                    )
                )
            return sites
        return []

    def _only_argument_vars(self, cfunc: Any, call: Any) -> bool:
        lvars = list(cfunc.get_lvars())
        pending = list(call.a)
        steps = 0
        while pending:
            steps += 1
            if steps > self._limits["tree_items"]:
                return False
            current = pending.pop(0)
            if current is None:
                continue
            if current.op == self._hx.cot_var:
                if not lvars[current.v.idx].is_arg_var:
                    return False
            else:
                specific = current.to_specific_type
                pending.extend([specific.x, specific.y])
        return True

    # -- one call site ----------------------------------------------------

    def _call_site(
        self,
        address: int,
        callee_name: str,
        matched_name: str,
        callee_ea: int,
        *,
        display: str | None = None,
        gate: bool = False,
        wrapped: int = 0,
        wrapper_of: str | None = None,
    ) -> dict[str, object]:
        params, reason, expected = self._arguments(
            address,
            callee_name,
            callee_ea,
            # A wrapper site types the wrapper, and the rule named the function
            # the wrapper calls, not the wrapper. Only a direct site is about a
            # callee a rule asked for by name.
            rule_named=wrapper_of is None,
        )
        return {
            "address": hex(address),
            "relative_address": self._relative(address),
            "function_name": callee_name,
            "matched_name": matched_name,
            "display_name": display or callee_name,
            "found_in": self._func_name(address),
            "wrapper_of": wrapper_of,
            "gate": gate,
            "wrapped_count": wrapped,
            "params": params,
            "params_reason": reason,
            "argument_count": None if params is None else len(params),
            "expected_argument_count": expected,
            "call": self._call_facts(address, callee_name),
        }

    def _arguments(
        self, call_ea: int, callee_name: str, callee_ea: int, *, rule_named: bool
    ) -> tuple[list[dict[str, object]] | None, str | None, int | None]:
        """This call's arguments, or exactly why they could not be recovered.

        A first attempt uses whatever IDA already knows. Only if that fails is
        the callee offered its pinned VulFi prototype, and only then is the
        recovery retried — once. That is the whole of the ``SetType`` trigger:
        a prototype is applied when, and only when, the arguments could not
        otherwise be recovered for a callee this rule named.
        """
        params, reason, expected = self._recover_arguments(
            call_ea, callee_name, callee_ea
        )
        if params is not None:
            return params, reason, expected
        if not self._apply_prototype(callee_ea, callee_name, rule_named):
            return None, reason, expected
        retried, retry_reason, expected = self._recover_arguments(
            call_ea, callee_name, callee_ea
        )
        if retried is not None:
            return retried, retry_reason, expected
        return None, f"{retry_reason} (after applying the pinned prototype)", expected

    def _recover_arguments(
        self, call_ea: int, callee_name: str, callee_ea: int
    ) -> tuple[list[dict[str, object]] | None, str | None, int | None]:
        """One recovery attempt against the database as it stands.

        An empty list is only a *verified* empty argument list. Hex-Rays builds
        a call node's argument list from what it decided the callee takes, so
        an empty one there is an observation; without a decompiler an empty
        operand list is the absence of one, and only IDA's own prototype can
        confirm that the callee really takes nothing. Upstream turned a failed
        disassembly recovery into an empty list, and so into an ``Info``
        finding; here that is a missing fact instead.
        """
        try:
            expected = self._expected_arguments(callee_ea)
            if self._hexrays:
                raw, reason = self._arguments_hexrays(call_ea, callee_name)
            else:
                raw, reason = self._arguments_disass(call_ea)
        except Exception as error:
            # An extraction that blew up recovered nothing; saying so keeps the
            # rest of the scan honest instead of ending it.
            self._warn(f"{callee_name}: {type(error).__name__}: {error}")
            return None, f"argument recovery failed: {type(error).__name__}", None
        if raw is None:
            return None, reason, expected
        if not raw:
            if expected == 0:
                return [], None, expected
            if expected is not None:
                return (
                    None,
                    f"no arguments were recovered, but {callee_name} takes"
                    f" {expected}",
                    expected,
                )
            if not self._hexrays:
                return (
                    None,
                    "no arguments were recovered and IDA has no prototype for"
                    f" {callee_name}, so an empty argument list is not verified",
                    expected,
                )
        return (
            [self._param_facts(item, call_ea, callee_name) for item in raw],
            None,
            expected,
        )

    def _expected_arguments(self, ea: int) -> int | None:
        tinfo = self._typeinf.tinfo_t()
        if not self._nalt.get_tinfo(tinfo, ea) or not tinfo.is_func():
            return None
        if tinfo.is_vararg_cc():
            return None
        return int(tinfo.get_nargs())

    def _arguments_hexrays(
        self, call_ea: int, callee_name: str
    ) -> tuple[list[Any] | None, str | None]:
        cfunc = self._decompile(call_ea)
        if cfunc is None:
            return None, "the decompiler produced no ctree for this function"
        items = self._tree(cfunc)
        if items is None:
            return None, "this function's ctree is over the scan budget"
        for item in items:
            if item.ea != call_ea or item.op != self._hx.cot_call:
                continue
            call = item.to_specific_type
            if self._callee_name(call) == callee_name.lower():
                return list(call.a), None
        return None, f"the ctree has no call to {callee_name} at this address"

    def _arguments_disass(self, call_ea: int) -> tuple[list[Any] | None, str | None]:
        """Every argument slot IDA reports, keeping the ones it cannot read.

        ``get_arg_addrs`` returns ``BADADDR`` whenever it cannot attribute the
        instruction that sets an argument, and an instruction that does not
        decode is the same kind of hole. Upstream compacts those slots away,
        which silently renumbers every later argument; a hole travels as
        ``None`` here so ``param[i]`` keeps meaning argument ``i`` and the
        unread one reads as unavailable instead of as its neighbour.
        """
        try:
            addresses = self._api.get_arg_addrs(call_ea)
        except Exception:  # upstream swallows this the same way
            addresses = None
        if addresses is None:
            return None, "IDA could not locate this call's argument instructions"
        return [self._argument_operand(param_ea) for param_ea in addresses], None

    def _argument_operand(self, param_ea: int) -> Any:
        if param_ea == self._idc.BADADDR:
            return None
        insn = self._ua.insn_t()
        if self._ua.decode_insn(insn, param_ea) == self._idc.BADADDR:
            return None
        feature = insn.get_canon_feature()
        if feature & 0x100:
            return (insn, insn.Op1)
        if feature & 0x200:
            return (insn, insn.Op2)
        if feature & 0x400:
            return (insn, insn.Op3)
        return None

    # -- argument facts ---------------------------------------------------

    def _param_facts(
        self, item: Any, call_ea: int, callee_name: str
    ) -> dict[str, object]:
        if item is None:
            # A slot IDA could not read: the position is real, its facts are not.
            return {"kind": "absent"}
        if self._hexrays:
            return self._ctree_param_facts(item, call_ea, callee_name)
        return self._operand_param_facts(item[1], call_ea)

    def _ctree_param_facts(
        self,
        expr: Any,
        call_ea: int,
        callee_name: str,
        anchor: Any = None,
    ) -> dict[str, object]:
        """Every ``Param`` predicate, answered once from the ctree.

        ``anchor`` is the ctree item a predicate walks up from. A call site
        has none of its own, so upstream's lookup by address is used there;
        an array or loop site passes the very item it was discovered as.
        """
        facts: dict[str, object] = {"kind": self._op_name(expr.op)}
        self._record(facts, "name", self._local_name, expr, call_ea)
        self._record(facts, "size_bytes", self._local_width, expr, call_ea)
        self._record(facts, "string", self._string_value, expr)
        self._record(facts, "number", self._number_value, expr)
        self._record(facts, "const_number", self._const_number, expr)
        self._record(facts, "constant", self._is_constant, expr, call_ea)
        self._record(facts, "indexed", self._used_as_index, expr, call_ea)
        self._record(
            facts, "sign_compared", self._sign_compared, expr, call_ea, anchor
        )
        self._record(
            facts, "nulled_after_call", self._nulled_after_call, call_ea, callee_name
        )
        self._record_calls(facts, expr, call_ea)
        return facts

    def _local(self, expr: Any, call_ea: int) -> Any:
        """The local variable this argument is, when it is one at all."""
        target = self._unwrap(expr)
        if target is None or target.op != self._hx.cot_var:
            raise _Unestablished("the argument is not a local variable")
        cfunc, _ = self._require_tree(call_ea)
        return cfunc.lvars[target.v.idx]

    def _local_name(self, expr: Any, call_ea: int) -> str:
        return self._local(expr, call_ea).name

    def _local_width(self, expr: Any, call_ea: int) -> int:
        return int(self._local(expr, call_ea).width)

    def _operand_param_facts(self, op: Any, call_ea: int) -> dict[str, object]:
        """Facts a disassembly-only backend can establish about one operand.

        ``size``, ``used_as_index``, ``is_sign_compared``, and the
        ``used_in_call_*`` pair are decompiler-only upstream, which answers
        them ``False``; each is left absent here instead. ``is_constant`` only
        travels when a literal was actually found, because upstream's negative
        rests on an assignment scan that needs a ctree.
        """
        facts: dict[str, object] = {"kind": f"op_t:{op.type}"}
        self._record(facts, "string", self._string_value_disass, op, call_ea)
        self._record(facts, "number", self._number_value_disass, op)
        self._record(facts, "const_number", self._const_number_disass, op)
        self._record(
            facts, "nulled_after_call", self._nulled_after_call_disass, call_ea
        )
        if facts.get("string") or facts.get("number") is not None:
            facts["constant"] = True
        return facts

    def _record(self, facts: dict, key: str, getter: Any, *args: Any) -> None:
        """Store one fact, or leave it out when IDA did not establish it."""
        try:
            facts[key] = getter(*args)
        except _Unestablished:
            return
        except Exception as error:
            self._warn(f"{key}: {type(error).__name__}: {error}")

    def _record_calls(self, facts: dict, expr: Any, call_ea: int) -> None:
        try:
            before, after = self._argument_calls(expr, call_ea)
        except _Unestablished:
            return
        except Exception as error:
            self._warn(f"calls_before: {type(error).__name__}: {error}")
            return
        facts["calls_before"] = before
        facts["calls_after"] = after

    # -- ctree predicates -------------------------------------------------

    def _string_value(self, expr: Any) -> str:
        """``Param.string_value`` over a ctree expression."""
        if expr is None:
            return ""
        hx = self._hx
        text = self._strlit(expr.obj_ea)
        if text:
            return text
        if expr.op == hx.cot_cast:
            if expr.x.op == hx.cot_obj:
                text = self._strlit(expr.x.obj_ea)
                if text:
                    return text
        elif expr.op == hx.cot_ref:
            text = self._strlit(expr.x.obj_ea)
            if text:
                return text
            if expr.x.op == hx.cot_idx:
                text = self._strlit(expr.x.x.obj_ea)
                if text:
                    return text
            if expr.x.obj_ea != self._idc.BADADDR:
                return self._cfstring(expr.x.obj_ea)
        else:
            pointer = self._idc.get_bytes(expr.obj_ea, self._ptr_size)
            if pointer:
                return self._strlit(
                    int.from_bytes(pointer, byteorder=self._endian)
                )
        return ""

    def _cfstring(self, ea: int) -> str:
        """A Core Foundation string, recognized the way upstream does."""
        pointer = self._idc.get_bytes(ea + 2 * self._ptr_size, self._ptr_size)
        length = self._idc.get_bytes(ea + 3 * self._ptr_size, self._ptr_size)
        if not pointer or not length:
            return ""
        raw = self._idc.get_strlit_contents(
            int.from_bytes(pointer, byteorder=self._endian)
        )
        if raw and len(raw) == int.from_bytes(length, byteorder=self._endian):
            return raw.decode("utf-8", "replace")
        return ""

    def _strlit(self, ea: int | None) -> str:
        if ea is None or ea == self._idc.BADADDR:
            return ""
        raw = self._idc.get_strlit_contents(ea)
        return raw.decode("utf-8", "replace") if raw else ""

    def _number_value(self, expr: Any) -> int | float | None:
        hx = self._hx
        if expr is None:
            return None
        if expr.op == hx.cot_num:
            return _finite(expr.n._value)
        if expr.op == hx.cot_fnum:
            return _finite(expr.fpc.fnum.float)
        if expr.op == hx.cot_cast:
            if expr.x.op == hx.cot_num:
                return _finite(expr.x.n._value)
            if expr.x.op == hx.cot_fnum:
                return _finite(expr.x.fpc.fnum.float)
        return None

    def _const_number(self, expr: Any) -> bool:
        hx = self._hx
        if expr is None:
            return False
        if expr.op in (hx.cot_num, hx.cot_fnum):
            return True
        return expr.op == hx.cot_cast and expr.x.op == hx.cot_num

    def _is_constant(self, expr: Any, call_ea: int) -> bool:
        if self._string_value(expr) != "" or self._number_value(expr) is not None:
            return True
        if expr is not None and expr.op == self._hx.cot_ref:
            return False
        assignments = self._assignments(expr, call_ea)
        if not assignments:
            return False
        for assignment in assignments:
            if not self._is_before(assignment.ea, call_ea):
                continue
            if (
                self._string_value(assignment.y) == ""
                and self._number_value(assignment.y) is None
            ):
                return False
        return True

    def _assignments(self, expr: Any, call_ea: int) -> list[Any]:
        target = self._unwrap(expr)
        cfunc, items = self._require_tree(call_ea)
        found: list[Any] = []
        for item in items:
            if not item.is_expr() or target != item.to_specific_type:
                continue
            parent = cfunc.body.find_parent_of(item)
            if parent is None:
                continue
            if self._hx.cot_asg <= parent.op <= self._hx.cot_asgumod:
                found.append(parent.to_specific_type)
        return found

    def _used_as_index(self, expr: Any, call_ea: int) -> bool:
        _, items = self._require_tree(call_ea)
        for item in items:
            if item.op == self._hx.cot_idx and item.to_specific_type.y == expr:
                return True
        return False

    def _sign_compared(self, expr: Any, call_ea: int, anchor: Any = None) -> bool:
        cfunc, items = self._require_tree(call_ea)
        if anchor is None:
            anchor = self._anchor(items, call_ea)
            if anchor is None:
                raise _Unestablished("no ctree item at this address")
        target = self._unwrap(expr)
        parent = cfunc.body.find_parent_of(anchor)
        steps = 0
        while parent is not None:
            steps += 1
            if steps > self._limits["tree_items"]:
                raise _Unestablished("parent walk over budget")
            if parent.op == self._hx.cit_if and self._in_signed_comparison(
                target, parent
            ):
                return True
            parent = cfunc.body.find_parent_of(parent)
        return False

    def _in_signed_comparison(self, target: Any, branch: Any) -> bool:
        hx = self._hx
        signed = (hx.cot_sge, hx.cot_sle, hx.cot_sgt, hx.cot_slt)
        operands: list[Any] = []
        pending = [branch.to_specific_type.cif.expr]
        for _ in range(self._limits["tree_items"]):
            if not pending:
                break
            expr = pending.pop()
            if expr is None:
                continue
            if expr.op in signed:
                operands.append(expr)
            else:
                pending.extend([expr.x, expr.y])
        for _ in range(self._limits["tree_items"]):
            if not operands:
                return False
            operand = operands.pop()
            if operand is None:
                continue
            if target == operand:
                return True
            operands.extend([operand.x, operand.y])
        return False

    def _nulled_after_call(self, call_ea: int, callee_name: str) -> bool:
        """Upstream's ``null_after_visitor``: any ``x = 0`` right after the call.

        Deliberately as coarse as upstream, which does not check that the
        cleared variable is the argument being asked about.
        """
        hx = self._hx
        _, items = self._require_tree(call_ea)
        seen_call = False
        statements = 0
        for item in items:
            if not item.is_expr():
                if seen_call:
                    statements += 1
                continue
            current = item.to_specific_type
            if (
                current.op == hx.cot_call
                and item.ea == call_ea
                and self._callee_name(current) == callee_name.lower()
            ):
                seen_call = True
            if not seen_call or statements >= 2:
                continue
            if (
                current.op == hx.cot_asg
                and current.y.op == hx.cot_num
                and current.y.numval() == 0
            ):
                return True
        return False

    def _argument_calls(
        self, expr: Any, call_ea: int
    ) -> tuple[list[str], list[str]]:
        """Callees that take this argument, split around the scanned call."""
        hx = self._hx
        target = self._unwrap(expr)
        _, items = self._require_tree(call_ea)
        before: list[str] = []
        after: list[str] = []
        for item in items:
            if item.op != hx.cot_call or item.ea == call_ea:
                continue
            call = item.to_specific_type
            if not self._takes(target, call):
                continue
            name = self._func_name(call.x.obj_ea)
            if not name:
                continue
            bucket = before if self._is_before(call.ea, call_ea) else after
            if name in bucket:
                continue
            if len(bucket) >= self._limits["names"]:
                raise _Unestablished("too many callees take this argument")
            bucket.append(name)
        return before, after

    def _takes(self, target: Any, call: Any) -> bool:
        for argument in call.a:
            pending = [argument, argument.x, argument.y, argument.z]
            for _ in range(self._limits["tree_items"]):
                if not pending:
                    break
                current = pending.pop(0)
                if current is None:
                    continue
                if target == current:
                    return True
                pending.extend([current.x, current.y, current.z])
        return False

    def _is_before(self, ea: int, call_ea: int) -> bool:
        """Upstream's block reachability test between two addresses."""
        func = self._funcs.get_func(ea)
        if func is None:
            raise _Unestablished("no containing function")
        flow = self._api.FlowChart(func)
        call_block = None
        source_block = None
        for block in flow:
            if block.start_ea <= ea <= block.end_ea:
                source_block = block
            if block.start_ea <= call_ea <= block.end_ea:
                call_block = block
        if call_block is None or source_block is None:
            raise _Unestablished("the call is outside this function's blocks")
        if call_block.start_ea == source_block.start_ea:
            return ea < call_ea
        checked = {call_block.start_ea}
        pending = list(call_block.preds())
        while pending:
            current = pending.pop(0)
            if current.start_ea in checked:
                continue
            checked.add(current.start_ea)
            if current.start_ea == source_block.start_ea:
                return True
            pending.extend(list(current.preds()))
        return False

    # -- disassembly-only predicates --------------------------------------

    def _string_value_disass(self, op: Any, call_ea: int) -> str:
        if op.type == self._idc.o_mem:
            text = self._strlit(op.addr)
            if text:
                return text
            pointer = self._idc.get_bytes(op.addr, self._ptr_size)
            if pointer:
                text = self._strlit(int.from_bytes(pointer, byteorder=self._endian))
                if text:
                    return text
        if op.type == self._idc.o_imm:
            text = self._strlit(op.value)
            if text:
                return text
        return self._nearby_string(call_ea)

    def _nearby_string(self, call_ea: int) -> str:
        """Upstream's reverse search: a string referenced just before the call.

        Like upstream this cannot tell one operand from another, so every
        argument of the same call sees the same answer. Upstream rescans every
        string in the database for every argument; the same references are
        indexed by containing function once here, in ``idautils.Strings``
        order, so the first match is still the one upstream would have found.
        """
        func = self._funcs.get_func(call_ea)
        if func is None:
            raise _Unestablished("no containing function")
        for reference, text in self._string_references().get(func.start_ea, ()):
            if reference >= call_ea:
                continue
            heads = list(self._utils.Heads(reference, call_ea))
            if len(heads) > 10:
                continue
            if any(head != call_ea and self._is_plain_call(head) for head in heads):
                return ""
            return text
        return ""

    def _string_references(self) -> dict[int, list[tuple[int, str]]]:
        """Where each function references a string literal, built once."""
        if self._strings is not None:
            return self._strings
        index: dict[int, list[tuple[int, str]]] = {}
        budget = self._limits["strings"]
        for text in self._utils.Strings():
            for xref in self._utils.XrefsTo(text.ea):
                holder = self._funcs.get_func(xref.frm)
                if holder is None:
                    continue
                if budget <= 0:
                    self._bounded = True
                    self._warn(
                        f"stopped at the {self._limits['strings']} string"
                        " reference budget"
                    )
                    self._strings = index
                    return index
                budget -= 1
                index.setdefault(holder.start_ea, []).append((xref.frm, str(text)))
        self._strings = index
        return index

    def _is_plain_call(self, ea: int) -> bool:
        insn = self._ua.insn_t()
        if self._ua.decode_insn(insn, ea) == self._idc.BADADDR:
            return False
        return insn.get_canon_feature() & 0x2 == 0x2

    def _number_value_disass(self, op: Any) -> int | float | None:
        return _finite(op.value) if op.type == self._idc.o_imm else None

    def _const_number_disass(self, op: Any) -> bool:
        return op.type == self._idc.o_imm

    def _nulled_after_call_disass(self, call_ea: int) -> bool:
        call = self._ua.insn_t()
        if self._ua.decode_insn(call, call_ea) == self._idc.BADADDR:
            raise _Unestablished("the call instruction did not decode")
        following = self._ua.insn_t()
        if self._ua.decode_insn(following, call.ea + call.size) == self._idc.BADADDR:
            raise _Unestablished("the next instruction did not decode")
        return following.Op2.type == self._idc.o_imm and following.Op2.value == 0

    # -- call facts -------------------------------------------------------

    def _call_facts(self, call_ea: int, callee_name: str) -> dict[str, object]:
        facts: dict[str, object] = {}
        self._record(facts, "reachable_from_names", self._reachable_from, call_ea)
        try:
            checked, values = self._return_check(call_ea, callee_name)
        except _Unestablished:
            return facts
        except Exception as error:
            self._warn(f"return_checked: {type(error).__name__}: {error}")
            return facts
        facts["return_checked"] = checked
        if values is not None:
            facts["return_check_values"] = values
        return facts

    def _reachable_from(self, call_ea: int) -> list[str]:
        start = self._funcs.get_func(call_ea)
        if start is None:
            raise _Unestablished("no containing function")
        names: list[str] = []
        seen = {start.start_ea}
        pending = [start.start_ea]
        while pending:
            if len(seen) > self._limits["callers"]:
                raise _Unestablished("the caller graph is over the scan budget")
            current = pending.pop(0)
            name = self._func_name(current)
            if name and name not in names:
                names.append(name)
            for xref in self._utils.XrefsTo(current):
                func = self._funcs.get_func(xref.frm)
                if func is None or func.start_ea in seen:
                    continue
                seen.add(func.start_ea)
                pending.append(func.start_ea)
        return names

    def _return_check(
        self, call_ea: int, callee_name: str
    ) -> tuple[bool, list[int | float] | None]:
        """Whether this call's return value is compared, and against what.

        ``None`` values mean the comparison was found but its constants were
        not, so ``return_value_checked(n)`` stays unanswerable rather than
        guessing. Upstream's deeply nested ``cot_asg`` search is reduced to
        "the first later comparison of the assigned variable".
        """
        if not self._hexrays:
            return self._return_check_disass(call_ea)
        hx = self._hx
        cfunc, items = self._require_tree(call_ea)
        for index, item in enumerate(items):
            if item.ea != call_ea or item.op != hx.cot_call:
                continue
            if self._callee_name(item.to_specific_type) != callee_name.lower():
                continue
            parent = cfunc.body.find_parent_of(item)
            if parent is not None and parent.op == hx.cot_cast:
                parent = cfunc.body.find_parent_of(parent)
            if parent is None:
                return False, []
            if hx.cot_eq <= parent.op <= hx.cot_ult:
                return True, self._comparison_values(parent.to_specific_type.y)
            if parent.op == hx.cit_if:
                condition = parent.to_specific_type.cif.expr
                return True, ([0] if condition.y is None else None)
            if parent.op in (hx.cot_lnot, hx.cot_lor, hx.cot_land):
                return True, None
            if parent.op == hx.cot_asg:
                return self._assigned_return_check(items, index, parent)
            return False, []
        raise _Unestablished("the ctree has no such call")

    def _assigned_return_check(
        self, items: list[Any], index: int, parent: Any
    ) -> tuple[bool, list[int | float] | None]:
        hx = self._hx
        assigned = parent.to_specific_type.x
        for item in items[index:]:
            if not item.is_expr():
                continue
            expr = item.to_specific_type
            if not hx.cot_eq <= expr.op <= hx.cot_ult:
                continue
            if expr.x is None or assigned != expr.x:
                continue
            return True, self._comparison_values(expr.y)
        return False, []

    def _comparison_values(self, operand: Any) -> list[int | float] | None:
        """The constants a comparison tests, with the signed reading upstream
        also accepts."""
        if operand is None:
            return None
        hx = self._hx
        if operand.op == hx.cot_num:
            value = int(operand.n._value)
            return [value, -((value ^ 0xFFFFFFFFFFFFFFFF) + 1)]
        if operand.op == hx.cot_fnum:
            return [_finite(operand.fpc.fnum.float)]
        return None

    def _return_check_disass(
        self, call_ea: int
    ) -> tuple[bool, list[int | float] | None]:
        func = self._funcs.get_func(call_ea)
        if func is None:
            raise _Unestablished("no containing function")
        for block in self._api.FlowChart(func):
            if not block.start_ea <= call_ea < block.end_ea:
                continue
            if len(list(block.succs())) <= 1:
                return False, []
            insn = self._ua.insn_t()
            if self._ua.decode_insn(insn, call_ea) == self._idc.BADADDR:
                raise _Unestablished("the call instruction did not decode")
            for _ in range(5):
                following = self._ua.insn_t()
                if (
                    self._ua.decode_insn(following, insn.ea + insn.size)
                    == self._idc.BADADDR
                ):
                    break
                insn = following
                if insn.get_canon_feature() & 0xFFFF == 0x300:
                    values = [
                        op.value
                        for op in insn.ops
                        if op.type == self._idc.o_imm
                    ]
                    return True, (values or None)
                if insn.ea >= block.end_ea:
                    # Upstream calls leaving the block a check, but cannot say
                    # against what.
                    return True, None
        return False, []

    # -- pseudo-rules -----------------------------------------------------

    def _pseudo_record(self, rule: dict[str, Any], kind: str) -> dict[str, object]:
        sites: list[dict[str, object]] = []
        notes: list[str] = []
        truncated = False
        if not self._hexrays:
            notes.append(
                f"{rule['function_names'][0]} needs the decompiler, which this"
                " scan did not use"
            )
            return {
                "rule_index": rule["index"],
                "kind": kind,
                "sites": [],
                "truncated": True,
                "notes": notes,
            }
        functions = self._code_functions
        if len(functions) > self._limits["functions"]:
            truncated = True
            self._bounded = True
            notes.append(
                f"decompiled the first {self._limits['functions']} of"
                f" {len(functions)} functions, the scan budget"
            )
            functions = functions[: self._limits["functions"]]
        for ea in functions:
            if len(sites) >= self._limits["sites"]:
                truncated = True
                self._bounded = True
                notes.append(
                    f"stopped at the {self._limits['sites']} site scan budget"
                )
                break
            self._trim()
            cfunc = self._decompile(ea)
            if cfunc is None:
                truncated = True
                notes.append(f"{self._func_name(ea)}: the decompiler produced no ctree")
                continue
            items = self._tree(cfunc)
            if items is None:
                truncated = True
                notes.append(f"{self._func_name(ea)}: ctree over the scan budget")
                continue
            finder = self._array_sites if kind == "array" else self._loop_sites
            sites.extend(finder(cfunc, items))
        return {
            "rule_index": rule["index"],
            "kind": kind,
            "sites": sites,
            "truncated": truncated,
            "notes": notes[:MAX_SCAN_WARNINGS],
        }

    def _array_sites(self, cfunc: Any, items: list[Any]) -> list[dict[str, object]]:
        """``get_array_accesses``: every indexing expression, base and index."""
        sites: list[dict[str, object]] = []
        for item in items:
            if item.op != self._hx.cot_idx:
                continue
            expr = item.to_specific_type
            sites.append(
                self._pseudo_site(
                    ARRAY_RULE_NAME, cfunc, item, expr.x, expr.y
                )
            )
        return sites

    def _loop_sites(self, cfunc: Any, items: list[Any]) -> list[dict[str, object]]:
        """``get_loops``: every bounded loop, as counter and check value."""
        hx = self._hx
        sites: list[dict[str, object]] = []
        for item in items:
            if item.op not in (hx.cit_while, hx.cit_for, hx.cit_do):
                continue
            try:
                counter, check = self._loop_operands(item)
            except Exception as error:
                self._warn(f"loop at {hex(item.ea)}: {type(error).__name__}: {error}")
                continue
            sites.append(
                self._pseudo_site(LOOP_RULE_NAME, cfunc, item, counter, check)
            )
        return sites

    def _loop_operands(self, item: Any) -> tuple[Any, Any]:
        hx = self._hx
        statement = item.to_specific_type
        if item.op == hx.cit_for:
            loop = statement.cfor
            if loop.expr.op == hx.cot_empty:
                return self._break_condition(loop.body)
            counter = loop.init.x
            return counter, self._check_value(counter, loop.expr)
        loop = statement.cwhile if item.op == hx.cit_while else statement.cdo
        op = loop.expr.op
        bounded = hx.cot_land <= op <= hx.cot_ult or op in (
            hx.cot_var,
            hx.cot_lnot,
        )
        if bounded:
            return self._condition_operands(loop.expr)
        return self._break_condition(loop.body)

    def _condition_operands(self, condition: Any) -> tuple[Any, Any]:
        """``parse_condition``: the counter and the value it is tested against.

        A condition with no explicit value yields a synthetic constant, which
        travels as a plain number fact rather than as upstream's dummy ctree
        node.
        """
        hx = self._hx
        if condition is None:
            return None, None
        if condition.op == hx.cot_lnot:
            return condition.x, 0
        if condition.op in (hx.cot_var, hx.cot_call, hx.cot_cast):
            return condition.x, 1
        if hx.cot_eq <= condition.op <= hx.cot_ult:
            return condition.x, condition.y
        if condition.op in (hx.cot_lor, hx.cot_land):
            left = self._condition_operands(condition.x)
            right = self._condition_operands(condition.y)
            if self._is_number(right[1]):
                return right
            return left
        return None, None

    def _is_number(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, int):
            return True
        return value.op == self._hx.cot_num

    def _check_value(self, counter: Any, comparison: Any) -> Any:
        left, right = self._condition_operands(comparison)
        if counter is not None and left is not None and left == counter:
            return right
        # IDA puts the constant in `y` for ordinary comparisons; for anything
        # else upstream returns `x` so a non-constant is not read as one.
        return left

    def _break_condition(self, body: Any) -> tuple[Any, Any]:
        block = body.cblock
        cursor = block.begin()
        for _ in range(self._limits["tree_items"]):
            if cursor == block.end():
                break
            if cursor.cur.op == self._hx.cit_if:
                branch = self._find_break(cursor.cur.cif)
                if branch is not None:
                    return self._condition_operands(branch.expr)
            cursor.next()
        return None, None

    def _find_break(self, branch: Any, depth: int = 0) -> Any:
        """The innermost ``if`` that leaves the loop, if there is one."""
        hx = self._hx
        if depth > 32:
            return None
        for block in (branch.ithen, branch.ielse):
            if block is None:
                continue
            cursor = block.cblock.begin()
            for _ in range(self._limits["tree_items"]):
                if cursor == block.cblock.end():
                    break
                if cursor.cur.op == hx.cit_if:
                    found = self._find_break(cursor.cur.cif, depth + 1)
                    if found is not None:
                        return found
                elif cursor.cur.op in (hx.cit_break, hx.cit_return):
                    return branch
                cursor.next()
        return None

    def _pseudo_site(
        self, name: str, cfunc: Any, anchor: Any, first: Any, second: Any
    ) -> dict[str, object]:
        address = self._addressable(cfunc, anchor)
        return {
            "address": hex(address),
            "relative_address": self._relative(address),
            "function_name": name,
            "matched_name": name,
            "display_name": name,
            "found_in": self._func_name(cfunc.entry_ea),
            "wrapper_of": None,
            "gate": False,
            "wrapped_count": 0,
            "params": [
                self._pseudo_param(first, name, address, anchor),
                self._pseudo_param(second, name, address, anchor),
            ],
            "params_reason": None,
            "argument_count": 2,
            "expected_argument_count": 2,
            "call": self._call_facts(address, name),
        }

    def _pseudo_param(
        self, operand: Any, name: str, address: int, anchor: Any
    ) -> dict[str, object]:
        if operand is None:
            # Upstream builds a `Param` around `None` here and lets every
            # predicate answer from it; an absent operand establishes nothing.
            return {"kind": "absent"}
        if isinstance(operand, int):
            # The synthetic constant upstream fabricates for a condition with
            # no explicit value, as a fact rather than as a ctree node.
            return {
                "kind": "num",
                "string": "",
                "number": operand,
                "const_number": True,
                "constant": True,
            }
        return self._ctree_param_facts(operand, address, name, anchor)

    # -- ctree plumbing ---------------------------------------------------

    def _decompile(self, ea: int) -> Any:
        """Decompile the function holding ``ea``, with its ctree materialized.

        ``cfunc_t.treeitems`` stays empty until the pseudocode is generated,
        which is why upstream binds ``code = decompiled_function.pseudocode``
        before every ctree walk. Without it every lookup below silently sees
        an empty tree.
        """
        func = self._funcs.get_func(ea)
        if func is None:
            return None
        cached = self._cfuncs.get(func.start_ea, _MISSING)
        if cached is not _MISSING:
            return cached
        try:
            cfunc = self._hx.decompile(func)
            if cfunc is not None:
                cfunc.get_pseudocode()
        except Exception as error:
            self._warn(f"{self._func_name(ea)}: {type(error).__name__}: {error}")
            cfunc = None
        self._cfuncs[func.start_ea] = cfunc
        return cfunc

    def _tree(self, cfunc: Any) -> list[Any] | None:
        cached = self._trees.get(cfunc.entry_ea, _MISSING)
        if cached is not _MISSING:
            return cached
        items = cfunc.treeitems
        if len(items) > self._limits["tree_items"]:
            self._bounded = True
            self._warn(
                f"{self._func_name(cfunc.entry_ea)}: {len(items)} ctree items,"
                f" over the {self._limits['tree_items']} item budget"
            )
            walked = None
        else:
            walked = list(items)
        self._trees[cfunc.entry_ea] = walked
        return walked

    def _require_tree(self, ea: int) -> tuple[Any, list[Any]]:
        cfunc = self._decompile(ea)
        if cfunc is None:
            raise _Unestablished("the decompiler produced no ctree")
        items = self._tree(cfunc)
        if items is None:
            raise _Unestablished("this function's ctree is over the scan budget")
        return cfunc, items

    def _trim(self) -> None:
        """Drop cached ctrees between sites, never while one is being read."""
        if len(self._cfuncs) > _CFUNC_CACHE:
            self._cfuncs.clear()
            self._trees.clear()

    def _anchor(self, items: list[Any], ea: int) -> Any:
        for item in items:
            if item.ea == ea:
                return item
        return None

    def _addressable(self, cfunc: Any, item: Any) -> int:
        """The nearest address this ctree item can be reported at.

        Hex-Rays leaves ``ea`` unset on expressions it cannot attribute to one
        instruction. Upstream reports those at ``BADADDR``; walking up to the
        enclosing statement keeps the finding addressable, and the occurrence
        ordinal separates two items that share a statement.
        """
        if item.ea != self._idc.BADADDR:
            return item.ea
        parent = cfunc.body.find_parent_of(item)
        steps = 0
        while parent is not None:
            steps += 1
            if steps > self._limits["tree_items"]:
                break
            if parent.ea != self._idc.BADADDR:
                return parent.ea
            parent = cfunc.body.find_parent_of(parent)
        return cfunc.entry_ea

    def _relative(self, address: int) -> str | None:
        if address < self._image_base:
            return None
        return hex(address - self._image_base)

    def _unwrap(self, expr: Any) -> Any:
        if expr is not None and expr.op == self._hx.cot_cast:
            return expr.x
        return expr

    def _callee_name(self, call: Any) -> str:
        name = self._func_name(call.x.obj_ea)
        if not name:
            name = self._idc.get_name(call.x.obj_ea) or ""
        return name.lower()

    def _op_name(self, op: int) -> str:
        if self._op_names is None:
            self._op_names = {
                value: key
                for key, value in vars(self._hx).items()
                if key.startswith(("cot_", "cit_")) and isinstance(value, int)
            }
        return self._op_names.get(op, str(op))

    def _func_name(self, ea: int) -> str:
        """Upstream ``utils.get_func_name``: the demangled name IDA shows."""
        name = self._pretty(self._idc.get_func_name(ea))
        if not name:
            name = self._pretty(self._idc.get_name(ea))
        return name or ""

    def _pretty(self, name: str | None) -> str:
        """Upstream ``utils.get_pretty_func_name``, without its slicing bug."""
        if not name:
            return ""
        demangled = self._idc.demangle_name(
            name, self._idc.get_inf_attr(self._idc.INF_SHORT_DN)
        )
        if not demangled:
            return name
        cut = demangled.find("(")
        return demangled[:cut] if cut >= 0 else demangled

    def _warn(self, message: str) -> None:
        if message in self._warnings or len(self._warnings) >= MAX_SCAN_WARNINGS:
            return
        self._warnings.append(message)


def _finite(value: object) -> int | float:
    """Reject a number JSON cannot carry rather than round it into a lie."""
    if isinstance(value, float) and not math.isfinite(value):
        raise _Unestablished("the value is not a finite number")
    return value  # type: ignore[return-value]


def _scan(payload: dict[str, object]) -> dict[str, object]:
    """Extract call-site, wrapper, array, and loop evidence for these rules."""
    return _Scanner(payload).run()


def _scan_rules(payload: dict[str, object]) -> list[dict[str, Any]]:
    """The rule shapes the worker needs; ``mark_if`` stays on the host."""
    raw = payload.get("rules")
    if not isinstance(raw, list) or not raw:
        raise OperationError("scan: 'rules' must be a non-empty list")
    rules: list[dict[str, Any]] = []
    for position, item in enumerate(raw):
        if not isinstance(item, dict):
            raise OperationError(f"scan: rules[{position}] must be an object")
        index = item.get("index")
        names = item.get("function_names")
        wrappers = item.get("wrappers")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise OperationError(f"scan: rules[{position}].index must be an index")
        if not isinstance(names, list) or not names:
            raise OperationError(
                f"scan: rules[{position}].function_names must be a non-empty list"
            )
        if not all(isinstance(name, str) and name for name in names):
            raise OperationError(
                f"scan: rules[{position}].function_names must be strings"
            )
        if not isinstance(wrappers, bool):
            raise OperationError(f"scan: rules[{position}].wrappers must be a bool")
        rules.append({"index": index, "function_names": names, "wrappers": wrappers})
    return rules


def _scan_prototypes(payload: dict[str, object]) -> dict[str, str]:
    raw = payload.get("prototypes", {})
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise OperationError("scan: 'prototypes' must be an object")
    for name, prototype in raw.items():
        if not isinstance(prototype, str) or not prototype:
            raise OperationError(f"scan: prototypes[{name!r}] must be a string")
    return dict(raw)


def _scan_limits(payload: dict[str, object]) -> dict[str, int]:
    """Merge requested limits, which may only tighten the shipped ceilings."""
    raw = payload.get("limits", {})
    if raw is None:
        return dict(SCAN_LIMITS)
    if not isinstance(raw, dict):
        raise OperationError("scan: 'limits' must be an object")
    unknown = sorted(set(raw) - set(SCAN_LIMITS))
    if unknown:
        raise OperationError(f"scan: unknown limit(s) {', '.join(unknown)}")
    limits = dict(SCAN_LIMITS)
    for name, ceiling in SCAN_LIMITS.items():
        if name not in raw:
            continue
        value = raw[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise OperationError(f"scan: limits[{name!r}] must be a positive integer")
        limits[name] = min(value, ceiling)
    return limits


# ---------------------------------------------------------------------------
# Managed IDB record: schema version 2.
#
# One UTF-8 JSON blob in netnode ``vulfi_mcp.v2``, blob ``(index=1, tag="S")``,
# is the authority for IDA findings and unlinked assessments. Upstream VulFi's
# ``vulfi_data`` netnode is a different, older store and is never read or
# written here.
#
# Every operation below performs the whole read/modify/write inside one worker
# call, so the host never holds half a record and two calls can never race
# through it. The adapter saves the database afterwards, because a netnode
# write that is not saved is not durable and IDA offers no transaction.
# ---------------------------------------------------------------------------

#: Netnode holding this server's record.
NETNODE_NAME: Final = "vulfi_mcp.v2"
#: Blob slot inside that netnode.
NETNODE_BLOB_INDEX: Final = 1
NETNODE_BLOB_TAG: Final = "S"
#: The only record layout this build reads or writes. A record that says
#: anything else belongs to a future build and is refused, never replaced.
SCHEMA_VERSION: Final = 2

#: Backend tag every row this worker stores carries.
BACKEND_NAME: Final = "ida"

#: Scope of a scan that ran the stock rules.
DEFAULT_SCOPE: Final = "default"
#: Prefix of a scope that ran agent-supplied rules.
CUSTOM_SCOPE_PREFIX: Final = "custom:"
#: Longest accepted ``custom:<scan_name>`` name.
MAX_SCAN_NAME_LENGTH: Final = 64

#: The four triage states, in the order results count them.
TRIAGE_STATUSES: Final[tuple[str, str, str, str]] = (
    "Not Checked",
    "False Positive",
    "Suspicious",
    "Vulnerable",
)
#: Status a freshly stored finding carries.
UNASSESSED_STATUS: Final = "Not Checked"

#: Longest accepted rationale, in characters. Rationale text is untrusted, so
#: it is stored exactly as supplied but is bounded and control-character free.
MAX_RATIONALE_LENGTH: Final = 4000
#: Whitespace a rationale may carry; every other control character is refused.
_ALLOWED_CONTROLS: Final = frozenset("\t\n\r")
#: Unicode categories a rationale may not carry: C0/C1 controls, and the
#: surrogates that would make the record impossible to encode as UTF-8.
_REFUSED_CATEGORIES: Final = frozenset({"Cc", "Cs"})

#: Largest page one read may ask for.
MAX_PAGE_LIMIT: Final = 200
#: Rules one scope may record.
MAX_SCOPE_RULES: Final = 1000
#: Largest record this worker will write, in bytes. A scan that would exceed
#: it fails loudly rather than truncate a scope into a quiet half-answer.
MAX_RECORD_BYTES: Final = 64 * 1024 * 1024

#: Finding facts the host establishes and the record stores verbatim.
_FINDING_FACTS: Final = (
    "id",
    "backend",
    "source",
    "binary_sha256",
    "rule_index",
    "rule_digest",
    "rule_name",
    "function_name",
    "found_in",
    "address_space",
    "address",
    "relative_address",
    "occurrence",
    "priority",
    "evidence",
)
#: Facts only this record may set. A scan payload never carries them, so a
#: rescan cannot smuggle an assessment in, and an assessment survives a rescan
#: only by being carried forward from the row with the exact same ID.
_TRIAGE_FACTS: Final = (
    "status",
    "rationale",
    "assessed_at",
    "triage_revision",
    "link_id",
    "link_revision",
)


def utc_now() -> str:
    """The current UTC time, in the one format this record stores."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_scan_name(name: object) -> str:
    """Accept one ``custom:<scan_name>`` name, or say exactly what is wrong.

    An ASCII identifier cannot carry ``:``, ``/`` or ``\\``, so a scan name can
    neither split a finding ID nor reach a path.
    """
    if not isinstance(name, str) or not name:
        raise OperationError("scan_name must be a non-empty string")
    if len(name) > MAX_SCAN_NAME_LENGTH:
        raise OperationError(
            f"scan_name is {len(name)} characters;"
            f" the limit is {MAX_SCAN_NAME_LENGTH}"
        )
    if not (name.isascii() and name.isidentifier()):
        raise OperationError(
            "scan_name must be an ASCII identifier, without ':' or a path"
            f" separator, got {name!r}"
        )
    return name


def validate_scope(scope: object) -> str:
    """Accept ``default`` or ``custom:<scan_name>``, and nothing else."""
    if not isinstance(scope, str) or not scope:
        raise OperationError("scope must be a non-empty string")
    if scope == DEFAULT_SCOPE:
        return scope
    if not scope.startswith(CUSTOM_SCOPE_PREFIX):
        raise OperationError(
            f"scope must be {DEFAULT_SCOPE!r} or"
            f" '{CUSTOM_SCOPE_PREFIX}<scan_name>', got {scope!r}"
        )
    validate_scan_name(scope[len(CUSTOM_SCOPE_PREFIX) :])
    return scope


def validate_status(status: object) -> str:
    """Accept exactly one of the four triage states."""
    if status not in TRIAGE_STATUSES:
        raise OperationError(
            f"status must be one of {' | '.join(TRIAGE_STATUSES)}, got {status!r}"
        )
    return str(status)


def validate_rationale(rationale: object) -> str:
    """Accept one assessment rationale as written, within bounds.

    The text is a reviewer's own words and is stored verbatim, so every code
    point that survives a JSON round trip is kept. What is refused is an empty
    or whitespace-only claim, a rationale past the length bound, and control
    characters other than ordinary whitespace.
    """
    if not isinstance(rationale, str):
        raise OperationError(
            f"rationale must be a string, got {type(rationale).__name__}"
        )
    if not rationale.strip():
        raise OperationError("rationale must not be empty or whitespace only")
    if len(rationale) > MAX_RATIONALE_LENGTH:
        raise OperationError(
            f"rationale is {len(rationale)} characters;"
            f" the limit is {MAX_RATIONALE_LENGTH}"
        )
    for position, character in enumerate(rationale):
        if character in _ALLOWED_CONTROLS:
            continue
        if unicodedata.category(character) in _REFUSED_CATEGORIES:
            raise OperationError(
                f"rationale carries the control character U+{ord(character):04X}"
                f" at position {position}"
            )
    return rationale


def validate_page(offset: object, limit: object) -> tuple[int, int]:
    """Accept one page window: ``0 <= offset`` and ``1 <= limit <= 200``."""
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OperationError(f"offset must be an integer >= 0, got {offset!r}")
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PAGE_LIMIT
    ):
        raise OperationError(
            f"limit must be an integer in 1..{MAX_PAGE_LIMIT}, got {limit!r}"
        )
    return offset, limit


def finding_order(row: dict[str, Any]) -> tuple[str, int, str, str]:
    """Total order over stored rows: address space, location, then ID.

    The numeric address orders a page the way a reader reads a binary; the
    textual address and the ID keep the order total when an address is not
    hexadecimal or two rows sit at one location.
    """
    address = str(row.get("address") or "")
    try:
        location = int(address, 16)
    except ValueError:
        location = -1
    return (
        str(row.get("address_space") or ""),
        location,
        address,
        str(row.get("id") or ""),
    )


# -- the netnode itself -----------------------------------------------------


def _netnode(*, create: bool) -> Any:
    """The record's netnode, or ``None`` when nothing was ever written."""
    import ida_netnode

    node = ida_netnode.netnode(NETNODE_NAME, 0, create)
    if not create and node.index() == ida_netnode.BADNODE:
        return None
    return node


def _empty_record() -> dict[str, Any]:
    """A record with nothing in it yet, including its reserved sections.

    ``preparation`` and every row's ``link_id``/``link_revision`` are Plan 2's
    and Plan 4's to fill. They are written now, empty, so that arriving at
    those plans is not a migration.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "managed_idb_id": None,
        "preparation": _empty_preparation(),
        "scopes": {},
    }


def _empty_preparation() -> dict[str, Any]:
    return {"analysis_id": None, "revision": 0, "coverage": {}, "catalog_key": None}


def _read_record() -> tuple[dict[str, Any], bytes | None]:
    """The stored record and its exact bytes, or a fresh record and ``None``."""
    node = _netnode(create=False)
    blob = (
        node.getblob(NETNODE_BLOB_INDEX, NETNODE_BLOB_TAG) if node is not None else None
    )
    if not blob:
        return _empty_record(), None
    stored = bytes(blob)
    try:
        record = json.loads(stored.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise OperationError(
            f"the {NETNODE_NAME} record is not readable UTF-8 JSON: {error}"
        ) from error
    if not isinstance(record, dict):
        raise OperationError(f"the {NETNODE_NAME} record is not a JSON object")
    version = record.get("schema_version")
    if version != SCHEMA_VERSION:
        raise SchemaVersionError(
            f"the {NETNODE_NAME} record is schema version {version!r};"
            f" this build reads and writes version {SCHEMA_VERSION} only,"
            " and will not overwrite it"
        )
    scopes = record.get("scopes")
    if not isinstance(scopes, dict):
        raise OperationError(f"the {NETNODE_NAME} record carries no 'scopes' object")
    for name, scope in scopes.items():
        if not isinstance(scope, dict) or not isinstance(scope.get("findings"), dict):
            raise OperationError(
                f"the {NETNODE_NAME} scope {name!r} is not a stored scope"
            )
        for key, row in scope["findings"].items():
            if not isinstance(row, dict):
                raise OperationError(
                    f"the {NETNODE_NAME} scope {name!r} holds {key!r} as"
                    f" {type(row).__name__}, which is not a finding"
                )
    if not isinstance(record.get("preparation"), dict):
        record["preparation"] = _empty_preparation()
    return record, stored


def _write_record(record: dict[str, Any]) -> bytes:
    """Write the record back as one canonical UTF-8 JSON blob.

    ``sort_keys`` and compact separators make the bytes a function of the
    record alone, so an unchanged record is byte-identical on disk and a
    reader can compare digests instead of guessing.
    """
    if not record.get("managed_idb_id"):
        # Created once, on the first write, and never again: Plan 2 uses it as
        # the catalog identity of a database whose original bytes are unknown.
        record["managed_idb_id"] = uuid.uuid4().hex
    record["schema_version"] = SCHEMA_VERSION
    payload = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(payload) > MAX_RECORD_BYTES:
        raise OperationError(
            f"the {NETNODE_NAME} record would be {len(payload)} bytes;"
            f" the limit is {MAX_RECORD_BYTES}"
        )
    node = _netnode(create=True)
    if not node.setblob(payload, NETNODE_BLOB_INDEX, NETNODE_BLOB_TAG):
        raise OperationError(f"IDA refused to store the {NETNODE_NAME} record")
    return payload


# -- reading the record out -------------------------------------------------


def _row(stored: dict[str, Any], scan_id: object) -> dict[str, Any]:
    """One stored row as it is reported: ``stale`` is derived, never stored."""
    row = dict(stored)
    row["stale"] = stored.get("last_seen_scan_id") != scan_id
    return row


def _rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Every reported row in the record, in page order."""
    rows: list[dict[str, Any]] = []
    for stored in record["scopes"].values():
        scan_id = stored.get("scan_id")
        rows.extend(_row(row, scan_id) for row in stored["findings"].values())
    rows.sort(key=finding_order)
    return rows


def _scope_summary(name: str, stored: dict[str, Any]) -> dict[str, object]:
    """One stored scope, as every record operation reports it.

    ``stale`` counts rows the scope's last scan did not observe again: a
    partial scan keeps them rather than retiring a call site it never looked
    at, so they are reported, and labelled, instead of silently dropped.
    """
    scan_id = stored.get("scan_id")
    findings = stored["findings"]
    return {
        "scope": name,
        "backend": stored.get("backend") or BACKEND_NAME,
        "scan_id": scan_id,
        "scanned_at": stored.get("scanned_at"),
        "coverage": stored.get("coverage"),
        "total": len(findings),
        "stale": sum(
            1 for row in findings.values() if row.get("last_seen_scan_id") != scan_id
        ),
    }


def _summary(
    record: dict[str, Any], blob: bytes | None, rows: list[dict[str, Any]]
) -> dict[str, object]:
    """What every record operation reports about the store as a whole.

    ``rows`` is every reported row of the whole record; the caller already
    built it to page or to count, and building it twice would walk the record
    twice for the same answer.
    """
    counts = dict.fromkeys(TRIAGE_STATUSES, 0)
    for row in rows:
        status = row.get("status")
        if status in counts:
            counts[status] += 1
    return {
        "mutated": False,
        "schema_version": SCHEMA_VERSION,
        "managed_idb_id": record.get("managed_idb_id"),
        "record_present": blob is not None,
        "record_digest": hashlib.sha256(blob).hexdigest() if blob else None,
        "record_bytes": len(blob) if blob else 0,
        "scopes": [
            _scope_summary(name, stored)
            for name, stored in sorted(record["scopes"].items())
        ],
        "target_total": len(rows),
        "stale_total": sum(1 for row in rows if row["stale"]),
        "status_counts": {BACKEND_NAME: dict(counts), "aggregate": dict(counts)},
    }


def _page(
    report: dict[str, object], rows: list[dict[str, Any]], offset: int, limit: int
) -> dict[str, object]:
    window = rows[offset : offset + limit]
    report["offset"] = offset
    report["limit"] = limit
    report["findings"] = window
    report["page_total"] = len(window)
    return report


# -- operations -------------------------------------------------------------


def _findings_page(payload: dict[str, object]) -> dict[str, object]:
    """Page stored rows across every scope of this backend, without rescanning."""
    offset, limit = validate_page(payload.get("offset", 0), payload.get("limit", 100))
    record, blob = _read_record()
    rows = _rows(record)
    return _page(_summary(record, blob, rows), rows, offset, limit)


def _store_scan(payload: dict[str, object]) -> dict[str, object]:
    """Commit one scan of one scope, preserving triage by exact finding ID.

    A ``complete`` scan replaces this scope's rows with exactly what it saw, so
    a row whose call site is gone is retired. A ``partial`` scan merges instead:
    every row it did not observe is kept with the scan ID that last saw it, so
    a reader can tell an assessed row that is stale from one that is current.
    Neither touches another scope, another backend, or the legacy netnode.
    """
    scope = validate_scope(payload.get("scope"))
    scan_id = _record_text(payload, "scan_id")
    scanned_at = _record_text(payload, "scanned_at")
    coverage = payload.get("coverage")
    if coverage not in ("complete", "partial"):
        raise OperationError(
            f"store_scan: coverage must be 'complete' or 'partial', got {coverage!r}"
        )
    rules = _store_rules(payload)
    rule_coverage = _store_rule_coverage(payload)
    warnings = _store_warnings(payload)
    observed = _store_findings(payload, scope, scan_id)
    offset, limit = validate_page(payload.get("offset", 0), payload.get("limit", 100))

    record, _ = _read_record()
    kept = record["scopes"].get(scope, {}).get("findings", {})
    # A complete scan replaces the scope with exactly what it saw. A partial
    # one starts from the rows it never looked at, because not deciding about
    # a call site is not the same as deciding there is nothing there.
    findings: dict[str, Any] = (
        {}
        if coverage == "complete"
        else {key: row for key, row in kept.items() if key not in observed}
    )
    for key, row in observed.items():
        previous = kept.get(key)
        if isinstance(previous, dict):
            # Exact ID only. A changed rule, a changed digest or a changed
            # occurrence ordinal produces a different ID, and the assessment
            # that belonged to the old one is orphaned on purpose.
            for fact in _TRIAGE_FACTS:
                if fact in previous:
                    row[fact] = previous[fact]
        findings[key] = row
    record["scopes"][scope] = {
        "backend": BACKEND_NAME,
        "rules": rules,
        "scan_id": scan_id,
        "scanned_at": scanned_at,
        "coverage": coverage,
        "rule_coverage": rule_coverage,
        "warnings": warnings,
        "findings": findings,
    }
    blob = _write_record(record)

    rows = _rows(record)
    report = _summary(record, blob, rows)
    report["mutated"] = True
    report["scope"] = scope
    report["coverage"] = coverage
    # The scope's own rows, taken out of the ordering the whole record was
    # already put in, rather than sorted a second time. A finding ID names
    # its own scope, so no other scope's row can answer to one of these keys.
    scoped = [row for row in rows if row.get("id") in findings]
    report["scope_total"] = len(scoped)
    report["scope_stale"] = sum(1 for row in scoped if row["stale"])
    return _page(report, scoped, offset, limit)


def _triage(payload: dict[str, object]) -> dict[str, object]:
    """Assess one stored finding, found by its exact ID and nothing else.

    A rejected request raises before anything is written, so the blob stays
    byte-identical and the adapter never saves the database. ``triage_revision``
    therefore counts accepted updates only.
    """
    finding_id = payload.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        raise OperationError("triage: 'finding_id' must be a non-empty string")
    status = validate_status(payload.get("status"))
    rationale = validate_rationale(payload.get("rationale"))

    record, _ = _read_record()
    located: tuple[str, dict[str, Any], dict[str, Any]] | None = None
    for name, entry in sorted(record["scopes"].items()):
        stored = entry["findings"].get(finding_id)
        if isinstance(stored, dict):
            located = (name, entry, stored)
            break
    if located is None:
        raise UnknownFindingError(
            f"no stored finding carries the id {finding_id!r};"
            " a rule change or a changed call-site ordering orphans an"
            " assessment rather than moving it"
        )
    name, entry, stored = located
    stored["status"] = status
    stored["rationale"] = rationale
    stored["assessed_at"] = utc_now()
    revision = stored.get("triage_revision")
    stored["triage_revision"] = (revision if isinstance(revision, int) else 0) + 1
    blob = _write_record(record)

    report = _summary(record, blob, _rows(record))
    report["mutated"] = True
    report["scope"] = name
    report["finding"] = _row(stored, entry.get("scan_id"))
    report["triage_revision"] = stored["triage_revision"]
    return report


# -- payload checking -------------------------------------------------------


def _record_text(payload: dict[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise OperationError(f"store_scan: {name!r} must be a non-empty string")
    return value


def _store_rules(payload: dict[str, object]) -> list[dict[str, Any]]:
    """The rules this scope ran, kept so the scope stays readable on its own."""
    raw = payload.get("rules")
    if not isinstance(raw, list) or not raw:
        raise OperationError("store_scan: 'rules' must be a non-empty list")
    if len(raw) > MAX_SCOPE_RULES:
        raise OperationError(
            f"store_scan: {len(raw)} rules exceed the {MAX_SCOPE_RULES} a scope"
            " may record"
        )
    for position, rule in enumerate(raw):
        if not isinstance(rule, dict):
            raise OperationError(f"store_scan: rules[{position}] must be an object")
    return [dict(rule) for rule in raw]


def _store_rule_coverage(payload: dict[str, object]) -> dict[str, Any]:
    """Per-rule outcome, keyed by the rule index it belongs to."""
    raw = payload.get("rule_coverage")
    if not isinstance(raw, list):
        raise OperationError("store_scan: 'rule_coverage' must be a list")
    coverage: dict[str, Any] = {}
    for position, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise OperationError(
                f"store_scan: rule_coverage[{position}] must be an object"
            )
        index = entry.get("rule_index")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            raise OperationError(
                f"store_scan: rule_coverage[{position}].rule_index must be an index"
            )
        if entry.get("state") not in ("evaluated", "unsupported", "failed"):
            raise OperationError(
                f"store_scan: rule_coverage[{position}].state must be"
                " evaluated, unsupported or failed"
            )
        coverage[str(index)] = {
            "backend": entry.get("backend") or BACKEND_NAME,
            "state": entry["state"],
            "reason": entry.get("reason"),
        }
    return coverage


def _store_warnings(payload: dict[str, object]) -> list[str]:
    raw = payload.get("warnings") or []
    if not isinstance(raw, list):
        raise OperationError("store_scan: 'warnings' must be a list")
    return [str(warning) for warning in raw[:MAX_SCAN_WARNINGS]]


def _store_findings(
    payload: dict[str, object], scope: str, scan_id: str
) -> dict[str, dict[str, Any]]:
    """The rows this scan observed, reduced to the facts the record stores."""
    raw = payload.get("findings")
    if not isinstance(raw, list):
        raise OperationError("store_scan: 'findings' must be a list")
    rows: dict[str, dict[str, Any]] = {}
    for position, item in enumerate(raw):
        if not isinstance(item, dict):
            raise OperationError(f"store_scan: findings[{position}] must be an object")
        row: dict[str, Any] = {}
        for fact in _FINDING_FACTS:
            if fact not in item:
                raise OperationError(
                    f"store_scan: findings[{position}] carries no {fact!r}"
                )
            row[fact] = item[fact]
        key = row["id"]
        if not isinstance(key, str) or not key:
            raise OperationError(
                f"store_scan: findings[{position}].id must be a non-empty string"
            )
        if row["backend"] != BACKEND_NAME:
            raise OperationError(
                f"store_scan: findings[{position}] claims backend"
                f" {row['backend']!r}, but this worker is {BACKEND_NAME!r}"
            )
        if row["source"] != scope:
            raise OperationError(
                f"store_scan: findings[{position}] claims scope"
                f" {row['source']!r}, not {scope!r}"
            )
        if key in rows:
            raise OperationError(
                f"store_scan: findings[{position}] repeats the id {key!r}"
            )
        row["status"] = UNASSESSED_STATUS
        row["rationale"] = ""
        row["assessed_at"] = None
        row["triage_revision"] = 0
        row["link_id"] = None
        row["link_revision"] = None
        row["last_seen_scan_id"] = scan_id
        rows[key] = row
    return rows


# ---------------------------------------------------------------------------
# Preparation operation: what one IDA database can recover before a scan.
#
# Four passes live here. ``functions`` looks at the executable bytes no
# function owns and at the addresses something references, decodes what it
# finds, and defines a function only where a call, a jump, a relocated
# pointer or an ELF symbol says the address is an entry point and the decode
# reaches a return without touching a byte an existing function owns.
# ``strings`` reads mapped bytes directly — never IDA's string list — and
# decodes bounded ASCII and both UTF-16 byte orders, then walks the
# instructions of the functions the first pass left behind and recovers the
# buffers they assemble out of immediate operands. ``structures`` reads the
# sized operands that really touch one named data object and defines a
# layout only where every access at an offset agrees on its width and the
# offsets tile the object. ``pointer_tables`` reads the loader's own
# relocation records at pointer-width aligned slots, follows each stored
# value into the image, and defines a table only where a relocation backs
# every slot of a run and every target lands somewhere mapped.
#
# Three rules shape every line below.
#
# **Evidence or nothing.** A recovered string carries the bytes it was
# decoded from and their addresses, or the instructions that wrote them and
# the value each one wrote. A defined function carries its decoded
# instructions, what made its entry an entry, and the gap that proves it
# overlaps nothing. What cannot be justified is reported as a candidate with
# the reason it is only a candidate; it is never applied and never dropped.
#
# **Bounded, and loud about it.** Every byte read, address examined,
# instruction decoded, function walked and candidate produced is charged to
# :class:`_PrepareBudget`, in the style of the expression interpreter's
# ``_charge``. A pass that runs out names the addresses it never reached in
# the range it was in, and names every range after it too. There is no
# silent truncation anywhere in this section.
#
# **The original bytes are not ours.** Everything here writes to the managed
# database the worker already has open, through IDA's own ``add_func``,
# ``create_strlit`` and ``apply_tinfo``, and the adapter saves it once at the
# end of the lease behind the rescue copy ``_save_session`` takes. There is
# no second save route, and no path from here to the operator's binary or
# supplied IDB.
# ---------------------------------------------------------------------------

#: The preparation passes this build runs, in dependency order. ``strings``
#: needs ``functions`` for its instruction stage; the two data passes read
#: the analysis as they find it and stand on their own, and run last because
#: a function the first pass recovers is a function whose operands and whose
#: entry the last two can then see.
PREPARE_PASSES: Final[tuple[str, ...]] = (
    "functions",
    "strings",
    "structures",
    "pointer_tables",
)

#: Ceilings on one preparation run. A payload may lower a bound, never raise
#: one, and a pass that hits a bound says which addresses it never reached.
PREPARE_LIMITS: Final[dict[str, int]] = {
    #: Mapped bytes read, across every range of every pass.
    "bytes": 64 * 1024 * 1024,
    #: Candidates one run may produce.
    "candidates": 2000,
    #: Addresses examined as a possible function entry.
    "seeds": 20000,
    #: Instructions decoded, across every pass.
    "instructions": 400000,
    #: Functions walked for instruction-derived strings.
    "functions": 5000,
    #: Wall-clock seconds the whole run may take.
    "seconds": 300,
}

#: Address space of everything one single-image database reports. The adapter
#: publishes the same constant; this module cannot import it.
ADDRESS_SPACE_IMAGE: Final = "image"

#: Most warnings one preparation result carries back.
MAX_PREPARE_WARNINGS: Final = 64

#: What one pass may claim about one address range, as the managed record
#: stores it. There is no fourth answer.
PREPARE_COVERAGES: Final[tuple[str, ...]] = ("complete", "partial", "unavailable")

#: Version of what the four passes above recover and how they justify it.
#: It rides in the backend capability fingerprint, so a build that changed
#: what a pass does re-runs preparation instead of reusing a revision an
#: older build recorded under the same name.
PREPARE_CONTRACT: Final = 1

#: Longest preparation identifier the managed record accepts. The ids this
#: server mints are far shorter; this bounds the ones a caller supplies.
MAX_ANALYSIS_ID_LENGTH: Final = 200

#: Bytes one recovered string may span, terminator included.
MAX_STRING_BYTES: Final = 4096
#: Shortest run of characters reported as a string. Shorter runs are mostly
#: coincidence in compiled code, and a scan that reported them would bury the
#: strings a reviewer is looking for.
MIN_STRING_CHARS: Final = 5
#: Characters a run needs before this pass will *define* it in the database
#: rather than only report it. Five printable bytes followed by a NUL happen
#: often inside unwind tables, relocation data and compressed sections, and a
#: string literal defined over those bytes is a false positive written into
#: the analysis. Reporting such a run costs a reviewer one line; defining it
#: costs them a wrong item. Longer runs are reported and defined.
MIN_DEFINED_STRING_CHARS: Final = 8
#: Bytes of one recovered string quoted verbatim in its evidence. The whole
#: run's digest is always carried, so a longer string is still checkable
#: without putting an unbounded slice of the image in a JSON result.
MAX_QUOTED_BYTES: Final = 256
#: Mapped bytes read per step while scanning a segment.
_READ_STEP: Final = 64 * 1024
#: Byte values a recovered string may contain.
_PRINTABLE: Final = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

#: Bytes one candidate function may span.
MAX_FUNCTION_BYTES: Final = 64 * 1024
#: Instructions decoded for one candidate function.
MAX_FUNCTION_INSTRUCTIONS: Final = 4096
#: Decoded instructions quoted in one function candidate's evidence.
MAX_QUOTED_INSTRUCTIONS: Final = 16
#: References listed for one examined address.
MAX_QUOTED_REFERENCES: Final = 16
#: Frame bytes one function's constant-write recovery tracks at once.
MAX_FRAME_BYTES: Final = 4096
#: Alignment an unreferenced gap address is retried at. Compilers align
#: function entries; an unaligned address with nothing pointing at it is not
#: an entry point, it is the middle of something.
_GAP_ALIGNMENT: Final = 16

#: Entry evidence that is strong enough to define a function, in the order a
#: single address's evidence is reported. A reference is stronger than a
#: name: something uses the address, rather than something labelled it.
_ENTRY_PROOF: Final = ("call_xref", "jump_xref", "data_pointer", "symbol")

#: The processor whose constant-write stack strings this build recovers.
_X86: Final = "metapc"
#: The frame-pointer register of that processor, in both bitnesses.
_FRAME_POINTER: Final = 5

#: Fields one object needs before its layout is a structure rather than a
#: variable. One offset accessed at one width is a typed global, and calling
#: that a structure would bury the objects that really have a layout.
MIN_STRUCTURE_FIELDS: Final = 2
#: Bytes of one data object this pass will examine. An object larger than
#: this is named in a warning rather than walked: the cost of reading every
#: referenced byte of a multi-megabyte array is charged to a run that has
#: other ranges to get to.
MAX_STRUCTURE_BYTES: Final = 4096
#: Instructions quoted as the use sites of one field. The counts of reads
#: and of writes are always exact; this bounds only how many are quoted.
MAX_QUOTED_USE_SITES: Final = 8
#: Prefix of every type this pass creates. The name carries the address the
#: layout was proven at and nothing else: a name that guessed at what the
#: object is for would be an inference this pass has no evidence for, and
#: the design keeps those as proposals.
_STRUCTURE_TYPE_PREFIX: Final = "vulfi_prep_struct_"
#: Widths a field may have. A sized operand of any other width is evidence
#: about bytes, not about a field this build can spell as a type.
_FIELD_WIDTHS: Final = (1, 2, 4, 8)
#: What ``tinfo_t.get_size`` answers for a type with no size of its own.
_UNKNOWN_TYPE_SIZE: Final = 0xFFFF_FFFF_FFFF_FFFF

#: Consecutive relocated slots one run needs before it is called a table.
#: One relocated pointer is a pointer, not a table, and the ones that form
#: no run are counted into a warning rather than reported one by one.
MIN_POINTER_TABLE_ENTRIES: Final = 2
#: Entries quoted in one table candidate's evidence. ``entry_count`` is
#: always the whole run.
MAX_QUOTED_TABLE_ENTRIES: Final = 64

#: Confidences this build publishes. They order candidates for review; none
#: of them is proof, and ``applied`` is the only claim that the database
#: changed.
_CONFIDENT: Final = 0.9
_LIKELY: Final = 0.7
_WEAK: Final = 0.4


class _PrepareBudgetError(Exception):
    """One preparation budget ran out, so its range is partial."""

    def __init__(self, budget: str, limit: int) -> None:
        super().__init__(
            f"the {budget} budget of {limit} ran out here, so the addresses"
            " below were never looked at"
        )
        self.budget = budget
        self.limit = limit


class _PrepareBudget:
    """What one preparation run may spend, charged as it is spent.

    One counter per kind of work, decremented by the code doing the work, and
    an exception the moment a counter would go negative — the same shape the
    expression interpreter's ``_charge`` uses. Nothing here truncates quietly:
    the pass that catches the exception is the one that knows which addresses
    it had not reached, and it is required to name them.
    """

    def __init__(self, limits: dict[str, int], clock: Callable[[], float]) -> None:
        self._limits = dict(limits)
        self._left = {
            name: value for name, value in limits.items() if name != "seconds"
        }
        self._clock = clock
        self._deadline = clock() + limits["seconds"]
        #: Budgets that really ran out, in the order they did.
        self.exhausted: list[str] = []

    def charge(self, name: str, amount: int = 1) -> None:
        """Spend ``amount`` of ``name``, or stop this range where it stands."""
        left = self._left[name] - amount
        if left < 0:
            self._stop(name)
        self._left[name] = left
        if self._clock() > self._deadline:
            self._stop("seconds")

    def left(self, name: str) -> int:
        return self._left[name]

    def _stop(self, name: str) -> NoReturn:
        if name not in self.exhausted:
            self.exhausted.append(name)
        raise _PrepareBudgetError(name, self._limits[name])


def validate_prepare_passes(value: object) -> tuple[str, ...]:
    """The passes to run, in dependency order, or exactly what is wrong.

    ``None`` means all four of them. A name outside that set is refused by
    name: accepting it and running something else would report a coverage
    nothing produced.
    """
    if value is None:
        return PREPARE_PASSES
    if not isinstance(value, (list, tuple)) or not value:
        raise OperationError(
            "prepare: 'passes' must be a non-empty list of pass names, one or"
            f" more of {', '.join(PREPARE_PASSES)}"
        )
    requested: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise OperationError(
                f"prepare: every pass must be a string, got {item!r}"
            )
        if item not in PREPARE_PASSES:
            raise OperationError(
                f"prepare: this build does not run a {item!r} pass; it runs"
                f" {', '.join(PREPARE_PASSES)}"
            )
        if item not in requested:
            requested.append(item)
    return tuple(name for name in PREPARE_PASSES if name in requested)


def validate_prepare_limits(value: object) -> dict[str, int]:
    """Merge requested limits, which may only tighten the shipped ceilings."""
    if value is None:
        return dict(PREPARE_LIMITS)
    if not isinstance(value, dict):
        raise OperationError("prepare: 'limits' must be an object")
    unknown = sorted(set(value) - set(PREPARE_LIMITS))
    if unknown:
        raise OperationError(f"prepare: unknown limit(s) {', '.join(unknown)}")
    limits = dict(PREPARE_LIMITS)
    for name, ceiling in PREPARE_LIMITS.items():
        if name not in value:
            continue
        requested = value[name]
        if (
            isinstance(requested, bool)
            or not isinstance(requested, int)
            or requested < 1
        ):
            raise OperationError(
                f"prepare: limits[{name!r}] must be a positive integer"
            )
        limits[name] = min(requested, ceiling)
    return limits


def validate_analysis_id(value: object) -> str:
    """Accept one preparation revision identifier, or say what is wrong."""
    if not isinstance(value, str) or not value.strip():
        raise OperationError(
            f"analysis_id must be a non-empty string, got {value!r}"
        )
    if len(value) > MAX_ANALYSIS_ID_LENGTH:
        raise OperationError(
            f"analysis_id is {len(value)} characters; the limit is"
            f" {MAX_ANALYSIS_ID_LENGTH}"
        )
    return value


# ---------------------------------------------------------------------------
# Proposals: what an agent may ask an operator to approve
# ---------------------------------------------------------------------------
#
# Everything below is about *data*. A proposal names one candidate this
# catalog already holds, quotes that candidate's own evidence back, and asks
# for one of five changes in a closed vocabulary. It is validated here, on
# the host, before any database is opened, and validated again in the worker
# before anything is applied, by this same code.
#
# The vocabulary being closed is the whole defence. Every field a proposal
# may carry is listed, every value a kind may carry is listed, and every
# string that becomes a symbol in the database has to be an ASCII identifier.
# A script, a provider command, a shell fragment or a Python expression
# cannot be spelled in it at all — not because it would be refused on its way
# to an interpreter, but because there is no interpreter anywhere on this
# path and no field that could carry one.

#: The five changes a proposal may ask for. The design names these and no
#: others, and a sixth is refused by name rather than ignored.
PROPOSAL_KINDS: Final[tuple[str, ...]] = (
    "name",
    "function_boundary",
    "string_decode",
    "structure_field",
    "pointer_table",
)

#: Where a proposal can be in its life. ``approved`` is the operator's
#: decision recorded *before* the write it authorizes, so a decision that was
#: never confirmed applied is visible afterwards rather than lost; ``applied``
#: is the only state that claims the managed artifact really changed.
PROPOSAL_STATES: Final[tuple[str, ...]] = (
    "pending",
    "approved",
    "rejected",
    "applied",
    "stale",
)

#: Proposals one request may carry.
MAX_PROPOSALS: Final = 50
#: Candidate evidence facts one proposal may quote back.
MAX_PROPOSAL_EVIDENCE_FACTS: Final = 32
#: Fields one proposed layout may describe.
MAX_PROPOSAL_FIELDS: Final = 64
#: Longest identifier a proposal may ask to write into the database.
MAX_PROPOSAL_NAME_LENGTH: Final = 64
#: Entries one proposed pointer table may cover.
MAX_PROPOSED_TABLE_ENTRIES: Final = 4096

#: Encodings a reviewed string may be *defined* with. UTF-16BE is absent on
#: purpose: this IDA registers no big-endian UTF-16 string type, so there is
#: no writer for one, and a proposal to define one is refused here rather
#: than accepted, reviewed, and discovered to be unapplicable at the moment
#: an operator has already approved it.
PROPOSAL_ENCODINGS: Final[tuple[str, ...]] = ("ascii", "utf-16le")

#: Widths a proposed field may have, matching what the structures pass can
#: spell as a type.
_PROPOSAL_WIDTHS: Final = (1, 2, 4, 8)

#: Exactly the fields one proposal carries. Anything else is refused by name.
_PROPOSAL_FIELDS: Final = frozenset(
    {
        "candidate_id",
        "kind",
        "address_space",
        "address",
        "value",
        "evidence",
        "rationale",
    }
)


def validate_proposal_request(value: object) -> list[object]:
    """Accept the shape of one ``vulfi_propose_recovery`` request.

    Only the shape. Each proposal inside it is validated on its own by
    :func:`validate_proposal`, so one unacceptable proposal is reported as
    one unacceptable proposal and the rest of the request still stands.
    """
    if not isinstance(value, list):
        raise OperationError(
            f"proposals must be a list, got {type(value).__name__}"
        )
    if not value:
        raise OperationError(
            "proposals: send at least one proposal; an empty list proposes"
            " nothing, which is not the same as proposing nothing be done"
        )
    if len(value) > MAX_PROPOSALS:
        raise OperationError(
            f"proposals carries {len(value)} entries; one request may carry"
            f" {MAX_PROPOSALS}"
        )
    return list(value)


def validate_proposal(value: object) -> dict[str, Any]:
    """Accept one proposal, or say exactly what is wrong with it.

    The returned body is normalized and carries the half-open address range
    the change covers, derived from the kind and the proposed value rather
    than supplied beside them: a reviewer is never shown a range the proposal
    itself did not imply, and there is no second spelling of it to disagree.
    """
    if not isinstance(value, dict):
        raise OperationError(
            f"a proposal must be an object, got {type(value).__name__}"
        )
    unknown = sorted(str(key) for key in set(value) - _PROPOSAL_FIELDS)
    if unknown:
        raise OperationError(
            f"a proposal carries {', '.join(unknown)}, which is not one of the"
            f" fields a proposal has ({', '.join(sorted(_PROPOSAL_FIELDS))});"
            " a proposal is data this server stores and shows an operator,"
            " never anything it runs"
        )
    kind = value.get("kind")
    if kind not in PROPOSAL_KINDS:
        raise OperationError(
            f"kind={kind!r} is not a change a proposal may ask for; the"
            f" permitted kinds are {', '.join(PROPOSAL_KINDS)}"
        )
    address = _proposal_whole(value.get("address"), "address")
    proposed, end = _PROPOSAL_VALUES[str(kind)](value.get("value"), address)
    return {
        "candidate_id": _proposal_text(
            value.get("candidate_id"), "candidate_id", MAX_ANALYSIS_ID_LENGTH
        ),
        "kind": str(kind),
        "address_space": _proposal_text(
            value.get("address_space"), "address_space", MAX_SCAN_NAME_LENGTH
        ),
        "address": address,
        "start": address,
        "end": end,
        "value": proposed,
        "evidence": _proposal_claim(value.get("evidence")),
        "rationale": _proposal_rationale(value.get("rationale")),
    }


def proposal_payload(proposal: dict[str, Any]) -> dict[str, Any]:
    """One validated proposal, back in the shape it was submitted in.

    :func:`validate_proposal` adds the address range the kind and the value
    imply, and refuses a proposal that carries a field it does not have. A
    validated body therefore cannot be sent anywhere that validates it again
    — the worker, which trusts nothing the host shaped — without first being
    reduced to what was really proposed. The derived range is not sent
    because the far side derives it, which is the only way there is one
    answer to what range a proposal covers.
    """
    return {field: proposal[field] for field in sorted(_PROPOSAL_FIELDS)}


def _proposal_rationale(value: object) -> str:
    """The agent's own words, bounded exactly as an assessment's are."""
    try:
        return validate_rationale(value)
    except OperationError as refused:
        raise OperationError(f"a proposal's {refused}") from refused


def _proposal_text(value: object, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationError(f"{what} must be a non-empty string, got {value!r}")
    if len(value) > limit:
        raise OperationError(
            f"{what} is {len(value)} characters; the limit is {limit}"
        )
    return value


def _proposal_whole(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise OperationError(f"{what} must be an integer >= 0, got {value!r}")
    return value


def _proposal_identifier(value: object, what: str) -> str:
    """One ASCII identifier, which is all a name written into a database is.

    This is where a proposed *value* stops being able to express anything
    executable: ``__import__('os').system('id')`` and ``$(id)`` are both
    refused here, as names, long before anything could ask what they mean.
    """
    if not isinstance(value, str) or not value:
        raise OperationError(f"{what} must be a non-empty string, got {value!r}")
    if len(value) > MAX_PROPOSAL_NAME_LENGTH:
        raise OperationError(
            f"{what} is {len(value)} characters; the limit is"
            f" {MAX_PROPOSAL_NAME_LENGTH}"
        )
    if not (value.isascii() and value.isidentifier()):
        raise OperationError(
            f"{what}={value!r} is not an ASCII identifier, and an identifier is"
            " all a name written into an analysis may be"
        )
    return value


def _proposal_claim(value: object) -> dict[str, Any]:
    """The candidate evidence this proposal rests on, quoted back verbatim.

    A proposal that cites nothing is refused here. Whether what it cites is
    *true* is decided against the stored candidate by
    :func:`vulfi_mcp.prepare.check_proposal_against_candidate`, which is the
    only place that has the candidate to compare with.
    """
    if not isinstance(value, dict):
        raise OperationError(
            "a proposal's evidence must be an object quoting the facts its"
            f" candidate records, got {type(value).__name__}"
        )
    if not value:
        raise OperationError(
            "a proposal's evidence is empty: quote at least one fact the named"
            " candidate records, so a reviewer can check the proposal against"
            " the evidence it claims to rest on"
        )
    if len(value) > MAX_PROPOSAL_EVIDENCE_FACTS:
        raise OperationError(
            f"a proposal's evidence quotes {len(value)} facts; the limit is"
            f" {MAX_PROPOSAL_EVIDENCE_FACTS}"
        )
    for key in value:
        if not isinstance(key, str) or not key:
            raise OperationError(
                f"a proposal's evidence is keyed by {key!r}, and every key must"
                " be the name of a fact the candidate records"
            )
    return dict(value)


def _proposal_value(
    value: object, kind: str, expected: tuple[str, ...]
) -> dict[str, Any]:
    """One proposed value, with exactly the keys its kind has and no others."""
    if not isinstance(value, dict):
        raise OperationError(
            f"a {kind} proposal's value must be an object, got"
            f" {type(value).__name__}"
        )
    held = {str(key) for key in value}
    unknown = sorted(held - set(expected))
    missing = sorted(set(expected) - held)
    if unknown or missing:
        raise OperationError(
            f"a {kind} proposal's value must carry exactly"
            f" {', '.join(expected)}"
            + (f"; it also carries {', '.join(unknown)}" if unknown else "")
            + (f"; it is missing {', '.join(missing)}" if missing else "")
        )
    return dict(value)


def _proposal_name_value(value: object, address: int) -> tuple[dict[str, Any], int]:
    fields = _proposal_value(value, "name", ("name",))
    return {"name": _proposal_identifier(fields["name"], "value.name")}, address + 1


def _proposal_boundary_value(
    value: object, address: int
) -> tuple[dict[str, Any], int]:
    fields = _proposal_value(value, "function_boundary", ("end",))
    end = _proposal_whole(fields["end"], "value.end")
    if end <= address:
        raise OperationError(
            f"value.end={end:#x} is not past the entry {address:#x}, so this"
            " proposal describes no function at all"
        )
    if end - address > MAX_FUNCTION_BYTES:
        raise OperationError(
            f"value.end={end:#x} is {end - address} bytes past the entry;"
            f" one function may span {MAX_FUNCTION_BYTES}"
        )
    return {"end": end}, end


def _proposal_string_value(value: object, address: int) -> tuple[dict[str, Any], int]:
    fields = _proposal_value(value, "string_decode", ("encoding", "length"))
    encoding = fields["encoding"]
    if encoding not in PROPOSAL_ENCODINGS:
        raise OperationError(
            f"value.encoding={encoding!r} is not an encoding this build can"
            f" define a string in; the ones it can are"
            f" {', '.join(PROPOSAL_ENCODINGS)}. A UTF-16BE run is reported"
            " with its exact bytes and never defined, because this IDA"
            " registers no big-endian UTF-16 string type and there is no"
            " writer to approve"
        )
    length = _proposal_whole(fields["length"], "value.length")
    if not 1 <= length <= MAX_STRING_BYTES:
        raise OperationError(
            f"value.length must be in 1..{MAX_STRING_BYTES}, got {length}"
        )
    return {"encoding": str(encoding), "length": length}, address + length


def _proposal_layout_value(value: object, address: int) -> tuple[dict[str, Any], int]:
    fields = _proposal_value(value, "structure_field", ("type_name", "fields"))
    type_name = _proposal_identifier(fields["type_name"], "value.type_name")
    rows = fields["fields"]
    if not isinstance(rows, list) or not rows:
        raise OperationError(
            "value.fields must be a non-empty list of the fields this layout"
            f" has, got {rows!r}"
        )
    if len(rows) > MAX_PROPOSAL_FIELDS:
        raise OperationError(
            f"value.fields describes {len(rows)} fields; the limit is"
            f" {MAX_PROPOSAL_FIELDS}"
        )
    described: list[dict[str, Any]] = []
    names: set[str] = set()
    reach = 0
    for index, row in enumerate(rows):
        entry = _proposal_value(row, f"structure_field fields[{index}]",
                                ("offset", "width", "name"))
        offset = _proposal_whole(entry["offset"], f"value.fields[{index}].offset")
        width = entry["width"]
        if width not in _PROPOSAL_WIDTHS:
            raise OperationError(
                f"value.fields[{index}].width must be one of"
                f" {', '.join(str(one) for one in _PROPOSAL_WIDTHS)},"
                f" got {width!r}"
            )
        if offset != reach:
            # A layout with a hole in it is a layout nobody established, and
            # one with an overlap is a union. Both are refused rather than
            # written into the database as if they were proven.
            raise OperationError(
                f"value.fields[{index}] starts at offset {offset} where the"
                f" fields before it reach {reach}: a proposed layout must"
                " cover its bytes from offset 0 with no gap and no overlap"
            )
        if offset % width:
            raise OperationError(
                f"value.fields[{index}] puts a {width}-byte field at offset"
                f" {offset}, which is not a multiple of its own width"
            )
        name = _proposal_identifier(entry["name"], f"value.fields[{index}].name")
        if name in names:
            raise OperationError(
                f"value.fields[{index}] repeats the field name {name!r}"
            )
        names.add(name)
        described.append({"offset": offset, "width": int(width), "name": name})
        reach = offset + int(width)
    return {"type_name": type_name, "fields": described}, address + reach


def _proposal_table_value(value: object, address: int) -> tuple[dict[str, Any], int]:
    fields = _proposal_value(value, "pointer_table", ("entry_count", "pointer_width"))
    count = _proposal_whole(fields["entry_count"], "value.entry_count")
    width = fields["pointer_width"]
    if width not in (4, 8):
        raise OperationError(
            f"value.pointer_width must be 4 or 8, got {width!r}"
        )
    if not MIN_POINTER_TABLE_ENTRIES <= count <= MAX_PROPOSED_TABLE_ENTRIES:
        raise OperationError(
            f"value.entry_count must be in {MIN_POINTER_TABLE_ENTRIES}.."
            f"{MAX_PROPOSED_TABLE_ENTRIES}, got {count}: one relocated pointer"
            " is a pointer, not a table"
        )
    return (
        {"entry_count": count, "pointer_width": int(width)},
        address + count * int(width),
    )


#: One validator per kind, each returning the normalized value and the end of
#: the address range that value implies.
_PROPOSAL_VALUES: Final[
    dict[str, Callable[[object, int], tuple[dict[str, Any], int]]]
] = {
    "name": _proposal_name_value,
    "function_boundary": _proposal_boundary_value,
    "string_decode": _proposal_string_value,
    "structure_field": _proposal_layout_value,
    "pointer_table": _proposal_table_value,
}


def validate_preparation_coverage(value: object) -> dict[str, str]:
    """Accept the bounded per-pass coverage the managed record may carry.

    This is the whole of what the IDB stores about what preparation found:
    one of three words per pass, and nothing else. The candidates themselves
    live in the catalog, which is the only place large enough to hold them
    and the only place a reader may page them from.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OperationError("record_preparation: 'coverage' must be an object")
    coverage: dict[str, str] = {}
    for name, state in value.items():
        if name not in PREPARE_PASSES:
            raise OperationError(
                f"record_preparation: this build does not run a {name!r} pass;"
                f" it runs {', '.join(PREPARE_PASSES)}"
            )
        if state not in PREPARE_COVERAGES:
            raise OperationError(
                f"record_preparation: coverage[{name!r}] is {state!r}; one of"
                f" {', '.join(PREPARE_COVERAGES)} is the only answer"
            )
        coverage[name] = state
    return coverage


def capability_fingerprint(capabilities: object) -> str:
    """One stable digest of what a backend could do for one exact database.

    A recorded preparation revision is reusable only while this answers the
    same thing it answered when the revision was made: a different IDA, a
    different processor module, a decompiler that has appeared or gone, a
    changed pass set or a changed budget all produce a different digest and
    therefore a re-run, rather than a result reused from a backend that no
    longer exists here.
    """
    try:
        canonical = json.dumps(
            capabilities, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as error:
        raise OperationError(f"capabilities are not JSON: {error}") from error
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _capabilities() -> dict[str, Any]:
    """What this build, this IDA and this database can do between them."""
    import ida_hexrays
    import ida_ida
    import idaapi

    return {
        "backend": BACKEND_NAME,
        "contract": PREPARE_CONTRACT,
        "ida_version": idaapi.get_kernel_version(),
        "processor": ida_ida.inf_get_procname(),
        "bits": 64 if ida_ida.inf_is_64bit() else 32,
        "endianness": "big" if ida_ida.inf_is_be() else "little",
        "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
        "passes": list(PREPARE_PASSES),
        "limits": dict(PREPARE_LIMITS),
    }


def _preparation_report(record: dict[str, Any]) -> dict[str, object]:
    """The bounded summary this database carries, and who could have made it.

    Every preparation operation answers with exactly this, so the reuse check
    and the run that satisfies it compare the same fields computed by the
    same code rather than two spellings of one idea.
    """
    import ida_loader
    import ida_nalt

    digest = ida_nalt.retrieve_input_file_sha256()
    capabilities = _capabilities()
    return {
        "backend": BACKEND_NAME,
        "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
        "input_file": ida_nalt.get_root_filename(),
        "input_sha256": digest.hex() if digest else None,
        "managed_idb_id": record.get("managed_idb_id"),
        "preparation": dict(record["preparation"]),
        "capabilities": capabilities,
        "capability_fingerprint": capability_fingerprint(capabilities),
    }


def _preparation_summary(payload: dict[str, object]) -> dict[str, object]:
    """Read the preparation summary, without changing or creating anything.

    ``mutated`` is ``False``, so the lease that ran this does not save: a
    reuse check must never be the reason a managed database was rewritten.
    """
    record, _ = _read_record()
    return {"mutated": False, **_preparation_report(record)}


def _record_preparation(payload: dict[str, object]) -> dict[str, object]:
    """Write the bounded preparation summary into the managed record.

    Only the summary. The revision is not set here: it moves in the same
    write as the change that earned it, inside the ``prepare`` operation, so
    there is no state in which the artifact moved and its revision did not,
    and none in which this call could move a revision nothing applied.
    """
    analysis_id = validate_analysis_id(payload.get("analysis_id"))
    coverage = validate_preparation_coverage(payload.get("coverage"))
    catalog_key = payload.get("catalog_key")
    if catalog_key is not None and (
        not isinstance(catalog_key, str)
        or not catalog_key.strip()
        or len(catalog_key) > MAX_ANALYSIS_ID_LENGTH
    ):
        raise OperationError(
            f"record_preparation: 'catalog_key' must be a non-empty string of"
            f" at most {MAX_ANALYSIS_ID_LENGTH} characters, got {catalog_key!r}"
        )
    record, _ = _read_record()
    preparation = record["preparation"]
    preparation["analysis_id"] = analysis_id
    preparation["coverage"] = coverage
    preparation["catalog_key"] = catalog_key
    _write_record(record)
    return {"mutated": True, **_preparation_report(record)}


def _ascii_run(raw: bytes, start: int) -> tuple[int, str] | None:
    """The NUL-terminated printable run at ``start``, with its byte length.

    A terminator is required. An unterminated tail of printable bytes is as
    often the start of the next thing as it is a string, and this pass would
    rather miss it than publish a boundary it cannot point at.
    """
    end = start
    stop = min(len(raw), start + MAX_STRING_BYTES - 1)
    while end < stop and raw[end] in _PRINTABLE:
        end += 1
    if end - start < MIN_STRING_CHARS or end >= len(raw) or raw[end] != 0:
        return None
    return end + 1 - start, raw[start:end].decode("ascii")


def _utf16_run(raw: bytes, start: int, *, big_endian: bool) -> tuple[int, str] | None:
    """The NUL-terminated UTF-16 run at ``start``, in one byte order.

    Only characters whose other byte is zero are accepted, which is ASCII
    inside UTF-16. A wider decode would have to guess at code pages this pass
    has no evidence for, and the design says to report those as attempted
    methods rather than as decoded text.
    """
    characters: list[str] = []
    end = start
    stop = min(len(raw), start + MAX_STRING_BYTES - 2)
    while end + 1 < stop:
        high, low = (raw[end], raw[end + 1]) if big_endian else (raw[end + 1], raw[end])
        if high != 0 or low not in _PRINTABLE:
            break
        characters.append(chr(low))
        end += 2
    if len(characters) < MIN_STRING_CHARS or end + 1 >= len(raw):
        return None
    if raw[end] != 0 or raw[end + 1] != 0:
        return None
    return end + 2 - start, "".join(characters)


def _alignment(address: int) -> int:
    """The largest power of two up to 64 that divides ``address``."""
    if address == 0:
        return 64
    return min(64, address & -address)


def _quoted(raw: bytes) -> dict[str, object]:
    """One byte run, as evidence: a bounded quote and the whole run's digest."""
    return {
        "bytes_hex": raw[:MAX_QUOTED_BYTES].hex(),
        "bytes_quoted": min(len(raw), MAX_QUOTED_BYTES),
        "bytes_sha256": hashlib.sha256(raw).hexdigest(),
    }


class _Preparation:
    """One bounded preparation run over the database this worker has open."""

    def __init__(self, payload: dict[str, object]) -> None:
        import ida_bytes
        import ida_fixup
        import ida_funcs
        import ida_ida
        import ida_idp
        import ida_loader
        import ida_nalt
        import ida_name
        import ida_segment
        import ida_typeinf
        import ida_ua
        import ida_xref
        import idaapi
        import idautils

        self._bytes = ida_bytes
        self._fixup = ida_fixup
        self._funcs = ida_funcs
        self._idp = ida_idp
        self._loader = ida_loader
        self._nalt = ida_nalt
        self._names = ida_name
        self._segment = ida_segment
        self._types = ida_typeinf
        self._ua = ida_ua
        self._xref = ida_xref
        self._api = idaapi
        self._utils = idautils

        self._passes = validate_prepare_passes(payload.get("passes"))
        self._limits = validate_prepare_limits(payload.get("limits"))
        self._budget = _PrepareBudget(self._limits, time.monotonic)
        self._processor = ida_ida.inf_get_procname()
        self._bits = 64 if ida_ida.inf_is_64bit() else 32
        self._image_base = idaapi.get_imagebase()
        #: Width and byte order of one pointer in this image, as the
        #: database itself reports them. Every table below is read with
        #: these two and reports them with its evidence, because "these
        #: bytes are a pointer" is a claim about both.
        self._pointer_width = self._bits // 8
        self._endianness = "big" if ida_ida.inf_is_be() else "little"
        #: The loader's own relocation kinds, by the code a fixup carries,
        #: so a cited relocation is named rather than numbered.
        self._fixup_names = {
            getattr(ida_fixup, name): name
            for name in dir(ida_fixup)
            if name.startswith("FIXUP_")
        }
        #: The IDA string type each encoding is defined with, where there is
        #: one. IDA 9.4 registers UTF-8, UTF-16LE and UTF-32LE and no
        #: big-endian UTF-16, so a UTF-16BE run is reported and not defined.
        self._string_types: dict[str, int | None] = {
            "ascii": ida_nalt.STRTYPE_C,
            "utf-16le": ida_nalt.STRTYPE_C_16,
            "utf-16be": None,
        }
        self._changes = (
            ida_idp.CF_CHG1,
            ida_idp.CF_CHG2,
            ida_idp.CF_CHG3,
            ida_idp.CF_CHG4,
            ida_idp.CF_CHG5,
            ida_idp.CF_CHG6,
        )
        self._candidates: list[dict[str, Any]] = []
        self._applied: list[str] = []
        self._warnings: list[str] = []
        self._skipped: list[dict[str, object]] = []
        #: Where the pass currently running had got to, so that a budget that
        #: runs out names the rest of the range instead of dropping it.
        self._cursor = 0
        #: Aligned gap addresses that decoded into nothing, counted rather
        #: than reported one by one: an address with no reference, no symbol
        #: and no complete decode is padding, and a candidate per padding
        #: slot would bury the candidates that mean something.
        self._gap_rejections = 0
        #: Printable runs that are already defined items, counted the same way.
        self._already_defined = 0
        #: Functions whose frame this build cannot follow.
        self._unsupported_frames = 0
        #: How far along the segment being scanned a recovered run already
        #: reaches, so a run read across a read step is reported once.
        self._claimed = 0
        #: Objects whose extent is past :data:`MAX_STRUCTURE_BYTES`, and
        #: relocated pointers that formed no run at all, counted rather than
        #: reported one by one for the same reason padding slots are.
        self._oversized_objects = 0
        self._lone_pointers = 0

    # -- entry point ------------------------------------------------------

    def run(self) -> dict[str, object]:
        record, _ = _read_record()
        preparation = record["preparation"]
        runners = {
            "functions": self._functions_pass,
            "strings": self._strings_pass,
            "structures": self._structures_pass,
            "pointer_tables": self._pointer_tables_pass,
        }
        results = [runners[name]() for name in self._passes]
        revision = preparation.get("revision") or 0
        written = False
        if self._applied:
            # The managed artifact changed, so the revision these results
            # describe is a new one. The bump rides in the same netnode write
            # the adapter saves with the changes themselves: there is no state
            # in which the artifact moved and its revision did not.
            revision = int(revision) + 1
            preparation["revision"] = revision
            _write_record(record)
            written = True
        elif not record.get("managed_idb_id"):
            # Nothing was applied, so the revision stands — but this database
            # has never been written to and so has no identity yet, and the
            # catalog keys a database-only target on exactly that identity.
            # Minting it here is what lets this run be recorded at all; the
            # alternative is a preparation of a supplied IDB that cannot be
            # stored because the thing it describes has no name.
            _write_record(record)
            written = True
        for result in results:
            result["artifact_revision"] = revision
        return {
            "mutated": written,
            # The same summary every preparation operation answers with, so
            # the reuse check that decided this run was needed compares like
            # with like when it next asks.
            **_preparation_report(record),
            "address_space": ADDRESS_SPACE_IMAGE,
            "image_base": self._image_base,
            "processor": self._processor,
            "artifact_revision": revision,
            "requested_passes": list(self._passes),
            "passes": results,
            "candidates": self._candidates,
            "applied_ids": list(self._applied),
            "skipped_prerequisites": self._skipped,
            "warnings": self._warnings[:MAX_PREPARE_WARNINGS],
            "bounded": bool(self._budget.exhausted),
        }

    # -- segments and ranges ----------------------------------------------

    def _segments(self) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for ea in self._utils.Segments():
            segment = self._segment.getseg(ea)
            if segment is None or segment.end_ea <= segment.start_ea:
                continue
            found.append(
                {
                    "name": self._segment.get_segm_name(segment)
                    or f"seg_{segment.start_ea:x}",
                    "start": segment.start_ea,
                    "end": segment.end_ea,
                    "executable": bool(segment.perm & self._segment.SEGPERM_EXEC),
                }
            )
        return found

    @staticmethod
    def _range(segment: dict[str, Any], stage: str) -> dict[str, Any]:
        return {
            "name": segment["name"],
            "stage": stage,
            "start": segment["start"],
            "end": segment["end"],
            "coverage": "complete",
            "unvisited": [],
            "reason": None,
        }

    def _unreached(
        self, segment: dict[str, Any], stage: str, reason: str
    ) -> dict[str, Any]:
        """A range the run never started, named rather than left out."""
        entry = self._range(segment, stage)
        entry["coverage"] = "partial"
        entry["unvisited"] = [{"start": segment["start"], "end": segment["end"]}]
        entry["reason"] = reason
        return entry

    def _stop_here(
        self, entry: dict[str, Any], segment: dict[str, Any], reason: str
    ) -> None:
        """Mark the range the budget ran out in, and name what is left of it."""
        entry["coverage"] = "partial"
        entry["reason"] = reason
        if self._cursor < segment["end"]:
            entry["unvisited"] = [{"start": self._cursor, "end": segment["end"]}]

    @staticmethod
    def _pass_result(
        name: str,
        ranges: list[dict[str, Any]],
        applied_ids: list[str],
        candidate_ids: list[str],
        warnings: list[str],
    ) -> dict[str, object]:
        states = {entry["coverage"] for entry in ranges}
        if not states or states == {"unavailable"}:
            coverage = "unavailable"
        elif states == {"complete"}:
            coverage = "complete"
        else:
            coverage = "partial"
        return {
            "pass": name,
            "backend": BACKEND_NAME,
            "ranges": ranges,
            "coverage": coverage,
            "applied_ids": applied_ids,
            "candidate_ids": candidate_ids,
            "warnings": warnings[:MAX_PREPARE_WARNINGS],
            "artifact_revision": None,
        }

    def _record(self, row: dict[str, Any]) -> None:
        self._candidates.append(row)
        if row["state"] == "applied":
            self._applied.append(row["candidate_id"])

    def _warn(self, message: str) -> None:
        if message in self._warnings or len(self._warnings) >= MAX_PREPARE_WARNINGS:
            return
        self._warnings.append(message)

    # -- the functions pass -------------------------------------------------

    def _functions_pass(self) -> dict[str, object]:
        """Define the entry points the evidence justifies, describe the rest."""
        first_candidate = len(self._candidates)
        first_applied = len(self._applied)
        self._gap_rejections = 0
        ranges: list[dict[str, Any]] = []
        stopped: str | None = None
        for segment in self._segments():
            if not segment["executable"]:
                continue
            if stopped is not None:
                ranges.append(self._unreached(segment, "code_scan", stopped))
                continue
            entry = self._range(segment, "code_scan")
            self._cursor = segment["start"]
            try:
                self._sweep_code(segment)
            except _PrepareBudgetError as exhausted:
                stopped = str(exhausted)
                self._stop_here(entry, segment, stopped)
            ranges.append(entry)
        warnings: list[str] = []
        if self._gap_rejections:
            warnings.append(
                f"{self._gap_rejections} aligned addresses in executable gaps"
                " decoded into no complete function and carry no reference or"
                " symbol; they are counted here rather than reported one by one"
            )
        if stopped is not None:
            warnings.append(stopped)
            self._warn(f"the functions pass stopped early: {stopped}")
        return self._pass_result(
            "functions",
            ranges,
            self._applied[first_applied:],
            [row["candidate_id"] for row in self._candidates[first_candidate:]],
            warnings,
        )

    def _sweep_code(self, segment: dict[str, Any]) -> None:
        """Walk one executable segment once, function chunks and gaps alike."""
        cursor = segment["start"]
        end = segment["end"]
        while cursor < end:
            self._cursor = cursor
            chunk = self._funcs.get_fchunk(cursor)
            if chunk is not None and chunk.end_ea > cursor:
                stop = min(chunk.end_ea, end)
                self._budget.charge("bytes", stop - cursor)
                self._defined_targets(segment, cursor, stop)
                cursor = stop
                continue
            following = self._funcs.get_next_fchunk(cursor)
            gap_end = end
            if following is not None and cursor < following.start_ea < end:
                gap_end = following.start_ea
            self._budget.charge("bytes", gap_end - cursor)
            self._scan_gap(segment, cursor, gap_end)
            cursor = gap_end

    def _defined_targets(
        self, segment: dict[str, Any], start: int, end: int
    ) -> None:
        """Report targets that land inside a function without being its entry."""
        for address in self._referenced(start, end):
            self._cursor = address
            owner = self._funcs.get_func(address)
            if owner is None or owner.start_ea == address:
                continue
            evidence = self._reference_evidence(address, owner)
            if evidence is None:
                # Only this function's own branches point here. That is not a
                # claim about an entry point, it is ordinary control flow.
                continue
            self._budget.charge("candidates")
            self._record(self._overlap_candidate(segment, address, evidence, owner))

    def _referenced(self, start: int, end: int) -> Iterator[int]:
        """Every address in ``[start, end)`` something refers to."""
        if start < end and self._bytes.has_xref(self._bytes.get_flags(start)):
            yield start
        address = start
        while address < end:
            self._budget.charge("seeds")
            address = self._bytes.next_that(address, end, self._bytes.has_xref)
            if address == self._api.BADADDR or address >= end:
                return
            yield address

    def _reference_evidence(
        self, address: int, owner: Any = None
    ) -> dict[str, object] | None:
        """What refers to ``address``, or ``None`` when only its own flow does.

        A jump whose source belongs to no function is the weakest of these on
        purpose. Inside an executable gap it is a branch from unrecognized
        code, which is ordinary control flow in something this pass has not
        identified yet — the same thing ``_defined_targets`` discounts inside
        a function. Treating it as an entry point would let a basic block in
        the middle of an unrecognized function be defined as a function of
        its own, splitting the real one and foreclosing recovering it later,
        which is precisely the false recovery this pass exists to avoid. It
        is kept, under its own kind, so the block is still described.
        """
        calls: list[int] = []
        jumps: list[int] = []
        pointers: list[int] = []
        unowned: list[int] = []
        for index, xref in enumerate(self._utils.XrefsTo(address)):
            if index >= MAX_QUOTED_REFERENCES:
                break
            if xref.type in (self._xref.fl_CN, self._xref.fl_CF):
                calls.append(xref.frm)
            elif xref.type in (self._xref.fl_JN, self._xref.fl_JF):
                source = self._funcs.get_func(xref.frm)
                if source is None:
                    unowned.append(xref.frm)
                elif owner is None or source.start_ea != owner.start_ea:
                    jumps.append(xref.frm)
            elif not xref.iscode and xref.type == self._xref.dr_O:
                pointers.append(xref.frm)
        for kind, sources in (
            ("call_xref", calls),
            ("jump_xref", jumps),
            ("data_pointer", pointers),
            ("unowned_jump", unowned),
        ):
            if sources:
                return {"kind": kind, "from": sorted(sources)}
        return None

    def _entry_evidence(self, address: int) -> dict[str, object] | None:
        """Why ``address`` might be an entry point, or ``None`` when nothing is."""
        flags = self._bytes.get_flags(address)
        symbol = self._names.get_name(address) if self._bytes.has_name(flags) else ""
        evidence = self._reference_evidence(address)
        if evidence is None and symbol:
            evidence = {"kind": "symbol", "from": []}
        elif evidence is None and address % _GAP_ALIGNMENT == 0:
            evidence = {"kind": "aligned_gap", "from": []}
        if evidence is None:
            return None
        evidence["symbol"] = symbol or None
        evidence["alignment"] = _alignment(address)
        return evidence

    def _scan_gap(self, segment: dict[str, Any], start: int, end: int) -> None:
        """Examine the addresses in one executable gap that could be entries."""
        cursor = start
        while cursor < end:
            self._cursor = cursor
            self._budget.charge("seeds")
            resume = cursor + 1
            evidence = self._entry_evidence(cursor)
            if evidence is not None:
                candidate = self._gap_candidate(segment, cursor, start, end, evidence)
                if candidate is None:
                    self._gap_rejections += 1
                else:
                    self._record(candidate)
                    # One decoded stretch is one answer, so the seeds after it
                    # start where it ends rather than inside it.
                    reached = candidate["evidence"]["defined_end"]
                    if reached is None:
                        reached = candidate["evidence"]["end"]
                    if reached is not None and reached > cursor:
                        resume = reached
            cursor = self._next_seed(resume, end)

    def _next_seed(self, resume: int, end: int) -> int:
        """The next address worth examining: aligned, or referred to."""
        aligned = (resume + _GAP_ALIGNMENT - 1) & ~(_GAP_ALIGNMENT - 1)
        aligned = min(max(aligned, resume), end)
        if resume >= end:
            return end
        referred = self._bytes.next_that(resume - 1, end, self._bytes.has_xref)
        if referred != self._api.BADADDR and resume <= referred < aligned:
            return referred
        return aligned

    def _gap_candidate(
        self,
        segment: dict[str, Any],
        entry: int,
        gap_start: int,
        gap_end: int,
        evidence: dict[str, object],
    ) -> dict[str, Any] | None:
        """Describe, and where the evidence allows it define, one entry point."""
        proven = evidence["kind"] in _ENTRY_PROOF
        decoded = self._decode_function(entry, gap_end)
        if decoded["refusal"] is not None and not proven:
            # Padding, data, or the middle of something: nothing says this is
            # an entry point and the bytes do not make a function either.
            return None
        self._budget.charge("candidates")
        state = "candidate"
        reason = decoded["refusal"]
        defined_end: int | None = None
        if reason is None and evidence["kind"] == "unowned_jump":
            sources = ", ".join(f"{source:#x}" for source in evidence["from"])
            reason = (
                f"only a jump from unrecognized code ({sources}) reaches"
                f" {entry:#x}, which is control flow inside something this"
                " pass has not identified, not an entry point; defining a"
                " function here would split whatever contains it"
            )
        elif reason is None and not proven:
            reason = (
                "no call, jump, relocated pointer or symbol establishes"
                f" {entry:#x} as an entry point, so its instructions are"
                " described and no function is created over them"
            )
        elif reason is None:
            failure = self._define_function(entry, decoded["end"])
            if failure is None:
                state = "applied"
                created = self._funcs.get_func(entry)
                defined_end = created.end_ea if created is not None else decoded["end"]
            else:
                reason = failure
        return {
            "candidate_id": f"ida:function:{entry:08x}",
            "kind": "function",
            "backend": BACKEND_NAME,
            "address_space": ADDRESS_SPACE_IMAGE,
            "address": entry,
            "confidence": _CONFIDENT if proven else _WEAK,
            "state": state,
            "reason": reason,
            "evidence": {
                "entry": entry,
                "end": decoded["end"],
                "defined_end": defined_end,
                "size": None if decoded["end"] is None else decoded["end"] - entry,
                "segment": segment["name"],
                "entry_evidence": evidence,
                "instructions": decoded["instructions"],
                "instruction_count": decoded["count"],
                "terminator": decoded["terminator"],
                "gap": {"start": gap_start, "end": gap_end},
                "overlaps": None,
            },
        }

    def _overlap_candidate(
        self,
        segment: dict[str, Any],
        address: int,
        evidence: dict[str, object],
        owner: Any,
    ) -> dict[str, Any]:
        """A target inside an existing function: described, never defined."""
        name = self._funcs.get_func_name(owner.start_ea)
        evidence["symbol"] = (
            self._names.get_name(address)
            if self._bytes.has_name(self._bytes.get_flags(address))
            else None
        )
        evidence["alignment"] = _alignment(address)
        decoded = self._decode_function(address, owner.end_ea)
        return {
            "candidate_id": f"ida:function:{address:08x}",
            "kind": "function",
            "backend": BACKEND_NAME,
            "address_space": ADDRESS_SPACE_IMAGE,
            "address": address,
            "confidence": _LIKELY,
            "state": "candidate",
            "reason": (
                f"{address:#x} is inside {name} ({owner.start_ea:#x}-"
                f"{owner.end_ea:#x}) and is not its entry, so defining a"
                " function here would redefine code that function already owns"
            ),
            "evidence": {
                "entry": address,
                "end": None,
                "defined_end": None,
                "size": None,
                "segment": segment["name"],
                "entry_evidence": evidence,
                "instructions": decoded["instructions"],
                "instruction_count": decoded["count"],
                "terminator": decoded["terminator"],
                "gap": None,
                "overlaps": {
                    "start": owner.start_ea,
                    "end": owner.end_ea,
                    "name": name,
                },
            },
        }

    def _decode_function(self, entry: int, limit: int) -> dict[str, Any]:
        """Decode from ``entry`` to a return, without leaving ``[entry, limit)``.

        A forward branch inside the range moves the end out past itself, so
        the first ``ret`` of a function with two exits does not become its
        boundary. Anything that cannot be decoded, anything that would run
        past ``limit``, and any jump to an address that is neither inside the
        range nor an existing function's entry refuses the whole range: a
        boundary this walk cannot prove is not a boundary worth writing down.
        """
        instruction = self._ua.insn_t()
        quoted: list[dict[str, object]] = []
        count = 0
        furthest = entry
        address = entry
        while address < limit:
            self._budget.charge("instructions")
            size = self._ua.decode_insn(instruction, address)
            if size <= 0:
                return self._undecoded(
                    quoted,
                    count,
                    f"the bytes at {address:#x} do not decode into an instruction",
                )
            count += 1
            if count > MAX_FUNCTION_INSTRUCTIONS:
                return self._undecoded(
                    quoted,
                    count,
                    f"more than {MAX_FUNCTION_INSTRUCTIONS} instructions decode"
                    f" from {entry:#x} without reaching a return",
                )
            if len(quoted) < MAX_QUOTED_INSTRUCTIONS:
                quoted.append(
                    {
                        "address": address,
                        "size": size,
                        "mnemonic": instruction.get_canon_mnem(),
                        "text": self._disassembly(address),
                    }
                )
            following = address + size
            if following > limit or following - entry > MAX_FUNCTION_BYTES:
                return self._undecoded(
                    quoted,
                    count,
                    f"the instruction at {address:#x} runs past {limit:#x}, which"
                    " is as far as this range can be proven to reach",
                )
            feature = instruction.get_canon_feature()
            if not feature & self._idp.CF_CALL:
                target = self._branch_target(instruction)
                if target is not None and entry <= target < limit:
                    furthest = max(furthest, target)
                elif target is not None and not self._is_entry(target):
                    return self._undecoded(
                        quoted,
                        count,
                        f"the branch at {address:#x} leaves this range for"
                        f" {target:#x}, which is not a function entry",
                    )
            if feature & self._idp.CF_STOP and following > furthest:
                if self._api.is_ret_insn(instruction):
                    terminator = "return"
                elif self._branch_target(instruction) is not None:
                    terminator = "tail_jump"
                else:
                    return self._undecoded(
                        quoted,
                        count,
                        f"the flow stops at {address:#x} without returning and"
                        " without a target this pass can resolve",
                    )
                return {
                    "end": following,
                    "instructions": quoted,
                    "count": count,
                    "terminator": terminator,
                    "refusal": None,
                }
            address = following
        return self._undecoded(
            quoted, count, f"no return ends the range that starts at {entry:#x}"
        )

    @staticmethod
    def _undecoded(
        quoted: list[dict[str, object]], count: int, refusal: str
    ) -> dict[str, Any]:
        return {
            "end": None,
            "instructions": quoted,
            "count": count,
            "terminator": None,
            "refusal": refusal,
        }

    def _branch_target(self, instruction: Any) -> int | None:
        operand = instruction.ops[0]
        if operand.type in (self._ua.o_near, self._ua.o_far):
            return int(operand.addr)
        return None

    def _is_entry(self, address: int) -> bool:
        function = self._funcs.get_func(address)
        return function is not None and function.start_ea == address

    def _disassembly(self, address: int) -> str:
        line = self._api.generate_disasm_line(address, 1)
        return self._api.tag_remove(line) if line else ""

    def _define_function(self, entry: int, end: int) -> str | None:
        """Create the function, or say why IDA would not. ``None`` means done."""
        try:
            created = bool(self._funcs.add_func(entry, end))
        except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
            return (
                f"IDA refused to create a function at {entry:#x}:"
                f" {type(error).__name__}: {error}"
            )
        if not created:
            return f"IDA refused to create a function at {entry:#x}"
        function = self._funcs.get_func(entry)
        if function is None or function.start_ea != entry:
            return f"IDA reported a function at {entry:#x} that it does not hold"
        if function.end_ea != end:
            self._warn(
                f"IDA ended the function at {entry:#x} at {function.end_ea:#x},"
                f" not at the {end:#x} this pass decoded"
            )
        return None

    # -- the strings pass ---------------------------------------------------

    def _strings_pass(self) -> dict[str, object]:
        """Read the mapped bytes, then the instructions that build buffers."""
        first_candidate = len(self._candidates)
        first_applied = len(self._applied)
        self._already_defined = 0
        self._unsupported_frames = 0
        warnings: list[str] = []
        ranges = self._raw_byte_strings(warnings)
        if "functions" in self._passes:
            ranges.extend(self._instruction_strings(warnings))
        else:
            ranges.extend(self._skip_instruction_stage(warnings))
        if self._already_defined:
            warnings.append(
                f"{self._already_defined} printable runs already belong to a"
                " defined item and are not reported again"
            )
        if self._unsupported_frames:
            warnings.append(
                f"{self._unsupported_frames} functions keep their locals without"
                " a frame pointer; this build follows constant writes through"
                " the frame pointer only, so their buffers were not recovered"
            )
        return self._pass_result(
            "strings",
            ranges,
            self._applied[first_applied:],
            [row["candidate_id"] for row in self._candidates[first_candidate:]],
            warnings,
        )

    def _raw_byte_strings(self, warnings: list[str]) -> list[dict[str, Any]]:
        """Stage one: every mapped byte, independent of any other pass."""
        ranges: list[dict[str, Any]] = []
        stopped: str | None = None
        for segment in self._segments():
            if stopped is not None:
                ranges.append(self._unreached(segment, "raw_bytes", stopped))
                continue
            entry = self._range(segment, "raw_bytes")
            self._cursor = segment["start"]
            try:
                self._scan_segment_bytes(segment, entry)
            except _PrepareBudgetError as exhausted:
                stopped = str(exhausted)
                self._stop_here(entry, segment, stopped)
            ranges.append(entry)
        if stopped is not None:
            warnings.append(stopped)
            self._warn(f"raw string discovery stopped early: {stopped}")
        return ranges

    def _scan_segment_bytes(
        self, segment: dict[str, Any], entry: dict[str, Any]
    ) -> None:
        base = segment["start"]
        end = segment["end"]
        # A run that starts inside one step is read to its end past the step
        # boundary, so the next step must not rediscover its tail as a
        # shorter string at a different address.
        self._claimed = base
        while base < end:
            self._cursor = base
            allowance = self._budget.left("bytes")
            take = min(_READ_STEP, end - base, max(allowance, 1))
            self._budget.charge("bytes", take)
            overlap = min(MAX_STRING_BYTES, end - base - take)
            raw = self._bytes.get_bytes(base, take + overlap)
            if raw is None or len(raw) < take:
                entry["coverage"] = (
                    "unavailable" if base == segment["start"] else "partial"
                )
                entry["reason"] = (
                    f"{segment['name']} holds no bytes in the image from"
                    f" {base:#x}, so nothing can be read out of it"
                )
                entry["unvisited"] = [{"start": base, "end": end}]
                return
            self._harvest_bytes(segment, base, raw, take)
            base += take

    def _harvest_bytes(
        self, segment: dict[str, Any], base: int, raw: bytes, take: int
    ) -> None:
        offset = max(0, self._claimed - base)
        while offset < take:
            found = self._longest_run(raw, offset, base + offset)
            if found is None:
                offset += 1
                continue
            length, text, encoding = found
            start = base + offset
            self._claimed = start + length
            held, defined = self._definition(start, start + length)
            if held is None:
                self._raw_string_candidate(
                    segment, start, text, encoding, raw[offset : offset + length]
                )
            elif defined == length:
                # IDA already holds every byte of this run; there is nothing
                # here to recover and nothing lost by not restating it.
                self._already_defined += 1
            else:
                # Part of the run is undefined and part of it is not. Dropping
                # it would lose the undefined part with no address and no
                # reason, so it is reported with both.
                self._raw_string_candidate(
                    segment,
                    start,
                    text,
                    encoding,
                    raw[offset : offset + length],
                    held=held,
                )
            offset += length

    def _longest_run(
        self, raw: bytes, offset: int, address: int
    ) -> tuple[int, str, str] | None:
        """The longest decodable run starting here, so encodings never overlap."""
        found: list[tuple[int, str, str]] = []
        plain = _ascii_run(raw, offset)
        if plain is not None:
            found.append((plain[0], plain[1], "ascii"))
        if address % 2 == 0:
            little = _utf16_run(raw, offset, big_endian=False)
            if little is not None:
                found.append((little[0], little[1], "utf-16le"))
            big = _utf16_run(raw, offset, big_endian=True)
            if big is not None:
                found.append((big[0], big[1], "utf-16be"))
        return max(found, key=operator.itemgetter(0)) if found else None

    def _definition(self, start: int, end: int) -> tuple[int | None, int]:
        """Where this range stops being undefined, and how many bytes are not.

        ``(None, 0)`` means every byte is free. Anything else names the first
        byte an item already holds, so a run that straddles a defined item
        and undefined bytes can say exactly where the two meet.
        """
        first: int | None = None
        defined = 0
        address = start
        while address < end:
            if not self._bytes.is_unknown(self._bytes.get_flags(address)):
                defined += 1
                if first is None:
                    first = address
            address += 1
        return first, defined

    def _raw_string_candidate(
        self,
        segment: dict[str, Any],
        start: int,
        text: str,
        encoding: str,
        raw: bytes,
        held: int | None = None,
    ) -> None:
        self._budget.charge("candidates")
        string_type = self._string_types[encoding]
        state = "candidate"
        reason: str | None = None
        if held is not None:
            reason = (
                f"an item already defined at {held:#x} holds part of this run,"
                " so the bytes are reported with their addresses and nothing"
                " already in the database is replaced"
            )
        elif segment["executable"]:
            # Undefined bytes in an executable segment are as likely to be
            # code IDA has not reached as they are to be text, and a string
            # defined over an instruction hides it. The bytes and their
            # addresses are reported; the database is left alone.
            reason = (
                f"{start:#x} is in the executable segment {segment['name']},"
                " where undefined bytes may be code this analysis has not"
                " decoded yet, so the run is reported and not defined"
            )
        elif len(text) < MIN_DEFINED_STRING_CHARS:
            reason = (
                f"{len(text)} printable characters followed by a terminator"
                " happen by chance in packed data, so this run is reported"
                f" with its bytes; {MIN_DEFINED_STRING_CHARS} or more are"
                " defined in the database"
            )
        elif string_type is None:
            reason = (
                "this IDA registers no big-endian UTF-16 string type, so these"
                " bytes are reported with their exact addresses and the"
                " database is left as it is"
            )
        else:
            failure = self._define_string(start, len(raw), string_type)
            if failure is None:
                state = "applied"
            else:
                reason = failure
        self._record(
            {
                "candidate_id": f"ida:string:{encoding}:{start:08x}",
                "kind": "string",
                "backend": BACKEND_NAME,
                "address_space": ADDRESS_SPACE_IMAGE,
                "address": start,
                "confidence": (
                    _CONFIDENT if len(text) >= MIN_DEFINED_STRING_CHARS else _LIKELY
                ),
                "state": state,
                "reason": reason,
                "evidence": {
                    "stage": "raw_bytes",
                    "method": "mapped bytes decoded in place",
                    "encoding": encoding,
                    "start": start,
                    "end": start + len(raw),
                    "length": len(raw),
                    "characters": len(text),
                    "terminator": "nul",
                    "text": text,
                    "segment": segment["name"],
                    "already_defined_at": held,
                    **_quoted(raw),
                },
            }
        )

    def _define_string(self, start: int, length: int, string_type: int) -> str | None:
        try:
            created = bool(self._bytes.create_strlit(start, length, string_type))
        except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
            return (
                f"IDA refused to define a string at {start:#x}:"
                f" {type(error).__name__}: {error}"
            )
        if not created:
            return f"IDA refused to define a string at {start:#x}"
        defined = self._bytes.get_item_size(start)
        if defined != length:
            self._warn(
                f"IDA defined {defined} bytes at {start:#x}, not the {length}"
                " this pass decoded"
            )
        return None

    # -- stage two: buffers that exist only in instructions -----------------

    def _skip_instruction_stage(self, warnings: list[str]) -> list[dict[str, Any]]:
        """Say which stage did not run, and what it was waiting for."""
        reason = (
            "instruction-derived string recovery reads the instructions of"
            " recovered functions, and the 'functions' pass was not requested,"
            " so this stage did not run"
        )
        self._skipped.append(
            {
                "pass": "strings",
                "stage": "instructions",
                "requires": "functions",
                "reason": reason,
            }
        )
        warnings.append(reason)
        self._warn(reason)
        return [
            self._unreached(segment, "instructions", reason)
            for segment in self._segments()
            if segment["executable"]
        ]

    def _instruction_strings(self, warnings: list[str]) -> list[dict[str, Any]]:
        executable = [
            segment for segment in self._segments() if segment["executable"]
        ]
        if self._processor != _X86:
            reason = (
                "constant-write string recovery is implemented for x86 and"
                f" x86-64, and this database is {self._processor!r}"
            )
            warnings.append(reason)
            self._warn(reason)
            ranges = []
            for segment in executable:
                entry = self._range(segment, "instructions")
                entry["coverage"] = "unavailable"
                entry["unvisited"] = [
                    {"start": segment["start"], "end": segment["end"]}
                ]
                entry["reason"] = reason
                ranges.append(entry)
            return ranges
        ranges = []
        stopped: str | None = None
        for segment in executable:
            if stopped is not None:
                ranges.append(self._unreached(segment, "instructions", stopped))
                continue
            entry = self._range(segment, "instructions")
            self._cursor = segment["start"]
            try:
                for address in self._utils.Functions(segment["start"], segment["end"]):
                    self._cursor = address
                    self._budget.charge("functions")
                    self._stack_strings(segment, address)
            except _PrepareBudgetError as exhausted:
                stopped = str(exhausted)
                self._stop_here(entry, segment, stopped)
            ranges.append(entry)
        if stopped is not None:
            warnings.append(stopped)
            self._warn(f"instruction-derived string recovery stopped early: {stopped}")
        return ranges

    def _stack_strings(self, segment: dict[str, Any], start: int) -> None:
        """Recover the buffers one function assembles out of immediates.

        Only writes whose value this walk can prove are kept: an immediate
        stored straight into the frame, or a register this walk watched an
        immediate being loaded into. Every other write to a tracked byte
        forgets that byte, a branch target forgets every register, and a
        store through a register this walk cannot resolve harvests what is
        known and starts again — a byte that might have been overwritten is
        not a byte this pass may quote.
        """
        function = self._funcs.get_func(start)
        if function is None:
            return
        if not function.flags & self._funcs.FUNC_FRAME:
            self._unsupported_frames += 1
            return
        frame: dict[int, dict[str, Any]] = {}
        registers: dict[int, bytes] = {}
        instruction = self._ua.insn_t()
        address = function.start_ea
        previous: int | None = None
        while address < function.end_ea:
            self._budget.charge("instructions")
            size = self._ua.decode_insn(instruction, address)
            if size <= 0:
                registers.clear()
                previous = None
                address += 1
                continue
            if previous is not None and self._reached_from_elsewhere(address, previous):
                # This walk is linear and the two sides of a branch are not:
                # bytes written only on the path that was not taken are not
                # bytes this block can be said to hold. Keeping them would
                # let one candidate be assembled out of two alternative
                # paths and spell a string that never exists at run time.
                registers.clear()
                self._harvest_frame(segment, function, frame)
                frame = {}
            if not self._apply_instruction(instruction, address, registers, frame):
                self._harvest_frame(segment, function, frame)
                frame = {}
                registers.clear()
            previous = address
            address += size
        self._harvest_frame(segment, function, frame)

    def _reached_from_elsewhere(self, address: int, previous: int) -> bool:
        """Whether anything but the instruction before it branches here."""
        if not self._bytes.has_xref(self._bytes.get_flags(address)):
            return False
        source = self._xref.get_first_cref_to(address)
        while source != self._api.BADADDR:
            if source != previous:
                return True
            source = self._xref.get_next_cref_to(address, source)
        return False

    def _apply_instruction(
        self,
        instruction: Any,
        address: int,
        registers: dict[int, bytes],
        frame: dict[int, dict[str, Any]],
    ) -> bool:
        """Fold one instruction in. ``False`` when the frame stops being provable."""
        feature = instruction.get_canon_feature()
        mnemonic = instruction.get_canon_mnem()
        if mnemonic in ("leave", "enter"):
            # The frame itself moves, so every offset this walk holds is about
            # a frame that no longer exists.
            return False
        if feature & self._idp.CF_CALL:
            registers.clear()
            return True
        destination = instruction.ops[0]
        source = instruction.ops[1]
        if mnemonic == "mov" and destination.type == self._ua.o_reg:
            if source.type == self._ua.o_imm:
                self._load_register(destination, source, registers)
                return True
        if (
            mnemonic == "mov"
            and destination.type == self._ua.o_displ
            and destination.reg == _FRAME_POINTER
        ):
            self._store_frame(
                instruction, address, destination, source, registers, frame
            )
            return True
        return self._forget(instruction, feature, registers, frame)

    def _load_register(
        self, destination: Any, source: Any, registers: dict[int, bytes]
    ) -> None:
        """Remember an immediate loaded into a register, where x86 proves it.

        A 4-byte load clears the upper half of the 64-bit register and an
        8-byte load sets all of it; a 1- or 2-byte load leaves the rest of the
        register whatever it already was, which this walk does not know.
        """
        width = self._ua.get_dtype_size(destination.dtype)
        if width not in (4, 8):
            registers.pop(destination.reg, None)
            return
        registers[destination.reg] = (source.value & ((1 << (width * 8)) - 1)).to_bytes(
            8, "little"
        )

    def _store_frame(
        self,
        instruction: Any,
        address: int,
        destination: Any,
        source: Any,
        registers: dict[int, bytes],
        frame: dict[int, dict[str, Any]],
    ) -> None:
        width = self._ua.get_dtype_size(destination.dtype)
        offset = self._signed(destination.addr)
        value: bytes | None = None
        if source.type == self._ua.o_imm and width <= 8:
            if self._ua.get_dtype_size(source.dtype) >= width or not (
                source.value >> (self._ua.get_dtype_size(source.dtype) * 8 - 1)
            ):
                value = (source.value & ((1 << (width * 8)) - 1)).to_bytes(
                    width, "little"
                )
        elif source.type == self._ua.o_reg and source.reg in registers:
            if self._ua.get_dtype_size(source.dtype) >= width:
                value = registers[source.reg][:width]
        if value is None:
            for index in range(width):
                frame.pop(offset + index, None)
            return
        if len(frame) + width > MAX_FRAME_BYTES:
            self._warn(
                f"a frame grew past {MAX_FRAME_BYTES} tracked bytes; the writes"
                f" at and after {address:#x} in that function were not followed"
            )
            return
        write = {
            "address": address,
            "mnemonic": instruction.get_canon_mnem(),
            "text": self._disassembly(address),
            "frame_offset": offset,
            "size": width,
            "value": value.hex(),
        }
        for index, byte in enumerate(value):
            frame[offset + index] = {"byte": byte, "write": write}

    def _forget(
        self,
        instruction: Any,
        feature: int,
        registers: dict[int, bytes],
        frame: dict[int, dict[str, Any]],
    ) -> bool:
        """Drop what this instruction may have changed. ``False`` if unknowable."""
        provable = True
        for index, operand in enumerate(instruction.ops):
            if operand.type == self._ua.o_void or index >= len(self._changes):
                break
            if not feature & self._changes[index]:
                continue
            if operand.type == self._ua.o_reg:
                if operand.reg == _FRAME_POINTER:
                    return False
                registers.pop(operand.reg, None)
            elif operand.type == self._ua.o_displ and operand.reg == _FRAME_POINTER:
                offset = self._signed(operand.addr)
                for step in range(self._ua.get_dtype_size(operand.dtype)):
                    frame.pop(offset + step, None)
            elif operand.type in (self._ua.o_mem, self._ua.o_phrase, self._ua.o_displ):
                # A write through an address this walk cannot resolve could
                # land anywhere, the frame included.
                provable = False
        return provable

    def _signed(self, value: int) -> int:
        limit = 1 << self._bits
        value &= limit - 1
        return value - limit if value >= limit >> 1 else value

    def _harvest_frame(
        self, segment: dict[str, Any], function: Any, frame: dict[int, dict[str, Any]]
    ) -> None:
        """Report the NUL-terminated runs the tracked frame bytes spell out."""
        if not frame:
            return
        group: list[int] = []
        for offset in sorted(frame):
            if group and offset != group[-1] + 1:
                self._harvest_group(segment, function, frame, group)
                group = []
            group.append(offset)
        self._harvest_group(segment, function, frame, group)

    def _harvest_group(
        self,
        segment: dict[str, Any],
        function: Any,
        frame: dict[int, dict[str, Any]],
        group: list[int],
    ) -> None:
        if len(group) < MIN_STRING_CHARS + 1:
            return
        data = bytes(frame[offset]["byte"] for offset in group)
        index = 0
        while index < len(data):
            run = _ascii_run(data, index)
            if run is None:
                index += 1
                continue
            length, text = run
            self._stack_candidate(
                segment, function, frame, group[index : index + length], text
            )
            index += length

    def _stack_candidate(
        self,
        segment: dict[str, Any],
        function: Any,
        frame: dict[int, dict[str, Any]],
        offsets: list[int],
        text: str,
    ) -> None:
        self._budget.charge("candidates")
        raw = bytes(frame[offset]["byte"] for offset in offsets)
        writes: dict[int, dict[str, Any]] = {}
        for offset in offsets:
            write = frame[offset]["write"]
            writes[write["address"]] = write
        first = min(writes)
        self._record(
            {
                # A stack buffer has no image address of its own, so the
                # candidate is anchored at the first instruction that writes
                # it: an address a reviewer can actually go to.
                "candidate_id": f"ida:string:stack:{function.start_ea:08x}:{first:08x}",
                "kind": "string",
                "backend": BACKEND_NAME,
                "address_space": ADDRESS_SPACE_IMAGE,
                "address": first,
                "confidence": _LIKELY,
                "state": "candidate",
                "reason": (
                    "a buffer assembled in a stack frame has no image address"
                    " to define, so its bytes are reported with the"
                    " instructions that write them"
                ),
                "evidence": {
                    "stage": "instructions",
                    "method": "constant writes into the frame, traced in order",
                    "encoding": "ascii",
                    "anchor": "first_constant_write",
                    "function": function.start_ea,
                    "function_end": function.end_ea,
                    "function_name": self._funcs.get_func_name(function.start_ea),
                    "frame_base": "frame pointer",
                    "frame_offset": offsets[0],
                    "length": len(raw),
                    "characters": len(text),
                    "terminator": "nul",
                    "text": text,
                    "segment": segment["name"],
                    "writes": [writes[key] for key in sorted(writes)],
                    **_quoted(raw),
                },
            }
        )

    # -- the structures pass ------------------------------------------------

    def _structures_pass(self) -> dict[str, object]:
        """Describe what the accesses prove about one object, and no more.

        The evidence is IDA's own read and write cross-references: an
        instruction that touches one byte of a named data object with a
        sized operand. An address being *taken* — ``dr_O``, an ``lea`` —
        says nothing about how many bytes anything reads through it and is
        not counted. A layout is defined only where every access at an
        offset agrees on its width, the offsets are naturally aligned, they
        do not overlap, and together they tile the object from its first
        byte to its last. Anything else is uncertain packing, which the
        design keeps as a proposal.
        """
        first_candidate = len(self._candidates)
        first_applied = len(self._applied)
        self._oversized_objects = 0
        ranges: list[dict[str, Any]] = []
        stopped: str | None = None
        for segment in self._segments():
            if segment["executable"]:
                continue
            if stopped is not None:
                ranges.append(self._unreached(segment, "instructions", stopped))
                continue
            entry = self._range(segment, "instructions")
            self._cursor = segment["start"]
            try:
                self._sweep_objects(segment, entry)
            except _PrepareBudgetError as exhausted:
                stopped = str(exhausted)
                self._stop_here(entry, segment, stopped)
            ranges.append(entry)
        warnings = [
            "this pass describes the objects whose use sites this analysis"
            " records; an object nothing is seen to touch leaves no evidence"
            " here, and its absence from this inventory is not a finding"
        ]
        if self._oversized_objects:
            warnings.append(
                f"{self._oversized_objects} named objects reach further than"
                f" {MAX_STRUCTURE_BYTES} bytes and were not walked; their"
                " layouts are not described either way"
            )
        if stopped is not None:
            warnings.append(stopped)
            self._warn(f"the structures pass stopped early: {stopped}")
        return self._pass_result(
            "structures",
            ranges,
            self._applied[first_applied:],
            [row["candidate_id"] for row in self._candidates[first_candidate:]],
            warnings,
        )

    def _sweep_objects(self, segment: dict[str, Any], entry: dict[str, Any]) -> None:
        """Examine every named object in one data segment, in address order."""
        bases = self._named_heads(segment)
        skipped: list[dict[str, int]] = []
        for index, base in enumerate(bases):
            self._cursor = base
            end = bases[index + 1] if index + 1 < len(bases) else segment["end"]
            if end - base > MAX_STRUCTURE_BYTES:
                self._oversized_objects += 1
                skipped.append({"start": base, "end": end})
                continue
            accesses = self._object_accesses(base, end)
            if len(accesses) < MIN_STRUCTURE_FIELDS:
                # One offset, or none, is a variable. Calling that a
                # structure would bury the objects that have a layout.
                continue
            self._budget.charge("candidates")
            self._record(self._structure_candidate(segment, base, end, accesses))
        if skipped:
            entry["coverage"] = "partial"
            entry["unvisited"] = skipped
            entry["reason"] = (
                f"{len(skipped)} objects in {segment['name']} reach further"
                f" than {MAX_STRUCTURE_BYTES} bytes, so their accesses were"
                " not collected and their layouts are not described"
            )

    def _named_heads(self, segment: dict[str, Any]) -> list[int]:
        """Every named address in ``segment``, which is where objects begin.

        The next name is also where this object stops: two names cannot
        describe one object, so a field is never inferred across one.
        """
        found: list[int] = []
        address = segment["start"]
        if address < segment["end"] and self._bytes.has_name(
            self._bytes.get_flags(address)
        ):
            found.append(address)
        while address < segment["end"]:
            self._budget.charge("seeds")
            address = self._bytes.next_that(
                address, segment["end"], self._bytes.has_name
            )
            if address == self._api.BADADDR or address >= segment["end"]:
                break
            found.append(address)
        return found

    def _object_accesses(
        self, base: int, end: int
    ) -> dict[int, dict[str, Any]]:
        """Every sized read or write of one byte of this object, by offset."""
        found: dict[int, dict[str, Any]] = {}
        address = base
        while address < end:
            self._cursor = address
            if self._bytes.has_xref(self._bytes.get_flags(address)):
                self._collect_accesses(address, base, found)
            self._budget.charge("seeds")
            address = self._bytes.next_that(address, end, self._bytes.has_xref)
            if address == self._api.BADADDR or address >= end:
                break
        return found

    def _collect_accesses(
        self, address: int, base: int, found: dict[int, dict[str, Any]]
    ) -> None:
        """Fold every sized access to ``address`` into its offset's evidence."""
        instruction = self._ua.insn_t()
        for xref in self._utils.XrefsTo(address):
            if xref.type not in (self._xref.dr_R, self._xref.dr_W):
                continue
            self._budget.charge("instructions")
            if self._ua.decode_insn(instruction, xref.frm) <= 0:
                continue
            for operand in instruction.ops:
                if operand.type == self._ua.o_void:
                    break
                if operand.type != self._ua.o_mem or operand.addr != address:
                    continue
                access = "write" if xref.type == self._xref.dr_W else "read"
                width = self._ua.get_dtype_size(operand.dtype)
                entry = found.setdefault(
                    address - base,
                    {"sizes": {}, "reads": 0, "writes": 0, "use_sites": []},
                )
                entry["sizes"][width] = entry["sizes"].get(width, 0) + 1
                entry["reads" if access == "read" else "writes"] += 1
                if len(entry["use_sites"]) < MAX_QUOTED_USE_SITES:
                    entry["use_sites"].append(
                        {
                            "address": xref.frm,
                            "mnemonic": instruction.get_canon_mnem(),
                            "text": self._disassembly(xref.frm),
                            "access": access,
                            "size": width,
                        }
                    )

    def _structure_candidate(
        self,
        segment: dict[str, Any],
        base: int,
        end: int,
        accesses: dict[int, dict[str, Any]],
    ) -> dict[str, Any]:
        """Describe, and where every access agrees define, one object layout."""
        conflicts = self._offset_conflicts(base, accesses)
        fields = [
            (offset, next(iter(accesses[offset]["sizes"])))
            for offset in sorted(accesses)
            if not any(entry["offset"] == offset for entry in conflicts)
        ]
        layout = None if conflicts else self._layout_refusal(fields, end - base)
        shape, stride = self._shape(fields)
        name = f"{_STRUCTURE_TYPE_PREFIX}{base:08x}"
        existing = self._existing_type(base)
        state = "candidate"
        reason = self._structure_refusal(base, existing, conflicts, layout)
        if reason is None:
            held = self._field_conflicts(base, fields)
            if held:
                reason = (
                    "the managed database already defines "
                    + "; ".join(held)
                    + ", and this pass replaces nothing that is already there"
                )
            else:
                failure = self._define_structure(base, fields, shape, name)
                if failure is None:
                    state = "applied"
                else:
                    reason = failure
        return {
            "candidate_id": f"ida:structure:{base:08x}",
            "kind": "structure",
            "backend": BACKEND_NAME,
            "address_space": ADDRESS_SPACE_IMAGE,
            "address": base,
            "confidence": _LIKELY if conflicts or layout else _CONFIDENT,
            "state": state,
            "reason": reason,
            "evidence": {
                "stage": "instructions",
                "method": (
                    "sized operands recorded as read and write cross-references"
                    " to the bytes of one named object"
                ),
                "object": base,
                "object_end": end,
                "object_size": end - base,
                "object_name": self._names.get_name(base) or None,
                "segment": segment["name"],
                "shape": shape,
                "stride": stride,
                "type_name": name if shape == "struct" else None,
                "field_count": len(fields),
                "fields": [
                    {
                        "offset": offset,
                        "size": width,
                        "name": f"field_{offset:x}",
                        "reads": accesses[offset]["reads"],
                        "writes": accesses[offset]["writes"],
                        "use_sites": accesses[offset]["use_sites"],
                    }
                    for offset, width in fields
                ],
                "use_site_count": sum(
                    entry["reads"] + entry["writes"] for entry in accesses.values()
                ),
                "conflicts": conflicts,
                "packing": layout,
                "existing_type": existing,
            },
        }

    def _offset_conflicts(
        self, base: int, accesses: dict[int, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Offsets the accesses themselves disagree about."""
        found: list[dict[str, Any]] = []
        for offset in sorted(accesses):
            sizes = sorted(accesses[offset]["sizes"])
            if len(sizes) > 1:
                widths = " and ".join(f"{size}" for size in sizes)
                found.append(
                    {
                        "offset": offset,
                        "sizes": sizes,
                        "reason": (
                            f"{base + offset:#x} is read or written {widths}"
                            " bytes wide by different instructions, and one"
                            " field cannot be both widths"
                        ),
                    }
                )
            elif sizes[0] not in _FIELD_WIDTHS:
                found.append(
                    {
                        "offset": offset,
                        "sizes": sizes,
                        "reason": (
                            f"{base + offset:#x} is touched {sizes[0]} bytes"
                            " wide, which is not a width this build spells as"
                            " a field"
                        ),
                    }
                )
        return found

    @staticmethod
    def _layout_refusal(
        fields: list[tuple[int, int]], size: int
    ) -> str | None:
        """Why these offsets are not a layout, or ``None`` when they are."""
        if not fields:
            return "no offset of this object is accessed at one agreed width"
        reach = 0
        for offset, width in fields:
            if offset % width:
                return (
                    f"offset {offset} is not a multiple of its own {width}-byte"
                    " width, so the layout this would define is one no"
                    " compiler produced"
                )
            if offset < reach:
                return (
                    f"offset {offset} starts inside the {reach - offset} bytes"
                    " the previous field already covers, which is a union"
                    " overlap rather than a field"
                )
            if offset > reach:
                return (
                    f"nothing is seen to touch the {offset - reach} bytes at"
                    f" offset {reach}, so how this object is packed there is"
                    " not established"
                )
            reach = offset + width
        if reach != size:
            return (
                f"the accesses cover {reach} of this object's {size} bytes, so"
                " the rest of it is unaccounted for"
            )
        return None

    @staticmethod
    def _shape(fields: list[tuple[int, int]]) -> tuple[str, int | None]:
        """``array`` with its stride when the fields are one repeated width.

        Offsets alone cannot tell an array of ``n`` elements from a record
        of ``n`` identical fields — they lay the same bytes out the same
        way — so the uniform case is spelled as the stride it demonstrably
        is, and the per-field evidence is reported either way. Neither
        spelling claims to know what the object is *for*; that inference is
        a proposal, not something this pass writes into the database.
        """
        if len(fields) < MIN_STRUCTURE_FIELDS:
            return "struct", None
        width = fields[0][1]
        if all(
            size == width and offset == index * width
            for index, (offset, size) in enumerate(fields)
        ):
            return "array", width
        return "struct", None

    def _structure_refusal(
        self,
        base: int,
        existing: dict[str, Any] | None,
        conflicts: list[dict[str, Any]],
        layout: str | None,
    ) -> str | None:
        """Why this object is only described, or ``None`` to go and define it."""
        if existing is not None:
            return (
                f"{base:#x} already carries the type {existing['name']}, which"
                " this pass reports and never replaces; what the accesses"
                " prove is in this candidate's evidence instead"
            )
        if conflicts:
            return "; ".join(entry["reason"] for entry in conflicts)
        return layout

    def _existing_type(self, address: int) -> dict[str, Any] | None:
        """The type the database already holds at ``address``, read back out."""
        return _type_at(address)

    def _field_conflicts(
        self, base: int, fields: list[tuple[int, int]]
    ) -> list[str]:
        """Definitions already in the database that these fields would replace."""
        return _held_definitions(base, fields, because="the accesses prove")

    def _member_type(self, width: int) -> Any:
        """An unsigned integer of ``width`` bytes: a size, not a meaning."""
        return _integer_member(width)

    def _define_structure(
        self, base: int, fields: list[tuple[int, int]], shape: str, name: str
    ) -> str | None:
        """Apply the proven layout, or say why IDA would not. ``None`` is done."""
        try:
            if shape == "array":
                layout = self._types.tinfo_t()
                if not layout.create_array(
                    self._member_type(fields[0][1]), len(fields)
                ):
                    return (
                        f"IDA refused to build an array of {len(fields)} by"
                        f" {fields[0][1]} bytes for {base:#x}"
                    )
            else:
                table = self._types.get_idati()
                # ``tinfo_t.get_named_type`` is the lookup that answers
                # "is this name a type": the module-level ``get_named_type``
                # needs ``NTF_TYPE`` and returns ``None`` for a registered
                # type without it, which is a guard that never fires.
                if self._types.tinfo_t().get_named_type(table, name):
                    return (
                        f"this database already holds a type called {name},"
                        " which this pass reports and never replaces"
                    )
                record = self._types.udt_type_data_t()
                record.is_union = False
                for offset, width in fields:
                    member = self._types.udm_t()
                    member.name = f"field_{offset:x}"
                    member.offset = offset * 8
                    member.size = width * 8
                    member.type = self._member_type(width)
                    record.push_back(member)
                layout = self._types.tinfo_t()
                if not layout.create_udt(record):
                    return f"IDA refused to build a structure for {base:#x}"
                code = layout.set_named_type(table, name)
                if code != 0:
                    return (
                        f"IDA refused to register the type {name} for"
                        f" {base:#x}: tinfo code {code}"
                    )
            applied = bool(
                self._types.apply_tinfo(
                    base, layout, self._types.TINFO_DEFINITE
                )
            )
        except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
            return (
                f"IDA refused to type {base:#x}:"
                f" {type(error).__name__}: {error}"
            )
        if not applied:
            return f"IDA refused to apply a layout at {base:#x}"
        return None

    # -- the pointer tables pass --------------------------------------------

    def _pointer_tables_pass(self) -> dict[str, object]:
        """Read the loader's relocations, and define only what they back.

        A slot is a pointer because a relocation record says the loader
        writes an address into it, not because the integer there happens to
        land somewhere mapped. Runs of consecutive relocated slots are
        tables; runs of aligned integers that merely look like pointers are
        reported with that reason and are never defined.
        """
        first_candidate = len(self._candidates)
        first_applied = len(self._applied)
        self._lone_pointers = 0
        ranges: list[dict[str, Any]] = []
        stopped: str | None = None
        for segment in self._segments():
            if segment["executable"]:
                continue
            if stopped is not None:
                ranges.append(self._unreached(segment, "raw_bytes", stopped))
                continue
            entry = self._range(segment, "raw_bytes")
            self._cursor = segment["start"]
            try:
                self._sweep_slots(segment, entry)
            except _PrepareBudgetError as exhausted:
                stopped = str(exhausted)
                self._stop_here(entry, segment, stopped)
            ranges.append(entry)
        warnings = [
            "this pass is an inventory of the tables the relocation records"
            f" and the {self._pointer_width}-byte aligned mapped bytes"
            " justify; it is not a claim that every pointer in this image"
            " was enumerated"
        ]
        if self._lone_pointers:
            warnings.append(
                f"{self._lone_pointers} relocated pointers stand alone rather"
                " than in a run, and one pointer is not a table; they are"
                " counted here rather than reported one by one"
            )
        if stopped is not None:
            warnings.append(stopped)
            self._warn(f"the pointer_tables pass stopped early: {stopped}")
        return self._pass_result(
            "pointer_tables",
            ranges,
            self._applied[first_applied:],
            [row["candidate_id"] for row in self._candidates[first_candidate:]],
            warnings,
        )

    def _sweep_slots(self, segment: dict[str, Any], entry: dict[str, Any]) -> None:
        """Walk one data segment's aligned slots, and name the bytes between."""
        width = self._pointer_width
        start = segment["start"]
        end = segment["end"]
        # A segment too short to reach its own first boundary has no slots
        # at all, and the gap that says so must stay inside the segment.
        first = min((start + width - 1) & ~(width - 1), end)
        whole = (end - first) // width
        limit = first + whole * width
        gaps: list[dict[str, int]] = []
        reasons: list[str] = []
        if first > start:
            gaps.append({"start": start, "end": first})
            reasons.append(
                f"{segment['name']} begins at {start:#x}, which is not a"
                f" {width}-byte boundary, so no whole pointer can be read"
                f" before {first:#x}"
            )
        run: list[dict[str, Any]] = []
        kind = ""
        address = first
        while address < limit:
            self._cursor = address
            self._budget.charge("seeds")
            self._budget.charge("bytes", width)
            raw = self._bytes.get_bytes(address, width)
            if raw is None or len(raw) < width:
                self._flush_run(segment, run, kind)
                entry["coverage"] = (
                    "unavailable" if address == first else "partial"
                )
                entry["reason"] = (
                    f"{segment['name']} holds no bytes in the image from"
                    f" {address:#x}, so no pointer can be read out of it"
                )
                entry["unvisited"] = [*gaps, {"start": address, "end": end}]
                return
            reasons.extend(
                self._misaligned(segment, address + 1, address + width)
            )
            slot = self._slot(address, raw)
            following = (
                "relocated"
                if slot["relocated"]
                else ("integer" if self._pointer_shaped(slot) else "")
            )
            if following != kind or not following:
                self._flush_run(segment, run, kind)
                run = []
                kind = following
            if following:
                run.append(slot)
            address += width
        self._flush_run(segment, run, kind)
        if limit < end:
            gaps.append({"start": limit, "end": end})
            reasons.append(
                f"the {end - limit} bytes at {limit:#x} are less than one"
                f" {width}-byte pointer, so the end of {segment['name']} is"
                " not a slot this pass can read"
            )
        reasons.extend(self._misaligned(segment, start, first))
        reasons.extend(self._misaligned(segment, limit, end))
        if gaps or reasons:
            entry["coverage"] = "partial"
            entry["unvisited"] = gaps
            entry["reason"] = "; ".join(reasons)

    def _misaligned(
        self, segment: dict[str, Any], start: int, end: int
    ) -> list[str]:
        """Report every relocation in ``[start, end)``, which no slot covers.

        These are the bytes an aligned grid steps over: the head of a
        segment that does not begin on a boundary, the tail too short to
        hold a pointer, and the inside of a slot whose own first byte is not
        relocated. A relocation there is still a relocation, and dropping it
        would lose it with no address and no reason.
        """
        reasons: list[str] = []
        for address in self._relocations_between(start, end):
            self._budget.charge("candidates")
            self._record(self._misaligned_candidate(segment, address))
            reasons.append(
                f"a relocation at {address:#x} lies outside every whole"
                f" {self._pointer_width}-byte slot of {segment['name']}"
            )
        return reasons

    def _relocations_between(self, start: int, end: int) -> list[int]:
        """Every address in ``[start, end)`` the loader relocates."""
        if start >= end or not self._fixup.contains_fixups(start, end - start):
            return []
        return [
            address
            for address in range(start, end)
            if self._fixup.exists_fixup(address)
        ]

    def _misaligned_candidate(
        self, segment: dict[str, Any], address: int
    ) -> dict[str, Any]:
        """One relocated pointer no aligned slot of this segment can contain.

        Two different things land here and they are not reported as one.
        An address off the pointer grid cannot start a slot; an address on
        the grid with fewer than a pointer's worth of segment left after it
        cannot finish one.
        """
        width = self._pointer_width
        raw = self._bytes.get_bytes(address, width) or b""
        slot = self._slot(address, raw)
        if address % width:
            classification = "misaligned_pointer"
            reason = (
                f"the relocated pointer at {address:#x} is aligned to"
                f" {_alignment(address)} bytes, not to the {width} a slot of"
                " this table grid would need, so it is reported where it is"
                " and no table is defined around it"
            )
        else:
            classification = "truncated_pointer"
            reason = (
                f"{segment['name']} ends {segment['end'] - address} bytes"
                f" after the relocation at {address:#x}, which is less than"
                f" the {width} one pointer takes, so it is reported where it"
                " is and no table is defined around it"
            )
        return {
            "candidate_id": f"ida:pointer_table:{address:08x}",
            "kind": "pointer_table",
            "backend": BACKEND_NAME,
            "address_space": ADDRESS_SPACE_IMAGE,
            "address": address,
            "confidence": _LIKELY,
            "state": "candidate",
            "reason": reason,
            "evidence": {
                "stage": "raw_bytes",
                "method": "a relocation record read where no whole slot is",
                "start": address,
                "end": address + len(raw),
                "segment": segment["name"],
                "classification": classification,
                "pointer_width": width,
                "endianness": self._endianness,
                "stride": None,
                "alignment": _alignment(address),
                "entry_count": 1,
                "entries": [slot],
                "existing_type": self._existing_type(address),
                **_quoted(raw),
            },
        }

    def _slot(self, address: int, raw: bytes) -> dict[str, Any]:
        """One pointer-width slot, read with this image's width and order."""
        data = self._fixup.fixup_data_t()
        relocated = bool(self._fixup.get_fixup(data, address))
        value = (
            int.from_bytes(raw, self._endianness)
            if len(raw) == self._pointer_width
            else None
        )
        target = None if value is None else self._segment.getseg(value)
        function = None if value is None else self._funcs.get_func(value)
        return {
            "address": address,
            "value": value,
            "relocated": relocated,
            "relocation": (
                self._fixup_names.get(data.get_type(), f"fixup {data.get_type()}")
                if relocated
                else None
            ),
            "relocation_target": data.off if relocated else None,
            "target_segment": (
                None if target is None else self._segment.get_segm_name(target)
            ),
            "target_executable": (
                None
                if target is None
                else bool(target.perm & self._segment.SEGPERM_EXEC)
            ),
            "target_is_function_entry": (
                function is not None and function.start_ea == value
            ),
            "target_function": None if function is None else function.start_ea,
        }

    def _pointer_shaped(self, slot: dict[str, Any]) -> bool:
        """Whether an unrelocated slot is even shaped like a pointer.

        A zero, a value outside the image, or a value that lands on nothing
        this analysis identifies is an integer with no claim on it. What is
        left is the hard case this pass exists to refuse: a mapped address
        that the analysis already knows as the start of something.
        """
        value = slot["value"]
        if not value or slot["target_segment"] is None:
            return False
        if slot["target_is_function_entry"]:
            return True
        flags = self._bytes.get_flags(value)
        return bool(self._bytes.is_head(flags) and not self._bytes.is_unknown(flags))

    def _flush_run(
        self, segment: dict[str, Any], run: list[dict[str, Any]], kind: str
    ) -> None:
        """Close one run of slots: a table, a counted pointer, or nothing."""
        if not run or not kind:
            return
        if kind == "relocated" and len(run) < MIN_POINTER_TABLE_ENTRIES:
            self._lone_pointers += len(run)
            return
        if kind == "integer" and not self._incidental_run(run):
            return
        self._budget.charge("candidates")
        self._record(self._table_candidate(segment, run, kind))

    @staticmethod
    def _incidental_run(run: list[dict[str, Any]]) -> bool:
        """Whether these unrelocated slots are worth reporting at all.

        Only a run that would be indistinguishable from a table but for the
        missing relocation: long enough, every value different, and every
        target on one side of the code/data line. Anything looser is noise
        that would bury the candidates a reviewer is here for.
        """
        if len(run) < MIN_POINTER_TABLE_ENTRIES:
            return False
        values = [slot["value"] for slot in run]
        if len(set(values)) != len(values):
            return False
        return len({slot["target_executable"] for slot in run}) == 1

    def _table_candidate(
        self, segment: dict[str, Any], run: list[dict[str, Any]], kind: str
    ) -> dict[str, Any]:
        """Describe, and where relocations back all of it define, one table."""
        width = self._pointer_width
        start = run[0]["address"]
        end = run[-1]["address"] + width
        classification = self._classify(run, kind)
        existing = self._existing_type(start)
        raw = self._bytes.get_bytes(start, end - start) or b""
        state = "candidate"
        reason = self._table_refusal(start, run, classification, existing)
        if reason is None:
            slots = [(index * width, width) for index in range(len(run))]
            held = self._field_conflicts(start, slots)
            if held:
                reason = (
                    "the managed database already defines "
                    + "; ".join(held)
                    + ", and this pass replaces nothing that is already there"
                )
            else:
                failure = self._define_table(start, len(run))
                if failure is None:
                    state = "applied"
                else:
                    reason = failure
        return {
            "candidate_id": f"ida:pointer_table:{start:08x}",
            "kind": "pointer_table",
            "backend": BACKEND_NAME,
            "address_space": ADDRESS_SPACE_IMAGE,
            "address": start,
            "confidence": _CONFIDENT if kind == "relocated" else _WEAK,
            "state": state,
            "reason": reason,
            "evidence": {
                "stage": "raw_bytes",
                "method": (
                    "consecutive aligned slots, each with a relocation record"
                    if kind == "relocated"
                    else "consecutive aligned integers with no relocation record"
                ),
                "start": start,
                "end": end,
                "segment": segment["name"],
                "classification": classification,
                "pointer_width": width,
                "endianness": self._endianness,
                "stride": width,
                "alignment": _alignment(start),
                "entry_count": len(run),
                "entries": run[:MAX_QUOTED_TABLE_ENTRIES],
                "existing_type": existing,
                **_quoted(raw),
            },
        }

    @staticmethod
    def _classify(run: list[dict[str, Any]], kind: str) -> str:
        """What this run of slots is, as far as its targets establish."""
        if kind != "relocated":
            return "unrelocated_integers"
        if any(slot["target_segment"] is None for slot in run):
            return "unmapped_targets"
        executable = {slot["target_executable"] for slot in run}
        if executable == {True}:
            if all(slot["target_is_function_entry"] for slot in run):
                return "function_pointer_table"
            return "jump_table"
        if executable == {False}:
            return "data_pointer_array"
        return "mixed_targets"

    def _table_refusal(
        self,
        start: int,
        run: list[dict[str, Any]],
        classification: str,
        existing: dict[str, Any] | None,
    ) -> str | None:
        """Why this run is only described, or ``None`` to go and define it."""
        if existing is not None:
            return (
                f"{start:#x} already carries the type {existing['name']}, which"
                " this pass reports and never replaces"
            )
        if classification == "unrelocated_integers":
            return (
                f"no relocation record backs any of these {len(run)} slots, so"
                " they are aligned integers that look like pointers; they are"
                " reported with their values and nothing is defined over them"
            )
        if classification == "jump_table":
            inside = [
                slot for slot in run if not slot["target_is_function_entry"]
            ]
            where = ", ".join(f"{slot['value']:#x}" for slot in inside)
            return (
                f"{where} {'are' if len(inside) > 1 else 'is'} inside code"
                " rather than at a function entry, so this run is as likely a"
                " jump table as a table of function pointers and the entries"
                " stay candidates"
            )
        if classification == "mixed_targets":
            return (
                "these slots point into both code and data, so what one"
                " element of this table is cannot be said from the targets"
            )
        if classification == "unmapped_targets":
            unmapped = [slot for slot in run if slot["target_segment"] is None]
            where = ", ".join(f"{slot['value']:#x}" for slot in unmapped)
            return (
                f"{where} {'land' if len(unmapped) > 1 else 'lands'} in no"
                " mapped segment of this image, so these bytes are not a"
                " table of pointers into it"
            )
        return None

    def _define_table(self, start: int, count: int) -> str | None:
        """Type the run as an array of pointers, or say why IDA would not."""
        try:
            element = self._types.tinfo_t()
            void = self._types.tinfo_t()
            void.create_simple_type(self._types.BTF_VOID)
            if not element.create_ptr(void):
                return f"IDA refused to build a pointer type for {start:#x}"
            table = self._types.tinfo_t()
            if not table.create_array(element, count):
                return (
                    f"IDA refused to build an array of {count} pointers for"
                    f" {start:#x}"
                )
            applied = bool(
                self._types.apply_tinfo(start, table, self._types.TINFO_DEFINITE)
            )
        except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
            return (
                f"IDA refused to type the table at {start:#x}:"
                f" {type(error).__name__}: {error}"
            )
        if not applied:
            return f"IDA refused to apply a pointer table at {start:#x}"
        return None


def _run_preparation(payload: dict[str, object]) -> dict[str, object]:
    """Recover what the evidence justifies, and describe what it does not."""
    return _Preparation(payload).run()


# ---------------------------------------------------------------------------
# Applying a proposal an operator approved
# ---------------------------------------------------------------------------
#
# This is the only code in this module that writes something nobody proved.
# The four passes above apply what their evidence establishes and describe
# everything else; what is applied here is a human's judgement about a
# candidate, which is a different warrant and is treated as one.
#
# Three rules follow from that.
#
# **The database decides, not the decision.** An approval carries the
# revision the operator reviewed against. If the artifact has moved on, or
# the bytes under the proposal are no longer the bytes its candidate
# recorded, or something has been defined over the range in the meantime,
# nothing is applied and the proposal is reported stale. The operator's
# approval is not a promise about a database they can no longer see.
#
# **Nothing is replaced.** A conflict is a refusal, never an overwrite: a
# name already there, a function already covering the range, an item or a
# type already defined over the bytes. That is also what makes the recovery
# below exact — the range held nothing of ours, so putting it back is a
# deletion and not a reconstruction.
#
# **A checkpoint is taken before the write and travels back with it.** The
# adapter keeps the bytes each save replaces, which covers the file; this
# covers the definition, so a host that cannot record the approval it just
# made durable can take it off again instead of leaving two stores
# disagreeing about what happened.

#: Defined items one site reports. The count is not bounded by this — a
#: conflict is reported whether or not every item of it is quoted.
MAX_QUOTED_SITE_ITEMS: Final = 64

#: Ranges one evidence read may ask about.
MAX_EVIDENCE_RANGES: Final = MAX_PROPOSALS


def _type_at(address: int) -> dict[str, Any] | None:
    """The type the database already holds at ``address``, read back out."""
    import ida_nalt
    import ida_typeinf

    held = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(held, address):
        return None
    fields: list[dict[str, Any]] = []
    details = ida_typeinf.udt_type_data_t()
    if held.is_udt() and held.get_udt_details(details):
        shape = "struct"
        fields = [
            {
                "name": member.name,
                "offset": member.offset // 8,
                "size": member.size // 8,
            }
            for member in details
        ]
    elif held.is_array():
        shape = "array"
        width = held.get_array_element().get_size()
        fields = [
            {"name": f"element_{index}", "offset": index * width, "size": width}
            for index in range(held.get_array_nelems())
        ]
    else:
        shape = "scalar"
    size = held.get_size()
    return {
        "name": str(held),
        # ``tinfo_t.get_size`` answers ``BADSIZE`` for a type with no size of
        # its own — an imported function's prototype, say — and publishing
        # that as a number no reader could use would be worse than saying it
        # is not known.
        "size": None if size == _UNKNOWN_TYPE_SIZE else size,
        "shape": shape,
        "fields": fields,
    }


def _held_definitions(
    base: int, fields: list[tuple[int, int]], *, because: str
) -> list[str]:
    """Definitions already in the database that these fields would replace.

    ``because`` names what claims the field width, because the two callers
    have different warrants for it: the structures pass has accesses that
    prove one, and a reviewed proposal has a layout an operator approved.
    """
    import ida_bytes

    found: list[str] = []
    for offset, width in fields:
        address = base + offset
        held = _type_at(address)
        if held is not None:
            found.append(f"the type {held['name']} at {address:#x}")
            continue
        flags = ida_bytes.get_flags(address)
        if ida_bytes.is_head(flags) and not ida_bytes.is_unknown(flags):
            size = ida_bytes.get_item_size(address)
            if size != width:
                found.append(
                    f"an item of {size} bytes at {address:#x}, where"
                    f" {because} a field of {width}"
                )
                continue
        inside = next(
            (
                step
                for step in range(address + 1, address + width)
                if ida_bytes.is_head(ida_bytes.get_flags(step))
            ),
            None,
        )
        if inside is not None:
            found.append(
                f"an item starting at {inside:#x}, inside the {width}-byte"
                f" field at {address:#x}"
            )
    return found


def _proposal_site(start: int, end: int) -> dict[str, Any]:
    """Everything an operator and a revalidation need about one range.

    The same facts answer both questions, deliberately: what the reviewer is
    shown before they confirm is exactly what the apply rechecks afterwards,
    so there is no second description of the database to drift apart from the
    first.
    """
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment

    segment = ida_segment.getseg(start)
    last = ida_segment.getseg(end - 1) if end > start else segment
    inside = (
        segment is not None
        and last is not None
        and segment.start_ea == last.start_ea
    )
    raw = ida_bytes.get_bytes(start, end - start) if inside else None
    raw = raw or b""
    # Every function overlapping the range, not only one containing its
    # start: a function that *begins* inside the range is just as much a
    # reason not to define another over it.
    owner = ida_funcs.get_func(start)
    walker = owner if owner is not None else ida_funcs.get_next_func(start)
    functions: list[dict[str, Any]] = []
    while inside and walker is not None and walker.start_ea < end:
        functions.append(
            {
                "start": walker.start_ea,
                "end": walker.end_ea,
                "name": ida_funcs.get_func_name(walker.start_ea),
            }
        )
        walker = ida_funcs.get_next_func(walker.start_ea)
    items: list[dict[str, Any]] = []
    cursor = start
    while inside and cursor < end and len(items) < MAX_QUOTED_SITE_ITEMS:
        item_flags = ida_bytes.get_flags(cursor)
        size = max(1, ida_bytes.get_item_size(cursor))
        if ida_bytes.is_head(item_flags) and not ida_bytes.is_unknown(item_flags):
            items.append(
                {
                    "address": cursor,
                    "size": size,
                    "is_string": bool(ida_bytes.is_strlit(item_flags)),
                }
            )
        cursor += size
    flags = ida_bytes.get_flags(start)
    holder = owner if owner is not None and owner.start_ea < end else None
    return {
        "start": start,
        "end": end,
        "size": end - start,
        "mapped": inside,
        "segment": None if not inside else (
            ida_segment.get_segm_name(segment) or f"seg_{segment.start_ea:x}"
        ),
        "segment_start": None if segment is None else segment.start_ea,
        "segment_end": None if segment is None else segment.end_ea,
        "name": ida_name.get_name(start) if ida_bytes.has_name(flags) else None,
        "function": None if not inside or holder is None else {
            "start": holder.start_ea,
            "end": holder.end_ea,
            "name": ida_funcs.get_func_name(holder.start_ea),
        },
        "functions": functions,
        "existing_type": _type_at(start) if inside else None,
        "items": items,
        **_quoted(raw),
    }


def _proposal_fields(proposal: dict[str, Any]) -> list[tuple[int, int]]:
    """The ``(offset, width)`` slots one proposal would define, if any."""
    kind = proposal["kind"]
    value = proposal["value"]
    if kind == "structure_field":
        return [(field["offset"], field["width"]) for field in value["fields"]]
    if kind == "pointer_table":
        width = value["pointer_width"]
        return [(index * width, width) for index in range(value["entry_count"])]
    return []


def _proposal_conflicts(proposal: dict[str, Any], site: dict[str, Any]) -> list[str]:
    """Everything already in the database that this proposal would replace.

    Noun phrases, so a caller can join them into its own sentence — the
    structures pass and this one have different sentences to put them in.
    :func:`_proposal_refusal` is what turns them into a decision.
    """
    start = proposal["start"]
    end = proposal["end"]
    kind = proposal["kind"]
    found: list[str] = []
    if kind == "name":
        if site["name"] is not None:
            found.append(f"the name {site['name']} at {start:#x}")
    elif kind == "function_boundary":
        for function in site["functions"]:
            found.append(
                f"the function {function['name']} over"
                f" [{function['start']:#x}, {function['end']:#x})"
            )
    elif kind == "string_decode":
        if site["existing_type"] is not None:
            found.append(
                f"the type {site['existing_type']['name']} at {start:#x}"
            )
        for item in site["items"]:
            found.append(
                f"an item of {item['size']} bytes at {item['address']:#x},"
                f" inside [{start:#x}, {end:#x})"
            )
    else:
        found.extend(
            _held_definitions(
                start, _proposal_fields(proposal), because="this layout puts"
            )
        )
    return found


def _proposal_refusal(proposal: dict[str, Any], site: dict[str, Any]) -> str | None:
    """Why this proposal may not be applied to this range, or ``None``.

    Two different things, one answer. An address outside any one mapped
    segment is not a conflict with something already there — there is nothing
    there at all — and a range that is mapped is refused only for what it
    already holds.
    """
    if not site["mapped"]:
        return (
            f"[{proposal['start']:#x}, {proposal['end']:#x}) is not inside one"
            " mapped segment of this image, so there is nothing there to"
            " define"
        )
    conflicts = _proposal_conflicts(proposal, site)
    if not conflicts:
        return None
    return (
        "the managed database already holds "
        + "; ".join(conflicts)
        + ", and a review replaces nothing that is already there"
    )


def _proposal_drift(
    proposal: dict[str, Any], candidate: dict[str, Any], site: dict[str, Any]
) -> str | None:
    """How the database has moved away from the candidate's own evidence.

    Only facts the candidate recorded and this site can recompute are
    compared, which is exactly the point: a proposal is approved against the
    evidence it cites, and the evidence it cites has to still be true of the
    database the change is about to be written to.
    """
    evidence = candidate.get("evidence")
    if not isinstance(evidence, dict):
        return None
    segment = evidence.get("segment")
    if isinstance(segment, str) and segment and segment != site["segment"]:
        return (
            f"the candidate was recovered from segment {segment} and"
            f" {proposal['start']:#x} is now in {site['segment']!r}"
        )
    digest = evidence.get("bytes_sha256")
    covers = (
        evidence.get("start") == proposal["start"]
        and evidence.get("end") == proposal["end"]
    )
    if isinstance(digest, str) and covers and digest != site["bytes_sha256"]:
        return (
            f"the bytes in [{proposal['start']:#x}, {proposal['end']:#x}) now"
            f" hash to {site['bytes_sha256']}, not to the {digest} this"
            " candidate recorded"
        )
    return None


def _proposal_effect(proposal: dict[str, Any]) -> str:
    """What approving this proposal would do, in one line for a reviewer."""
    start = proposal["start"]
    end = proposal["end"]
    value = proposal["value"]
    if proposal["kind"] == "name":
        return f"name {start:#x} {value['name']}"
    if proposal["kind"] == "function_boundary":
        return f"create a function over [{start:#x}, {end:#x})"
    if proposal["kind"] == "string_decode":
        return (
            f"define a {value['encoding']} string of {value['length']} bytes"
            f" at {start:#x}"
        )
    if proposal["kind"] == "structure_field":
        fields = ", ".join(
            f"{field['name']}@{field['offset']}:{field['width']}"
            for field in value["fields"]
        )
        return f"type {start:#x} as {value['type_name']} {{{fields}}}"
    return (
        f"type {start:#x} as an array of {value['entry_count']} pointers"
        f" {value['pointer_width']} bytes wide"
    )


def _proposal_evidence(payload: dict[str, object]) -> dict[str, object]:
    """Report what each proposed range holds now, without changing anything.

    ``mutated`` is ``False``: showing an operator what is there, and checking
    a submission against it, must never be the reason a managed database was
    rewritten.
    """
    raw = payload.get("proposals")
    if not isinstance(raw, list):
        raise OperationError(
            f"proposal_evidence: 'proposals' must be a list, got {raw!r}"
        )
    if len(raw) > MAX_EVIDENCE_RANGES:
        raise OperationError(
            f"proposal_evidence: {len(raw)} proposals is more than the"
            f" {MAX_EVIDENCE_RANGES} one call may ask about"
        )
    record, _ = _read_record()
    reviewed = []
    for item in raw:
        proposal = validate_proposal(item)
        site = _proposal_site(proposal["start"], proposal["end"])
        reviewed.append(
            {
                "candidate_id": proposal["candidate_id"],
                "kind": proposal["kind"],
                "start": proposal["start"],
                "end": proposal["end"],
                "site": site,
                "conflicts": _proposal_conflicts(proposal, site),
                "refusal": _proposal_refusal(proposal, site),
                "effect": _proposal_effect(proposal),
            }
        )
    return {
        "mutated": False,
        **_preparation_report(record),
        "address_space": ADDRESS_SPACE_IMAGE,
        "proposals": reviewed,
    }


def _apply_name(proposal: dict[str, Any]) -> str | None:
    import ida_name

    wanted = proposal["value"]["name"]
    try:
        named = bool(
            ida_name.set_name(proposal["start"], wanted, ida_name.SN_CHECK)
        )
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        return (
            f"IDA refused to name {proposal['start']:#x}:"
            f" {type(error).__name__}: {error}"
        )
    if not named:
        return (
            f"IDA refused to name {proposal['start']:#x} {wanted!r}; a name"
            " this database already uses elsewhere is the usual reason"
        )
    return None


def _apply_function_boundary(proposal: dict[str, Any]) -> str | None:
    import ida_funcs

    entry = proposal["start"]
    end = proposal["end"]
    try:
        created = bool(ida_funcs.add_func(entry, end))
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        return (
            f"IDA refused to create a function at {entry:#x}:"
            f" {type(error).__name__}: {error}"
        )
    if not created:
        return f"IDA refused to create a function at {entry:#x}"
    function = ida_funcs.get_func(entry)
    if function is None or function.start_ea != entry:
        return f"IDA reported a function at {entry:#x} that it does not hold"
    return None


def _apply_string_decode(proposal: dict[str, Any]) -> str | None:
    import ida_bytes
    import ida_nalt

    start = proposal["start"]
    length = proposal["value"]["length"]
    string_type = {
        "ascii": ida_nalt.STRTYPE_C,
        "utf-16le": ida_nalt.STRTYPE_C_16,
    }[proposal["value"]["encoding"]]
    try:
        created = bool(ida_bytes.create_strlit(start, length, string_type))
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        return (
            f"IDA refused to define a string at {start:#x}:"
            f" {type(error).__name__}: {error}"
        )
    if not created:
        return f"IDA refused to define a string at {start:#x}"
    defined = ida_bytes.get_item_size(start)
    if defined != length:
        return (
            f"IDA defined {defined} bytes at {start:#x}, not the {length} this"
            " proposal named, so the definition does not match what was"
            " approved"
        )
    return None


def _integer_member(width: int) -> Any:
    """An unsigned integer of ``width`` bytes: a size, not a meaning."""
    import ida_typeinf

    member = ida_typeinf.tinfo_t()
    member.create_simple_type(
        {
            1: ida_typeinf.BTF_UINT8,
            2: ida_typeinf.BTF_UINT16,
            4: ida_typeinf.BTF_UINT32,
            8: ida_typeinf.BTF_UINT64,
        }[width]
    )
    return member


def _apply_structure_field(proposal: dict[str, Any]) -> str | None:
    import ida_typeinf

    base = proposal["start"]
    name = proposal["value"]["type_name"]
    try:
        table = ida_typeinf.get_idati()
        if ida_typeinf.tinfo_t().get_named_type(table, name):
            return (
                f"this database already holds a type called {name}, which a"
                " review replaces nothing that is already there"
            )
        record = ida_typeinf.udt_type_data_t()
        record.is_union = False
        for field in proposal["value"]["fields"]:
            member = ida_typeinf.udm_t()
            member.name = field["name"]
            member.offset = field["offset"] * 8
            member.size = field["width"] * 8
            member.type = _integer_member(field["width"])
            record.push_back(member)
        layout = ida_typeinf.tinfo_t()
        if not layout.create_udt(record):
            return f"IDA refused to build the structure {name} for {base:#x}"
        code = layout.set_named_type(table, name)
        if code != 0:
            return (
                f"IDA refused to register the type {name} for {base:#x}:"
                f" tinfo code {code}"
            )
        applied = bool(
            ida_typeinf.apply_tinfo(base, layout, ida_typeinf.TINFO_DEFINITE)
        )
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        return (
            f"IDA refused to type {base:#x}: {type(error).__name__}: {error}"
        )
    if not applied:
        return f"IDA refused to apply the layout {name} at {base:#x}"
    return None


def _apply_pointer_table(proposal: dict[str, Any]) -> str | None:
    import ida_typeinf

    start = proposal["start"]
    count = proposal["value"]["entry_count"]
    try:
        element = ida_typeinf.tinfo_t()
        void = ida_typeinf.tinfo_t()
        void.create_simple_type(ida_typeinf.BTF_VOID)
        if not element.create_ptr(void):
            return f"IDA refused to build a pointer type for {start:#x}"
        table = ida_typeinf.tinfo_t()
        if not table.create_array(element, count):
            return (
                f"IDA refused to build an array of {count} pointers for"
                f" {start:#x}"
            )
        applied = bool(
            ida_typeinf.apply_tinfo(start, table, ida_typeinf.TINFO_DEFINITE)
        )
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        return (
            f"IDA refused to type the table at {start:#x}:"
            f" {type(error).__name__}: {error}"
        )
    if not applied:
        return f"IDA refused to apply a pointer table at {start:#x}"
    return None


#: What each change could overwrite, and therefore what a checkpoint has to
#: be empty of for the recovery below to be exact. Naming a byte replaces a
#: name and nothing else; creating a function replaces a function; the three
#: that type bytes replace a type and the items under it. The facts a change
#: cannot touch are left out on purpose — an instruction already decoded
#: where a name is being set is not something ``set_name`` disturbs, and
#: refusing to recover because of one would strand every change made over
#: code IDA had already decoded.
_REPLACEABLE_BY: Final[dict[str, tuple[str, ...]]] = {
    "name": ("name",),
    "function_boundary": ("function",),
    "string_decode": ("existing_type", "items"),
    "structure_field": ("existing_type", "items"),
    "pointer_table": ("existing_type", "items"),
}

#: One writer per kind. There is no sixth entry and no default: a kind with
#: no safe writer is refused in validation, never applied approximately.
_PROPOSAL_WRITERS: Final[dict[str, Callable[[dict[str, Any]], str | None]]] = {
    "name": _apply_name,
    "function_boundary": _apply_function_boundary,
    "string_decode": _apply_string_decode,
    "structure_field": _apply_structure_field,
    "pointer_table": _apply_pointer_table,
}


def _apply_reviewed_proposal(payload: dict[str, object]) -> dict[str, object]:
    """Apply one approved proposal, or say exactly why nothing was applied.

    A refusal is a result, not an exception: the host has an approval
    recorded against this proposal and has to be able to write down what
    became of it. The one thing this never returns is a revision it did not
    move — ``applied`` and the new ``revision`` are set together, in the same
    record write the adapter then saves, or neither is.
    """
    proposal = validate_proposal(payload.get("proposal"))
    expected = _proposal_whole(payload.get("expected_revision"), "expected_revision")
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        raise OperationError(
            "apply_reviewed_proposal: 'candidate' must be the stored candidate"
            f" this proposal names, got {candidate!r}"
        )
    record, _ = _read_record()
    preparation = record["preparation"]
    revision = int(preparation.get("revision") or 0)
    site = _proposal_site(proposal["start"], proposal["end"])
    report: dict[str, object] = {
        "mutated": False,
        "applied": False,
        "stale": False,
        "revision": revision,
        "previous_revision": revision,
        "expected_revision": expected,
        "effect": _proposal_effect(proposal),
        "site": site,
        "checkpoint": None,
        "reason": None,
        **_preparation_report(record),
    }
    if revision != expected:
        report["stale"] = True
        report["reason"] = (
            f"this approval was made against revision {expected} and the"
            f" managed artifact now carries revision {revision}, so the"
            " evidence it rests on is not the evidence it would be applied"
            " to; nothing was applied"
        )
        return report
    drift = _proposal_drift(proposal, candidate, site)
    if drift is not None:
        report["stale"] = True
        report["reason"] = f"{drift}; nothing was applied"
        return report
    refusal = _proposal_refusal(proposal, site)
    if refusal is not None:
        report["reason"] = refusal
        return report
    checkpoint = {
        "kind": proposal["kind"],
        "start": proposal["start"],
        "end": proposal["end"],
        "name": site["name"],
        "function": site["function"],
        "existing_type": site["existing_type"],
        "items": site["items"],
        "type_name": proposal["value"].get("type_name"),
    }
    failure = _PROPOSAL_WRITERS[proposal["kind"]](proposal)
    if failure is not None:
        report["reason"] = failure
        return report
    revision += 1
    preparation["revision"] = revision
    _write_record(record)
    report.update(
        mutated=True,
        applied=True,
        revision=revision,
        checkpoint=checkpoint,
        site=_proposal_site(proposal["start"], proposal["end"]),
        **_preparation_report(record),
    )
    return report


def _recover_reviewed_proposal(payload: dict[str, object]) -> dict[str, object]:
    """Put back what one applied proposal replaced, from its checkpoint.

    This is exact rather than approximate because the apply refused every
    conflict: the range held no name, no function, no item and no type of
    ours before the change, so taking the change off is a deletion. A
    checkpoint that says otherwise is reported as unrecoverable instead of
    being half-undone.
    """
    checkpoint = payload.get("checkpoint")
    if not isinstance(checkpoint, dict):
        raise OperationError(
            "recover_reviewed_proposal: 'checkpoint' must be the object the"
            f" apply returned, got {checkpoint!r}"
        )
    import ida_bytes
    import ida_funcs
    import ida_name

    kind = checkpoint.get("kind")
    start = _proposal_whole(checkpoint.get("start"), "checkpoint.start")
    end = _proposal_whole(checkpoint.get("end"), "checkpoint.end")
    if kind not in PROPOSAL_KINDS:
        raise OperationError(
            f"recover_reviewed_proposal: checkpoint.kind={kind!r} is not one"
            f" of {', '.join(PROPOSAL_KINDS)}"
        )
    held = [
        fact for fact in _REPLACEABLE_BY[str(kind)] if checkpoint.get(fact)
    ]
    if held:
        # A definition of the kind this change could have replaced was
        # already there. The apply refuses those, so this should not happen —
        # and if it has, taking the change off would delete something that
        # was not ours to delete. The divergence is reported rather than
        # guessed at.
        return {
            "mutated": False,
            "recovered": False,
            "reason": (
                f"the checkpoint for [{start:#x}, {end:#x}) records"
                f" {', '.join(held)} that a {kind} change would have replaced,"
                " which this build cannot rebuild; the managed artifact is"
                " left exactly as the apply left it"
            ),
            "site": _proposal_site(start, end),
        }
    failures: list[str] = []
    try:
        if kind == "name":
            if not ida_name.set_name(start, "", ida_name.SN_NOCHECK):
                failures.append(f"IDA refused to clear the name at {start:#x}")
        elif kind == "function_boundary":
            if not ida_funcs.del_func(start):
                failures.append(f"IDA refused to delete the function at {start:#x}")
        else:
            import ida_nalt

            ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, end - start)
            ida_nalt.del_tinfo(start)
            name = checkpoint.get("type_name")
            if isinstance(name, str) and name:
                import ida_typeinf

                ida_typeinf.del_named_type(
                    ida_typeinf.get_idati(), name, ida_typeinf.NTF_TYPE
                )
    except Exception as error:  # noqa: BLE001 - IDA raises bare exceptions
        failures.append(f"{type(error).__name__}: {error}")
    record, _ = _read_record()
    preparation = record["preparation"]
    revision = int(preparation.get("revision") or 0) + 1
    preparation["revision"] = revision
    _write_record(record)
    return {
        "mutated": True,
        "recovered": not failures,
        "revision": revision,
        "reason": "; ".join(failures) or None,
        "site": _proposal_site(start, end),
        **_preparation_report(record),
    }


#: Every operation ``run`` accepts, by name. Each takes the JSON payload and
#: returns a JSON-native dictionary.
_OPERATIONS: Final[dict[str, Callable[[dict[str, object]], dict[str, object]]]] = {
    "apply_reviewed_proposal": _apply_reviewed_proposal,
    "database_summary": _database_summary,
    "findings_page": _findings_page,
    "prepare": _run_preparation,
    "preparation_summary": _preparation_summary,
    "proposal_evidence": _proposal_evidence,
    "record_preparation": _record_preparation,
    "recover_reviewed_proposal": _recover_reviewed_proposal,
    "scan": _scan,
    "store_scan": _store_scan,
    "triage": _triage,
}
