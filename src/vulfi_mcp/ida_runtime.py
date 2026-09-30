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
import unicodedata
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, TypeAlias, TypeVar

if TYPE_CHECKING:  # pragma: no cover - the worker never imports the package.
    from vulfi_mcp.rules import Rule

__all__ = [
    "MAX_COMPREHENSION_ITERATIONS",
    "MAX_EXPRESSION_LENGTH",
    "MAX_EXPRESSION_NODES",
    "MAX_PAGE_LIMIT",
    "MAX_RATIONALE_LENGTH",
    "MAX_SCAN_NAME_LENGTH",
    "NETNODE_BLOB_INDEX",
    "NETNODE_BLOB_TAG",
    "NETNODE_NAME",
    "PRIORITIES",
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
    "evaluate_rule",
    "finding_order",
    "run",
    "utc_now",
    "validate_expression",
    "validate_page",
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


def _element_kind(node: ast.expr, bound: dict[str, str]) -> str:
    """Static kind of one element of ``node``, or ``_UNKNOWN``."""
    return _ELEMENT_KINDS.get(_infer_kind(node, bound), _UNKNOWN)


def _list_kind(element: str) -> str:
    """Static kind of a list whose elements are all of kind ``element``."""
    return _LIST_KINDS.get(element, _LIST)


def _infer_kind(node: ast.expr, bound: dict[str, str]) -> str:
    """Infer what kind of value an expression produces, without any facts.

    Receivers in this language are a closed set, so an unmistakable kind lets
    :class:`_Validator` reject a method call on the wrong receiver before any
    IDB is opened. Anything not inferable is ``_UNKNOWN`` and stays permissive.
    """
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
        return _element_kind(node.value, bound)
    if isinstance(node, ast.List):
        kinds = {_infer_kind(element, bound) for element in node.elts}
        return _list_kind(kinds.pop()) if len(kinds) == 1 else _LIST
    if isinstance(node, ast.ListComp):
        inner = dict(bound)
        for generator in node.generators:
            if isinstance(generator.target, ast.Name):
                inner[generator.target.id] = _element_kind(generator.iter, bound)
        return _list_kind(_infer_kind(node.elt, inner))
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
            table = _METHODS.get(_RECEIVER_TYPES.get(_infer_kind(func.value, bound)))
            if table is not None and func.attr in table:
                return table[func.attr].result
            return _METHOD_RESULTS.get(func.attr, _UNKNOWN)
    return _UNKNOWN


class _Validator:
    """Walks one parsed branch and rejects everything outside the whitelist."""

    __slots__ = ("_nodes",)

    def __init__(self) -> None:
        self._nodes = 0

    def check(self, node: ast.AST, bound: dict[str, str]) -> None:
        self._count()
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

    def _apply_prototype(self, ea: int, name: str) -> bool:
        """Type a rule-named function VulFi ships a prototype for, once.

        Upstream applied a prototype to every function it recognized, up
        front. This runs only after argument recovery for a call to ``ea``
        actually failed, which is the only state in which a missing prototype
        is what the recovery lacked: a function IDA already types, and one the
        decompiler recovered arguments for on its own, are never rewritten. It
        is the only write this operation makes, it happens in the managed
        database alone, and every application is reported back as
        ``applied_prototypes``.
        """
        if not name or ea in self._typed:
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
        params, reason, expected = self._arguments(address, callee_name, callee_ea)
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
        self, call_ea: int, callee_name: str, callee_ea: int
    ) -> tuple[list[dict[str, object]] | None, str | None, int | None]:
        """This call's arguments, or exactly why they could not be recovered.

        A first attempt uses whatever IDA already knows. Only if that fails is
        the callee offered its pinned VulFi prototype, and only then is the
        recovery retried — once. That is the whole of the ``SetType`` trigger:
        a prototype is applied when, and only when, the arguments could not
        otherwise be recovered.
        """
        params, reason, expected = self._recover_arguments(
            call_ea, callee_name, callee_ea
        )
        if params is not None:
            return params, reason, expected
        if not self._apply_prototype(callee_ea, callee_name):
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


#: Every operation ``run`` accepts, by name. Each takes the JSON payload and
#: returns a JSON-native dictionary.
_OPERATIONS: Final[dict[str, Callable[[dict[str, object]], dict[str, object]]]] = {
    "database_summary": _database_summary,
    "findings_page": _findings_page,
    "scan": _scan,
    "store_scan": _store_scan,
    "triage": _triage,
}
