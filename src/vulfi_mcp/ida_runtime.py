"""Restricted, IDA-free core that evaluates VulFi ``mark_if`` expressions.

Upstream VulFi (Accenture/VulFi commit ``0bb7fdf8``) evaluated every ``mark_if``
branch with :func:`eval`. Agent-authored rules are untrusted input here, so this
module parses each branch into an abstract syntax tree and interprets only a
whitelist of nodes, names, operators, builtins, and receiver methods. There is
no :func:`eval` and no :func:`exec` anywhere.

This file is shipped to the IDA worker **by path**
(``ida_nexus.RemoteModule("<path>/ida_runtime.py", codec="json")``) and executes
as a standalone module inside another interpreter. It therefore imports nothing
from the :mod:`vulfi_mcp` package at runtime, uses no relative imports, and
imports nothing from IDA at module load; IDA APIs are imported inside worker
functions only. Rules arrive as plain JSON-native dictionaries.

Nothing here may depend on the module being registered in ``sys.modules``: a
loader that only executes the source would break ``@dataclass(slots=True)``,
which is why the fact types below are plain frozen dataclasses.

:class:`Param` and :class:`FunctionCall` are pure fact carriers: each predicate
answers from facts a backend verified and supplied. A fact that was not supplied
is :data:`UNAVAILABLE` and raises :class:`UnavailableEvidenceError` rather than
answering ``False``, so a backend that cannot recover an argument is reported as
``unsupported``/``partial`` instead of as a clean negative.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Final, Literal, NoReturn, TypeAlias, TypeVar

if TYPE_CHECKING:  # pragma: no cover - the worker never imports the package.
    from vulfi_mcp.rules import Rule

__all__ = [
    "MAX_COMPREHENSION_ITERATIONS",
    "MAX_EXPRESSION_LENGTH",
    "MAX_EXPRESSION_NODES",
    "PRIORITIES",
    "UNAVAILABLE",
    "BranchPriority",
    "ExpressionBudgetError",
    "ExpressionError",
    "ExpressionEvaluationError",
    "FunctionCall",
    "InvalidExpressionError",
    "Param",
    "RuleContext",
    "Unavailable",
    "UnavailableEvidenceError",
    "evaluate_rule",
    "validate_expression",
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
#: Most comprehension items one branch may produce, counting every ``range()``
#: it builds and every item any comprehension iterates.
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
SizeFact: TypeAlias = int | None | Unavailable
NamesFact: TypeAlias = tuple[str, ...] | Unavailable
ValuesFact: TypeAlias = tuple[int | float, ...] | Unavailable

_FactValue = TypeVar("_FactValue")


def _fact(value: _FactValue | Unavailable, name: str) -> _FactValue:
    """Return a supplied fact, or refuse to answer when it was never supplied."""
    if isinstance(value, Unavailable):
        raise UnavailableEvidenceError(f"the {name!r} fact is unavailable", fact=name)
    return value


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
        base = name[1:] if name[:1] in (".", "_") else name
        spellings.update((base, f".{base}", f"_{base}"))
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
    #: ``size()``: width in bytes of the backing variable, ``None`` when unknown.
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

    def size(self) -> int | None:
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


@dataclass(frozen=True)
class _MethodSpec:
    call: Callable[..., object]
    min_args: int
    max_args: int


_METHODS: Final[dict[type, dict[str, _MethodSpec]]] = {
    Param: {
        "size": _MethodSpec(Param.size, 0, 0),
        "used_as_index": _MethodSpec(Param.used_as_index, 0, 0),
        "is_constant": _MethodSpec(Param.is_constant, 0, 0),
        "is_const_number": _MethodSpec(Param.is_const_number, 0, 0),
        "is_sign_compared": _MethodSpec(Param.is_sign_compared, 0, 0),
        "set_to_null_after_call": _MethodSpec(Param.set_to_null_after_call, 0, 0),
        "string_value": _MethodSpec(Param.string_value, 0, 0),
        "number_value": _MethodSpec(Param.number_value, 0, 0),
        "used_in_call_before": _MethodSpec(Param.used_in_call_before, 1, 1),
        "used_in_call_after": _MethodSpec(Param.used_in_call_after, 1, 1),
    },
    FunctionCall: {
        "reachable_from": _MethodSpec(FunctionCall.reachable_from, 1, 1),
        "return_value_checked": _MethodSpec(FunctionCall.return_value_checked, 0, 1),
    },
    str: {
        "lower": _MethodSpec(_string_lower, 0, 0),
        "split": _MethodSpec(_string_split, 0, 1),
        "startswith": _MethodSpec(_string_startswith, 1, 1),
    },
}


def _merged_arities() -> dict[str, tuple[int, int]]:
    merged: dict[str, tuple[int, int]] = {}
    for table in _METHODS.values():
        for name, spec in table.items():
            low, high = merged.get(name, (spec.min_args, spec.max_args))
            merged[name] = (min(low, spec.min_args), max(high, spec.max_args))
    return merged


_METHOD_ARITIES: Final[dict[str, tuple[int, int]]] = _merged_arities()
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
    _Validator().check(tree, frozenset())
    return tree


class _Validator:
    """Walks one parsed branch and rejects everything outside the whitelist."""

    __slots__ = ("_nodes",)

    def __init__(self) -> None:
        self._nodes = 0

    def check(self, node: ast.AST, bound: frozenset[str]) -> None:
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

    def _check_name(self, node: ast.Name, bound: frozenset[str]) -> None:
        self._check_load(node)
        if node.id not in bound and node.id not in _BOUND_NAMES:
            raise InvalidExpressionError(
                f"unknown name {node.id!r}; only"
                f" {', '.join(sorted(_BOUND_NAMES))} are bound"
            )

    def _check_comprehension(self, node: ast.ListComp, bound: frozenset[str]) -> None:
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
        inner = bound | {target.id}
        for condition in generator.ifs:
            self.check(condition, inner)
        self.check(node.elt, inner)

    def _check_call(self, node: ast.Call, bound: frozenset[str]) -> None:
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
            self._check_arity(func.attr, _METHOD_ARITIES[func.attr], node)
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
            return any(item == element for element in container)
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
        if not 0 <= index < len(params):
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
            return any(self._truth(value, node) for value in values)
        bounds = [
            self._index(value, argument)
            for value, argument in zip(arguments, node.args)
        ]
        if len(bounds) == 3 and bounds[2] == 0:
            raise ExpressionEvaluationError("range() step must not be zero")
        span = range(*bounds)
        if len(span) > MAX_COMPREHENSION_ITERATIONS:
            raise ExpressionBudgetError(
                f"range() would iterate {len(span)} items, over the"
                f" {MAX_COMPREHENSION_ITERATIONS} iteration budget"
            )
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
                self._iterations += 1
                if self._iterations > MAX_COMPREHENSION_ITERATIONS:
                    raise ExpressionBudgetError(
                        f"expression is over the {MAX_COMPREHENSION_ITERATIONS}"
                        f" comprehension iteration budget"
                    )
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
