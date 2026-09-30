"""VulFi rule schema, pinned stock rules, digests, and the agent rule template.

The stock rules and prototypes in ``data/`` are copied verbatim from
Accenture/VulFi commit ``0bb7fdf8ccb906600cc209c35daf05774172acc8`` and remain
under the Apache-2.0 license shipped beside them as
``vulfi_mcp/data/Accenture-VulFi-LICENSE`` (``THIRD_PARTY_LICENSES/`` links to it
in the source tree).

Nothing in this module imports IDA.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Final, TypedDict

__all__ = [
    "MarkIf",
    "PRIORITIES",
    "Rule",
    "canonical_rule_digest",
    "load_stock_rules",
    "rule_template",
    "validate_rules",
]

#: ``mark_if`` branches, evaluated in this order.
PRIORITIES: Final[tuple[str, str, str]] = ("High", "Medium", "Low")

_RULE_KEYS: Final[tuple[str, ...]] = ("name", "function_names", "wrappers", "mark_if")


class MarkIf(TypedDict):
    """Restricted expressions evaluated in ``High``, ``Medium``, ``Low`` order."""

    High: str
    Medium: str
    Low: str


class Rule(TypedDict):
    """A stock or agent-authored VulFi rule; exactly these four keys."""

    name: str
    function_names: list[str]
    wrappers: bool
    mark_if: MarkIf


def validate_rules(raw: object) -> tuple[Rule, ...]:
    """Validate untrusted rule JSON and return independent copies.

    Rules keep their submitted order and are never deduplicated: two rules may
    share a ``name`` and stay distinct. Every error names the offending rule
    index, e.g. ``rules[3]: 'wrappers' must be a boolean``.
    """
    if not isinstance(raw, list):
        raise ValueError(
            f"rules: expected a JSON list of rule objects, got {type(raw).__name__}"
        )
    return tuple(_validate_rule(item, index) for index, item in enumerate(raw))


def canonical_rule_digest(rule: Rule) -> str:
    """SHA-256 of the canonical UTF-8 JSON encoding of ``rule``."""
    canonical = json.dumps(
        rule, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_stock_rules() -> tuple[Rule, ...]:
    """Load and validate the 24 pinned VulFi rules shipped with the package."""
    payload = (
        resources.files(__package__).joinpath("data/rules.json").read_text("utf-8")
    )
    return validate_rules(json.loads(payload))


def rule_template() -> dict[str, object]:
    """Describe the rule schema, examples, expression language, and limits."""
    return {
        "rule_schema": {
            "type": "object",
            "required_keys": list(_RULE_KEYS),
            "additional_keys": "rejected",
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "Non-empty label carried on every finding. Names need not be"
                        " unique; rules are identified by their full definition."
                    ),
                },
                "function_names": {
                    "type": "array",
                    "items": "string",
                    "min_items": 1,
                    "description": "Exact names of the called functions to match.",
                },
                "wrappers": {
                    "type": "boolean",
                    "description": (
                        "Also inspect call sites of one-level wrappers around the"
                        " named functions."
                    ),
                },
                "mark_if": {
                    "type": "object",
                    "required_keys": list(PRIORITIES),
                    "values": "string",
                    "description": (
                        "Restricted expressions evaluated in High, Medium, Low order;"
                        " the first true branch sets the finding priority. Use"
                        " \"False\" or \"\" for a branch that never matches."
                    ),
                },
            },
        },
        "example_rules": [
            {
                "name": "Buffer Overflow",
                "function_names": ["strcpy", "strcat"],
                "wrappers": True,
                "mark_if": {
                    "High": (
                        "not param[1].is_constant()"
                        " and not param[1].used_in_call_before(['strlen'])"
                    ),
                    "Medium": "False",
                    "Low": "not param[1].is_constant()",
                },
            },
            {
                "name": "Format String",
                "function_names": ["sprintf"],
                "wrappers": False,
                "mark_if": {
                    "High": (
                        "any([not param[i + 1].is_constant()"
                        " for i in range(len(param[1].string_value().split('%')))"
                        " if param[1].string_value().split('%')[i].startswith('s')])"
                    ),
                    "Medium": "'%s' in param[1].string_value()",
                    "Low": "not function_call.return_value_checked()",
                },
            },
        ],
        "expression_language": {
            "description": (
                "Each mark_if branch is a single VulFi-shaped expression parsed into a"
                " restricted AST and interpreted. Only the facts, operators, builtins,"
                " methods, and literal values listed here are accepted."
            ),
            "facts": {
                "param[i]": (
                    "Zero-based recovered call argument; supports the param methods"
                    " below."
                ),
                "param_count": "Number of recovered arguments at the call site.",
                "function_call": (
                    "The matched call site itself; supports the function_call methods"
                    " below."
                ),
            },
            "operators": [
                "and",
                "or",
                "not",
                "==",
                "!=",
                "<",
                "<=",
                ">",
                ">=",
                "in",
                "not in",
                "+",
                "-",
                "*",
                "//",
                "%",
            ],
            "forms": [
                "indexing, such as param[0] or split_result[i]",
                "literal strings, integers, booleans, None, and lists",
                "parenthesised sub-expressions",
                "list comprehension over a bounded range, such as"
                " [not param[i].is_constant() for i in range(param_count) if i > 0]",
            ],
            "builtins": ["any", "len", "range"],
            "string_methods": ["lower", "split", "startswith"],
            "param_methods": [
                "is_constant()",
                "string_value()",
                "number_value()",
                "used_as_index()",
                "is_sign_compared()",
                "set_to_null_after_call()",
                "used_in_call_before(['strlen'])",
            ],
            "function_call_methods": [
                "return_value_checked()",
                "return_value_checked(param_count - 2)",
            ],
            "limits": {
                "expression": (
                    "One bounded expression per branch; oversized or unsupported"
                    " syntax is rejected with a rule-indexed error."
                ),
                "iteration": (
                    "Comprehensions, any(), and range() iterate a bounded number of"
                    " elements; an over-budget expression is rejected."
                ),
                "calls": (
                    "Only the listed builtins, string methods, and fact methods may be"
                    " called; user-defined and arbitrary callables are rejected."
                ),
            },
        },
        "safety_notes": [
            "Agent-authored expressions are untrusted input: they are interpreted"
            " from a restricted AST, never with Python eval or exec.",
            "Imports, dunder and attribute access beyond the listed methods,"
            " arbitrary calls, assignment, and mutation are rejected with a"
            " rule-indexed error such as rules[3]: ....",
            "Rules are validated in full before any binary, IDB, or netnode is"
            " opened or modified.",
        ],
        "coverage_notes": [
            "Branches are evaluated in High, Medium, Low order; the first branch"
            " that evaluates true sets the finding priority.",
            "A verified empty argument list may produce an Info finding. Argument"
            " recovery that is unavailable is reported as an unsupported rule or"
            " partial scan coverage, never as an Info finding and never as a clean"
            " negative.",
            "Every submitted rule is reported as evaluated, unsupported, or failed"
            " with a reason.",
            "Rules are never deduplicated by name: same-named rules keep separate"
            " digests, findings, and assessments.",
        ],
    }


def _validate_rule(item: object, index: int) -> Rule:
    where = f"rules[{index}]"
    if not isinstance(item, dict):
        raise ValueError(
            f"{where}: expected a rule object, got {type(item).__name__}"
        )

    for key in _RULE_KEYS:
        if key not in item:
            raise ValueError(f"{where}: missing key {key!r}")
    unexpected = sorted(set(item) - set(_RULE_KEYS))
    if unexpected:
        listed = ", ".join(repr(key) for key in unexpected)
        raise ValueError(f"{where}: unexpected key(s) {listed}")

    name = item["name"]
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{where}: 'name' must be a non-empty string")

    function_names = item["function_names"]
    if not isinstance(function_names, list):
        raise ValueError(f"{where}: 'function_names' must be a list of strings")
    if not function_names:
        raise ValueError(f"{where}: 'function_names' must not be empty")
    for position, function_name in enumerate(function_names):
        if not isinstance(function_name, str) or not function_name.strip():
            raise ValueError(
                f"{where}: function_names[{position}] must be a non-empty string"
            )

    wrappers = item["wrappers"]
    if not isinstance(wrappers, bool):
        raise ValueError(f"{where}: 'wrappers' must be a boolean")

    mark_if = item["mark_if"]
    if not isinstance(mark_if, dict):
        raise ValueError(
            f"{where}: 'mark_if' must be an object with"
            f" {', '.join(PRIORITIES)} string branches"
        )
    unexpected = sorted(set(mark_if) - set(PRIORITIES))
    if unexpected:
        listed = ", ".join(repr(key) for key in unexpected)
        raise ValueError(f"{where}: 'mark_if' has unexpected branch(es) {listed}")
    for priority in PRIORITIES:
        if priority not in mark_if:
            raise ValueError(f"{where}: 'mark_if' is missing the {priority!r} branch")
        if not isinstance(mark_if[priority], str):
            raise ValueError(f"{where}: mark_if[{priority!r}] must be a string")

    return {
        "name": name,
        "function_names": list(function_names),
        "wrappers": wrappers,
        "mark_if": {priority: mark_if[priority] for priority in PRIORITIES},
    }
