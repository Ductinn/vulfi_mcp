"""Behavior tests for the packaged VulFi rule contracts."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import pytest

from vulfi_mcp.ida_runtime import (
    MAX_COMPREHENSION_ITERATIONS,
    MAX_EXPRESSION_DEPTH,
    MAX_EXPRESSION_LENGTH,
    MAX_EXPRESSION_NODES,
)
from vulfi_mcp.rules import (
    canonical_rule_digest,
    load_stock_rules,
    rule_template,
    validate_rules,
)

SORTED_PRIORITIES = ["High", "Low", "Medium"]


def make_rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "name": "Buffer Overflow",
        "function_names": ["strcpy"],
        "wrappers": False,
        "mark_if": {
            "High": "not param[1].is_constant()",
            "Medium": "False",
            "Low": "False",
        },
    }
    rule.update(overrides)
    return rule


def test_stock_rules_validate_and_duplicate_names_keep_distinct_digests() -> None:
    stock = load_stock_rules()

    assert len(stock) == 24
    assert [rule["name"] for rule in stock].count("Format String") > 1
    for rule in stock:
        assert sorted(rule["mark_if"]) == SORTED_PRIORITIES
        assert rule["function_names"]
    # Same-named rules are kept apart by their full definition, never deduplicated.
    assert len({canonical_rule_digest(rule) for rule in stock}) == 24

    twins = validate_rules(
        [
            make_rule(function_names=["strcpy"]),
            make_rule(function_names=["strcat"]),
        ]
    )
    assert len(twins) == 2
    assert twins[0]["name"] == twins[1]["name"]
    assert canonical_rule_digest(twins[0]) != canonical_rule_digest(twins[1])

    reordered = {
        "mark_if": dict(reversed(list(twins[0]["mark_if"].items()))),
        "wrappers": twins[0]["wrappers"],
        "function_names": list(twins[0]["function_names"]),
        "name": twins[0]["name"],
    }
    digest = canonical_rule_digest(twins[0])
    assert canonical_rule_digest(reordered) == digest
    assert len(digest) == 64 and digest == digest.lower()


def test_stock_rules_are_not_shared_mutable_state() -> None:
    first = load_stock_rules()
    first[0]["function_names"].append("injected")
    first[0]["mark_if"]["High"] = "True"

    assert load_stock_rules()[0]["function_names"] != first[0]["function_names"]
    assert load_stock_rules()[0]["mark_if"]["High"] != "True"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        pytest.param(
            [make_rule(), make_rule(mark_if={"High": "True", "Medium": "False"})],
            r"rules\[1\].*mark_if.*Low",
            id="missing-priority-branch",
        ),
        pytest.param(
            [make_rule(function_names=[])],
            r"rules\[0\].*function_names.*empty",
            id="empty-function-names",
        ),
        pytest.param(
            [make_rule(), make_rule(), make_rule(mark_if={"High": "True", "Medium": "False", "Low": 0})],
            r"rules\[2\].*mark_if\['Low'\].*string",
            id="non-string-branch",
        ),
        pytest.param(
            [make_rule(wrappers="yes")],
            r"rules\[0\].*wrappers.*boolean",
            id="wrong-wrappers-type",
        ),
        pytest.param(
            [make_rule(function_names="strcpy")],
            r"rules\[0\].*function_names.*list",
            id="function-names-not-a-list",
        ),
        pytest.param(
            [{**make_rule(), "priority": "High"}],
            r"rules\[0\].*unexpected key.*priority",
            id="extra-top-level-key",
        ),
        pytest.param(
            [{k: v for k, v in make_rule().items() if k != "name"}],
            r"rules\[0\].*missing key.*name",
            id="missing-top-level-key",
        ),
        pytest.param(
            [make_rule(), "strcpy"],
            r"rules\[1\].*object",
            id="rule-not-an-object",
        ),
        pytest.param({"name": "x"}, r"rules: .*list", id="not-a-list"),
    ],
)
def test_invalid_mark_if_rejected(raw: object, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        validate_rules(raw)


def test_validate_rules_does_not_mutate_or_deduplicate_input() -> None:
    raw = [make_rule(), make_rule()]
    snapshot = json.dumps(raw, sort_keys=True)

    validated = validate_rules(raw)

    assert len(validated) == 2
    assert json.dumps(raw, sort_keys=True) == snapshot
    validated[0]["function_names"].append("memcpy")
    assert raw[0]["function_names"] == ["strcpy"]


def test_empty_mark_if_branch_is_accepted_as_never_matching() -> None:
    # rule_template() publishes "" as a valid never-matching branch; keep it valid.
    rule = make_rule(mark_if={"High": "not param[1].is_constant()", "Medium": "", "Low": ""})

    validated = validate_rules([rule])

    assert validated[0]["mark_if"] == {
        "High": "not param[1].is_constant()",
        "Medium": "",
        "Low": "",
    }


def test_rule_template_example_roundtrips() -> None:
    template = rule_template()

    assert json.loads(json.dumps(template, ensure_ascii=False)) == template

    schema = template["rule_schema"]
    assert schema["required_keys"] == ["name", "function_names", "wrappers", "mark_if"]
    assert sorted(schema["properties"]["mark_if"]["required_keys"]) == SORTED_PRIORITIES

    examples = template["example_rules"]
    assert examples
    validated = validate_rules(examples)
    for example in validated:
        assert sorted(example["mark_if"]) == SORTED_PRIORITIES

    language = template["expression_language"]
    assert set(language["facts"]) == {"param[i]", "param_count", "function_call"}
    assert "is_constant()" in language["param_methods"]
    assert "return_value_checked()" in language["function_call_methods"]
    assert set(language["builtins"]) == {"any", "len", "range"}
    assert set(language["string_methods"]) == {"lower", "split", "startswith"}
    assert {"and", "not", "in", "=="} <= set(language["operators"])
    assert "list comprehension" in " ".join(language["forms"]).lower()
    assert language["limits"]

    notes = " ".join(template["safety_notes"] + template["coverage_notes"]).lower()
    assert "untrusted" in notes
    assert "eval" in notes
    assert "unsupported" in notes and "partial" in notes
    assert "info" in notes


def test_published_limits_name_every_budget_an_expression_can_be_refused_by() -> None:
    # An agent authors inside these numbers, so a budget the interpreter
    # charges and the template omits is a refusal the author was never told
    # about: `in`/`not in` scans share the iteration counter, and nesting depth
    # is bounded as well as length and node count.
    limits = rule_template()["expression_language"]["limits"]
    published = " ".join(limits.values())

    for enforced in (
        MAX_EXPRESSION_LENGTH,
        MAX_EXPRESSION_NODES,
        MAX_EXPRESSION_DEPTH,
        MAX_COMPREHENSION_ITERATIONS,
    ):
        assert str(enforced) in published, f"{enforced} is enforced but unpublished"

    charged = limits["iteration"]
    for construct in ("any()", "range()", "not in"):
        assert construct in charged, f"{construct} is charged but unpublished"


def test_packaged_data_is_importable_from_the_installed_package() -> None:
    data = resources.files("vulfi_mcp").joinpath("data")

    rules = json.loads(data.joinpath("rules.json").read_text("utf-8"))
    prototypes = json.loads(data.joinpath("prototypes.json").read_text("utf-8"))

    assert isinstance(rules, list) and len(rules) == 24
    assert isinstance(prototypes, dict) and len(prototypes) == 441
    assert prototypes["strcpy"] == "char* strcpy(char* dest, char* src);"
    assert validate_rules(rules) == load_stock_rules()

    license_text = data.joinpath("Accenture-VulFi-LICENSE").read_text("utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
