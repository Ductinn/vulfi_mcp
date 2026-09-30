"""Behavior tests for the managed record's IDA-free validators.

These decide what an agent's arguments may be *before* any database is opened:
a scope name that could split a finding ID or reach a path, a status outside
the four, an untrusted rationale, a page window. They import nothing from IDA
and run on an ordinary contributor machine, which is exactly where their
boundaries have to hold — the live tests that also exercise them are skipped
without a licensed IDA.
"""

from __future__ import annotations

from typing import Any

import pytest

from vulfi_mcp.ida_runtime import (
    MAX_PAGE_LIMIT,
    MAX_RATIONALE_LENGTH,
    MAX_SCAN_NAME_LENGTH,
    TRIAGE_STATUSES,
    OperationError,
    finding_order,
    validate_page,
    validate_rationale,
    validate_scan_name,
    validate_scope,
    validate_status,
)


def test_a_rejection_is_an_ordinary_bad_argument_error() -> None:
    # The adapter refuses a bad status or page on the host and its caller sees
    # a ValueError, not a worker-specific type it would have to know about.
    assert issubclass(OperationError, ValueError)
    with pytest.raises(ValueError):
        validate_status("vulnerable")


@pytest.mark.parametrize(
    "scope",
    [
        "default",
        "custom:stock",
        "custom:_private",
        "custom:scan9",
        "custom:" + "a" * MAX_SCAN_NAME_LENGTH,
    ],
)
def test_accepted_scopes_are_returned_unchanged(scope: str) -> None:
    assert validate_scope(scope) == scope


@pytest.mark.parametrize(
    ("scope", "message"),
    [
        pytest.param("", "non-empty string", id="empty"),
        pytest.param(None, "non-empty string", id="none"),
        pytest.param(5, "non-empty string", id="not-a-string"),
        pytest.param("Default", "'default' or", id="wrong-case"),
        pytest.param("stock", "'default' or", id="bare-name"),
        pytest.param("custom", "'default' or", id="prefix-without-colon"),
        pytest.param("custom:", "non-empty string", id="empty-scan-name"),
        # A scan name that could split a finding ID or reach a path.
        pytest.param("custom:a:b", "ASCII identifier", id="colon"),
        pytest.param("custom:../etc/passwd", "ASCII identifier", id="traversal"),
        pytest.param("custom:a/b", "ASCII identifier", id="slash"),
        pytest.param("custom:a\\b", "ASCII identifier", id="backslash"),
        pytest.param("custom:has space", "ASCII identifier", id="space"),
        pytest.param("custom:caf\u00e9", "ASCII identifier", id="non-ascii"),
        pytest.param("custom:9lead", "ASCII identifier", id="leading-digit"),
        pytest.param(
            "custom:" + "a" * (MAX_SCAN_NAME_LENGTH + 1),
            f"the limit is {MAX_SCAN_NAME_LENGTH}",
            id="over-length",
        ),
    ],
)
def test_refused_scopes_say_exactly_what_is_wrong(scope: Any, message: str) -> None:
    with pytest.raises(OperationError) as refusal:
        validate_scope(scope)

    assert message in str(refusal.value)


def test_scan_name_accepts_an_ascii_identifier_and_nothing_else() -> None:
    assert validate_scan_name("a") == "a"
    assert validate_scan_name("_x9") == "_x9"
    assert validate_scan_name("a" * MAX_SCAN_NAME_LENGTH) == "a" * MAX_SCAN_NAME_LENGTH

    for refused in ("", None, b"name", "a b", "a-b", "a.b", "\u00e9tude", "a" * 65):
        with pytest.raises(OperationError):
            validate_scan_name(refused)


def test_status_accepts_the_four_states_verbatim() -> None:
    assert TRIAGE_STATUSES == (
        "Not Checked",
        "False Positive",
        "Suspicious",
        "Vulnerable",
    )
    for status in TRIAGE_STATUSES:
        assert validate_status(status) == status


@pytest.mark.parametrize(
    "status",
    ["", None, True, 0, "not checked", "NOT CHECKED", "Not  Checked", "Triaged"],
)
def test_a_status_outside_the_four_is_refused(status: Any) -> None:
    with pytest.raises(OperationError) as refusal:
        validate_status(status)

    assert "status must be one of" in str(refusal.value)


@pytest.mark.parametrize(
    "rationale",
    [
        pytest.param("plain ascii", id="ascii"),
        pytest.param("\u30d0\u30c3\u30d5\u30a1\u6ea2\u308c", id="japanese"),
        pytest.param("d\u00e9passement de tampon", id="french"),
        pytest.param("\U0001f480 exploitable", id="emoji"),
        pytest.param("two\nlines\tand\ra return", id="ordinary-whitespace"),
        pytest.param(" leading and trailing ", id="surrounding-space"),
        pytest.param("a" * MAX_RATIONALE_LENGTH, id="at-the-length-limit"),
    ],
)
def test_an_accepted_rationale_is_kept_exactly_as_written(rationale: str) -> None:
    # A reviewer's own words are stored verbatim: nothing is trimmed, escaped
    # or normalized on the way in.
    assert validate_rationale(rationale) == rationale


@pytest.mark.parametrize(
    ("rationale", "message"),
    [
        pytest.param("", "empty or whitespace only", id="empty"),
        pytest.param("   \t\n ", "empty or whitespace only", id="whitespace-only"),
        pytest.param(None, "must be a string", id="none"),
        pytest.param(b"bytes", "must be a string", id="bytes"),
        pytest.param(
            "a" * (MAX_RATIONALE_LENGTH + 1),
            f"the limit is {MAX_RATIONALE_LENGTH}",
            id="over-length",
        ),
        pytest.param("bell \x07 here", "U+0007 at position 5", id="c0-control"),
        pytest.param("esc \x1b[31m", "U+001B at position 4", id="escape-sequence"),
        pytest.param("null \x00 byte", "U+0000 at position 5", id="nul"),
        pytest.param("next \x85 line", "U+0085 at position 5", id="c1-control"),
        pytest.param("lone \ud800 half", "U+D800 at position 5", id="surrogate"),
    ],
)
def test_a_refused_rationale_names_what_it_carries(rationale: Any, message: str) -> None:
    with pytest.raises(OperationError) as refusal:
        validate_rationale(rationale)

    assert message in str(refusal.value)


@pytest.mark.parametrize(
    ("offset", "limit"),
    [(0, 1), (0, MAX_PAGE_LIMIT), (7, 100), (10**9, 1)],
)
def test_an_accepted_page_window_comes_back_unchanged(offset: int, limit: int) -> None:
    assert validate_page(offset, limit) == (offset, limit)


@pytest.mark.parametrize(
    ("offset", "limit", "message"),
    [
        pytest.param(-1, 100, "offset must be an integer >= 0", id="negative-offset"),
        pytest.param(True, 100, "offset must be an integer >= 0", id="boolean-offset"),
        pytest.param(1.0, 100, "offset must be an integer >= 0", id="float-offset"),
        pytest.param("0", 100, "offset must be an integer >= 0", id="string-offset"),
        pytest.param(None, 100, "offset must be an integer >= 0", id="none-offset"),
        pytest.param(0, 0, f"in 1..{MAX_PAGE_LIMIT}", id="empty-page"),
        pytest.param(0, -5, f"in 1..{MAX_PAGE_LIMIT}", id="negative-limit"),
        pytest.param(0, MAX_PAGE_LIMIT + 1, f"in 1..{MAX_PAGE_LIMIT}", id="over-limit"),
        pytest.param(0, True, f"in 1..{MAX_PAGE_LIMIT}", id="boolean-limit"),
        pytest.param(0, 1.5, f"in 1..{MAX_PAGE_LIMIT}", id="float-limit"),
        pytest.param(0, None, f"in 1..{MAX_PAGE_LIMIT}", id="none-limit"),
    ],
)
def test_a_page_outside_its_bounds_is_refused(
    offset: Any, limit: Any, message: str
) -> None:
    with pytest.raises(OperationError) as refusal:
        validate_page(offset, limit)

    assert message in str(refusal.value)


def test_rows_order_by_address_space_then_location_then_id() -> None:
    rows: list[dict[str, Any]] = [
        {"address_space": "image", "address": "0x10", "id": "b"},
        {"address_space": "image", "address": "0x10", "id": "a"},
        # Lexically "0x9" sorts after "0x10"; a reader reads it before.
        {"address_space": "image", "address": "0x9", "id": "a"},
        {"address_space": "image", "address": "not hexadecimal", "id": "q"},
        {"address_space": "heap", "address": "0xff", "id": "z"},
    ]

    assert [row["id"] for row in sorted(rows, key=finding_order)] == [
        "z",
        "q",
        "a",
        "a",
        "b",
    ]
    # The order is total: two rows at one address differ only by ID.
    assert finding_order(rows[1]) < finding_order(rows[0])


def test_a_row_missing_its_facts_orders_instead_of_raising() -> None:
    # The record may hold a row a foreign build wrote; paging it must not blow
    # up before the caller ever sees it.
    assert finding_order({}) == ("", -1, "", "")
    assert finding_order({"address": None, "id": None}) == ("", -1, "", "")
