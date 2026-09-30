"""Live IDA coverage of the managed IDB's own findings record.

Every claim here is about bytes a real IDA 9.4 database kept. Each test scans a
compiled fixture through a managed IDB, lets the lease close, and reads the
record back through a fresh one, so "survives a reopen" means the netnode
survived being saved, unpacked and repacked — not that a dictionary stayed in
memory. Nothing is stubbed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ida_nexus import DatabaseOpenOptions, RemoteError

from vulfi_mcp.contracts import Finding
from vulfi_mcp.ida_adapter import (
    _lease,
    ensure_managed_idb,
    findings_ida,
    scan_ida,
    triage_ida,
)
from vulfi_mcp.rules import Rule, load_stock_rules, validate_rules

pytestmark = pytest.mark.requires_ida

STOCK: tuple[Rule, ...] = load_stock_rules()

#: The stock rule that matches this fixture's three `strcpy` call sites.
BUFFER_OVERFLOW: Rule = next(
    rule for rule in STOCK if rule["function_names"][0] == "strcpy"
)

#: Two rules that share one name and match the same two call sites. Their
#: definitions differ, so their canonical digests differ, so the rows they
#: produce at one address are two rows and not one.
DUPLICATE_NAME = "Buffer Overflow"
PRIMARY_RULES: tuple[Rule, ...] = validate_rules(
    [
        {
            "name": DUPLICATE_NAME,
            "function_names": ["strcpy"],
            "wrappers": False,
            "mark_if": {
                "High": "not param[1].is_constant()",
                "Medium": "False",
                "Low": "False",
            },
        },
        {
            "name": DUPLICATE_NAME,
            "function_names": ["strcpy"],
            "wrappers": False,
            "mark_if": {
                "High": "not param[1].is_constant() and param_count == 2",
                "Medium": "False",
                "Low": "False",
            },
        },
    ]
)

#: A second scope, so a write to one scope can be shown not to reach another.
OTHER_RULES: tuple[Rule, ...] = validate_rules(
    [
        {
            "name": "Environment Read",
            "function_names": ["getenv"],
            "wrappers": False,
            "mark_if": {"High": "True", "Medium": "False", "Low": "False"},
        }
    ]
)

PRIMARY_SCOPE = "custom:t5_primary"
OTHER_SCOPE = "custom:t5_other"

#: Assessments in two scripts and two alphabets, so a record that mangles
#: non-ASCII text on the way through JSON and UTF-8 cannot pass.
VULNERABLE_RATIONALE = "危険: source is attacker-controlled — c'est évident ✅"
FALSE_POSITIVE_RATIONALE = "無害: 固定長 copy, résultat sûr ✔"

#: Renaming the callee is how a call site stops being observable: the rule
#: matches a name, so a database where no function answers to `strcpy` has
#: nothing for it to find.
_RETIRE_STRCPY = """
import ida_name, idautils

wanted = {"strcpy", ".strcpy", "_strcpy"}
renamed = []
for ea, name in list(idautils.Names()):
    if name in wanted:
        ida_name.set_name(
            ea,
            "vulfi_retired_" + name.lstrip("._"),
            ida_name.SN_NOWARN | ida_name.SN_FORCE,
        )
        renamed.append(name)
renamed
"""

_READ_BLOB = """
import ida_netnode

node = ida_netnode.netnode("vulfi_mcp.v2", 0, False)
blob = None if node.index() == ida_netnode.BADNODE else node.getblob(1, "S")
None if blob is None else bytes(blob).hex()
"""

_WRITE_FUTURE_BLOB = """
import ida_netnode, json

payload = json.dumps(
    {"schema_version": 3, "scopes": {}, "written_by": "a later build"}
).encode("utf-8")
node = ida_netnode.netnode("vulfi_mcp.v2", 0, True)
node.setblob(payload, 1, "S")
payload.hex()
"""


def _in_database(managed: str, code: str) -> Any:
    """Run one statement inside the managed database, and save what it did.

    It borrows the adapter's own lease so the database is released and
    repacked before the next scan opens it, exactly as a real operation
    would leave it.
    """
    target = Path(managed)
    with _lease(target, DatabaseOpenOptions(worker_cwd=str(target.parent))) as handle:
        result = handle.execute_python(code)
        assert not result["stderr"], result["stderr"]
        assert handle.save_database()["saved"]
    return result["result"]


def _site(rows: list[Finding], rule_index: int, found_in: str) -> Finding:
    """The one row a given rule produced in a given caller."""
    matches = [
        row
        for row in rows
        if row["rule_index"] == rule_index and row["found_in"] == found_in
    ]
    assert len(matches) == 1, f"rule {rule_index} in {found_in}: {len(matches)} rows"
    return matches[0]


def _by_id(rows: list[Finding]) -> dict[str, Finding]:
    return {row["id"]: row for row in rows}


def _digest(page: dict[str, Any]) -> str:
    health = page["store_health"]["ida"]
    assert health["available"] is True
    assert health["schema_version"] == 2
    return health["record_digest"]


def _scope(result: dict[str, Any], scope: str) -> dict[str, Any]:
    """The store's own summary of one scope, out of any result that carries it."""
    summaries = [
        entry
        for entry in result["store_health"]["ida"]["scopes"]
        if entry["scope"] == scope
    ]
    assert len(summaries) == 1, f"{scope}: {len(summaries)} summaries"
    return summaries[0]


def test_independent_assessments_survive_reopen(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    managed = ensure_managed_idb(str(compiled_calls))
    primary = scan_ida(
        managed, PRIMARY_RULES, PRIMARY_SCOPE, path=str(compiled_calls)
    )
    other = scan_ida(managed, OTHER_RULES, OTHER_SCOPE, path=str(compiled_calls))

    assert primary["coverage"] == "complete"
    # Two rules over the two variable-source `strcpy` sites; the constant one
    # matches neither, in either rule.
    assert primary["scope_total"] == 4
    assert other["scope_total"] == 1
    assert primary["store_health"]["ida"]["managed_idb_id"]
    assert (
        other["store_health"]["ida"]["managed_idb_id"]
        == primary["store_health"]["ida"]["managed_idb_id"]
    ), "the managed IDB identity is created once and never reissued"

    rows = primary["findings"]
    first = _site(rows, 0, "copy_from_argument")
    second = _site(rows, 1, "copy_from_argument")

    # One address, one name, two rules: two rows that never collide.
    assert first["address"] == second["address"]
    assert first["rule_name"] == second["rule_name"] == DUPLICATE_NAME
    assert first["rule_digest"] != second["rule_digest"]
    assert first["id"] != second["id"]
    assert first["id"] == (
        f"ida:{PRIMARY_SCOPE}:0:{first['rule_digest']}"
        f":image:{first['address']}:{first['occurrence']}"
    )
    assert first["status"] == "Not Checked"
    assert first["triage_revision"] == 0
    assert first["stale"] is False
    assert first["link_id"] is None and first["link_revision"] is None

    vulnerable = first
    innocuous = _site(rows, 1, "copy_from_environment")
    assessed = triage_ida(
        managed, vulnerable["id"], "Vulnerable", VULNERABLE_RATIONALE
    )
    cleared = triage_ida(
        managed, innocuous["id"], "False Positive", FALSE_POSITIVE_RATIONALE
    )

    assert assessed["triage_revision"] == 1
    assert assessed["finding"]["status"] == "Vulnerable"
    assert assessed["finding"]["assessed_at"].endswith("Z")
    assert cleared["triage_revision"] == 1
    assert cleared["finding"]["status"] == "False Positive"

    # Reopened: the record, not a cached result, is what answers.
    page = findings_ida(managed, 0, 200, path=str(compiled_calls))
    stored = _by_id(page["findings"])
    assert page["target_total"] == 5
    assert page["page_total"] == 5
    assert page["stale_total"] == 0
    assert page["target_total_complete"] is False
    assert page["store_health"]["catalog"]["available"] is False
    assert page["status_counts"]["ida"] == {
        "Not Checked": 3,
        "False Positive": 1,
        "Suspicious": 0,
        "Vulnerable": 1,
    }

    assert stored[vulnerable["id"]]["status"] == "Vulnerable"
    assert stored[vulnerable["id"]]["rationale"] == VULNERABLE_RATIONALE
    assert stored[innocuous["id"]]["status"] == "False Positive"
    assert stored[innocuous["id"]]["rationale"] == FALSE_POSITIVE_RATIONALE
    # The sibling row at the very same address kept its own assessment.
    assert stored[second["id"]]["status"] == "Not Checked"
    assert stored[second["id"]]["rationale"] == ""
    assert [
        row["status"] for row in page["findings"] if row["source"] == OTHER_SCOPE
    ] == ["Not Checked"]

    # A complete rescan of this scope carries both assessments forward by
    # exact ID and leaves the other scope alone.
    rescan = scan_ida(managed, PRIMARY_RULES, PRIMARY_SCOPE, path=str(compiled_calls))
    carried = _by_id(rescan["findings"])
    assert rescan["scope_total"] == 4
    assert rescan["target_total"] == 5
    assert carried[vulnerable["id"]]["status"] == "Vulnerable"
    assert carried[vulnerable["id"]]["rationale"] == VULNERABLE_RATIONALE
    assert carried[vulnerable["id"]]["triage_revision"] == 1
    assert carried[vulnerable["id"]]["stale"] is False
    assert carried[innocuous["id"]]["triage_revision"] == 1

    # Editing one rule changes its digest, so its rows are new rows. The old
    # assessment is orphaned on purpose and is never moved onto them; the rule
    # that did not change keeps its own row, and its assessment with it.
    edited = validate_rules(
        [
            {
                **PRIMARY_RULES[0],
                "mark_if": {
                    **PRIMARY_RULES[0]["mark_if"],
                    "High": "param_count == 2 and not param[1].is_constant()",
                },
            },
            PRIMARY_RULES[1],
        ]
    )
    orphaned = scan_ida(managed, edited, PRIMARY_SCOPE, path=str(compiled_calls))
    after = _by_id(orphaned["findings"])

    assert orphaned["scope_total"] == 4
    assert vulnerable["id"] not in after
    assert {row["status"] for row in after.values() if row["rule_index"] == 0} == {
        "Not Checked"
    }
    assert after[innocuous["id"]]["status"] == "False Positive"
    assert after[innocuous["id"]]["triage_revision"] == 1

    # Three rescans of one scope later, the other scope still carries the scan
    # that wrote it: a rescan replaces its own scope and reaches no further.
    assert _scope(orphaned, OTHER_SCOPE) == _scope(page, OTHER_SCOPE)
    assert _scope(orphaned, OTHER_SCOPE)["scan_id"] == other["scan_id"]


def test_partial_rescan_keeps_stale_until_complete(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    managed = ensure_managed_idb(str(compiled_calls))
    rules = (BUFFER_OVERFLOW,)
    complete = scan_ida(managed, rules, "default", path=str(compiled_calls))

    assert complete["coverage"] == "complete"
    assert complete["scope_total"] == 2
    target = _site(complete["findings"], 0, "copy_from_argument")
    assessed = triage_ida(
        managed, target["id"], "Suspicious", "unbounded copy of caller input"
    )
    assert assessed["triage_revision"] == 1

    # A disassembly-only rescan recovers both arguments but cannot establish
    # `is_constant`, so it decides nothing about either site. It must not read
    # as "these findings are gone".
    partial = scan_ida(
        managed, rules, "default", path=str(compiled_calls), decompiler="disabled"
    )

    assert partial["coverage"] == "partial"
    assert partial["scope_health"]["ida"]["observed_findings"] == 0
    assert partial["scope_health"]["ida"]["stale_findings"] == 2
    assert partial["scope_total"] == 2
    kept = _by_id(partial["findings"])
    assert kept[target["id"]]["stale"] is True
    assert kept[target["id"]]["status"] == "Suspicious"
    assert kept[target["id"]]["triage_revision"] == 1
    assert kept[target["id"]]["last_seen_scan_id"] == complete["scan_id"]
    assert partial["store_health"]["ida"]["stale_total"] == 2

    # Now remove the evidence from this managed copy, and let a scan that did
    # decide about every one of its rules run again.
    assert _in_database(managed, _RETIRE_STRCPY) == [".strcpy", "strcpy"]

    retired = scan_ida(managed, rules, "default", path=str(compiled_calls))

    assert retired["coverage"] == "complete"
    assert retired["scope_health"]["ida"]["call_sites"] == 0
    assert retired["scope_total"] == 0
    assert retired["findings"] == []

    page = findings_ida(managed, 0, 100, path=str(compiled_calls))
    assert page["target_total"] == 0
    assert page["findings"] == []
    assert page["stale_total"] == 0
    assert page["status_counts"]["aggregate"]["Suspicious"] == 0


def test_unknown_id_bad_status_empty_rationale_and_bad_page_do_not_write(
    compiled_calls: Path, managed_data_dir: Path, tmp_path: Path
) -> None:
    managed = ensure_managed_idb(str(compiled_calls))
    scanned = scan_ida(
        managed, (BUFFER_OVERFLOW,), "default", path=str(compiled_calls)
    )
    target = _site(scanned["findings"], 0, "copy_from_argument")
    before = findings_ida(managed, 0, 100, path=str(compiled_calls))
    digest = _digest(before)
    assert digest

    # Only the record can know whether an ID exists, so this one is refused
    # there — and refused rather than matched to the nearest similar row.
    unknown_id = target["id"] + "9"
    with pytest.raises(RemoteError) as unknown:
        triage_ida(managed, unknown_id, "Vulnerable", "no such row")
    assert unknown_id in str(unknown.value)

    # Everything else is refused before a database is opened at all: each of
    # these names a database that does not exist, and none of them reports
    # that, because none of them ever looks.
    absent = str(tmp_path / "never-created.i64")
    with pytest.raises(ValueError) as status:
        triage_ida(absent, target["id"], "Probably Bad", "a usable rationale")
    assert "Not Checked" in str(status.value)

    for blank in ("", "   ", "\t\n "):
        with pytest.raises(ValueError) as empty:
            triage_ida(absent, target["id"], "Vulnerable", blank)
        assert "empty" in str(empty.value)

    with pytest.raises(ValueError) as control:
        triage_ida(absent, target["id"], "Vulnerable", "bell\x07inside")
    assert "U+0007" in str(control.value)

    with pytest.raises(ValueError) as long:
        triage_ida(absent, target["id"], "Vulnerable", "x" * 4001)
    assert "4001" in str(long.value)

    for offset, limit in ((-1, 10), (0, 0), (0, 201), (0, -5)):
        with pytest.raises(ValueError):
            findings_ida(absent, offset, limit)

    # Not one of those wrote a byte: the record is the same record.
    after = findings_ida(managed, 0, 100, path=str(compiled_calls))
    assert _digest(after) == digest
    assert after["findings"] == before["findings"]
    assert [row["triage_revision"] for row in after["findings"]] == [0, 0]
    assert after["status_counts"]["ida"]["Not Checked"] == 2

    # A page past the end is a valid, empty page — not an error, and not the
    # first page over again.
    tail = findings_ida(managed, 50, 100, path=str(compiled_calls))
    assert tail["findings"] == []
    assert tail["page_total"] == 0
    assert tail["target_total"] == 2
    assert _digest(tail) == digest


def test_unknown_schema_version_is_refused_without_overwriting(
    compiled_calls: Path, managed_data_dir: Path
) -> None:
    managed = ensure_managed_idb(str(compiled_calls))
    scan_ida(managed, (BUFFER_OVERFLOW,), "default", path=str(compiled_calls))

    future = _in_database(managed, _WRITE_FUTURE_BLOB)

    with pytest.raises(RemoteError) as refused:
        findings_ida(managed, 0, 100)
    assert "schema version 3" in str(refused.value)

    with pytest.raises(RemoteError):
        scan_ida(managed, (BUFFER_OVERFLOW,), "default", path=str(compiled_calls))
    with pytest.raises(RemoteError):
        triage_ida(managed, "ida:default:0:x:image:0x1:0", "Vulnerable", "anything")

    # Refused, every time, and still exactly the bytes the later build wrote.
    assert _in_database(managed, _READ_BLOB) == future
