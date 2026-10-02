"""Public linked triage, health, pause, and reviewed conflict resolution.

A linked edit from either finding id must travel the existing journal. A
page must say which stores answered, and a missing catalog is unavailable
rather than zero. A partial scan that did not reconfirm a member pauses the
link; a failed scope that found nothing does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conftest import CC_FLAGS, FIXTURES, ghidra_bridge, ghidra_url, missing_prerequisite
from vulfi_mcp.catalog import catalog_path, get_catalog, open_catalog
from vulfi_mcp.ida_adapter import (
    ManagedDatabaseError,
    ensure_managed_idb,
    findings_ida,
    invoke_ida,
    scan_ida,
    triage_ida,
)
from vulfi_mcp.ida_runtime import OperationError, utc_now
from vulfi_mcp.operator import link_briefing, review_link
from vulfi_mcp.prepare import scan_target
from vulfi_mcp.rules import Rule, canonical_rule_digest
from vulfi_mcp.server import _replay_startup, vulfi_findings, vulfi_triage

pytestmark = pytest.mark.requires_ida

PROVIDER_LOCK = Path(tempfile.gettempdir()) / "vulfi-ghidra-{}-{}.lock".format(
    urlsplit(ghidra_url()).hostname or "127.0.0.1",
    urlsplit(ghidra_url()).port or 80,
)
LOCK_TIMEOUT = 300.0
COPY_RULE: Rule = {
    "name": "Unchecked Copy",
    "function_names": ["strcpy", "wcscpy"],
    "wrappers": False,
    "mark_if": {
        "High": "not param[1].is_constant()",
        "Medium": "False",
        "Low": "False",
    },
}
MISS_RULE: Rule = {
    "name": "Absent Callee",
    "function_names": ["vulfi_no_such_function"],
    "wrappers": False,
    "mark_if": {"High": "False", "Medium": "False", "Low": "False"},
}
SCOPE = "default"
INITIAL_STATUS = "False Positive"
INITIAL_RATIONALE = "reviewed pair, not yet reassessed"
IDA_STATUS = "Suspicious"
IDA_RATIONALE = "the source argument is still not a constant"
EXTERNAL_STATUS = "Vulnerable"
EXTERNAL_RATIONALE = "reassessed from the external finding id"
OUT_OF_BAND_STATUS = "Not Checked"
OUT_OF_BAND_RATIONALE = "changed in the IDB without the catalog"
RESOLVED_STATUS = "Suspicious"
RESOLVED_RATIONALE = "reviewer chose this assessment after the conflict"
STATUSES = ("Not Checked", "False Positive", "Suspicious", "Vulnerable")


@pytest.fixture(autouse=True)
def provider_lock(request: pytest.FixtureRequest) -> Iterator[None]:
    """Hold the one GhidraMCP server while a test actually uses it."""
    if request.node.get_closest_marker("requires_ghidra") is None:
        yield
        return
    PROVIDER_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(PROVIDER_LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        while True:
            try:
                import fcntl

                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    pytest.fail(
                        "another process has held the GhidraMCP server at"
                        f" {ghidra_url()} for more than {LOCK_TIMEOUT:.0f}s"
                        f" ({PROVIDER_LOCK})"
                    )
                time.sleep(0.5)
        yield
    finally:
        import fcntl

        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)


@pytest.fixture
def ghidra_config(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    config = tmp_path / "providers.toml"
    config.write_text(
        "\n".join(
            (
                "[ghidra]",
                'transport = "stdio"',
                f'command = "{ghidra_bridge()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "bridge.err"}"',
                "",
                "[ghidra.env]",
                'PATH = "/usr/bin:/bin"',
                f'HOME = "{tmp_path / "bridge-home"}"',
                f'GHIDRA_MCP_URL = "{ghidra_url()}"',
                'GHIDRA_MCP_LOG_LEVEL = "WARNING"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
                "[[ghidra.binaries]]",
                f'local = "{managed_data_dir}"',
                f'remote = "{managed_data_dir}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "bridge-home").mkdir(exist_ok=True)
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


def _compile(tmp_path: Path, name: str) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / name
    completed = subprocess.run(
        [compiler, *CC_FLAGS, "-o", str(binary), str(FIXTURES / "vulfi_calls.c")],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return binary


def _reopen(read):
    """One retry after IDA 9.4 rolls a bad pack back to the previous generation."""
    try:
        return read()
    except Exception as failed:
        if "the save before this one left a database it cannot read" not in str(failed):
            raise
        return read()


def _ida_rows(binary: Path) -> tuple[str, list[dict]]:
    managed = ensure_managed_idb(str(binary))
    result = scan_ida(managed, (COPY_RULE,), SCOPE, path=str(binary))
    digest = canonical_rule_digest(COPY_RULE)
    rows = [row for row in result["findings"] if row["rule_digest"] == digest]
    assert len(rows) >= 2, "the fixture must yield a linked row and an unlinked one"
    return managed, rows


def _ghidra_row(binary: Path) -> dict:
    result = scan_target(str(binary), (COPY_RULE,), SCOPE, backend="ghidra")
    digest = canonical_rule_digest(COPY_RULE)
    rows = [
        row
        for row in result["findings"]
        if row["backend"] == "ghidra" and row["rule_digest"] == digest
    ]
    assert rows, f"Ghidra produced no strcpy finding: {result['rule_coverage']}"
    return rows[0]


def _link_once(binary: Path) -> dict[str, object]:
    managed, rows = _ida_rows(binary)
    ida_row = rows[0]
    external = _ghidra_row(binary)
    created = review_link(
        str(binary),
        ida_row["id"],
        external["id"],
        str(binary),
        "new",
        INITIAL_STATUS,
        INITIAL_RATIONALE,
    )
    assert created["sync_state"] == "synchronized", created
    assert created["confirmed"] is True
    return {
        "managed": managed,
        "ida": ida_row,
        "unlinked": rows[1],
        "external": external,
        "link_id": str(created["link_id"]),
        "link_revision": int(created["link_revision"]),
    }


def _linked_pair(binary: Path) -> dict[str, object]:
    last: BaseException | None = None
    for _attempt in range(2):
        try:
            return _link_once(binary)
        except (ManagedDatabaseError, KeyError, AssertionError) as failed:
            last = failed
    assert last is not None
    raise last


def _command() -> str:
    candidate = Path(sys.executable).parent / "vulfi-mcp"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which("vulfi-mcp")
    if found:
        return found
    raise AssertionError("vulfi-mcp is not installed in this environment")


def _page(path: str, binary_path: str | None = None, offset: int = 0, limit: int = 100):
    return _reopen(
        lambda: vulfi_findings(path, binary_path=binary_path, offset=offset, limit=limit)
    )


def _by_id(page: dict, finding_id: str) -> dict:
    return next(row for row in page["findings"] if row["id"] == finding_id)


def _link_view(page: dict, link_id: str) -> dict:
    links = page.get("links")
    assert isinstance(links, list), page
    return next(item for item in links if item.get("link_id") == link_id)


def _stored_link(binary: Path, link_id: str) -> dict:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        stored = catalog.link(link_id)
    finally:
        catalog.close()
    assert stored is not None
    return stored


def _location(row: dict) -> tuple[str, int, str]:
    address = str(row.get("address") or "")
    try:
        location = int(address, 16 if address.lower().startswith("0x") else 10)
    except ValueError:
        location = -1
    return str(row.get("address_space") or ""), location, str(row.get("id") or "")


def _counts_include_both(page: dict, status: str) -> None:
    counts = page["status_counts"]
    assert "ida" in counts and "ghidra" in counts, counts
    assert counts["aggregate"][status] == counts["ida"][status] + counts["ghidra"][status]
    assert counts["ida"][status] >= 1
    assert counts["ghidra"][status] >= 1
    for name in ("ida", "ghidra", "aggregate"):
        assert set(counts[name]) == set(STATUSES)


def _neighbor(row: dict) -> dict:
    """A similar call site: same address, different digest and ordinal.

    Identity is the digest and the ordinal, not the function name. The name
    is left empty on purpose so a match on it cannot look like a relink.
    """
    occurrence = int(row["occurrence"]) + 1
    digest = "b" * 64
    neighbor = dict(row)
    neighbor["occurrence"] = occurrence
    neighbor["rule_digest"] = digest
    neighbor["rule_name"] = "Similar Copy"
    neighbor["function_name"] = ""
    neighbor["id"] = (
        f"ghidra:{SCOPE}:0:{digest}:{row['address_space']}:{row['address']}:{occurrence}"
    )
    neighbor["status"] = "Not Checked"
    neighbor["rationale"] = ""
    neighbor["assessed_at"] = None
    neighbor["link_id"] = None
    neighbor["link_revision"] = None
    neighbor["stale"] = False
    return neighbor


@pytest.mark.requires_ghidra
def test_triage_both_directions_survives_reopen(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """Either finding id writes the same journaled decision, and both rows remain.

    The production change that must fail this test is triaging only the store
    named by the id, or collapsing the pair into one vulnerability.
    """
    binary = _compile(tmp_path, "linked-triage")
    pair = _linked_pair(binary)
    ida_id = pair["ida"]["id"]
    external_id = pair["external"]["id"]
    before = _stored_link(binary, pair["link_id"])

    via_ida = vulfi_triage(str(binary), ida_id, IDA_STATUS, IDA_RATIONALE)
    assert via_ida["sync_state"] == "synchronized", via_ida
    both = via_ida.get("findings") or []
    assert {row["id"] for row in both} == {ida_id, external_id}

    ida_page = _reopen(lambda: findings_ida(pair["managed"], 0, 200, path=str(binary)))
    ida_row = next(row for row in ida_page["findings"] if row["id"] == ida_id)
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        external_row = catalog.external_finding(external_id)
    finally:
        catalog.close()
    assert external_row is not None
    assert ida_row["status"] == external_row["status"] == IDA_STATUS
    assert ida_row["rationale"] == external_row["rationale"] == IDA_RATIONALE
    assert ida_row["assessed_at"] == external_row["assessed_at"]
    assert ida_row["assessed_at"]
    assert ida_row["link_revision"] == external_row["link_revision"]
    assert int(ida_row["link_revision"]) == before["link_revision"] + 1
    assert ida_row["triage_revision"] == external_row["triage_revision"]

    vulfi_triage(str(binary), external_id, EXTERNAL_STATUS, EXTERNAL_RATIONALE)
    reopened = _page(str(binary))
    ida_again = _by_id(reopened, ida_id)
    external_again = _by_id(reopened, external_id)
    assert ida_again["status"] == external_again["status"] == EXTERNAL_STATUS
    assert ida_again["rationale"] == external_again["rationale"] == EXTERNAL_RATIONALE
    assert ida_again["assessed_at"] == external_again["assessed_at"]
    assert ida_again["link_revision"] == external_again["link_revision"]
    assert int(ida_again["link_revision"]) == before["link_revision"] + 2
    assert ida_again["triage_revision"] == external_again["triage_revision"]
    assert ida_again["id"] != external_again["id"]
    _counts_include_both(reopened, EXTERNAL_STATUS)
    assert reopened["loaded"] == reopened["page_total"]
    assert reopened["target_total"] >= 2
    assert reopened["findings"] == sorted(reopened["findings"], key=_location)
    view = _link_view(reopened, pair["link_id"])
    assert view["sync_state"] == "synchronized"
    assert "ghidra" in reopened["scope_health"]
    assert "ida" in reopened["scope_health"]


@pytest.mark.requires_ghidra
def test_changed_or_stale_member_pauses_without_relink(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A partial scan that missed a member pauses; a failed empty scope does not.

    The production change that must fail this test is pausing on every stale
    bit, or copying the linked assessment onto a similar neighbor.
    """
    binary = _compile(tmp_path, "linked-pause")
    pair = _linked_pair(binary)
    external = pair["external"]
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="failed-empty-scope",
            scanned_at=utc_now(),
            state="failed",
            coverage=None,
            reason="unsupported rule rewritten as failed; no findings",
            findings=[],
        )
    held = _stored_link(binary, pair["link_id"])
    assert held["sync_state"] != "paused"
    assert held["status"] == INITIAL_STATUS
    quiet = _page(str(binary))
    assert _link_view(quiet, pair["link_id"])["sync_state"] != "paused"
    assert _by_id(quiet, external["id"])["stale"] is True
    assert _by_id(quiet, external["id"])["status"] == INITIAL_STATUS

    neighbor = _neighbor(external)
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="partial-saw-a-neighbor",
            scanned_at=utc_now(),
            state="evaluated",
            coverage="partial",
            reason="this scan saw another row and not the linked member",
            findings=[neighbor],
        )
    paused = _page(str(binary))
    view = _link_view(paused, pair["link_id"])
    assert view["sync_state"] == "paused", paused
    assert _stored_link(binary, pair["link_id"])["sync_state"] == "paused"
    similar = _by_id(paused, neighbor["id"])
    assert similar["link_id"] is None
    assert similar["status"] != INITIAL_STATUS
    assert similar["rationale"] != INITIAL_RATIONALE
    member = _by_id(paused, external["id"])
    assert member["stale"] is True
    assert member["status"] == INITIAL_STATUS
    with pytest.raises(Exception):
        vulfi_triage(str(binary), external["id"], "Vulnerable", "must not propagate")
    untouched = _page(str(binary))
    assert _by_id(untouched, neighbor["id"])["status"] != "Vulnerable"
    assert _by_id(untouched, pair["ida"]["id"])["status"] == INITIAL_STATUS


@pytest.mark.requires_ghidra
def test_triage_without_a_findings_read_pauses_a_missed_member(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A partial scan that missed the member pauses before triage writes.

    The production change that must fail this test is journaling the new
    decision in ``vulfi_triage`` before pause is enforced. Paging findings
    first is what the older test does, and that hides the write.
    """
    binary = _compile(tmp_path, "linked-triage-before-page")
    pair = _linked_pair(binary)
    external_id = pair["external"]["id"]
    ida_id = pair["ida"]["id"]
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="partial-missed-member-no-page",
            scanned_at=utc_now(),
            state="evaluated",
            coverage="partial",
            reason="this scan saw another row and not the linked member",
            findings=[_neighbor(pair["external"])],
        )
    with pytest.raises(Exception):
        vulfi_triage(str(binary), external_id, "Vulnerable", "must not propagate")
    held = _stored_link(binary, pair["link_id"])
    assert held["sync_state"] == "paused", held
    assert held["status"] == INITIAL_STATUS
    assert held["rationale"] == INITIAL_RATIONALE
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        external_row = catalog.external_finding(external_id)
    finally:
        catalog.close()
    assert external_row is not None
    assert external_row["status"] == INITIAL_STATUS
    assert external_row["rationale"] == INITIAL_RATIONALE
    ida_page = _reopen(lambda: findings_ida(pair["managed"], 0, 200, path=str(binary)))
    ida_row = next(row for row in ida_page["findings"] if row["id"] == ida_id)
    assert ida_row["status"] == INITIAL_STATUS
    assert ida_row["rationale"] == INITIAL_RATIONALE


@pytest.mark.requires_ghidra
def test_empty_ida_index_after_complete_rescan_pauses(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A complete rescan that retires the only IDA member pauses the link.

    The production change that must fail this test is treating an empty IDA
    index as unknown. The link stays synchronized, and triage then moves the
    external row before the mirror fails into pending.
    """
    binary = _compile(tmp_path, "linked-empty-ida")
    pair = _linked_pair(binary)
    external_id = pair["external"]["id"]
    ida_id = pair["ida"]["id"]
    retired = _reopen(
        lambda: scan_ida(pair["managed"], (MISS_RULE,), SCOPE, path=str(binary))
    )
    assert retired["coverage"] == "complete", retired
    assert all(row["id"] != ida_id for row in retired["findings"]), retired
    ida_after = _reopen(lambda: findings_ida(pair["managed"], 0, 200, path=str(binary)))
    assert ida_after["findings"] == [], ida_after
    held = _stored_link(binary, pair["link_id"])
    assert held["sync_state"] == "paused", held
    with pytest.raises(Exception):
        vulfi_triage(str(binary), external_id, "Vulnerable", "must not propagate")
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        external_row = catalog.external_finding(external_id)
        stored = catalog.link(pair["link_id"])
    finally:
        catalog.close()
    assert external_row is not None
    assert external_row["status"] == INITIAL_STATUS
    assert external_row["rationale"] == INITIAL_RATIONALE
    assert stored is not None
    assert stored["sync_state"] == "paused"
    assert stored["status"] == INITIAL_STATUS


@pytest.mark.requires_ghidra
def test_complete_external_rescan_pauses_instead_of_dropping_the_link(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A digest change stores the new site and pauses; it does not crash after IDA saved.

    The production change that must fail this test is letting ON DELETE
    RESTRICT abort ``record_external_scan`` after the IDA scope has saved.
    Dropping the link to make the delete succeed, or copying the old
    assessment onto the new id, is the same hole.
    """
    binary = _compile(tmp_path, "linked-external-digest")
    pair = _linked_pair(binary)
    old_external_id = pair["external"]["id"]
    ida_before = _reopen(lambda: findings_ida(pair["managed"], 0, 200, path=str(binary)))
    ida_ids = {row["id"] for row in ida_before["findings"]}
    ida_status = {
        row["id"]: (row["status"], row["rationale"]) for row in ida_before["findings"]
    }
    assert pair["ida"]["id"] in ida_ids
    changed: Rule = {
        "name": "Unchecked Copy Retargeted",
        "function_names": ["strcpy", "wcscpy"],
        "wrappers": False,
        "mark_if": {
            "High": "not param[1].is_constant()",
            "Medium": "False",
            "Low": "False",
        },
    }
    result = scan_target(str(binary), (changed,), SCOPE, backend="ghidra")
    assert result["findings"], result
    held = _stored_link(binary, pair["link_id"])
    assert held["sync_state"] == "paused", held
    assert held["external_finding_id"] == old_external_id
    new_digest = canonical_rule_digest(changed)
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        old = catalog.external_finding(old_external_id)
        page = catalog.page_external_findings(0, 200)
    finally:
        catalog.close()
    assert old is not None
    assert old["status"] == INITIAL_STATUS
    assert old["rationale"] == INITIAL_RATIONALE
    new_rows = [
        row
        for row in page["findings"]
        if row["backend"] == "ghidra" and row["rule_digest"] == new_digest
    ]
    assert new_rows, page
    assert all(row["id"] != old_external_id for row in new_rows)
    assert all(row["status"] == "Not Checked" for row in new_rows)
    assert all(row["rationale"] in ("", None) for row in new_rows)
    ida_after = _reopen(lambda: findings_ida(pair["managed"], 0, 200, path=str(binary)))
    assert {row["id"] for row in ida_after["findings"]} == ida_ids
    assert {
        row["id"]: (row["status"], row["rationale"]) for row in ida_after["findings"]
    } == ida_status





@pytest.mark.requires_ghidra
def test_offline_and_conflict_visible_to_paging(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """Paging names pending, conflict, and a missing catalog; resolve journals a new event.

    The production change that must fail this test is hiding those states, or
    overwriting the IDB without a new guarded event.
    """
    binary = _compile(tmp_path, "linked-conflict")
    pair = _linked_pair(binary)
    managed = pair["managed"]
    ida_id = pair["ida"]["id"]
    external_id = pair["external"]["id"]

    for kwargs in ({"offset": -1}, {"limit": 0}, {"limit": 201}):
        with pytest.raises(Exception) as refused:
            vulfi_findings(str(binary), **kwargs)
        assert "offset" in str(refused.value) or "limit" in str(refused.value)
    window = _page(str(binary), offset=0, limit=1)
    assert window["offset"] == 0
    assert window["limit"] == 1
    assert window["loaded"] == 1
    assert window["page_total"] == 1

    idb_only = _page(managed)
    assert all(row["backend"] == "ida" for row in idb_only["findings"])
    assert idb_only["store_health"]["catalog"]["available"] is False
    assert idb_only["target_total_complete"] is False
    assert idb_only["sync_state"] == "unavailable"
    assert "ghidra" not in idb_only["status_counts"]
    assert idb_only["target_total"] == sum(idb_only["status_counts"]["ida"].values())
    joined = _page(managed, binary_path=str(binary))
    assert {ida_id, external_id} <= {row["id"] for row in joined["findings"]}
    assert joined["store_health"]["catalog"]["available"] is True
    assert joined["sync_state"] == "synchronized"
    assert joined["target_total"] > idb_only["target_total"]

    catalog = open_catalog(str(binary))
    try:
        started = catalog.begin_linked_update(
            pair["link_id"], pair["link_revision"], IDA_STATUS, IDA_RATIONALE
        )
        payload = dict(started["payload"])
        payload["idb_path"] = str(tmp_path / "missing.i64")
        catalog._connection.execute(
            "UPDATE sync_events SET payload = ? WHERE event_id = ?",
            (json.dumps(payload), started["event_id"]),
        )
        catalog._connection.commit()
    finally:
        catalog.close()
    pending = _page(str(binary))
    assert _link_view(pending, pair["link_id"])["sync_state"] == "pending"
    assert pending["sync_state"] == "pending"
    ida_during = _reopen(lambda: findings_ida(managed, 0, 200, path=str(binary)))
    during = next(row for row in ida_during["findings"] if row["id"] == ida_id)
    assert during["status"] == INITIAL_STATUS

    catalog = open_catalog(str(binary))
    try:
        catalog._connection.execute(
            "UPDATE sync_events SET payload = ? WHERE event_id = ?",
            (json.dumps(started["payload"]), started["event_id"]),
        )
        catalog._connection.commit()
    finally:
        catalog.close()
    from vulfi_mcp.server import replay_linked_updates

    replayed = replay_linked_updates(str(binary))
    assert replayed and replayed[0]["sync_state"] == "synchronized"

    triage_ida(managed, ida_id, OUT_OF_BAND_STATUS, OUT_OF_BAND_RATIONALE)
    conflicted = _page(str(binary))
    assert _link_view(conflicted, pair["link_id"])["sync_state"] == "conflict"
    assert conflicted["sync_state"] == "conflict"
    kept = _reopen(lambda: findings_ida(managed, 0, 200, path=str(binary)))
    kept_row = next(row for row in kept["findings"] if row["id"] == ida_id)
    assert kept_row["status"] == OUT_OF_BAND_STATUS
    assert kept_row["rationale"] == OUT_OF_BAND_RATIONALE
    events_before = _event_ids(binary, pair["link_id"])

    declined = subprocess.run(
        [
            _command(),
            "resolve",
            "--path",
            str(binary),
            "--link-id",
            pair["link_id"],
            "--source",
            "external",
            "--status",
            RESOLVED_STATUS,
            "--rationale",
            RESOLVED_RATIONALE,
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        input="no\n",
    )
    assert declined.returncode != 0
    assert _stored_link(binary, pair["link_id"])["sync_state"] == "conflict"

    reviewed = subprocess.run(
        [
            _command(),
            "resolve",
            "--path",
            str(binary),
            "--link-id",
            pair["link_id"],
            "--source",
            "external",
            "--status",
            RESOLVED_STATUS,
            "--rationale",
            RESOLVED_RATIONALE,
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        input="external\n",
    )
    assert reviewed.returncode == 0, reviewed.stderr + reviewed.stdout
    dialogue = reviewed.stderr
    prompt_at = dialogue.find("Type 'external'")
    assert prompt_at != -1, dialogue
    before_prompt = dialogue[:prompt_at].lower()
    assert "image base" in before_prompt, dialogue
    assert "bytes" in before_prompt and "xref" in before_prompt, dialogue
    result = json.loads(reviewed.stdout)
    assert result["confirmed"] is True
    assert result["sync_state"] == "synchronized"
    assert result["event_id"] not in events_before
    settled = _page(str(binary))
    ida_settled = _by_id(settled, ida_id)
    external_settled = _by_id(settled, external_id)
    assert ida_settled["status"] == external_settled["status"] == RESOLVED_STATUS
    assert ida_settled["rationale"] == external_settled["rationale"] == RESOLVED_RATIONALE
    assert _link_view(settled, pair["link_id"])["sync_state"] == "synchronized"
    assert int(ida_settled["link_revision"]) > pair["link_revision"]

    stored = catalog_path()
    aside = stored.with_suffix(".sqlite3.aside")
    stored.rename(aside)
    try:
        offline = _page(str(binary))
    finally:
        aside.rename(stored)
    assert offline["store_health"]["catalog"]["available"] is False
    assert offline["target_total_complete"] is False
    assert offline["sync_state"] == "unavailable"
    assert "ghidra" not in offline["status_counts"]
    assert offline["target_total"] == sum(offline["status_counts"]["ida"].values())
    assert offline["target_total"] > 0
    assert all(row["backend"] == "ida" for row in offline["findings"])


def _event_ids(binary: Path, link_id: str) -> set[str]:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        rows = catalog._connection.execute(
            "SELECT event_id FROM sync_events WHERE link_id = ?",
            (link_id,),
        ).fetchall()
    finally:
        catalog.close()
    return {str(row[0]) for row in rows}


def _event_state(binary: Path, event_id: str) -> str:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        row = catalog._connection.execute(
            "SELECT state FROM sync_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    finally:
        catalog.close()
    assert row is not None, event_id
    return str(row[0])


def _external_pad(binary: Path, count: int) -> None:
    """Rows that sort ahead of a real Ghidra finding, in another scope."""
    digest = "c" * 64
    findings = []
    for ordinal in range(1, count + 1):
        findings.append(
            {
                "id": f"ghidra:custom:pad:0:{digest}:ghidra:image:0x{ordinal:x}:0",
                "backend": "ghidra",
                "source": "custom:pad",
                "rule_index": 0,
                "rule_digest": digest,
                "rule_name": "Pad",
                "function_name": "",
                "found_in": "pad",
                "address_space": "ghidra:image",
                "address": ordinal,
                "occurrence": 0,
                "priority": "High",
                "evidence": {},
            }
        )
    catalog = open_catalog(str(binary))
    try:
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:pad",
            scan_id="scan-pad",
            scanned_at=utc_now(),
            state="evaluated",
            coverage="complete",
            findings=findings,
        )
    finally:
        catalog.close()


def _store_page_two(binary: Path, managed: str) -> str:
    """201 IDA rows so the last one is on the second page of 200."""
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    scope = "custom:pad"
    findings = []
    target = ""
    for ordinal in range(1, 202):
        address = "0x7fffffff" if ordinal == 201 else f"0x{ordinal:x}"
        finding_id = f"ida:{scope}:0:{'d' * 64}:image:{address}:0"
        if ordinal == 201:
            target = finding_id
        findings.append(
            {
                "id": finding_id,
                "backend": "ida",
                "source": scope,
                "binary_sha256": digest,
                "rule_index": 0,
                "rule_digest": "d" * 64,
                "rule_name": "Pad",
                "function_name": "",
                "found_in": "pad",
                "address_space": "image",
                "address": address,
                "relative_address": None,
                "occurrence": 0,
                "priority": "High",
                "evidence": {},
            }
        )
    invoke_ida(
        managed,
        "store_scan",
        {
            "scope": scope,
            "scan_id": "scan-page-two",
            "scanned_at": utc_now(),
            "coverage": "complete",
            "rules": [{"name": "Pad", "function_names": ["pad"], "mark_if": {}}],
            "rule_coverage": [
                {"rule_index": 0, "state": "evaluated", "backend": "ida"}
            ],
            "warnings": [],
            "findings": findings,
            "offset": 0,
            "limit": 1,
        },
    )
    return target


@pytest.mark.requires_ghidra
def test_startup_replay_confirms_pending_before_any_findings_read(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A restart finishes the pending save before any public findings read.

    Opening the managed IDB as if it were the binary, then swallowing that
    refusal, leaves the crash window open. This test never calls
    ``vulfi_findings``.
    """
    binary = _compile(tmp_path, "startup-replay")
    pair = _linked_pair(binary)
    catalog = open_catalog(str(binary))
    try:
        started = catalog.begin_linked_update(
            str(pair["link_id"]),
            int(pair["link_revision"]),
            EXTERNAL_STATUS,
            "restart must finish this save",
        )
    finally:
        catalog.close()
    assert started["sync_state"] == "pending", started
    event_id = str(started["event_id"])

    _replay_startup()

    assert _event_state(binary, event_id) == "confirmed"
    stored = _stored_link(binary, str(pair["link_id"]))
    assert stored["sync_state"] == "synchronized", stored
    ida_page = _reopen(
        lambda: findings_ida(str(pair["managed"]), 0, 200, path=str(binary))
    )
    ida_row = next(row for row in ida_page["findings"] if row["id"] == pair["ida"]["id"])
    assert ida_row["status"] == EXTERNAL_STATUS
    assert ida_row["rationale"] == "restart must finish this save"


@pytest.mark.requires_ghidra
def test_triage_result_names_requested_id_past_first_page(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A linked edit names the requested row, not whoever sorted onto page one."""
    binary = _compile(tmp_path, "past-page")
    pair = _linked_pair(binary)
    external_id = str(pair["external"]["id"])
    _external_pad(binary, 220)
    result = vulfi_triage(
        str(binary),
        external_id,
        EXTERNAL_STATUS,
        "named row, not a neighbor",
    )
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        stored = catalog.external_finding(external_id)
    finally:
        catalog.close()
    assert stored is not None
    assert result["finding"]["id"] == external_id
    assert result["triage_revision"] == int(stored["triage_revision"])
    assert result["finding"]["triage_revision"] == result["triage_revision"]


def test_page_two_finding_reaches_briefing(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    """A finding past the first IDA page is still the row the briefing reads."""
    binary = _compile(tmp_path, "page-two")
    managed = ensure_managed_idb(str(binary))
    target = _store_page_two(binary, managed)
    digest = "e" * 64
    external_id = f"ghidra:default:0:{digest}:ghidra:image:0x1000:0"
    catalog = open_catalog(str(binary))
    try:
        catalog.record_external_scan(
            backend="ghidra",
            scope="default",
            scan_id="scan-brief",
            scanned_at=utc_now(),
            state="evaluated",
            coverage="partial",
            findings=[
                {
                    "id": external_id,
                    "backend": "ghidra",
                    "source": "default",
                    "rule_index": 0,
                    "rule_digest": digest,
                    "rule_name": "Brief",
                    "function_name": "",
                    "found_in": "brief",
                    "address_space": "ghidra:image",
                    "address": 0x1000,
                    "occurrence": 0,
                    "priority": "High",
                    "evidence": {},
                }
            ],
        )
    finally:
        catalog.close()
    briefing = link_briefing(str(binary), target, external_id, str(binary))
    assert isinstance(briefing["ida"], dict), briefing
    assert briefing["ida"]["id"] == target


def test_two_external_scopes_both_appear(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    """One backend keeps every scope, the way the IDA side already does."""
    binary = tmp_path / "two-scopes.bin"
    binary.write_bytes(b"\x7fELF" + b"not-a-real-image")
    with open_catalog(str(binary)) as catalog:
        for scope in ("default", "custom:night"):
            catalog.record_external_scan(
                backend="ghidra",
                scope=scope,
                scan_id=f"scan-{scope}",
                scanned_at=utc_now(),
                state="evaluated",
                coverage="complete",
                findings=[],
            )
    page = vulfi_findings(str(binary))
    health = page["scope_health"]["ghidra"]
    assert isinstance(health, dict), health
    scopes = health["scopes"]
    assert isinstance(scopes, list), health
    assert {item["scope"] for item in scopes} == {"default", "custom:night"}
