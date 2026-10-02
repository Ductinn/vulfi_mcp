"""Journaled linked triage: two crash windows, one conflict, one outage.

A later assessment is not a second write that hopes both stores agree. These
tests create a real reviewed link, then interrupt the next decision after the
SQLite event and after the IDB save. Replay must finish each window once.
An IDB revision that moved on its own is a conflict, not a stale bit. A
missing catalog blocks the linked edit and still lets an unlinked IDA row
change.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from conftest import (
    CC_FLAGS,
    FIXTURES,
    ghidra_bridge,
    ghidra_url,
    missing_prerequisite,
)
from vulfi_mcp.catalog import catalog_path, get_catalog
from vulfi_mcp.ida_adapter import (
    ManagedDatabaseError,
    ensure_managed_idb,
    findings_ida,
    scan_ida,
    triage_ida,
)
from vulfi_mcp.operator import review_link
from vulfi_mcp.prepare import scan_target
from vulfi_mcp.rules import Rule, canonical_rule_digest
from vulfi_mcp.server import apply_linked_update

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
SCOPE = "default"
INITIAL_STATUS = "False Positive"
INITIAL_RATIONALE = "reviewed pair, not yet reassessed"
UPDATE_STATUS = "Suspicious"
UPDATE_RATIONALE = "the source argument is still not a constant"
OUT_OF_BAND_STATUS = "Vulnerable"
OUT_OF_BAND_RATIONALE = "changed in the IDB without the catalog"


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


def _ida_rows(binary: Path) -> tuple[str, list[dict]]:
    managed = ensure_managed_idb(str(binary))
    result = scan_ida(managed, (COPY_RULE,), SCOPE, path=str(binary))
    rows = [
        row
        for row in result["findings"]
        if row["rule_digest"] == canonical_rule_digest(COPY_RULE)
    ]
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


def _linked_pair(binary: Path) -> dict[str, object]:
    last: BaseException | None = None
    for _attempt in range(2):
        try:
            return _link_once(binary)
        except (ManagedDatabaseError, KeyError, AssertionError) as failed:
            last = failed
    assert last is not None
    raise last


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
        "link_id": created["link_id"],
        "link_revision": int(created["link_revision"]),
    }


def _ida_finding(managed: str, binary: Path, finding_id: str) -> dict:
    page = _reopen(lambda: findings_ida(managed, 0, 200, path=str(binary)))
    return next(row for row in page["findings"] if row["id"] == finding_id)


def _reopen(read):
    """One retry after IDA 9.4 rolls a bad pack back to the previous generation."""
    try:
        return read()
    except ManagedDatabaseError as failed:
        if "the save before this one left a database it cannot read" not in str(failed):
            raise
        return read()

def _external_finding(binary: Path, finding_id: str) -> dict:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        stored = catalog.external_finding(finding_id)
    finally:
        catalog.close()
    assert stored is not None
    return stored


def _pending_update(binary: Path, link_id: str) -> dict:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        rows = catalog._connection.execute(
            "SELECT e.event_id, e.kind, e.state, e.expected_link_revision,"
            " e.intended_ida_revision, l.status, l.rationale, l.sync_state,"
            " l.link_revision, f.status, f.rationale, f.triage_revision"
            " FROM sync_events e"
            " JOIN links l ON l.link_id = e.link_id"
            " JOIN external_findings f ON f.finding_id = l.external_finding_id"
            " WHERE e.link_id = ? AND e.state = 'pending'",
            (link_id,),
        ).fetchall()
    finally:
        catalog.close()
    assert len(rows) == 1, rows
    row = rows[0]
    assert row[1] == "update"
    return {
        "event_id": row[0],
        "kind": row[1],
        "state": row[2],
        "expected_link_revision": row[3],
        "intended_ida_revision": row[4],
        "link_status": row[5],
        "link_rationale": row[6],
        "sync_state": row[7],
        "link_revision": row[8],
        "external_status": row[9],
        "external_rationale": row[10],
        "external_revision": row[11],
    }


def _kill_after(binary: Path, phase: str, link_id: str, revision: int) -> None:
    """Run one update phase in a disposable process, then kill it.

    ``begin`` stops after the SQLite event. ``save`` stops after the IDB
    save and before the catalog confirmation. The process is still alive at
    the marker, which is the crash window, and is killed rather than allowed
    to finish.
    """
    marker = binary.parent / f"{phase}.ready"
    script = textwrap.dedent(
        """
        import os
        import sys
        import time
        from pathlib import Path

        from vulfi_mcp.catalog import open_catalog
        from vulfi_mcp.ida_adapter import mirror_linked_ida
        from vulfi_mcp.server import apply_linked_update

        binary, phase, link_id, revision, marker = sys.argv[1:]
        if phase == "begin":
            with open_catalog(binary) as catalog:
                started = catalog.begin_linked_update(
                    link_id,
                    int(revision),
                    os.environ["VULFI_UPDATE_STATUS"],
                    os.environ["VULFI_UPDATE_RATIONALE"],
                )
            Path(marker).write_text(str(started["event_id"]), encoding="utf-8")
            time.sleep(float(os.environ.get("VULFI_CRASH_HOLD", "60")))
            raise SystemExit("the disposable server was not killed")
        if phase == "save":
            with open_catalog(binary) as catalog:
                started = catalog.begin_linked_update(
                    link_id,
                    int(revision),
                    os.environ["VULFI_UPDATE_STATUS"],
                    os.environ["VULFI_UPDATE_RATIONALE"],
                )
                payload = started["payload"]
            mirrored = mirror_linked_ida(
                str(payload["idb_path"]),
                str(payload["ida_finding_id"]),
                str(started["event_id"]),
                int(payload["expected_ida_revision"]),
                dict(payload["decision"]),
            )
            if not (mirrored.get("applied") or mirrored.get("already")):
                raise SystemExit(f"IDB save did not land: {mirrored!r}")
            Path(marker).write_text(str(started["event_id"]), encoding="utf-8")
            time.sleep(float(os.environ.get("VULFI_CRASH_HOLD", "60")))
            raise SystemExit("the disposable server was not killed")
        finished = apply_linked_update(
            binary,
            link_id,
            int(revision),
            os.environ["VULFI_UPDATE_STATUS"],
            os.environ["VULFI_UPDATE_RATIONALE"],
        )
        Path(marker).write_text(str(finished.get("sync_state")), encoding="utf-8")
        """
    )
    env = os.environ.copy()
    env["VULFI_UPDATE_STATUS"] = UPDATE_STATUS
    env["VULFI_UPDATE_RATIONALE"] = UPDATE_RATIONALE
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
            str(binary),
            phase,
            link_id,
            str(revision),
            str(marker),
        ],
        env=env,
    )
    deadline = time.monotonic() + 300
    try:
        while not marker.is_file():
            if child.poll() is not None:
                raise AssertionError(
                    f"disposable server exited {child.returncode} before {phase}"
                )
            if time.monotonic() >= deadline:
                raise AssertionError(f"disposable server never reached {phase}")
            time.sleep(0.2)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=30)


def _restart_replay(binary: Path) -> list[dict]:
    """A new process replays whatever the killed server left pending."""
    script = textwrap.dedent(
        """
        import json
        import sys
        from pathlib import Path

        from vulfi_mcp.server import replay_linked_updates

        Path(sys.argv[2]).write_text(
            json.dumps(replay_linked_updates(sys.argv[1])), encoding="utf-8"
        )
        """
    )
    finished = binary.parent / "replay.json"
    if finished.exists():
        finished.unlink()
    completed = subprocess.run(
        [sys.executable, "-c", script, str(binary), str(finished)],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        timeout=300,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(finished.read_text(encoding="utf-8"))


@pytest.mark.requires_ghidra
def test_interrupt_after_pending_then_replay(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A kill after the SQLite event leaves the old IDB, then replay writes it once.

    The production change that must fail this test is saving the IDB before
    the event exists, or applying that event twice so the revision moves by
    two.
    """
    binary = _compile(tmp_path, "pending")
    pair = _linked_pair(binary)
    ida_id = pair["ida"]["id"]
    before = _ida_finding(pair["managed"], binary, ida_id)
    _kill_after(binary, "begin", str(pair["link_id"]), int(pair["link_revision"]))

    pending = _pending_update(binary, str(pair["link_id"]))
    assert pending["sync_state"] == "pending"
    assert pending["link_status"] == UPDATE_STATUS
    assert pending["external_status"] == UPDATE_STATUS
    assert pending["external_rationale"] == UPDATE_RATIONALE
    assert pending["link_revision"] == pair["link_revision"]
    old = _ida_finding(pair["managed"], binary, ida_id)
    assert old["status"] == before["status"]
    assert old["triage_revision"] == before["triage_revision"]

    finished = _restart_replay(binary)
    assert finished and finished[0]["sync_state"] == "synchronized"
    assert finished[0]["confirmed"] is True
    mirrored = _ida_finding(pair["managed"], binary, ida_id)
    external = _external_finding(binary, pair["external"]["id"])
    assert mirrored["status"] == UPDATE_STATUS
    assert external["status"] == UPDATE_STATUS
    assert mirrored["triage_revision"] == before["triage_revision"] + 1
    assert external["triage_revision"] == pair["external"]["triage_revision"] + 2
    again = _restart_replay(binary)
    assert again == []
    assert _ida_finding(pair["managed"], binary, ida_id)["triage_revision"] == (
        before["triage_revision"] + 1
    )


@pytest.mark.requires_ghidra
def test_interrupt_after_idb_save_then_replay(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A kill after the IDB save finalizes the pending event without a second revision.

    The production change that must fail this test is treating the two stores
    as one commit, or incrementing the IDB revision again because SQLite had
    not yet said confirmed.
    """
    binary = _compile(tmp_path, "saved")
    pair = _linked_pair(binary)
    ida_id = pair["ida"]["id"]
    before = _ida_finding(pair["managed"], binary, ida_id)
    _kill_after(binary, "save", str(pair["link_id"]), int(pair["link_revision"]))

    pending = _pending_update(binary, str(pair["link_id"]))
    assert pending["state"] == "pending"
    saved = _ida_finding(pair["managed"], binary, ida_id)
    assert saved["status"] == UPDATE_STATUS
    assert saved["triage_revision"] == before["triage_revision"] + 1

    finished = _restart_replay(binary)
    assert finished and finished[0]["sync_state"] == "synchronized"
    assert _ida_finding(pair["managed"], binary, ida_id)["triage_revision"] == (
        before["triage_revision"] + 1
    )
    again = _restart_replay(binary)
    assert again == []
    assert _ida_finding(pair["managed"], binary, ida_id)["triage_revision"] == (
        before["triage_revision"] + 1
    )
    assert _external_finding(binary, pair["external"]["id"])["status"] == UPDATE_STATUS


@pytest.mark.requires_ghidra
def test_out_of_band_revision_conflicts(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """An IDB revision that moved outside the journal is a conflict, not an overwrite.

    The production change that must fail this test is writing the catalog
    decision over that independent assessment, or calling the row stale.
    """
    binary = _compile(tmp_path, "conflict")
    pair = _linked_pair(binary)
    ida_id = pair["ida"]["id"]
    _reopen(
        lambda: triage_ida(
            pair["managed"],
            ida_id,
            OUT_OF_BAND_STATUS,
            OUT_OF_BAND_RATIONALE,
            path=str(binary),
        )
    )
    moved = _ida_finding(pair["managed"], binary, ida_id)
    result = apply_linked_update(
        str(binary),
        str(pair["link_id"]),
        int(pair["link_revision"]),
        UPDATE_STATUS,
        UPDATE_RATIONALE,
    )
    assert result["sync_state"] == "conflict"
    assert result["sync_state"] != "synchronized"
    kept = _ida_finding(pair["managed"], binary, ida_id)
    assert kept["status"] == OUT_OF_BAND_STATUS
    assert kept["rationale"] == OUT_OF_BAND_RATIONALE
    assert kept["triage_revision"] == moved["triage_revision"]
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        stored = catalog.link(str(pair["link_id"]))
    finally:
        catalog.close()
    assert stored is not None
    assert stored["sync_state"] == "conflict"
    assert stored["link_revision"] == pair["link_revision"]
    assert stored.get("stale") is not True


@pytest.mark.requires_ghidra
def test_offline_catalog_blocks_linked_not_unlinked(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """No catalog means no linked edit, and an unlinked IDA row still changes.

    The production change that must fail this test is mirroring the linked
    decision into the IDB after SQLite is gone, or refusing the unlinked row
    because the catalog is gone.
    """
    binary = _compile(tmp_path, "offline")
    pair = _linked_pair(binary)
    linked_before = _ida_finding(pair["managed"], binary, pair["ida"]["id"])
    store = catalog_path()
    assert store.is_file()
    store.unlink()
    with pytest.raises(Exception) as refused:
        apply_linked_update(
            str(binary),
            str(pair["link_id"]),
            int(pair["link_revision"]),
            UPDATE_STATUS,
            UPDATE_RATIONALE,
        )
    assert "synchron" not in str(refused.value).lower()
    untouched = _ida_finding(pair["managed"], binary, pair["ida"]["id"])
    assert untouched["status"] == linked_before["status"]
    assert untouched["triage_revision"] == linked_before["triage_revision"]
    updated = _reopen(
        lambda: triage_ida(
            pair["managed"],
            pair["unlinked"]["id"],
            UPDATE_STATUS,
            UPDATE_RATIONALE,
            path=str(binary),
        )
    )
    assert updated["finding"]["status"] == UPDATE_STATUS
    assert updated["finding"]["id"] == pair["unlinked"]["id"]
    assert updated["finding"]["link_id"] is None
