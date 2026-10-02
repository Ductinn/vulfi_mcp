"""Reviewed links: identity is the binary, the rule, and the call site.

A link is not a shared function name and not a shared number. These tests
scan a real binary, or construct two stores that only look alike, and check
that a link is created only when the original-binary SHA-256, the full rule
digest, and a verified address-space mapping of the same call site all
agree — and that an interrupted creation stays pending until replay finishes
it.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
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
from vulfi_mcp.catalog import get_catalog, open_catalog
from vulfi_mcp.ida_adapter import (
    ensure_managed_idb,
    findings_ida,
    scan_ida,
)
from vulfi_mcp.ida_runtime import TRIAGE_STATUSES
from vulfi_mcp.operator import review_link, replay_pending_links
from vulfi_mcp.prepare import scan_target
from vulfi_mcp.rules import Rule, canonical_rule_digest, load_stock_rules

pytestmark = pytest.mark.requires_ida

PROVIDER_LOCK = Path(tempfile.gettempdir()) / "vulfi-ghidra-{}-{}.lock".format(
    urlsplit(ghidra_url()).hostname or "127.0.0.1",
    urlsplit(ghidra_url()).port or 80,
)
LOCK_TIMEOUT = 300.0

#: High asks only whether the source argument is constant. The stock buffer
#: overflow rule also asks whether ``strlen`` ran first, and this Ghidra build
#: does not state that fact, so a pair scanned with the stock rule would have
#: an IDA row and no external row to link. Two names, so the external row
#: stores an empty function name and a link cannot be cheating by matching it.
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


def _compile(tmp_path: Path, name: str, *, flags: tuple[str, ...] = CC_FLAGS) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / name
    source = FIXTURES / "vulfi_calls.c"
    completed = __import__("subprocess").run(
        [compiler, *flags, "-o", str(binary), str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return binary


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ida_scan(binary: Path) -> tuple[str, dict]:
    managed = ensure_managed_idb(str(binary))
    result = scan_ida(managed, (COPY_RULE,), SCOPE, path=str(binary))
    assert result["findings"], "IDA produced no strcpy finding to link"
    return managed, result["findings"][0]


def _ghidra_scan(binary: Path) -> dict:
    result = scan_target(str(binary), (COPY_RULE,), SCOPE, backend="ghidra")
    rows = [
        row
        for row in result["findings"]
        if row["backend"] == "ghidra" and row["rule_digest"] == canonical_rule_digest(COPY_RULE)
    ]
    assert rows, f"Ghidra produced no strcpy finding: {result['rule_coverage']}"
    return rows[0]


def _links(binary: Path) -> list[tuple]:
    catalog = get_catalog(str(binary))
    assert catalog is not None
    try:
        return catalog._connection.execute(
            "SELECT link_id, sync_state, link_revision, ida_finding_id,"
            " external_finding_id, proof, status, rationale, chosen_source"
            " FROM links"
        ).fetchall()
    finally:
        catalog.close()


def _elf_file_offset(binary: Path, rva: int) -> int | None:
    raw = binary.read_bytes()
    if raw[:4] != b"\x7fELF" or raw[4] != 2:
        return None
    little = raw[5] == 1
    endian = "little" if little else "big"
    phoff = int.from_bytes(raw[32:40], endian)
    phentsize = int.from_bytes(raw[54:56], endian)
    phnum = int.from_bytes(raw[56:58], endian)
    for index in range(phnum):
        entry = raw[phoff + index * phentsize : phoff + (index + 1) * phentsize]
        if int.from_bytes(entry[0:4], endian) != 1:
            continue
        offset = int.from_bytes(entry[8:16], endian)
        vaddr = int.from_bytes(entry[16:24], endian)
        filesz = int.from_bytes(entry[32:40], endian)
        if vaddr <= rva < vaddr + filesz:
            return offset + (rva - vaddr)
    return None


@pytest.mark.requires_ghidra
def test_reviewed_pair_uses_hash_digest_and_call_site_proof(
    tmp_path: Path, managed_data_dir: Path, ghidra_config: Path
) -> None:
    """A link records the SHA, the full digest, and the call-site proof.

    The production change that must fail this test is linking on a shared
    function name or a shared virtual address, or forgetting the proof when
    either store is reopened.
    """
    binary = _compile(tmp_path, "calls")
    managed, ida_row = _ida_scan(binary)
    external = _ghidra_scan(binary)
    digest = canonical_rule_digest(COPY_RULE)
    assert ida_row["rule_digest"] == digest
    assert external["rule_digest"] == digest
    # Identity is not the callee name. A multi-name rule stores none, and
    # this pair is accepted because the digest and the call site agree.
    assert "function_name" not in {
        ida_row["id"],
        external["id"],
    }

    created = review_link(
        str(binary),
        ida_row["id"],
        external["id"],
        str(binary),
        "external",
        "Suspicious",
        "same call site, reviewed from the external assessment",
    )
    assert created["confirmed"] is True
    assert created["sync_state"] == "synchronized"
    assert created["link_revision"] == 1
    proof = created["proof"]
    assert proof["source_sha256"] == _sha(binary)
    assert proof["rule_digest"] == digest
    assert proof["managed_idb_id"]
    rva = int(str(proof["rva"]), 16)
    file_offset = _elf_file_offset(binary, rva)
    assert file_offset is not None
    stored_bytes = bytes.fromhex(str(proof["bytes"]))
    assert stored_bytes
    assert binary.read_bytes()[file_offset : file_offset + len(stored_bytes)] == stored_bytes
    assert proof["xrefs"], "a call site with no source xref is not this call site"
    assert proof["ida_address_space"] == "image"
    assert proof["external_address_space"] == "ghidra:image"
    # Equal numbers are not the mapping. The proof carries both bases.
    assert "ida_image_base" in proof and "external_image_base" in proof

    reopened = get_catalog(str(binary))
    assert reopened is not None
    try:
        held = reopened.link(str(created["link_id"]))
    finally:
        reopened.close()
    assert held["sync_state"] == "synchronized"
    assert held["link_revision"] == 1
    assert held["proof"]["rule_digest"] == digest
    assert held["proof"]["source_sha256"] == _sha(binary)
    assert held["status"] == "Suspicious"

    page = findings_ida(managed, 0, 200, path=str(binary))
    mirrored = next(row for row in page["findings"] if row["id"] == ida_row["id"])
    assert mirrored["link_id"] == created["link_id"]
    assert mirrored["link_revision"] == 1
    assert mirrored["status"] == "Suspicious"
    assert mirrored["rationale"] == "same call site, reviewed from the external assessment"
    assert mirrored["triage_revision"] == ida_row["triage_revision"] + 1


def test_same_numeric_address_different_space_or_sha_rejected(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Equal addresses do not make one call site.

    The production change that must fail this test is accepting a link
    because two findings print the same number.
    """
    binary = _compile(tmp_path, "calls")
    other = tmp_path / "other"
    other.write_bytes(binary.read_bytes() + b"\x00not-the-same")
    managed, ida_row = _ida_scan(binary)
    address = ida_row["address"]

    with open_catalog(str(other)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="scan-other",
            scanned_at="2026-10-02T00:00:00Z",
            state="evaluated",
            coverage="complete",
            rules=[dict(COPY_RULE)],
            findings=[
                {
                    "id": f"ghidra:{_sha(other)}:{SCOPE}:0:{ida_row['rule_digest']}:ghidra:image:{address}:0",
                    "backend": "ghidra",
                    "source": SCOPE,
                    "rule_index": 0,
                    "rule_digest": ida_row["rule_digest"],
                    "rule_name": COPY_RULE["name"],
                    "function_name": "strcpy",
                    "found_in": "main",
                    "address_space": "ghidra:image",
                    "address": address,
                    "relative_address": None,
                    "occurrence": 0,
                    "priority": "High",
                    "evidence": {"matched_branch": "High"},
                }
            ],
        )
        foreign_id = (
            f"ghidra:{_sha(other)}:{SCOPE}:0:{ida_row['rule_digest']}:ghidra:image:{address}:0"
        )

    refused = review_link(
        str(binary),
        ida_row["id"],
        foreign_id,
        str(binary),
        "ida",
        "False Positive",
        "these numbers match and the binaries do not",
    )
    assert refused["confirmed"] is False
    assert "sha" in refused["reason"].lower() or "digest" in refused["reason"].lower()
    assert _links(binary) == []

    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="scan-space",
            scanned_at="2026-10-02T00:00:01Z",
            state="evaluated",
            coverage="complete",
            rules=[dict(COPY_RULE)],
            findings=[
                {
                    "id": f"ghidra:{_sha(binary)}:{SCOPE}:0:{ida_row['rule_digest']}:ghidra:overlay:{address}:0",
                    "backend": "ghidra",
                    "source": SCOPE,
                    "rule_index": 0,
                    "rule_digest": ida_row["rule_digest"],
                    "rule_name": COPY_RULE["name"],
                    "function_name": ida_row["function_name"],
                    "found_in": ida_row["found_in"],
                    "address_space": "ghidra:overlay",
                    "address": address,
                    "relative_address": None,
                    "occurrence": 0,
                    "priority": "High",
                    "evidence": {"matched_branch": "High"},
                }
            ],
        )
    overlay_id = (
        f"ghidra:{_sha(binary)}:{SCOPE}:0:{ida_row['rule_digest']}:ghidra:overlay:{address}:0"
    )
    spaced = review_link(
        str(binary),
        ida_row["id"],
        overlay_id,
        str(binary),
        "new",
        "Vulnerable",
        "same number, different address space",
    )
    assert spaced["confirmed"] is False
    assert "space" in spaced["reason"].lower() or "image base" in spaced["reason"].lower()
    assert _links(binary) == []

    # Distinct image bases, same numeric address. The provider proof is the
    # construction: the live query is replaced with a base that does not
    # produce the IDA RVA, which is the disagreement a rebased image has.
    import vulfi_mcp.operator as operator

    def _other_base(target: str, address_value: int, names: tuple[str, ...]) -> dict:
        return {
            "image_base": 0x10000,
            "address": address_value,
            "relative_address": hex(address_value - 0x10000),
            "bytes": "90",
            "xrefs": [],
            "address_space": "ghidra:image",
        }

    monkeypatch.setattr(operator, "prove_provider_call_site", _other_base)
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:rebased",
            scan_id="scan-base",
            scanned_at="2026-10-02T00:00:02Z",
            state="evaluated",
            coverage="complete",
            rules=[dict(COPY_RULE)],
            findings=[
                {
                    "id": f"ghidra:{_sha(binary)}:custom:rebased:0:{ida_row['rule_digest']}:ghidra:image:{address}:0",
                    "backend": "ghidra",
                    "source": "custom:rebased",
                    "rule_index": 0,
                    "rule_digest": ida_row["rule_digest"],
                    "rule_name": COPY_RULE["name"],
                    "function_name": "strcpy",
                    "found_in": "main",
                    "address_space": "ghidra:image",
                    "address": address,
                    "relative_address": None,
                    "occurrence": 0,
                    "priority": "High",
                    "evidence": {"matched_branch": "High", "rule_function_names": ["strcpy"]},
                }
            ],
        )
    rebased_id = (
        f"ghidra:{_sha(binary)}:custom:rebased:0:{ida_row['rule_digest']}:ghidra:image:{address}:0"
    )
    based = review_link(
        str(binary),
        ida_row["id"],
        rebased_id,
        str(binary),
        "ida",
        "False Positive",
        "same number, different image base",
    )
    assert based["confirmed"] is False
    assert "image base" in based["reason"].lower() or "rva" in based["reason"].lower()
    assert _links(binary) == []
    assert managed  # the IDA finding stayed where the scan put it


def test_stale_digest_and_unverified_idb_refused(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    """Name agreement does not survive a different rule, a partial scan, or a provisional IDB.

    A stale bit left by a failed scan that recorded no findings is not this
    refusal: that row was not looked at again, and its assessment still stands.
    """
    binary = _compile(tmp_path, "calls")
    managed, ida_row = _ida_scan(binary)
    address = ida_row["address"]
    other_digest = "ab" * 32

    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope=SCOPE,
            scan_id="scan-digest",
            scanned_at="2026-10-02T00:00:00Z",
            state="evaluated",
            coverage="complete",
            rules=[dict(COPY_RULE)],
            findings=[
                {
                    "id": f"ghidra:{_sha(binary)}:{SCOPE}:0:{other_digest}:ghidra:image:{address}:0",
                    "backend": "ghidra",
                    "source": SCOPE,
                    "rule_index": 0,
                    "rule_digest": other_digest,
                    "rule_name": COPY_RULE["name"],
                    "function_name": ida_row["function_name"] or "strcpy",
                    "found_in": ida_row["found_in"],
                    "address_space": "ghidra:image",
                    "address": address,
                    "relative_address": None,
                    "occurrence": 0,
                    "priority": "High",
                    "evidence": {"matched_branch": "High"},
                }
            ],
        )
    digest_id = f"ghidra:{_sha(binary)}:{SCOPE}:0:{other_digest}:ghidra:image:{address}:0"
    digest_refused = review_link(
        str(binary),
        ida_row["id"],
        digest_id,
        str(binary),
        "ida",
        "False Positive",
        "same function name, different rule",
    )
    assert digest_refused["confirmed"] is False
    assert "digest" in digest_refused["reason"].lower()
    assert _links(binary) == []

    real_digest = ida_row["rule_digest"]
    kept_id = f"ghidra:{_sha(binary)}:custom:partial:0:{real_digest}:ghidra:image:{address}:0"
    other_id = f"ghidra:{_sha(binary)}:custom:partial:0:{real_digest}:ghidra:image:0x1000:0"
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:partial",
            scan_id="scan-full",
            scanned_at="2026-10-02T00:00:03Z",
            state="evaluated",
            coverage="complete",
            findings=[
                _row(kept_id, address, real_digest, "custom:partial"),
                _row(other_id, "0x1000", real_digest, "custom:partial"),
            ],
        )
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:partial",
            scan_id="scan-partial",
            scanned_at="2026-10-02T00:00:04Z",
            state="evaluated",
            coverage="partial",
            findings=[_row(other_id, "0x1000", real_digest, "custom:partial")],
        )
        stale = catalog.external_finding(kept_id)
    assert stale is not None and stale["stale"] is True
    stale_refused = review_link(
        str(binary),
        ida_row["id"],
        kept_id,
        str(binary),
        "external",
        "Suspicious",
        "a partial scan did not reconfirm this row",
    )
    assert stale_refused["confirmed"] is False
    assert "stale" in stale_refused["reason"].lower()
    assert _links(binary) == []

    # A failed scan that recorded no findings sets the same bit and is not
    # "not reconfirmed". The refusal, if any, must not be that bit.
    failed_id = f"ghidra:{_sha(binary)}:custom:failed:0:{real_digest}:ghidra:image:{address}:0"
    with open_catalog(str(binary)) as catalog:
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:failed",
            scan_id="scan-seen",
            scanned_at="2026-10-02T00:00:05Z",
            state="evaluated",
            coverage="complete",
            findings=[_row(failed_id, address, real_digest, "custom:failed")],
        )
        catalog.record_external_scan(
            backend="ghidra",
            scope="custom:failed",
            scan_id="scan-died",
            scanned_at="2026-10-02T00:00:06Z",
            state="failed",
            coverage=None,
            reason="the provider died before it named a call site",
            findings=[],
        )
        failed_row = catalog.external_finding(failed_id)
    assert failed_row is not None and failed_row["stale"] is True
    failed_attempt = review_link(
        str(binary),
        ida_row["id"],
        failed_id,
        str(binary),
        "new",
        "Vulnerable",
        "the failed scan did not reconfirm anything, including this row",
    )
    assert "stale" not in failed_attempt["reason"].lower()

    idb_only = tmp_path / "provisional.i64"
    shutil.copy(managed, idb_only)
    with open_catalog(str(idb_only), "abc123") as catalog:
        assert catalog.source_sha256 is None
    provisional = review_link(
        str(idb_only),
        ida_row["id"],
        failed_id,
        str(binary),
        "ida",
        "False Positive",
        "an unverified database is not this binary",
    )
    assert provisional["confirmed"] is False
    assert "provisional" in provisional["reason"].lower() or "source" in provisional["reason"].lower()
    assert _links(binary) == [] or all(row[1] != "synchronized" for row in _links(binary))


def _row(identifier: str, address: str, digest: str, scope: str) -> dict:
    return {
        "id": identifier,
        "backend": "ghidra",
        "source": scope,
        "rule_index": 0,
        "rule_digest": digest,
        "rule_name": COPY_RULE["name"],
        "function_name": "strcpy",
        "found_in": "main",
        "address_space": "ghidra:image",
        "address": address,
        "relative_address": None,
        "occurrence": 0,
        "priority": "High",
        "evidence": {"matched_branch": "High", "rule_function_names": ["strcpy"]},
    }


@pytest.mark.requires_ghidra
def test_interrupted_link_creation_remains_pending(
    tmp_path: Path,
    managed_data_dir: Path,
    ghidra_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A creation that dies before the IDB save is pending, then finishes once.

    The production change that must fail this test is reporting synchronized
    before the save, or incrementing the IDA revision a second time on replay.
    """
    from vulfi_mcp.ida_adapter import ManagedDatabaseError
    import vulfi_mcp.operator as operator

    binary = _compile(tmp_path, "calls")
    managed, ida_row = _ida_scan(binary)
    external = _ghidra_scan(binary)
    real_mirror = operator.mirror_linked_ida

    def _stop(idb_path: str, finding_id: str, event_id: str, expected: int, decision: dict) -> dict:
        raise ManagedDatabaseError(f"stopped before saving {idb_path}")

    monkeypatch.setattr(operator, "mirror_linked_ida", _stop)
    pending = review_link(
        str(binary),
        ida_row["id"],
        external["id"],
        str(binary),
        "ida",
        "False Positive",
        "the external row is recorded before the IDB is saved",
    )
    assert pending["confirmed"] is False
    assert pending["sync_state"] == "pending"
    rows = _links(binary)
    assert rows and rows[0][1] == "pending"
    assert all(row[1] != "synchronized" for row in rows)

    page = findings_ida(managed, 0, 200, path=str(binary))
    untouched = next(row for row in page["findings"] if row["id"] == ida_row["id"])
    assert untouched["link_id"] is None
    assert untouched["status"] == "Not Checked"
    assert untouched["triage_revision"] == ida_row["triage_revision"]

    with get_catalog(str(binary)) as catalog:
        stored = catalog.external_finding(external["id"])
    assert stored is not None
    assert stored["status"] == "False Positive"
    assert stored["triage_revision"] == external["triage_revision"] + 1

    monkeypatch.setattr(operator, "mirror_linked_ida", real_mirror)
    finished = replay_pending_links(str(binary))
    assert finished and finished[0]["sync_state"] == "synchronized"
    assert finished[0]["confirmed"] is True
    again = replay_pending_links(str(binary))
    assert again == []

    page = findings_ida(managed, 0, 200, path=str(binary))
    mirrored = next(row for row in page["findings"] if row["id"] == ida_row["id"])
    assert mirrored["link_id"] == pending["link_id"]
    assert mirrored["status"] == "False Positive"
    assert mirrored["triage_revision"] == ida_row["triage_revision"] + 1
    assert _links(binary)[0][1] == "synchronized"
    assert _links(binary)[0][2] == 1
    assert set(TRIAGE_STATUSES)  # the four statuses remain the only vocabulary
