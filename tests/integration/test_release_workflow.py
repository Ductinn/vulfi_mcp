"""One cross-system transition earlier tests do not compose.

``test_review_cli`` approves a function boundary and a later IDA scan finds
the call that boundary made visible. ``test_linked_mcp`` links a call both
backends already reported and reopens that pair. Neither asks whether the
call that exists only because of the approval has a Ghidra row, nor places
an unsupported radare2 structural rule next to a strings/functions pass on
that same binary.

Measured on this Ghidra build, it does not. The unreferenced executable
section is loaded, and no function is defined over it, so ``get_xrefs_to``
has no call at that RVA. The nearby ``strcpy`` in ``main`` is a different
call. Linking those two rows would attach the recovered site to its
neighbor. This test fails if that link is stored, if a later IDA scan misses
the recovered call, or if radare2 hides an unsupported structural rule
behind a pass that actually ran.
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

from conftest import ghidra_bridge, ghidra_url, missing_prerequisite, names_the_rollback
from vulfi_mcp.catalog import get_catalog
from vulfi_mcp.ida_adapter import ManagedDatabaseError, scan_ida
from vulfi_mcp.operator import prove_provider_call_site
from vulfi_mcp.rules import Rule, load_stock_rules, validate_rules
from vulfi_mcp.server import vulfi_prepare, vulfi_propose_recovery, vulfi_scan

pytestmark = [pytest.mark.requires_ida, pytest.mark.requires_ghidra]

PROVIDER_LOCK = Path(tempfile.gettempdir()) / "vulfi-ghidra-{}-{}.lock".format(
    urlsplit(ghidra_url()).hostname or "127.0.0.1",
    urlsplit(ghidra_url()).port or 80,
)
LOCK_TIMEOUT = 300.0
SCAN_NAME = "releaseflow"
SCOPE = f"custom:{SCAN_NAME}"
CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline", "-fPIE", "-pie")

FIXTURE_SOURCE = """\
#include <string.h>

char vulfi_review_destination[64];

/* Unreferenced executable bytes. IDA decodes them and creates no function:
 * nothing establishes an entry point, so preparation leaves a candidate.
 * The call is invisible to a scan until an operator approves that boundary.
 * This Ghidra build loads the section and does not define a function over
 * it, so it has no xref at the call. */
__asm__(
    ".section .vulfi_review_code,\\"ax\\",@progbits\\n"
    ".balign 16\\n"
    "  endbr64\\n"
    "  call strcpy@PLT\\n"
    "  ret\\n"
    ".previous\\n");

__asm__(
    ".section .vulfi_review_text,\\"a\\",@progbits\\n"
    ".balign 16\\n"
    "  .ascii \\"vulfi-release-marker\\"\\n"
    "  .byte 0x00\\n"
    ".previous\\n");

int main(int argc, char **argv)
{
    if (argc > 1)
        strcpy(vulfi_review_destination, argv[1]);
    return 0;
}
"""

COPY_RULE: Rule = {
    "name": "Any Copy",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {"High": "True", "Medium": "False", "Low": "False"},
}


def _r2mcp() -> Path:
    return Path(os.environ.get("VULFI_R2MCP") or "/tmp/vulfi-providers/r2mcp/src/r2mcp")


def _r2_prefix() -> Path:
    return Path(os.environ.get("VULFI_R2_PREFIX") or "/tmp/vulfi-providers/r2")


@pytest.fixture(autouse=True)
def provider_lock(request: pytest.FixtureRequest) -> Iterator[None]:
    """Hold the one GhidraMCP server while this test actually uses it."""
    if request.node.get_closest_marker("requires_ghidra") is None:
        yield
        return
    PROVIDER_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(PROVIDER_LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        import fcntl

        while True:
            try:
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
def providers(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """IDA, Ghidra, and radare2, as one operator config file."""
    server = _r2mcp()
    library = _r2_prefix() / "lib"
    if not server.is_file() or not os.access(server, os.X_OK) or not library.is_dir():
        missing_prerequisite(
            f"radare2-mcp 1.8.8 is not at {server} with libraries in {library}"
        )
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
                "[r2]",
                'transport = "stdio"',
                f'command = "{server}"',
                "args = []",
                f'stderr_log = "{tmp_path / "r2mcp.err"}"',
                "",
                "[r2.env]",
                f'PATH = "{_r2_prefix() / "bin"}:/usr/bin:/bin"',
                f'LD_LIBRARY_PATH = "{library}"',
                f'HOME = "{tmp_path / "r2-home"}"',
                "",
                "[[r2.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
                "[[r2.binaries]]",
                f'local = "{managed_data_dir}"',
                f'remote = "{managed_data_dir}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "bridge-home").mkdir()
    (tmp_path / "r2-home").mkdir()
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


def _compile(tmp_path: Path) -> Path:
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so the release fixture cannot be built")
    source = tmp_path / "vulfi_release.c"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    binary = tmp_path / "vulfi_release"
    completed = subprocess.run(
        [compiler, *CC_FLAGS, "-o", str(binary), str(source)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return binary


def _command() -> str:
    candidate = Path(sys.executable).with_name("vulfi-mcp")
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which("vulfi-mcp")
    if found:
        return found
    missing_prerequisite("vulfi-mcp is not installed, so the operator CLI cannot run")
    return ""


def _cli(*arguments: str, answer: str) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [_command(), *arguments],
        input=f"{answer}\n",
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ},
    )
    if completed.returncode != 0:
        reported = ManagedDatabaseError(f"{completed.stderr}\n{completed.stdout}")
        if names_the_rollback(reported):
            raise reported
    return completed


def _json_result(completed: subprocess.CompletedProcess[str]) -> dict:
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as broken:
        raise AssertionError(completed.stderr or completed.stdout) from broken


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _address(row: dict) -> int:
    return int(str(row["address"]), 16)


def _hidden_candidate(target: str, analysis_id: str) -> dict:
    page = __import__(
        "vulfi_mcp.server", fromlist=["vulfi_preparation"]
    ).vulfi_preparation(target, analysis_id, offset=0, limit=200)
    rows = [
        row
        for row in page["candidates"]
        if row["kind"] == "function"
        and row["evidence"].get("segment") == ".vulfi_review_code"
    ]
    assert rows, page
    hidden = min(rows, key=lambda row: int(row["address"]))
    assert hidden["state"] == "candidate", hidden
    assert hidden["backend"] == "ida"
    return hidden


def _inside(findings: list[dict], start: int, end: int) -> list[dict]:
    return [row for row in findings if start <= _address(row) < end]


def _structural_rule() -> Rule:
    """The stock rule that needs argument structure, not a name match."""
    for rule in load_stock_rules():
        high = rule["mark_if"]["High"]
        if (
            rule["name"] == "Buffer Overflow"
            and "strcpy" in rule["function_names"]
            and "used_in_call_before" in high
            and "is_constant" in high
        ):
            return rule
    raise AssertionError("the stock Buffer Overflow rule is not in the package")


def _rva(proof: dict, address: int) -> str | None:
    relative = proof.get("relative_address")
    if isinstance(relative, str) and relative:
        return relative
    base = proof.get("image_base")
    if isinstance(base, str):
        base = int(base, 16)
    if isinstance(base, int) and address >= base:
        return hex(address - base)
    return None


def _ghidra_rvas(target: str, rows: list[dict]) -> list[dict]:
    seen = []
    for row in rows:
        proof = prove_provider_call_site(target, _address(row), ("strcpy",))
        seen.append(
            {
                "id": row["id"],
                "address": row["address"],
                "rva": _rva(proof, _address(row)),
                "function_name": row.get("function_name"),
            }
        )
    return seen


def test_preparation_approval_changes_later_linked_scan(
    tmp_path: Path,
    managed_data_dir: Path,
    providers: Path,
    durable_or_reported,
) -> None:
    """A reviewed recovery reveals an IDA call Ghidra does not have, so the link is refused."""
    binary = _compile(tmp_path)
    target = str(binary)
    source_hash = _digest(binary)
    with durable_or_reported() as produced:
        prepared = vulfi_prepare(target, backend="ida")
        produced.append(prepared["idb_path"])
        analysis_id = prepared["analysis_id"]
        revision = prepared["preparation_revision"]
        hidden = _hidden_candidate(target, analysis_id)
        entry = int(hidden["address"])
        end = hidden["evidence"]["end"]
        assert isinstance(end, int) and end > entry

        before = scan_ida(
            prepared["idb_path"], validate_rules([COPY_RULE]), SCOPE, path=target
        )
        assert _inside(before["findings"], entry, end) == []
        assert any(row["found_in"] == "main" for row in before["findings"])

        submitted = vulfi_propose_recovery(
            target,
            analysis_id,
            [
                {
                    "candidate_id": hidden["candidate_id"],
                    "kind": "function_boundary",
                    "address_space": "image",
                    "address": entry,
                    "value": {"end": end},
                    "evidence": {
                        "segment": ".vulfi_review_code",
                        "terminator": hidden["evidence"]["terminator"],
                    },
                    "rationale": "the decoded instructions run to a return",
                }
            ],
        )
        assert submitted["accepted_total"] == 1, submitted
        proposal_id = submitted["proposals"][0]["proposal_id"]
        approved = _json_result(
            _cli(
                "review",
                "approve",
                "--path",
                target,
                "--proposal-id",
                proposal_id,
                "--expected-revision",
                str(revision),
                "--json",
                answer="approve",
            )
        )
        assert approved["applied"] is True, approved
        assert approved["approved_revision"] == revision + 1

        scanned = vulfi_scan(
            target, rules=[COPY_RULE], scan_name=SCAN_NAME, backend="ida"
        )
        assert scanned["preparation_revision"] == revision + 1
        inside = _inside(scanned["findings"], entry, end)
        assert len(inside) == 1, scanned["findings"]
        ida_row = inside[0]
        wanted = ida_row.get("relative_address")
        assert isinstance(wanted, str) and wanted, ida_row

        external = vulfi_scan(
            target, rules=[COPY_RULE], scan_name=SCAN_NAME, backend="ghidra"
        )
        ghidra_rows = [row for row in external["findings"] if row["backend"] == "ghidra"]
        assert ghidra_rows, external["rule_coverage"]
        proved = _ghidra_rvas(target, ghidra_rows)
        assert all(item["rva"] != wanted for item in proved), {
            "recovered_rva": wanted,
            "ghidra": proved,
        }
        # Same rule name is not a match. The only Ghidra strcpy is main's.
        neighbor = ghidra_rows[0]
        refused = _cli(
            "link",
            "--path",
            target,
            "--ida-id",
            ida_row["id"],
            "--external-id",
            neighbor["id"],
            "--binary",
            target,
            "--source",
            "new",
            "--status",
            "Suspicious",
            "--rationale",
            "these calls are not the same site",
            "--json",
            answer="new",
        )
        text = f"{refused.stderr}\n{refused.stdout}"
        assert refused.returncode == 1, text
        assert "Type '" not in text, text
        assert "relative address" in text.lower(), text
        payload = json.loads(refused.stdout)
        assert payload["confirmed"] is False
        assert payload["sync_state"] == "unlinked"
        catalog = get_catalog(target)
        assert catalog is not None
        try:
            stored = catalog._connection.execute("SELECT count(*) FROM links").fetchone()
        finally:
            catalog.close()
        assert stored[0] == 0

        r2_prepared = vulfi_prepare(
            target,
            backend="r2",
            passes=["strings", "functions", "structures"],
        )
        routed = {row["pass"]: row for row in r2_prepared["routing"]}
        assert set(routed) == {"strings", "functions", "structures"}
        for name in ("strings", "functions"):
            assert routed[name]["backend"] == "r2", routed[name]
            assert routed[name]["coverage"] != "unavailable", routed[name]
            assert routed[name]["state"] != "unavailable", routed[name]
        assert routed["structures"]["coverage"] == "unavailable", routed["structures"]
        assert routed["structures"]["backend"] is None
        working = {row["pass"]: row for row in r2_prepared["passes"]}
        assert working["strings"]["coverage"] != "unavailable"
        assert working["functions"]["coverage"] != "unavailable"
        assert working["structures"]["coverage"] == "unavailable", working["structures"]
        assert working["structures"]["ranges"]
        assert all(
            item["coverage"] == "unavailable" for item in working["structures"]["ranges"]
        )

        structural = _structural_rule()
        r2_scan = vulfi_scan(
            target,
            rules=[structural],
            scan_name="releasegap",
            backend="r2",
        )
        coverage = [
            row
            for row in r2_scan["rule_coverage"]
            if row["backend"] == "r2" and row["rule_index"] == 0
        ]
        assert len(coverage) == 1, r2_scan["rule_coverage"]
        assert coverage[0]["state"] == "unsupported", coverage[0]
        reason = coverage[0]["reason"] or ""
        assert "param" in reason or "calls_before" in reason, reason
        assert r2_scan["findings"] == []
        assert _digest(binary) == source_hash
