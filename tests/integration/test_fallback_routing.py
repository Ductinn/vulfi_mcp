"""Per-pass and per-rule routing, against real IDA, Ghidra and radare2.

Nothing here is mocked. The IDA backend runs in a licensed local idalib
worker, the Ghidra backend is a real headless GhidraMCP 6.0.0 server reached
over a real MCP stdio bridge, and the radare2 backend is a real
``radareorg/radare2-mcp`` 1.8.8 process. The point of the file is the routing
decision itself: which backend answered which pass, which rules came back
unsupported and why, and what the catalog holds afterwards.

Three gates run here, and each one skips with the exact missing prerequisite
and the command that supplies it. ``VULFI_REQUIRE_LIVE=1`` turns every one of
those skips into a failure, so a run that claims live coverage cannot have
quietly touched nothing. The Ghidra gate is the ``requires_ghidra`` marker in
``tests/conftest.py`` plus the per-test exclusive lock below, because that
provider is a single JVM with a single current program; the radare2 gate is an
autouse fixture that performs a real MCP handshake, because a built executable
that cannot find ``libr_core`` is a missing prerequisite only a started
session can see.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import (
    CC_FLAGS,
    FIXTURES,
    GHIDRA_START_HINT,
    ghidra_bridge,
    ghidra_url,
    missing_prerequisite,
)

from vulfi_mcp.catalog import get_catalog
from vulfi_mcp.ida_adapter import existing_managed_idb
from vulfi_mcp.prepare import (
    UnverifiedBinaryError,
    findings_across_backends,
    prepare_target,
    preparation_page,
    scan_target,
    triage_across_backends,
)
from vulfi_mcp.rules import Rule, load_stock_rules

ALL_PASSES = ["strings", "functions", "structures", "pointer_tables"]

#: The same endpoint-keyed lock ``tests/integration/test_ghidra_provider.py``
#: takes, for the same reason: two processes driving one JVM move each other's
#: current program. Keyed on the URL because that is the only coordinate every
#: client of that server shares.
PROVIDER_LOCK = Path(tempfile.gettempdir()) / "vulfi-ghidra-{}-{}.lock".format(
    urlsplit(ghidra_url()).hostname or "127.0.0.1",
    urlsplit(ghidra_url()).port or 80,
)
LOCK_TIMEOUT = 300.0

DEFAULT_R2MCP = "/tmp/vulfi-providers/r2mcp/src/r2mcp"
DEFAULT_R2_PREFIX = "/tmp/vulfi-providers/r2"
R2MCP_ENV = "VULFI_R2MCP"
R2_PREFIX_ENV = "VULFI_R2_PREFIX"
R2_BUILD_HINT = (
    "build it with the commands in"
    " .superpowers/sdd/2026-09-29-vulfi-mcp-fallback/task-3-report.md"
    " (/tmp is cleared by a reboot)"
)
R2_SERVER_NAME = "Radare2 MCP Connector"
R2_SERVER_VERSION = "1.8.8"


# --------------------------------------------------------------------------
# gates
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def provider_lock(request: pytest.FixtureRequest) -> Iterator[None]:
    """Hold the one GhidraMCP server for the duration of one test."""
    if request.node.get_closest_marker("requires_ghidra") is None:
        yield
        return
    PROVIDER_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = os.open(PROVIDER_LOCK, os.O_CREAT | os.O_RDWR, 0o666)
    deadline = time.monotonic() + LOCK_TIMEOUT
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    missing_prerequisite(
                        "another process has held the GhidraMCP server at"
                        f" {ghidra_url()} for more than {LOCK_TIMEOUT:.0f}s"
                        f" ({PROVIDER_LOCK}); this adapter needs it to itself"
                    )
                time.sleep(0.5)
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            os.close(handle)


def r2mcp_path() -> Path:
    return Path(os.environ.get(R2MCP_ENV) or DEFAULT_R2MCP)


def r2_prefix() -> Path:
    return Path(os.environ.get(R2_PREFIX_ENV) or DEFAULT_R2_PREFIX)


def r2_env() -> dict[str, str]:
    prefix = r2_prefix()
    return {
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "LD_LIBRARY_PATH": str(prefix / "lib"),
    }


@lru_cache(maxsize=1)
def _missing_r2_prerequisite() -> str | None:
    server = r2mcp_path()
    if not server.is_file() or not os.access(server, os.X_OK):
        return (
            f"the r2mcp server is not at {server} (set {R2MCP_ENV} to the"
            f" executable, or {R2_BUILD_HINT})"
        )
    if not (r2_prefix() / "lib").is_dir():
        return (
            f"radare2 is not installed at {r2_prefix()} (set {R2_PREFIX_ENV}"
            f" to its prefix, or {R2_BUILD_HINT})"
        )
    try:
        name, version = asyncio.run(_r2_handshake())
    except Exception as refused:  # noqa: BLE001 - every failure is the same gate
        return (
            f"the r2mcp server at {server} did not answer an MCP handshake"
            f" ({type(refused).__name__}: {refused}); {R2_BUILD_HINT}"
        )
    if (name, version) != (R2_SERVER_NAME, R2_SERVER_VERSION):
        return (
            f"the server at {server} is {name!r} {version!r}, and these tests"
            f" are pinned against {R2_SERVER_NAME!r} {R2_SERVER_VERSION!r}"
        )
    return None


async def _r2_handshake() -> tuple[str, str]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(
        command=str(r2mcp_path()), args=[], env=r2_env()
    )
    with open(os.devnull, "a", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=None) as session:
                started = await session.initialize()
                return started.server_info.name, started.server_info.version


def require_r2() -> None:
    reason = _missing_r2_prerequisite()
    if reason is not None:
        missing_prerequisite(reason)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def compiled_fallback(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_fallback.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite(
            "gcc is not installed, so vulfi_fallback.c cannot be built"
        )
    binary = tmp_path / "vulfi_fallback"
    completed = subprocess.run(
        [
            str(compiler),
            "-O0",
            "-fno-builtin",
            "-fno-inline",
            "-fPIE",
            "-pie",
            "-o",
            str(binary),
            str(FIXTURES / "vulfi_fallback.c"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_fallback.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@pytest.fixture
def compiled_calls(tmp_path: Path) -> Path:
    """Compile ``tests/fixtures/vulfi_calls.c`` into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so vulfi_calls.c cannot be built")
    binary = tmp_path / "vulfi_calls"
    completed = subprocess.run(
        [str(compiler), *CC_FLAGS, "-o", str(binary), str(FIXTURES / "vulfi_calls.c")],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling vulfi_calls.c failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@pytest.fixture
def both_providers(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """The operator's configuration for both providers, and nothing else."""
    environment = r2_env()
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
                f'command = "{r2mcp_path()}"',
                "args = []",
                f'stderr_log = "{tmp_path / "r2mcp.err"}"',
                "",
                "[r2.env]",
                f'PATH = "{environment["PATH"]}"',
                f'LD_LIBRARY_PATH = "{environment["LD_LIBRARY_PATH"]}"',
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
    (tmp_path / "bridge-home").mkdir(exist_ok=True)
    (tmp_path / "r2-home").mkdir(exist_ok=True)
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


# --------------------------------------------------------------------------
# small readers, so a failure explains itself
# --------------------------------------------------------------------------


def routing_for(result: dict[str, Any], name: str) -> dict[str, Any]:
    rows = [row for row in result["routing"] if row["pass"] == name]
    assert rows, f"no routing row for {name!r} in {result['routing']}"
    return rows[0]


def rule_routing(result: dict[str, Any]) -> list[dict[str, Any]]:
    rows = result["scope_health"].get("routing")
    assert isinstance(rows, list), result["scope_health"]
    return rows


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# the tests
# --------------------------------------------------------------------------


@pytest.mark.requires_ida
@pytest.mark.requires_ghidra
def test_decompiler_unavailable_runs_real_fallback(
    compiled_calls: Path, both_providers: Path, managed_data_dir: Path
) -> None:
    """IDA without Hex-Rays keeps what it can prove; Ghidra supplies the rest.

    The decompiler is really switched off for the IDA extraction — the same
    disassembly-only path IDA itself falls back to — so the rules that need an
    argument fact come back ``unsupported`` from IDA with a reason rather than
    as clean negatives. Each of those is then asked of the live Ghidra MCP,
    and the rules it can establish from high P-code are evaluated there. Every
    rule neither backend could establish is enumerated with the fact that was
    missing.
    """
    require_r2()
    rules = load_stock_rules()
    result = scan_target(
        str(compiled_calls),
        rules,
        "default",
        backend="auto",
        decompiler="disabled",
    )

    # IDA ran and said so, over a disassembly-only analysis.
    assert result["backend"] == "ida"
    assert result["scope_health"]["ida"]["decompiler_requested"] == "disabled"
    assert result["scope_health"]["ida"]["analysis_mode"] == "disassembly"

    ida_states = {
        entry["rule_index"]: entry
        for entry in result["rule_coverage"]
        if entry["backend"] == "ida"
    }
    assert len(ida_states) == len(rules)
    unsupported_by_ida = {
        index for index, entry in ida_states.items() if entry["state"] != "evaluated"
    }
    assert unsupported_by_ida, (
        "with the decompiler disabled at least one stock rule must lack the"
        f" facts it needs: {ida_states}"
    )
    for index in sorted(unsupported_by_ida):
        assert ida_states[index]["reason"], ida_states[index]

    # Ghidra was asked about exactly those rules, and about no others.
    ghidra_states = {
        entry["rule_index"]: entry
        for entry in result["rule_coverage"]
        if entry["backend"] == "ghidra"
    }
    assert set(ghidra_states) <= unsupported_by_ida, (
        "a rule IDA already answered must never be asked of another backend"
    )

    routed = {row["rule_index"]: row for row in rule_routing(result)}
    assert len(routed) == len(rules)
    answered_by = {
        index: row["backend"] for index, row in routed.items() if row["backend"]
    }
    assert set(answered_by.values()) <= {"ida", "ghidra", "r2"}

    # Every rule nobody could establish names the fact that was missing, and
    # names the backend that said so.
    for index, row in sorted(routed.items()):
        if row["backend"] is not None:
            continue
        assert row["state"] in ("unsupported", "failed", "unavailable", "unverified")
        assert row["reason"], row
        assert row["attempts"], row
        for attempt in row["attempts"]:
            assert attempt["backend"] in ("ida", "ghidra", "r2")
            if attempt["outcome"] != "answered":
                assert attempt["reason"], attempt

    # A scan that had an unsupported rule in it is never complete.
    assert result["coverage"] == "partial"
    # The catalog answered, and its totals are real rather than assumed.
    assert result["store_health"]["catalog"]["available"] is True

    # radare2's own contribution is preparation evidence, not rule coverage:
    # it establishes one rule fact and 23 of the 24 stock rules are
    # unsupported on it. Its independently supported pass is run here, as a
    # separate request against the same bytes.
    prepared = prepare_target(str(compiled_calls), backend="r2", passes=ALL_PASSES)
    assert prepared["backend"] == "r2"
    assert prepared["idb_path"] is None
    answered = {
        row["pass"]: row for row in prepared["routing"] if row["state"] == "answered"
    }
    assert set(answered) == {"strings", "functions"}, prepared["routing"]
    for name in ("strings", "functions"):
        assert answered[name]["backend"] == "r2"
        assert answered[name]["coverage"] in ("complete", "partial")
    for name in ("structures", "pointer_tables"):
        row = routing_for(prepared, name)
        assert row["state"] == "unsupported", row
        assert row["backend"] is None
        assert "radare2-mcp 1.8.8 exposes no tool" in str(row["reason"])
    # A pass r2 reported unavailable is recorded as r2's own statement, so a
    # later read can tell it from a pass nobody ever asked about.
    recorded = {
        (entry["pass"], entry["backend"]): entry for entry in prepared["passes"]
    }
    assert ("structures", "r2") in recorded
    assert recorded[("structures", "r2")]["coverage"] == "unavailable"
    assert recorded[("functions", "r2")]["artifact_revision"] is None


@pytest.mark.requires_ida
def test_provider_timeout_and_hash_mismatch_preserve_assessments(
    compiled_calls: Path,
    tmp_path: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    durable_or_reported: Callable[[], AbstractContextManager[list[str]]],
) -> None:
    """A provider that cannot be reached never retires a stored row.

    The first scan runs with both providers unreachable, which is honest
    ``unavailable`` coverage. The second runs with Ghidra's operator map
    pointing at a same-named file with different bytes, which is an identity
    refusal rather than a capability one. Neither may delete a row, and the
    IDA scope they sit beside is untouched by both.

    This scans one target three times, so it saves the managed database three
    times, and IDA 9.4.260714's open bad-pack defect applies — see
    ``tests/conftest.py``. The body runs under the repository's own tolerance
    for that one named vendor defect: either every assertion below stood, or
    the loss was reported *and* the rolled-back database is still internally
    consistent. Do not delete the tolerance to make this test look tidier.
    """
    with durable_or_reported() as produced:
        rules = load_stock_rules()
        monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(tmp_path / "absent.toml"))
        # The decompiler is off, so some rules really do fall through to the
        # providers — which is the only way an unreachable provider can be
        # observed deciding anything.
        first = scan_target(
            str(compiled_calls),
            rules,
            "custom:probe",
            backend="auto",
            decompiler="disabled",
        )
        managed = existing_managed_idb(str(compiled_calls))
        assert managed is not None
        produced.append(managed)
        ida_rows = {row["id"] for row in first["findings"] if row["backend"] == "ida"}
        routed = {row["rule_index"]: row for row in rule_routing(first)}
        reached = [
            row
            for row in routed.values()
            if any(item["backend"] != "ida" for item in row["attempts"])
        ]
        assert reached, routed
        for row in reached:
            for attempt in row["attempts"]:
                if attempt["backend"] == "ida":
                    continue
                assert attempt["outcome"] == "unavailable", (row["rule_index"], attempt)
                assert "is configured" in str(attempt["reason"])

        # Now give Ghidra a map that resolves to a same-named, different-bytes
        # file. The refusal is an identity failure, and the chain stops there
        # rather than letting radare2 answer for a binary nobody matched.
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / compiled_calls.name).write_bytes(b"\x7fELFnot the same image")
        config = tmp_path / "providers.toml"
        config.write_text(
            "\n".join(
                (
                    "[ghidra]",
                    'transport = "stdio"',
                    'command = "/bin/false"',
                    "args = []",
                    "",
                    "[[ghidra.binaries]]",
                    f'local = "{compiled_calls.parent}"',
                    f'remote = "{elsewhere}"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
        second = scan_target(
            str(compiled_calls),
            rules,
            "custom:probe",
            backend="auto",
            decompiler="disabled",
        )
        routed = {row["rule_index"]: row for row in rule_routing(second)}
        refused = [
            row
            for row in routed.values()
            if any(item["outcome"] == "unverified" for item in row["attempts"])
        ]
        assert refused, routed
        for row in refused:
            assert row["state"] == "unverified"
            assert "does not hash to the same bytes" in str(row["reason"])
            assert [item["backend"] for item in row["attempts"]][-1] == "ghidra", (
                "an identity refusal must stop the chain, not advance past it"
            )

        # The IDA scope is exactly where it was. Nothing an unreachable or
        # unverifiable provider did touched it.
        page = findings_across_backends(str(compiled_calls), None, 0, 200)
        assert {row["id"] for row in page["findings"] if row["backend"] == "ida"} >= (
            ida_rows
        )
        assert page["store_health"]["ida"]["available"] is True


@pytest.mark.requires_ghidra
def test_two_separate_requests_restore_r2_analysis(
    compiled_calls: Path, both_providers: Path, managed_data_dir: Path
) -> None:
    """Prepare, then scan, as two separate requests against a stateless server.

    radare2 keeps nothing between sessions, so the second request has to open
    and analyse the file again rather than inherit anything. What must not
    happen is the second request reporting a clean zero because the first
    request's in-memory state is gone.
    """
    require_r2()
    before = digest(compiled_calls)
    prepared = prepare_target(str(compiled_calls), backend="r2", passes=["functions"])
    first = routing_for(prepared, "functions")
    assert first["state"] == "answered"
    assert first["backend"] == "r2"
    entries = [
        row for row in prepared["candidates"] if row["kind"] == "function"
    ]
    assert entries, prepared["candidates"]

    # A second, entirely separate request. The catalog is read from disk and
    # the provider is opened again from scratch.
    page = preparation_page(str(compiled_calls))
    assert page["available"] is True
    assert page["idb_path"] is None
    stored = {row["candidate_id"] for row in page["candidates"]}
    assert {row["candidate_id"] for row in entries} <= stored

    again = prepare_target(str(compiled_calls), backend="r2", passes=["functions"])
    second = routing_for(again, "functions")
    assert second["state"] == "answered"
    assert second["backend"] == "r2"
    # An external revision is never reported reused: its reusability would be
    # a claim about a session that is open now.
    assert again["reused"] is False
    repeated = {
        row["address"] for row in again["candidates"] if row["kind"] == "function"
    }
    assert repeated >= {row["address"] for row in entries}
    assert digest(compiled_calls) == before, "the operator's file was modified"


@pytest.mark.requires_ida
def test_idb_only_cannot_aggregate_unverified_binary(
    compiled_calls: Path, tmp_path: Path, managed_data_dir: Path
) -> None:
    """An unrelated binary never joins a database's stores.

    The database records the digest of the bytes it was built from. A
    ``binary_path`` that hashes to something else is refused by name, the two
    stores stay separate, and the IDA rows are still readable on their own.
    """
    rules = load_stock_rules()[:1]
    scan_target(str(compiled_calls), rules, "default", backend="ida")
    managed = existing_managed_idb(str(compiled_calls))
    assert managed is not None
    saved = tmp_path / "saved.i64"
    shutil.copyfile(managed, saved)

    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"\x7fELF" + b"a different image entirely" * 64)
    with pytest.raises(UnverifiedBinaryError) as refused:
        findings_across_backends(str(compiled_calls), str(unrelated), 0, 50)
    assert "different images" in str(refused.value) or "not the file named" in str(
        refused.value
    )
    assert "nothing was" in str(refused.value).lower()

    # Without a binary_path a database-only read still answers with its own
    # rows and says why the other store was not joined.
    page = findings_across_backends(str(compiled_calls), None, 0, 50)
    assert page["store_health"]["ida"]["available"] is True
    assert isinstance(page["store_health"]["catalog"], dict)

    # And the supplied binary that *is* the right one verifies.
    joined = findings_across_backends(
        str(compiled_calls), str(compiled_calls), 0, 50
    )
    assert joined["store_health"]["catalog"]["available"] is True
    catalog = get_catalog(str(compiled_calls))
    assert catalog is not None
    with catalog:
        assert catalog.source_sha256 == digest(compiled_calls)


@pytest.mark.requires_ghidra
def test_provider_pseudocode_without_facts_is_not_clean(
    compiled_calls: Path, both_providers: Path, managed_data_dir: Path
) -> None:
    """Decompiled C that names a dangerous call is not a verdict either way.

    The fixture really calls ``strcpy``. radare2's decompiler would show that
    text, and its argument annotations are measured wrong on this very
    binary, so the stock rules that index ``param`` must come back
    ``unsupported`` naming the missing fact — never ``High``, never ``Info``,
    and never a clean negative.
    """
    require_r2()
    rules = load_stock_rules()
    result = scan_target(str(compiled_calls), rules, "default", backend="r2")

    states = {
        entry["rule_index"]: entry
        for entry in result["rule_coverage"]
        if entry["backend"] == "r2"
    }
    assert len(states) == len(rules), states
    unsupported = {
        index for index, entry in states.items() if entry["state"] == "unsupported"
    }
    evaluated = {
        index for index, entry in states.items() if entry["state"] == "evaluated"
    }
    # radare2 establishes exactly one structural rule fact
    # (``reachable_from_names``), and no stock rule consumes it. Twenty-three
    # of the twenty-four therefore cannot be answered on this backend at all;
    # the twenty-fourth needs no fact and is answerable only where its target
    # function is in the image. On a fixture that does not call it, that rule
    # is unsupported too — which is the honest answer, not a clean negative.
    assert len(unsupported) >= 23, sorted(
        (index, states[index]["state"]) for index in states
    )
    assert not [index for index, entry in states.items() if entry["state"] == "failed"]
    for index in sorted(unsupported):
        reason = str(states[index]["reason"])
        assert reason
        assert (
            "param" in reason
            or "return_value_checked" in reason
            or "radare2-mcp 1.8.8" in reason
            or "none of them is in the" in reason
        ), (index, reason)
    for index in sorted(evaluated):
        # An evaluated rule on this backend rests on facts, never on text.
        assert states[index]["reason"] is None, states[index]

    # No finding was invented from text, and the IDA store is reported as one
    # nobody looked in rather than one that was empty.
    assert all(row["backend"] != "ida" for row in result["findings"])
    assert result["store_health"]["ida"]["available"] is False
    assert "not opened" in str(result["store_health"]["ida"]["reason"])
    assert result["coverage"] == "partial"

    # The scope that was written says it covered part of the image, so none of
    # its rows could ever be retired by it.
    scope = result["scope_health"]["r2"]
    assert scope["state"] == "evaluated"
    assert scope["coverage"] == "partial"
    assert scope["reason"]


@pytest.mark.requires_ida
def test_an_unverified_binary_refuses_triage_before_it_writes(
    compiled_calls: Path, tmp_path: Path, managed_data_dir: Path
) -> None:
    """Identity is settled before the assessment, not reported after it.

    A refusal that arrives once the status, rationale and revision have
    already changed is not a refusal; it is a mutation with an error message,
    and retrying it increments the revision again.
    """
    rules = load_stock_rules()
    scanned = scan_target(str(compiled_calls), rules, "default", backend="ida")
    rows = [row for row in scanned["findings"] if row["backend"] == "ida"]
    assert rows, scanned["findings"]
    finding_id = str(rows[0]["id"])

    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"\x7fELF" + b"a different image entirely" * 64)
    for _ in range(2):
        with pytest.raises(UnverifiedBinaryError):
            triage_across_backends(
                str(compiled_calls),
                finding_id,
                "Vulnerable",
                "this should never be committed",
                str(unrelated),
            )

    page = findings_across_backends(str(compiled_calls), None, 0, 200)
    held = [row for row in page["findings"] if row["id"] == finding_id]
    assert held, page["findings"]
    # Nothing was written: not the status, not the rationale, and above all
    # not the revision, which two refused attempts would have moved twice.
    assert held[0]["status"] == "Not Checked"
    assert held[0]["rationale"] == ""
    assert held[0]["triage_revision"] == 0
