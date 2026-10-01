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

from vulfi_mcp.catalog import get_catalog, open_catalog
from vulfi_mcp.ida_adapter import existing_managed_idb
from vulfi_mcp.prepare import (
    UnverifiedBinaryError,
    _coverage,
    _record,
    _reused_routing,
    _route_passes,
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


# --------------------------------------------------------------------------
# fix round 2: a real mid-call refusal is failed, and stays failed
# --------------------------------------------------------------------------


@pytest.mark.requires_ghidra
def test_a_drifted_list_strings_failure_survives_a_later_complete_answer(
    compiled_calls: Path,
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session that opened and then had a pass refused is failed, and stays so.

    Drifting the pinned ``list_strings`` schema is not "this backend has no
    typed tool". The refusal has to be stored as a failed attempt in the
    provider's own words, and a later backend that completes the same pass
    must not erase it into a clean complete answer. ``structures`` has no
    typed tool and stays unsupported.
    """
    require_r2()
    import vulfi_mcp.prepare as prepare
    import vulfi_mcp.providers.ghidra as ghidra

    pins = dict(ghidra.PINNED_SCHEMAS)
    pins["list_strings"] = "0" * 64
    monkeypatch.setattr(ghidra, "PINNED_SCHEMAS", pins)
    real = prepare._PREPARE["r2"]

    async def complete_strings(target: str, passes: tuple[str, ...]) -> tuple[Any, ...]:
        produced = await real(target, passes)
        forced = []
        for entry in produced:
            row = dict(entry)
            # A real strings pass on this fixture is partial — code is not
            # swept — and that would hide the defect. The defect is a later
            # *complete* answer rebuilding the row as if nothing failed.
            if row.get("pass") == "strings":
                row["coverage"] = "complete"
            forced.append(row)
        return tuple(forced)

    monkeypatch.setitem(prepare._PREPARE, "r2", complete_strings)
    requested = ("strings", "structures")
    routed = _route_passes(str(compiled_calls), ("ghidra", "r2"), requested)
    strings = routing_for({"routing": routed.routing}, "strings")
    structures = routing_for({"routing": routed.routing}, "structures")
    ghidra_strings = next(
        item for item in strings["attempts"] if item["backend"] == "ghidra"
    )
    ghidra_structures = next(
        item for item in structures["attempts"] if item["backend"] == "ghidra"
    )
    report = _record(
        str(compiled_calls), "ghidra", ("ghidra", "r2"), requested, routed
    )
    reopened = get_catalog(str(compiled_calls))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("strings",), stored)
    detail = (
        f"ghidra attempt={ghidra_strings!r}\n"
        f"structures attempt={ghidra_structures!r}\n"
        f"fresh={strings!r}\n"
        f"reused={reused!r}\n"
        f"revision_coverage={_coverage(stored)!r}"
    )
    assert ghidra_strings["outcome"] == "failed", detail
    assert ghidra_strings["reason"], detail
    assert "list_strings" in ghidra_strings["reason"], detail
    assert "named no reason" not in ghidra_strings["reason"], detail
    assert ghidra_structures["outcome"] == "unsupported", detail
    assert reused["coverage"] != "complete", detail
    assert not (reused["state"] == "answered" and reused["attempts"] == []), detail
    failed = [item for item in reused["attempts"] if item["outcome"] == "failed"]
    assert failed and failed[0]["backend"] == "ghidra", detail
    assert failed[0]["reason"] and "list_strings" in failed[0]["reason"], detail
    assert "named no reason" not in failed[0]["reason"], detail
    assert _coverage(stored) != "complete", detail
    # The later answer may sit beside the failure. It must not replace it.
    assert reused["backend"] == "r2", detail


def test_an_r2_unavailable_pass_is_failed_and_not_dropped(
    compiled_calls: Path,
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """r2's per-pass refusal is failed; a missing tool stays unsupported.

    ``_unavailable_pass`` keeps the refusal on the ranges. That is still a
    session that opened and could not finish, and a later complete answer
    must not drop it. ``structures`` has no typed tool and stays unsupported.
    The strings pass beside the drifted tool is not taken down with it.
    """
    require_r2()
    import vulfi_mcp.providers.r2 as r2

    pins = dict(r2.PINNED_SCHEMAS)
    pins["list_symbols"] = "0" * 64
    monkeypatch.setattr(r2, "PINNED_SCHEMAS", pins)
    requested = ("strings", "functions", "structures")
    routed = _route_passes(str(compiled_calls), ("r2",), requested)
    functions = routing_for({"routing": routed.routing}, "functions")
    strings = routing_for({"routing": routed.routing}, "strings")
    structures = routing_for({"routing": routed.routing}, "structures")
    (functions_attempt,) = functions["attempts"]
    (strings_attempt,) = strings["attempts"]
    (structures_attempt,) = structures["attempts"]
    report = _record(str(compiled_calls), "r2", ("r2",), requested, routed)
    # r2 is last in every public chain, so the later complete answer is
    # written beside the failure the way a chain that advanced would write it.
    with open_catalog(str(compiled_calls)) as catalog:
        catalog.record_pass(
            report["analysis_id"],
            {
                "pass": "functions",
                "backend": "ghidra",
                "ranges": [{"start": 0x1000, "end": 0x2000}],
                "coverage": "complete",
                "applied_ids": [],
                "candidate_ids": [],
                "candidates": [],
                "warnings": [],
                "artifact_revision": None,
            },
        )
    reopened = get_catalog(str(compiled_calls))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("functions",), stored)
    detail = (
        f"functions={functions_attempt!r}\n"
        f"strings={strings_attempt!r}\n"
        f"structures={structures_attempt!r}\n"
        f"reused={reused!r}"
    )
    assert functions_attempt["outcome"] == "failed", detail
    assert (
        functions_attempt["reason"]
        and "list_symbols" in functions_attempt["reason"]
    ), detail
    assert "named no reason" not in functions_attempt["reason"], detail
    assert strings_attempt["outcome"] == "answered", detail
    assert structures_attempt["outcome"] == "unsupported", detail
    assert any(
        item["backend"] == "r2"
        and item["outcome"] == "failed"
        and item["reason"]
        and "list_symbols" in item["reason"]
        for item in reused["attempts"]
    ), detail
    assert reused["coverage"] != "complete", detail
    assert not (reused["state"] == "answered" and reused["attempts"] == []), detail



def _own_r2mcp_pids() -> list[int]:
    """r2mcp processes this test started, not the Ghidra JVM."""
    me = str(os.getpid())
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        comm_end = stat.rfind(")")
        if comm_end < 0:
            continue
        fields = stat[comm_end + 2 :].split()
        if len(fields) < 2 or fields[1] != me:
            continue
        comm = stat[stat.find("(") + 1 : comm_end]
        if comm == "r2mcp":
            found.append(int(entry.name))
    return found


def _data_only_elf(tmp_path: Path) -> Path:
    """An ELF whose sections are readable and none are executable.

    A normal image keeps the strings pass ``partial`` when a read dies,
    because executable sections are an intentional skip. This image has no
    such skip, so a dead read is the whole pass.
    """
    source = tmp_path / "dataonly.c"
    source.write_text('const char vulfi_only[] = "vulfi-data-only-marker";\n', encoding="utf-8")
    script = tmp_path / "dataonly.ld"
    script.write_text("SECTIONS { .rodata 0x400000 : { *(.rodata*) } }\n", encoding="utf-8")
    binary = tmp_path / "dataonly"
    completed = subprocess.run(
        [
            "gcc",
            "-nostdlib",
            "-nostartfiles",
            "-e",
            "0",
            "-Wl,-T," + str(script),
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"building a data-only ELF failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


def _r2mcp_children() -> list[int]:
    me = str(os.getpid())
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        comm_end = stat.rfind(")")
        if comm_end < 0:
            continue
        fields = stat[comm_end + 2 :].split()
        if len(fields) < 2 or fields[1] != me:
            continue
        if stat[stat.find("(") + 1 : comm_end] == "r2mcp":
            found.append(int(entry.name))
    return found


def _kill_r2_before_hexdump(monkeypatch: pytest.MonkeyPatch) -> None:
    """SIGKILL this test's r2mcp child on the first read, then call through.

    The session has already opened and analysed: ``_read`` is the first
    ``hexdump``. The refusal has to be the dead child's own connection error.
    Ghidra is not signalled.
    """
    import signal

    import vulfi_mcp.providers.r2 as r2

    real = r2._read

    async def kill_then_read(session: Any, start: int, length: int) -> bytes:
        # Each session has its own child. Kill it once, on the read that
        # would have been hexdump, then let the real call observe the death.
        for pid in _r2mcp_children():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
        return await real(session, start, length)

    monkeypatch.setattr(r2, "_read", kill_then_read)


def _killed_strings_row(binary: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    requested = ("strings", "structures")
    routed = _route_passes(str(binary), ("r2",), requested)
    strings = routing_for({"routing": routed.routing}, "strings")
    structures = routing_for({"routing": routed.routing}, "structures")
    report = _record(str(binary), "r2", ("r2",), requested, routed)
    with open_catalog(str(binary)) as catalog:
        catalog.record_pass(
            report["analysis_id"],
            {
                "pass": "strings",
                "backend": "ghidra",
                "ranges": [{"start": 0x1000, "end": 0x2000}],
                "coverage": "complete",
                "applied_ids": [],
                "candidate_ids": [],
                "candidates": [],
                "warnings": [],
                "artifact_revision": None,
            },
        )
    reopened = get_catalog(str(binary))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("strings",), stored)
    held = [
        {
            "backend": entry["backend"],
            "coverage": entry["coverage"],
            "reasons": [item.get("reason") for item in entry.get("ranges", []) if isinstance(item, dict)],
            "warnings": entry.get("warnings"),
        }
        for entry in stored
        if entry["pass"] == "strings"
    ]
    return {"strings": strings, "structures": structures, "held": held}, reused


def test_a_killed_r2_read_is_failed_on_both_image_shapes(
    compiled_calls: Path,
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A dead r2mcp child during a read is failed, skip or no skip.

    SIGKILL before ``hexdump``. On a data-only image every range is that
    read, so the pass is unavailable and was recorded ``unsupported``. On a
    normal ELF the executable sections are an intentional skip, so the same
    kill was recorded ``answered``/``partial`` and the chain did not advance.
    Both must be ``failed`` with the child's own refusal. ``structures`` has
    no typed tool and stays unsupported. A later complete answer may sit
    beside the failure and must not report ``complete``.
    """
    require_r2()
    data_only = _data_only_elf(tmp_path)
    _kill_r2_before_hexdump(monkeypatch)
    data_rows, data_reused = _killed_strings_row(data_only)
    # A second session, killed the same way. The patch is still installed.
    elf_rows, elf_reused = _killed_strings_row(compiled_calls)
    detail = (
        f"data strings={data_rows['strings']!r}\n"
        f"data structures={data_rows['structures']!r}\n"
        f"data reused={data_reused!r}\n"
        f"elf strings={elf_rows['strings']!r}\n"
        f"elf structures={elf_rows['structures']!r}\n"
        f"elf reused={elf_reused!r}\n"
        f"data held={data_rows['held']!r}\n"
        f"elf held={elf_rows['held']!r}"
    )
    for label, rows, reused in (
        ("data-only", data_rows, data_reused),
        ("elf", elf_rows, elf_reused),
    ):
        attempt = next(
            item for item in rows["strings"]["attempts"] if item["backend"] == "r2"
        )
        assert attempt["outcome"] == "failed", detail
        assert attempt["reason"], detail
        assert "named no reason" not in attempt["reason"], detail
        assert "Connection closed" in attempt["reason"] or "MCP" in attempt["reason"], detail
        assert rows["structures"]["attempts"][0]["outcome"] == "unsupported", detail
        assert reused["coverage"] != "complete", detail
        assert not (reused["state"] == "answered" and reused["attempts"] == []), detail
        assert any(
            item["backend"] == "r2" and item["outcome"] == "failed" and item["reason"]
            for item in reused["attempts"]
        ), detail
        assert label


def test_a_read_budget_stop_is_not_a_failed_pass(
    compiled_calls: Path,
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running out of read budget is a partial answer, not a dead session."""
    require_r2()
    import vulfi_mcp.providers.r2 as r2

    monkeypatch.setattr(r2, "MAX_PASS_READ_BYTES", 1)
    routed = _route_passes(str(compiled_calls), ("r2",), ("strings", "structures"))
    strings = routing_for({"routing": routed.routing}, "strings")
    structures = routing_for({"routing": routed.routing}, "structures")
    (strings_attempt,) = strings["attempts"]
    (structures_attempt,) = structures["attempts"]
    assert strings_attempt["outcome"] != "failed", strings
    assert strings_attempt["outcome"] == "answered", strings
    assert strings["coverage"] != "complete", strings
    assert structures_attempt["outcome"] == "unsupported", structures


def _one_mapped_section_elf(tmp_path: Path) -> Path:
    """An ELF with one mapped section, and that section is not executable.

    A normal data-only link still maps ``.interp`` and the dynamic tables.
    Killing the child on ``lookup_address`` then dies on the next section's
    ``hexdump``, and that sweep refusal hides the corroboration catch. This
    image has nothing after the one read.
    """
    source = tmp_path / "one-section.c"
    source.write_text(
        'const char vulfi_only[] = "vulfi-data-only-marker";\n',
        encoding="utf-8",
    )
    script = tmp_path / "one-section.ld"
    script.write_text(
        "SECTIONS {\n"
        "  .rodata 0x400000 : { *(.rodata*) }\n"
        "  /DISCARD/ : { *(*) }\n"
        "}\n",
        encoding="utf-8",
    )
    binary = tmp_path / "one-section"
    completed = subprocess.run(
        [
            "gcc",
            "-nostdlib",
            "-nostartfiles",
            "-static",
            "-Wl,--no-dynamic-linker",
            "-e",
            "0",
            "-Wl,-T," + str(script),
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"building a one-section ELF failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


def _kill_r2_on_lookup_address(monkeypatch: pytest.MonkeyPatch) -> None:
    """SIGKILL this test's r2mcp child on the first flag lookup, then call through.

    The strings have already been read. ``lookup_address`` only asks whether
    radare2 holds a flag at an address the pass already has bytes for. The
    refusal has to be the dead child's own connection error.
    """
    import signal

    import vulfi_mcp.providers.r2 as r2

    real = r2._call

    async def kill_on_lookup(session: Any, tool: str, **arguments: Any) -> str:
        if tool == "lookup_address":
            for pid in _r2mcp_children():
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    continue
        return await real(session, tool, **arguments)

    monkeypatch.setattr(r2, "_call", kill_on_lookup)


def test_a_killed_lookup_on_one_section_keeps_the_read(
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A dead flag lookup after a one-section read is not a clean complete.

    The bytes were already read. ``lookup_address`` is corroboration, so the
    measured strings stay, coverage is not complete, reuse carries the dead
    child's refusal, and the chain does not discard the read or ask the next
    backend to stand in for it.
    """
    require_r2()
    import vulfi_mcp.prepare as prepare
    from vulfi_mcp.providers.ghidra import GhidraUnavailableError

    binary = _one_mapped_section_elf(tmp_path)
    _kill_r2_on_lookup_address(monkeypatch)
    asked: list[str] = []

    async def next_backend(target: str, passes: tuple[str, ...]) -> tuple[Any, ...]:
        asked.extend(passes)
        if "strings" in passes:
            raise AssertionError(
                "the chain advanced over a strings read that had already"
                f" succeeded: {passes!r}"
            )
        raise GhidraUnavailableError(
            "sentinel: ghidra was not asked to replace a measured strings read"
        )

    monkeypatch.setitem(prepare._PREPARE, "ghidra", next_backend)
    requested = ("strings", "structures")
    routed = _route_passes(str(binary), ("r2", "ghidra"), requested)
    strings = routing_for({"routing": routed.routing}, "strings")
    structures = routing_for({"routing": routed.routing}, "structures")
    report = _record(str(binary), "r2", ("r2", "ghidra"), requested, routed)
    reopened = get_catalog(str(binary))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("strings",), stored)
    texts = [
        str((row.get("evidence") or {}).get("text") or "")
        for _entry, rows in routed.results
        if _entry.get("pass") == "strings"
        for row in rows.values()
    ]
    detail = (
        f"strings={strings!r}\n"
        f"structures={structures!r}\n"
        f"reused={reused!r}\n"
        f"texts={texts!r}\n"
        f"asked={asked!r}\n"
        f"stored={stored!r}"
    )
    assert any("vulfi-data-only-marker" in text for text in texts), detail
    assert strings["state"] == "answered", detail
    assert strings["backend"] == "r2", detail
    assert strings["coverage"] != "complete", detail
    assert "strings" not in asked, detail
    failed = [item for item in strings["attempts"] if item["outcome"] == "failed"]
    assert failed and failed[0]["backend"] == "r2", detail
    assert failed[0]["reason"], detail
    assert "Connection closed" in failed[0]["reason"] or "MCP" in failed[0]["reason"], detail
    assert structures["attempts"][0]["outcome"] == "unsupported", detail
    assert reused["state"] == "answered", detail
    assert reused["coverage"] != "complete", detail
    assert reused["backend"] == "r2", detail
    assert any(
        item["backend"] == "r2"
        and item["outcome"] == "failed"
        and item["reason"]
        and ("Connection closed" in item["reason"] or "MCP" in item["reason"])
        for item in reused["attempts"]
    ), detail


def _measured_rows(routed: Any, name: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [
        (entry, rows)
        for entry, rows in routed.results
        if entry.get("pass") == name and rows
    ]


def test_an_extent_refusal_keeps_the_functions(
    compiled_calls: Path,
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused extent is not laundered by the next call, and not a sweep death.

    ``disassemble_function`` refuses. ``xrefs_to`` still answers, so the catch
    itself has to mark the pass. The function rows stay, coverage is not
    complete, and reuse carries the refusal.
    """
    require_r2()
    import vulfi_mcp.prepare as prepare
    import vulfi_mcp.providers.r2 as r2
    from vulfi_mcp.providers.client import ProviderError
    from vulfi_mcp.providers.ghidra import GhidraUnavailableError

    real = r2._call
    refusal = "disassemble_function refused: connection closed"

    async def refuse_extent(session: Any, tool: str, **arguments: Any) -> str:
        if tool == "disassemble_function":
            raise ProviderError(refusal)
        return await real(session, tool, **arguments)

    monkeypatch.setattr(r2, "_call", refuse_extent)
    asked: list[str] = []

    async def next_backend(target: str, passes: tuple[str, ...]) -> tuple[Any, ...]:
        asked.extend(passes)
        if "functions" in passes:
            raise AssertionError(
                "the chain advanced over function rows that were already"
                f" measured: {passes!r}"
            )
        raise GhidraUnavailableError("sentinel: not standing in for functions")

    monkeypatch.setitem(prepare._PREPARE, "ghidra", next_backend)
    requested = ("functions", "structures")
    routed = _route_passes(str(compiled_calls), ("r2", "ghidra"), requested)
    functions = routing_for({"routing": routed.routing}, "functions")
    structures = routing_for({"routing": routed.routing}, "structures")
    report = _record(str(compiled_calls), "r2", ("r2", "ghidra"), requested, routed)
    reopened = get_catalog(str(compiled_calls))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("functions",), stored)
    measured = _measured_rows(routed, "functions")
    kinds = [
        (row.get("evidence") or {}).get("reference_kinds")
        for _entry, rows in measured
        for row in rows.values()
    ]
    detail = (
        f"functions={functions!r}\n"
        f"structures={structures!r}\n"
        f"reused={reused!r}\n"
        f"asked={asked!r}\n"
        f"candidates={len(kinds)} kinds={kinds[:4]!r}"
    )
    assert measured, detail
    assert any(kind is not None for kind in kinds), detail
    assert functions["state"] == "answered", detail
    assert functions["backend"] == "r2", detail
    assert functions["coverage"] != "complete", detail
    assert "functions" not in asked, detail
    failed = [item for item in functions["attempts"] if item["outcome"] == "failed"]
    assert failed and failed[0]["reason"] and refusal in failed[0]["reason"], detail
    assert structures["attempts"][0]["outcome"] == "unsupported", detail
    assert reused["state"] == "answered", detail
    assert reused["backend"] == "r2", detail
    assert reused["coverage"] != "complete", detail
    assert any(
        item["outcome"] == "failed" and item["reason"] and refusal in item["reason"]
        for item in reused["attempts"]
    ), detail


def _refuse_ghidra_tool(monkeypatch: pytest.MonkeyPatch, tool: str, refusal: str) -> None:
    import vulfi_mcp.providers.ghidra as ghidra
    from vulfi_mcp.providers.client import ProviderError

    real = ghidra._call_json

    async def refuse(session: Any, called: str, **arguments: Any) -> dict[str, Any]:
        if called == tool:
            raise ProviderError(refusal)
        return await real(session, called, **arguments)

    monkeypatch.setattr(ghidra, "_call_json", refuse)


def _ghidra_kept(
    binary: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    want_candidate_reason: str | None = None,
) -> str:
    """Route one live Ghidra functions pass and return a failure detail.

    The next backend is a sentinel. It must not be asked for ``functions``.
    """
    import vulfi_mcp.prepare as prepare
    from vulfi_mcp.providers.r2 import R2UnavailableError

    asked: list[str] = []

    async def next_backend(target: str, passes: tuple[str, ...]) -> tuple[Any, ...]:
        asked.extend(passes)
        if "functions" in passes:
            raise AssertionError(
                "the chain advanced over a functions pass that had already"
                f" measured something: {passes!r}"
            )
        raise R2UnavailableError("sentinel: not standing in for functions")

    monkeypatch.setitem(prepare._PREPARE, "r2", next_backend)
    requested = ("functions", "structures")
    routed = _route_passes(str(binary), ("ghidra", "r2"), requested)
    functions = routing_for({"routing": routed.routing}, "functions")
    structures = routing_for({"routing": routed.routing}, "structures")
    report = _record(str(binary), "ghidra", ("ghidra", "r2"), requested, routed)
    reopened = get_catalog(str(binary))
    assert reopened is not None
    with reopened:
        stored = reopened.pass_results(report["analysis_id"])
    (reused,) = _reused_routing(("functions",), stored)
    measured = [
        (entry, rows)
        for entry, rows in routed.results
        if entry.get("pass") == "functions" and entry.get("ranges")
    ]
    reasons = [
        row.get("reason")
        for _entry, rows in routed.results
        if _entry.get("pass") == "functions"
        for row in rows.values()
    ]
    detail = (
        f"functions={functions!r}\n"
        f"structures={structures!r}\n"
        f"reused={reused!r}\n"
        f"asked={asked!r}\n"
        f"ranges={len(measured)} reasons={reasons[:6]!r}"
    )
    assert measured, detail
    assert functions["state"] == "answered", detail
    assert functions["backend"] == "ghidra", detail
    assert functions["coverage"] != "complete", detail
    assert "functions" not in asked, detail
    failed = [item for item in functions["attempts"] if item["outcome"] == "failed"]
    assert failed and failed[0]["backend"] == "ghidra" and failed[0]["reason"], detail
    assert structures["attempts"][0]["outcome"] == "unsupported", detail
    assert reused["state"] == "answered" and reused["backend"] == "ghidra", detail
    assert reused["coverage"] != "complete", detail
    assert any(
        item["outcome"] == "failed" and item["reason"] == failed[0]["reason"]
        for item in reused["attempts"]
    ), detail
    if want_candidate_reason is not None:
        assert any(
            isinstance(reason, str) and want_candidate_reason in reason
            for reason in reasons
        ), detail
    return str(failed[0]["reason"])


@pytest.mark.requires_ghidra
def test_a_refused_control_flow_keeps_the_measured_functions(
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``analyze_control_flow`` refusing does not erase the functions pass."""
    refusal = "analyze_control_flow refused: connection closed"
    _refuse_ghidra_tool(monkeypatch, "analyze_control_flow", refusal)
    reason = _ghidra_kept(_readable_function_elf(tmp_path), monkeypatch)
    assert refusal in reason, reason


@pytest.mark.requires_ghidra
def test_a_refused_sixteen_byte_read_keeps_the_measured_functions(
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The 16-byte corroboration read refusing does not erase the pass."""
    import inspect

    import vulfi_mcp.providers.ghidra as ghidra
    from vulfi_mcp.providers.client import ProviderError

    refusal = "the 16-byte read refused: connection closed"
    real = ghidra._read

    async def refuse_corroboration(session: Any, start: int, length: int) -> bytes:
        caller = inspect.currentframe()
        name = caller.f_back.f_code.co_name if caller is not None and caller.f_back else ""
        if length == 16 and name == "_functions_pass":
            raise ProviderError(refusal)
        return await real(session, start, length)

    monkeypatch.setattr(ghidra, "_read", refuse_corroboration)
    reason = _ghidra_kept(_readable_function_elf(tmp_path), monkeypatch)
    assert refusal in reason, reason


def _readable_function_elf(tmp_path: Path) -> Path:
    """A function, an unmarked entry, and a pointer, with no unreadable block.

    The stock fallback image has a ``.bss`` GhidraMCP cannot read. That sweep
    refusal fails the whole functions pass and hides the corroboration catch
    the test is about. This image's blocks are initialized and readable.
    """
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite("gcc is not installed, so the corroboration image cannot be built")
    source = tmp_path / "readable.c"
    source.write_text(
        r"""void defined(int value) {
    int total = value + 1;
    __asm__ volatile(".globl vulfi_tail\nvulfi_tail:");
    total += 3;
    (void)total;
}
__asm__(
    ".section .vulfi_hidden,\"ax\",@progbits\n"
    ".balign 16\n"
    "  endbr64\n"
    "  mov %edi,%eax\n"
    "  add $0x2a,%eax\n"
    "  ret\n"
    ".previous\n"
);
__asm__(
    ".section .vulfi_ptrs,\"aw\",@progbits\n"
    ".balign 8\n"
    ".globl vulfi_pointer_table\n"
    "vulfi_pointer_table:\n"
    "  .quad .vulfi_hidden\n"
    "  .quad vulfi_tail\n"
    ".previous\n"
);
""",
        encoding="utf-8",
    )
    binary = tmp_path / "readable"
    completed = subprocess.run(
        [
            str(compiler),
            "-nostdlib",
            "-nostartfiles",
            "-static",
            "-Wl,--no-dynamic-linker",
            "-e",
            "0",
            "-O0",
            "-fno-builtin",
            "-fno-inline",
            "-o",
            str(binary),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"building a readable function ELF failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


@pytest.mark.requires_ghidra
def test_a_refused_create_function_keeps_the_candidate(
    both_providers: Path,
    managed_data_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``create_function`` refusing stays on the pass, and the candidate stays."""
    refusal = "create_function refused: connection closed"
    _refuse_ghidra_tool(monkeypatch, "create_function", refusal)
    binary = _readable_function_elf(tmp_path)
    reason = _ghidra_kept(
        binary,
        monkeypatch,
        want_candidate_reason="the provider refused to define this entry",
    )
    assert refusal in reason, reason
