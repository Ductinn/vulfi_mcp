"""Independent external scopes, and the routing decisions that fill them.

Every test here runs on the host with no licensed IDA and no external
provider process. What they cover is the part of Plan 3 Task 4 that is true
whether or not a provider happens to be up: how a backend's own
``default``/``custom:<scan_name>`` scope is stored, what a partial or failed
scan is allowed to do to the rows it did not observe, what the chain does when
a backend cannot be reached or cannot be shown to be reading the same bytes,
and what the version 1 to version 2 catalog migration does to a database an
earlier commit wrote.

The live halves — a real Ghidra session answering a rule, a real radare2
session answering a pass, a real IDA database refusing to aggregate an
unrelated binary — are in ``tests/integration/test_fallback_routing.py``,
because a provider's behaviour is not something this file may assert from a
stand-in.
"""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from vulfi_mcp import catalog as catalog_module
from vulfi_mcp.catalog import (
    SCHEMA_VERSION,
    CatalogError,
    CatalogSchemaError,
    UnverifiedAssociationError,
    catalog_path,
    get_catalog,
    open_catalog,
)
from vulfi_mcp.prepare import (
    BACKEND_CHAINS,
    PreparationError,
    _external_scope_report,
    _merged_counts,
    _route_passes,
    backend_chain,
    resolve_backend,
)
from vulfi_mcp.rules import load_stock_rules

#: The two external tables exactly as schema version 1 declared them, copied
#: from the commit that shipped them. Written out rather than derived, because
#: a migration test that builds its "old" database from the *new* definitions
#: proves nothing at all.
V1_EXTERNAL_SCOPES = """
    CREATE TABLE IF NOT EXISTS external_scopes (
        scope_id               TEXT PRIMARY KEY,
        target_key             TEXT NOT NULL
                               REFERENCES targets(target_key) ON DELETE CASCADE,
        backend                TEXT NOT NULL,
        scope                  TEXT NOT NULL,
        scan_id                TEXT,
        scanned_at             TEXT,
        coverage               TEXT,
        capability_fingerprint TEXT,
        UNIQUE (target_key, backend, scope)
    )
"""
V1_EXTERNAL_FINDINGS = """
    CREATE TABLE IF NOT EXISTS external_findings (
        finding_id        TEXT PRIMARY KEY,
        scope_id          TEXT NOT NULL
                          REFERENCES external_scopes(scope_id) ON DELETE CASCADE,
        rule_id           TEXT NOT NULL,
        rule_digest       TEXT NOT NULL,
        address_space     TEXT NOT NULL,
        address           INTEGER,
        occurrence        INTEGER NOT NULL DEFAULT 0,
        evidence          TEXT NOT NULL,
        status            TEXT NOT NULL,
        rationale         TEXT,
        triage_revision   INTEGER NOT NULL DEFAULT 0,
        last_seen_scan_id TEXT,
        updated_at        TEXT NOT NULL,
        UNIQUE (scope_id, rule_id, address_space, address, occurrence)
    )
"""

DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def _binary(tmp_path: Path, payload: bytes = b"\x7fELFscopes") -> Path:
    target = tmp_path / "subject"
    target.write_bytes(payload)
    return target


def _finding(
    backend: str,
    scope: str,
    address: int,
    *,
    rule_index: int = 0,
    priority: str = "High",
    occurrence: int = 0,
) -> dict[str, Any]:
    space = f"{backend}:image"
    return {
        "id": (
            f"{backend}:{scope}:{rule_index}:{DIGEST}"
            f":{space}:0x{address:x}:{occurrence}"
        ),
        "backend": backend,
        "source": scope,
        "binary_sha256": None,
        "rule_index": rule_index,
        "rule_digest": DIGEST,
        "rule_name": "Buffer Overflow",
        "function_name": "strcpy",
        "found_in": "handler",
        "address_space": space,
        "address": f"0x{address:x}",
        "relative_address": None,
        "occurrence": occurrence,
        "priority": priority,
        "status": "Not Checked",
        "rationale": "",
        "assessed_at": None,
        "triage_revision": 0,
        "link_id": None,
        "link_revision": None,
        "last_seen_scan_id": "",
        "stale": False,
        "evidence": {"matched_branch": priority},
    }


def _record(
    catalog: Any,
    backend: str,
    scope: str,
    scan_id: str,
    *,
    state: str = "evaluated",
    coverage: str | None = "complete",
    findings: list[dict[str, Any]] | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    return catalog.record_external_scan(
        backend=backend,
        scope=scope,
        scan_id=scan_id,
        scanned_at="2026-10-01T00:00:00Z",
        state=state,
        coverage=coverage,
        reason=reason,
        capability_fingerprint="adapter-test",
        rules=[],
        rule_coverage=[],
        warnings=[],
        findings=findings or [],
    )


def _ids(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row["id"]) for row in rows}


# -- the schema move, and what it does to a database already on disk --------


def _build_version_one(store: Path) -> None:
    """One real version 1 catalog, with a row in every table it declares."""
    store.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(store)
    try:
        for statement in catalog_module._SCHEMA:
            if "external_scopes" in statement or "external_findings" in statement:
                continue
            connection.execute(statement)
        connection.execute(V1_EXTERNAL_SCOPES)
        connection.execute(V1_EXTERNAL_FINDINGS)
        connection.execute(
            "INSERT INTO targets (target_key, source_sha256, managed_idb_id,"
            " source_proof, created_at, updated_at)"
            " VALUES ('sha256:old', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', NULL, NULL, 'then', 'then')"
        )
        connection.execute(
            "INSERT INTO analyses (analysis_id, target_key, requested_backend,"
            " artifact_path, capability_fingerprint, revision, created_at,"
            " updated_at) VALUES ('prep-old', 'sha256:old', 'ida', '/old.i64',"
            " 'fp', 3, 'then', 'then')"
        )
        connection.execute(
            "INSERT INTO passes (analysis_id, name, backend, coverage, ranges,"
            " applied_ids, candidate_ids, warnings, artifact_revision,"
            " recorded_at) VALUES ('prep-old', 'strings', 'ida', 'partial',"
            " '[]', '[]', '[]', '[]', 3, 'then')"
        )
        # Version 1 declared these two tables and this module never wrote
        # them. The migration is checked against a database that *did*, so the
        # claim being proved is "no row is lost", not "no row existed".
        connection.execute(
            "INSERT INTO external_scopes (scope_id, target_key, backend, scope,"
            " scan_id, scanned_at, coverage, capability_fingerprint)"
            " VALUES ('xscope-old', 'sha256:old', 'ghidra', 'default',"
            " 'scan-old', 'then', 'partial', 'fp-old')"
        )
        connection.execute(
            "INSERT INTO external_findings (finding_id, scope_id, rule_id,"
            " rule_digest, address_space, address, occurrence, evidence,"
            " status, rationale, triage_revision, last_seen_scan_id,"
            " updated_at) VALUES ('ghidra:default:0:x:ghidra:image:0x1000:0',"
            " 'xscope-old', '0:x', 'x', 'ghidra:image', 4096, 0, '{}',"
            " 'Vulnerable', 'reviewed by hand', 2, 'scan-old', 'then')"
        )
        connection.execute("PRAGMA user_version = 1")
        connection.commit()
    finally:
        connection.close()


def test_a_version_one_catalog_migrates_with_every_row_intact(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The claim the schema bump rests on is that 1 -> 2 only widens two tables.
    # This proves it against a database that really is at version 1 and really
    # has rows in every table — including the two being altered — rather than
    # against a fresh database stamped with the new number.
    store = catalog_path()
    _build_version_one(store)
    binary = _binary(tmp_path)

    with open_catalog(str(binary)) as catalog:
        connection = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
        try:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
            assert connection.execute(
                "SELECT revision FROM analyses WHERE analysis_id = 'prep-old'"
            ).fetchone() == (3,)
            assert connection.execute(
                "SELECT coverage FROM passes WHERE analysis_id = 'prep-old'"
            ).fetchone() == ("partial",)
            held = connection.execute(
                "SELECT status, rationale, triage_revision, stale, priority,"
                " rule_index FROM external_findings"
            ).fetchone()
            # The assessment an operator made under version 1 survives the
            # migration untouched, and the column that did not exist arrives
            # with the only default that is true of a row no scan has missed.
            assert held == ("Vulnerable", "reviewed by hand", 2, 0, "Info", -1)
            assert connection.execute(
                "SELECT state, reason FROM external_scopes"
            ).fetchone() == ("unavailable", None)
        finally:
            connection.close()
        # And the migrated store is usable, not merely readable.
        assert catalog.external_scopes() == []


def test_a_newer_catalog_is_refused_by_name_rather_than_migrated(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The other direction of the gate. A build that reads version 2 must
    # refuse a version 3 database and name both numbers, which is exactly the
    # refusal a version 1 build gives a version 2 database.
    store = catalog_path()
    _build_version_one(store)
    connection = sqlite3.connect(store)
    try:
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(CatalogSchemaError) as refused:
        open_catalog(str(_binary(tmp_path)))
    assert str(SCHEMA_VERSION + 1) in str(refused.value)
    assert str(SCHEMA_VERSION) in str(refused.value)


def test_the_previous_build_refuses_this_builds_catalog_by_name(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # Loaded from git rather than described: the claim is about code this task
    # does not edit, so the test runs that code.
    repository = Path(__file__).resolve().parents[1]
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed, so the previous build cannot be read")
    shown = subprocess.run(
        [git, "show", "HEAD:src/vulfi_mcp/catalog.py"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
    )
    if shown.returncode != 0:
        pytest.skip(f"git show HEAD:src/vulfi_mcp/catalog.py failed: {shown.stderr}")
    previous = tmp_path / "catalog_at_head.py"
    previous.write_text(shown.stdout, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("vulfi_catalog_at_head", previous)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["vulfi_catalog_at_head"] = module
    try:
        spec.loader.exec_module(module)
        if module.SCHEMA_VERSION >= SCHEMA_VERSION:
            pytest.skip(
                f"HEAD already carries schema version {module.SCHEMA_VERSION};"
                " there is no older build to refuse this one"
            )
        # This build writes the catalog...
        open_catalog(str(_binary(tmp_path))).close()
        # ...and the previous one will not touch it, naming both versions.
        with pytest.raises(module.CatalogSchemaError) as refused:
            module.open_catalog(str(_binary(tmp_path)))
        assert str(SCHEMA_VERSION) in str(refused.value)
        assert str(module.SCHEMA_VERSION) in str(refused.value)
    finally:
        sys.modules.pop("vulfi_catalog_at_head", None)


# -- external rows belong to the original binary ----------------------------


def test_external_rows_need_the_original_binarys_digest(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # A database-only target has no original-binary digest, and an external
    # row is identified by one. Filing it under a provisional key would create
    # a row that could never be joined to the image it describes, so the store
    # refuses outright rather than inventing a namespace for it.
    database = tmp_path / "subject.i64"
    database.write_bytes(b"IDA2 provisional")
    with open_catalog(str(database), "7f3a1c6e9b2d4f508a1c6e9b2d4f5081") as catalog:
        assert catalog.source_sha256 is None
        with pytest.raises(UnverifiedAssociationError) as refused:
            _record(catalog, "ghidra", "default", "scan-1")
    assert "SHA-256 namespace" in str(refused.value)
    assert "Nothing was stored" in str(refused.value)


def test_an_unrelated_binary_cannot_claim_a_databases_external_rows(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The catalog half of the IDB-only aggregation refusal: a binary whose
    # bytes are not the ones the database records cannot be attached to it,
    # whatever its name is.
    database = tmp_path / "subject.i64"
    database.write_bytes(b"IDA2 provisional")
    unrelated = tmp_path / "somewhere" / "subject"
    unrelated.parent.mkdir()
    unrelated.write_bytes(b"\x7fELFsomething else entirely")
    with open_catalog(str(database), "7f3a1c6e9b2d4f508a1c6e9b2d4f5081") as catalog:
        with pytest.raises(UnverifiedAssociationError):
            catalog.attach_source(
                str(unrelated), {"kind": "input_fingerprint", "sha256": "b" * 64}
            )
        assert catalog.source_sha256 is None


# -- what a partial, failed or complete scan may do to a stored scope -------


def test_partial_and_failed_scans_keep_rows_stale_and_preserve_assessments(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = _binary(tmp_path)
    kept = _finding("ghidra", "default", 0x401000)
    gone = _finding("ghidra", "default", 0x402000)
    with open_catalog(str(binary)) as catalog:
        _record(catalog, "ghidra", "default", "scan-1", findings=[kept, gone])
        assessed = catalog.assess_external_finding(
            gone["id"], "Vulnerable", "reachable from the parser"
        )
        assert assessed["triage_revision"] == 1

        # A scan that ran but covered only part of the image saw one row. The
        # other is not evidence of absence: it stays, it is marked stale, and
        # the assessment on it is untouched.
        partial = _record(
            catalog,
            "ghidra",
            "default",
            "scan-2",
            coverage="partial",
            findings=[kept],
            reason="the provider's segment listing was cut short",
        )
        assert partial["retired"] == []
        assert partial["stale"] == [gone["id"]]
        still = catalog.external_finding(gone["id"])
        assert still is not None
        assert still["stale"] is True
        assert still["status"] == "Vulnerable"
        assert still["rationale"] == "reachable from the parser"
        assert still["triage_revision"] == 1
        assert catalog.external_finding(kept["id"])["stale"] is False

        # A scan that could not finish at all may retire even less. It is not
        # a clean sweep with nothing in it.
        failed = _record(
            catalog,
            "ghidra",
            "default",
            "scan-3",
            state="failed",
            coverage=None,
            findings=[],
            reason="get_function_pcode no longer matches its pinned schema",
        )
        assert failed["retired"] == []
        assert set(failed["stale"]) == {kept["id"], gone["id"]}
        scope = catalog.external_scope("ghidra", "default")
        assert scope["state"] == "failed"
        assert scope["coverage"] is None
        assert "pinned schema" in str(scope["reason"])
        assert scope["total"] == 2
        assert scope["stale_total"] == 2


def test_a_later_complete_scan_retires_only_that_backend_and_scope(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = _binary(tmp_path)
    kept = _finding("ghidra", "default", 0x401000)
    gone = _finding("ghidra", "default", 0x402000)
    other_scope = _finding("ghidra", "custom:nightly", 0x403000)
    other_backend = _finding("r2", "default", 0x404000)
    with open_catalog(str(binary)) as catalog:
        _record(catalog, "ghidra", "default", "scan-1", findings=[kept, gone])
        _record(
            catalog,
            "ghidra",
            "custom:nightly",
            "scan-n",
            findings=[other_scope],
        )
        _record(catalog, "r2", "default", "scan-r", findings=[other_backend])
        _record(
            catalog,
            "ghidra",
            "default",
            "scan-2",
            coverage="partial",
            findings=[kept],
        )
        assert catalog.external_finding(gone["id"])["stale"] is True

        complete = _record(
            catalog, "ghidra", "default", "scan-3", findings=[kept]
        )
        # Exactly one row retired, and it is the one this scope's complete
        # scan really did not observe again.
        assert complete["retired"] == [gone["id"]]
        assert complete["stale"] == []
        assert catalog.external_finding(gone["id"]) is None
        assert catalog.external_finding(kept["id"]) is not None
        # Nothing else moved: not the other scope of the same backend, and
        # not the other backend's scope.
        assert catalog.external_finding(other_scope["id"]) is not None
        assert catalog.external_finding(other_backend["id"]) is not None
        totals = catalog.external_totals()
        assert totals["by_backend"]["ghidra"]["total"] == 2
        assert totals["by_backend"]["r2"]["total"] == 1
        assert totals["stale"] == 0


def test_a_scope_cannot_claim_a_coverage_the_scan_did_not_produce(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The pairing is checked rather than assumed. A scan that reports itself
    # failed and complete in one breath is the one row this store must never
    # hold, because `complete` is the only thing allowed to retire anything.
    with open_catalog(str(_binary(tmp_path))) as catalog:
        with pytest.raises(CatalogError) as refused:
            _record(catalog, "r2", "default", "scan-1", state="failed")
        assert "covered nothing" in str(refused.value)
        with pytest.raises(CatalogError):
            _record(catalog, "r2", "default", "scan-1", coverage=None)


def test_a_backend_asked_fewer_rules_than_the_scan_cannot_retire_rows() -> None:
    # The rule that keeps per-rule routing from quietly deleting evidence. A
    # backend reached only for the rules an earlier one could not answer has
    # not looked at the others, so its scope is partial however well the rules
    # it *was* asked went.
    rules = load_stock_rules()
    asked = [3, 7]
    states = {index: ("evaluated", None) for index in asked}
    report = _external_scope_report("ghidra", rules, asked, states, True, None)
    assert report["state"] == "evaluated"
    assert report["coverage"] == "partial"
    assert "were answered before the ghidra backend was reached" in str(
        report["reason"]
    )

    whole = {index: ("evaluated", None) for index in range(len(rules))}
    full = _external_scope_report(
        "ghidra", rules, list(range(len(rules))), whole, True, None
    )
    assert full["coverage"] == "complete"
    assert full["reason"] is None

    # One truncated read is a veto on its own, with every rule evaluated.
    bounded = _external_scope_report(
        "ghidra", rules, list(range(len(rules))), whole, False, None
    )
    assert bounded["coverage"] == "partial"
    assert "could not read in full" in str(bounded["reason"])


def test_counts_over_no_store_are_absent_rather_than_zero() -> None:
    # An empty mapping says "nothing answered". A table of zeroes says "every
    # store answered and held nothing", and only one of those is true of a
    # target with no store.
    assert _merged_counts({}, {}) == {}
    merged = _merged_counts(
        {"ida": {"Not Checked": 2, "Vulnerable": 1}},
        {"ghidra": {"Not Checked": 1}},
    )
    # The aggregate counts findings, not deduplicated vulnerabilities.
    assert merged["aggregate"]["Not Checked"] == 3
    assert merged["aggregate"]["Vulnerable"] == 1


# -- what the chain does when a backend cannot be reached or proved ---------


def _providers_toml(tmp_path: Path, body: str, monkeypatch: Any) -> Path:
    config = tmp_path / "providers.toml"
    config.write_text(body, encoding="utf-8")
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(config))
    return config


def test_an_unconfigured_provider_is_unavailable_and_the_chain_goes_on(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No configuration at all. Both providers are *unavailable* — nobody
    # looked — which is not the same claim as a pass that ran and found
    # nothing, and the chain asks each of them in turn rather than stopping at
    # the first.
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(tmp_path / "absent.toml"))
    binary = _binary(tmp_path)
    routed = _route_passes(str(binary), ("ghidra", "r2"), ("strings", "functions"))
    assert routed.results == []
    assert routed.idb_path is None
    for row in routed.routing:
        assert row["backend"] is None
        assert row["state"] == "unavailable"
        assert row["coverage"] == "unavailable"
        assert [item["backend"] for item in row["attempts"]] == ["ghidra", "r2"]
        assert {item["outcome"] for item in row["attempts"]} == {"unavailable"}
        for attempt in row["attempts"]:
            assert "is configured" in str(attempt["reason"])


def test_an_unprovable_identity_stops_the_chain_instead_of_advancing(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Ghidra is configured, but its operator-verified map does not carry this
    # file. "We cannot show this provider is reading the same bytes" is not
    # "this provider had nothing to offer", so the pass stops there: radare2
    # is never asked, and nothing it might have said can be reported as this
    # target's answer.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _providers_toml(
        tmp_path,
        "\n".join(
            (
                "[ghidra]",
                'transport = "stdio"',
                'command = "/bin/false"',
                "args = []",
                "",
                "[[ghidra.binaries]]",
                f'local = "{elsewhere}"',
                f'remote = "{elsewhere}"',
                "",
                "[r2]",
                'transport = "stdio"',
                'command = "/bin/false"',
                "args = []",
                "",
                "[[r2.binaries]]",
                f'local = "{tmp_path}"',
                f'remote = "{tmp_path}"',
                "",
            )
        ),
        monkeypatch,
    )
    binary = _binary(tmp_path)
    routed = _route_passes(str(binary), ("ghidra", "r2"), ("strings",))
    (row,) = routed.routing
    assert row["state"] == "unverified"
    assert row["backend"] is None
    assert [item["backend"] for item in row["attempts"]] == ["ghidra"]
    assert row["attempts"][0]["outcome"] == "unverified"
    assert "operator-configured binary map" in str(row["reason"])


def test_a_mapped_file_with_different_bytes_is_an_identity_refusal(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same basename, different bytes, through the operator's own map. The
    # digests are compared here, before a session is opened, so nothing is
    # analysed and nothing is written.
    here = tmp_path / "here"
    there = tmp_path / "there"
    here.mkdir()
    there.mkdir()
    (here / "subject").write_bytes(b"\x7fELFthe real one")
    (there / "subject").write_bytes(b"\x7fELFa different one")
    _providers_toml(
        tmp_path,
        "\n".join(
            (
                "[r2]",
                'transport = "stdio"',
                'command = "/bin/false"',
                "args = []",
                "",
                "[[r2.binaries]]",
                f'local = "{here}"',
                f'remote = "{there}"',
                "",
            )
        ),
        monkeypatch,
    )
    routed = _route_passes(str(here / "subject"), ("r2",), ("strings",))
    (row,) = routed.routing
    assert row["state"] == "unverified"
    assert "does not hash to the same bytes" in str(row["reason"])
    assert "Nothing was analysed" in str(row["reason"])
    assert routed.results == []


# -- the selector itself ----------------------------------------------------


def test_every_named_backend_resolves_to_a_chain_that_starts_at_it() -> None:
    assert backend_chain("auto") == ("ida", "ghidra", "r2")
    for name in ("ida", "ghidra", "r2"):
        assert backend_chain(name) == (name,)
        assert resolve_backend(name) == name
    assert resolve_backend("auto") == "ida"
    assert set(BACKEND_CHAINS) == {"auto", "ida", "ghidra", "r2"}


def test_a_backend_this_design_does_not_name_is_refused() -> None:
    with pytest.raises(PreparationError) as refused:
        backend_chain("binaryninja")
    assert "not a backend this design names" in str(refused.value)
    assert "auto, ida, ghidra, r2" in str(refused.value)


def test_a_catalog_that_is_not_there_is_unavailable_not_empty(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # A read never creates the store it could not find, and "there is no
    # store" is the answer rather than "this target has no external rows".
    assert get_catalog(str(_binary(tmp_path))) is None
    assert not catalog_path().exists()
    assert list(managed_data_dir.rglob("*.sqlite3")) == []
