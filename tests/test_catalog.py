"""The preparation catalog: one identity per target, and an absence that says so.

Every test here runs on the host without a licensed IDA. The catalog keys a
target by the SHA-256 of its original bytes when those bytes exist, and by the
provisional ``managed_idb_id`` the netnode minted when only a database does;
the second identity may not be joined to raw bytes until a fingerprint or a
segment-byte association actually verifies the relationship. A catalog that is
not there is unavailable, which is a different answer from a catalog with no
candidates in it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from vulfi_mcp.catalog import (
    ASSOCIATION_ASSERTED,
    ASSOCIATION_VERIFIED,
    CATALOG_NAME,
    MIN_SEGMENT_PROOF_BYTES,
    SCHEMA_VERSION,
    CatalogError,
    CatalogSchemaError,
    ReadOnlyCatalogError,
    UnknownAnalysisError,
    UnverifiedAssociationError,
    catalog_path,
    get_catalog,
    open_catalog,
)

#: A ``managed_idb_id`` of exactly the shape ``ida_runtime`` mints on the first
#: netnode write (``uuid.uuid4().hex``). Written out rather than read from a
#: database, because nothing here may need IDA to run.
PROVISIONAL = "7f3a1c6e9b2d4f508a1c6e9b2d4f5081"
OTHER_PROVISIONAL = "0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f6"

#: Suffixes a stray store would carry, anywhere it does not belong.
_STORE_SUFFIXES = frozenset({".sqlite", ".sqlite3", ".db"})


def _write_binary(path: Path, payload: bytes) -> str:
    """Write ``payload`` and return the SHA-256 the catalog must key it by."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _pass_result(
    name: str = "strings",
    *,
    candidates: list[dict[str, object]] | None = None,
    coverage: str = "complete",
) -> dict[str, object]:
    """One pass result of the shape Task 2's worker produces."""
    rows = [
        {
            "candidate_id": "cand-1",
            "kind": "string",
            "backend": "ida",
            "address_space": "image",
            "address": 0x401000,
            "evidence": {"bytes": "68656c6c6f", "encoding": "ascii"},
            "confidence": 0.9,
            "state": "candidate",
            "reason": None,
        },
        {
            "candidate_id": "cand-2",
            "kind": "string",
            "backend": "ida",
            "address_space": "image",
            "address": 0x401020,
            "evidence": {"bytes": "77006f00", "encoding": "utf-16le"},
            "confidence": 0.5,
            "state": "candidate",
            "reason": "decoding is ambiguous",
        },
    ]
    return {
        "pass": name,
        "backend": "ida",
        "ranges": [{"start": 0x401000, "end": 0x402000}],
        "coverage": coverage,
        "applied_ids": [],
        "candidates": rows if candidates is None else candidates,
        "warnings": [],
        "artifact_revision": 1,
    }


def _store_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*") if p.suffix in _STORE_SUFFIXES)


def _targets(store: Path) -> list[tuple[str, str | None, str | None]]:
    connection = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
    try:
        return sorted(
            connection.execute(
                "SELECT target_key, source_sha256, managed_idb_id FROM targets"
            ).fetchall()
        )
    finally:
        connection.close()


# -- identity ---------------------------------------------------------------


def test_binary_sha_namespaces_two_catalogs(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # Same file name, different bytes, different build directories: the name is
    # not the identity, and one build's candidates may not answer for another.
    first = tmp_path / "build-a" / "service"
    second = tmp_path / "build-b" / "service"
    # Deliberately larger than one hash chunk, so streaming the file in pieces
    # is exercised rather than assumed.
    first_sha = _write_binary(first, b"\x7fELF" + b"first-build-" * 120_000)
    second_sha = _write_binary(second, b"\x7fELF" + b"second-build-" * 120_000)
    assert first_sha != second_sha

    with open_catalog(str(first)) as one, open_catalog(str(second)) as two:
        assert one.source_sha256 == first_sha
        assert two.source_sha256 == second_sha
        assert one.target_key == f"sha256:{first_sha}"
        assert two.target_key == f"sha256:{second_sha}"
        assert one.target_key != two.target_key
        assert one.managed_idb_id is None
        # One shared store, two namespaced targets inside it.
        assert one.database_path == two.database_path
        assert one.database_path == (managed_data_dir / CATALOG_NAME).resolve()

    assert _targets(one.database_path) == sorted(
        [
            (f"sha256:{first_sha}", first_sha, None),
            (f"sha256:{second_sha}", second_sha, None),
        ]
    )
    # Nothing was written beside either source tree.
    assert _store_files(first.parent) == []
    assert _store_files(second.parent) == []
    repo_root = Path(__file__).resolve().parents[1]
    assert repo_root not in one.database_path.parents


def test_one_targets_analysis_is_not_visible_from_another(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    first = tmp_path / "build-a" / "service"
    second = tmp_path / "build-b" / "service"
    _write_binary(first, b"\x7fELFone")
    _write_binary(second, b"\x7fELFtwo")

    with open_catalog(str(first)) as one:
        one.record_pass("analysis-one", _pass_result())
    with open_catalog(str(second)) as two:
        two.record_pass("analysis-two", _pass_result())
        assert two.page_candidates("analysis-two", 0, 10)["total"] == 2
        with pytest.raises(UnknownAnalysisError):
            two.page_candidates("analysis-one", 0, 10)


def test_idb_only_keeps_provisional_identity(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    database = tmp_path / "work" / "firmware.i64"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"IDA2\x00 packed database bytes, never hashed")
    # Same basename, unrelated bytes: the trap this identity rule exists for.
    unrelated = tmp_path / "downloads" / "firmware"
    unrelated_sha = _write_binary(unrelated, b"\x7fELF" + b"unrelated" * 2048)

    with open_catalog(str(database), PROVISIONAL) as catalog:
        assert catalog.target_key == f"idb:{PROVISIONAL}"
        assert catalog.managed_idb_id == PROVISIONAL
        # The original bytes are unknown, and the catalog says so rather than
        # guessing a hash from the database it was handed.
        assert catalog.source_sha256 is None
        catalog.record_pass("analysis-idb", _pass_result())

        with pytest.raises(UnverifiedAssociationError):
            catalog.attach_source(str(unrelated))
        with pytest.raises(UnverifiedAssociationError):
            catalog.attach_source(
                str(unrelated), {"kind": "input_fingerprint", "sha256": "ab" * 32}
            )
        with pytest.raises(UnverifiedAssociationError):
            catalog.attach_source(
                str(unrelated),
                {
                    "kind": "segment_bytes",
                    "spans": [
                        {
                            "address": 0x401000,
                            "file_offset": 0,
                            "bytes": "90" * 512,
                        }
                    ],
                },
            )
        assert catalog.source_sha256 is None

    # A matching file name is not evidence, so the raw bytes cannot claim the
    # provisional target through the open path either.
    with pytest.raises(UnverifiedAssociationError):
        open_catalog(str(unrelated), PROVISIONAL)

    with open_catalog(str(database), PROVISIONAL) as reopened:
        assert reopened.target_key == f"idb:{PROVISIONAL}"
        assert reopened.managed_idb_id == PROVISIONAL
        assert reopened.source_sha256 is None
        assert reopened.page_candidates("analysis-idb", 0, 10)["total"] == 2

    assert _targets(catalog_path()) == [(f"idb:{PROVISIONAL}", None, PROVISIONAL)]
    # Opening the unrelated binary on its own is a separate target, not a join.
    with open_catalog(str(unrelated)) as separate:
        assert separate.target_key == f"sha256:{unrelated_sha}"
    assert len(_targets(catalog_path())) == 2


def test_an_idb_without_a_provisional_id_cannot_be_keyed(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")
    with pytest.raises(CatalogError, match="managed_idb_id"):
        open_catalog(str(database))
    # The refusal happens before anything is created.
    assert not managed_data_dir.exists()


def test_a_target_that_is_not_a_file_is_refused(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    with pytest.raises(CatalogError, match="no such"):
        open_catalog(str(tmp_path / "absent"))
    assert not managed_data_dir.exists()


# -- verified association ---------------------------------------------------


def test_a_verified_fingerprint_attaches_the_original_bytes(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")
    original = tmp_path / "original" / "firmware"
    original_sha = _write_binary(original, b"\x7fELF" + b"the real input" * 1024)

    with open_catalog(str(database), PROVISIONAL) as catalog:
        catalog.record_pass("analysis-idb", _pass_result())
        attached = catalog.attach_source(
            str(original), {"kind": "input_fingerprint", "sha256": original_sha}
        )
        assert attached["source_sha256"] == original_sha
        # The key stays the one its rows were written under: a verified
        # association adds knowledge, it does not re-home an analysis.
        assert attached["target_key"] == f"idb:{PROVISIONAL}"
        assert catalog.source_sha256 == original_sha

    # Now the original binary resolves to that same target, candidates and all.
    with open_catalog(str(original)) as by_bytes:
        assert by_bytes.target_key == f"idb:{PROVISIONAL}"
        assert by_bytes.managed_idb_id == PROVISIONAL
        assert by_bytes.page_candidates("analysis-idb", 0, 10)["total"] == 2
    assert _targets(catalog_path()) == [
        (f"idb:{PROVISIONAL}", original_sha, PROVISIONAL)
    ]


def test_a_segment_byte_association_must_match_the_file(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")
    payload = b"\x7fELF" + bytes(range(256)) * 16
    original = tmp_path / "original" / "firmware"
    original_sha = _write_binary(original, payload)
    span = payload[0x100 : 0x100 + MIN_SEGMENT_PROOF_BYTES]

    with open_catalog(str(database), PROVISIONAL) as catalog:
        # Too few bytes to mean anything, even though they do match.
        with pytest.raises(UnverifiedAssociationError, match="bytes"):
            catalog.attach_source(
                str(original),
                {
                    "kind": "segment_bytes",
                    "spans": [
                        {
                            "address": 0x400100,
                            "file_offset": 0x100,
                            "bytes": span[:8].hex(),
                        }
                    ],
                },
            )
        # Right length, wrong offset: the bytes are not where the proof claims.
        with pytest.raises(UnverifiedAssociationError):
            catalog.attach_source(
                str(original),
                {
                    "kind": "segment_bytes",
                    "spans": [
                        {
                            "address": 0x400100,
                            "file_offset": 0x101,
                            "bytes": span.hex(),
                        }
                    ],
                },
            )
        assert catalog.source_sha256 is None

        attached = catalog.attach_source(
            str(original),
            {
                "kind": "segment_bytes",
                "spans": [
                    {"address": 0x400100, "file_offset": 0x100, "bytes": span.hex()}
                ],
            },
        )
        assert attached["source_sha256"] == original_sha
        assert catalog.source_sha256 == original_sha


def test_a_repeated_span_does_not_reach_the_segment_proof_threshold(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The cheapest forgery there is: four bytes of ELF magic, which every ELF
    # carries at offset 0, repeated until the byte count clears the threshold.
    # Sixty-four copies of one span prove exactly what one copy proves.
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")
    unrelated = tmp_path / "downloads" / "unrelated"
    _write_binary(unrelated, b"\x7fELF" + b"nothing to do with that database" * 64)
    repeated = {
        "kind": "segment_bytes",
        "spans": [
            {"address": 0x401000, "file_offset": 0, "bytes": "7f454c46"}
            for _ in range(MIN_SEGMENT_PROOF_BYTES // 4)
        ],
    }

    with open_catalog(str(database), PROVISIONAL) as catalog:
        with pytest.raises(UnverifiedAssociationError, match="distinct"):
            catalog.attach_source(str(unrelated), repeated)
        # Two spans that merely touch at one byte are the same forgery, smaller.
        with pytest.raises(UnverifiedAssociationError, match="distinct"):
            catalog.attach_source(
                str(unrelated),
                {
                    "kind": "segment_bytes",
                    "spans": [
                        {
                            "address": 0x401000,
                            "file_offset": 0,
                            "bytes": unrelated.read_bytes()[:200].hex(),
                        },
                        {
                            "address": 0x401000 + 199,
                            "file_offset": 199,
                            "bytes": unrelated.read_bytes()[199:300].hex(),
                        },
                    ],
                },
            )
        assert catalog.source_sha256 is None
        assert catalog.source_association is None

    # Nothing was joined, and the unrelated binary is still its own target.
    assert _targets(catalog_path()) == [(f"idb:{PROVISIONAL}", None, PROVISIONAL)]


def test_distinct_spans_may_abut_without_overlapping(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")
    payload = b"\x7fELF" + bytes(range(256)) * 16
    original = tmp_path / "original" / "firmware"
    original_sha = _write_binary(original, payload)
    half = MIN_SEGMENT_PROOF_BYTES // 2

    with open_catalog(str(database), PROVISIONAL) as catalog:
        attached = catalog.attach_source(
            str(original),
            {
                "kind": "segment_bytes",
                "spans": [
                    {
                        "address": 0x400100,
                        "file_offset": 0x100,
                        "bytes": payload[0x100 : 0x100 + half].hex(),
                    },
                    {
                        "address": 0x400100 + half,
                        "file_offset": 0x100 + half,
                        "bytes": payload[0x100 + half : 0x100 + 2 * half].hex(),
                    },
                ],
            },
        )
        assert attached["source_sha256"] == original_sha
        assert attached["source_association"] == ASSOCIATION_VERIFIED


def test_an_unseen_database_id_is_recorded_as_asserted_not_verified(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # Preparation hands open_catalog the binary and the database it just built
    # from it. That join is taken on the caller's word, so it is stored as an
    # assertion: a later database-only read inherits the identity and can see
    # that nobody compared any bytes.
    binary = tmp_path / "service"
    binary_sha = _write_binary(binary, b"\x7fELF" + b"the prepared image" * 512)
    with open_catalog(str(binary)) as first:
        assert first.source_association is None
        first.record_pass("analysis-bytes", _pass_result())
    with open_catalog(str(binary), OTHER_PROVISIONAL) as joined:
        assert joined.target_key == f"sha256:{binary_sha}"
        assert joined.managed_idb_id == OTHER_PROVISIONAL
        assert joined.source_association == ASSOCIATION_ASSERTED

    database = tmp_path / "unrelated.i64"
    database.write_bytes(b"IDA2\x00 some other packed database entirely")
    with open_catalog(str(database), OTHER_PROVISIONAL) as by_database:
        # The digest still comes back, because that is what the row says, but
        # it is flagged as asserted rather than passed off as verified.
        assert by_database.source_sha256 == binary_sha
        assert by_database.source_association == ASSOCIATION_ASSERTED
        page = by_database.page_candidates("analysis-bytes", 0, 10)
        assert page["source_association"] == ASSOCIATION_ASSERTED

    stored = sqlite3.connect(f"file:{catalog_path()}?mode=ro", uri=True)
    try:
        proof = stored.execute(
            "SELECT source_proof FROM targets WHERE target_key = ?",
            (f"sha256:{binary_sha}",),
        ).fetchone()[0]
    finally:
        stored.close()
    assert json.loads(proof)["kind"] == "asserted_by_caller"


def test_an_asserted_join_is_upgraded_by_a_real_proof(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    binary_sha = _write_binary(binary, b"\x7fELF" + b"the prepared image" * 512)
    with open_catalog(str(binary), OTHER_PROVISIONAL) as asserted:
        assert asserted.source_association == ASSOCIATION_ASSERTED
        upgraded = asserted.attach_source(
            str(binary), {"kind": "input_fingerprint", "sha256": binary_sha}
        )
        assert upgraded["source_association"] == ASSOCIATION_VERIFIED
    with open_catalog(str(binary), OTHER_PROVISIONAL) as reopened:
        assert reopened.source_association == ASSOCIATION_VERIFIED


def test_bytes_that_answer_for_one_database_do_not_answer_for_another(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    binary_sha = _write_binary(binary, b"\x7fELF" + b"one image" * 512)
    with open_catalog(str(binary), PROVISIONAL) as first:
        assert first.managed_idb_id == PROVISIONAL
    with pytest.raises(UnverifiedAssociationError, match="different database"):
        open_catalog(str(binary), OTHER_PROVISIONAL)
    assert _targets(catalog_path()) == [
        (f"sha256:{binary_sha}", binary_sha, PROVISIONAL)
    ]


def test_two_targets_cannot_claim_the_same_original_bytes(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    original = tmp_path / "firmware"
    original_sha = _write_binary(original, b"\x7fELF" + b"shared bytes" * 512)
    first = tmp_path / "first.i64"
    first.write_bytes(b"IDA2\x00 one")
    second = tmp_path / "second.i64"
    second.write_bytes(b"IDA2\x00 two")
    proof = {"kind": "input_fingerprint", "sha256": original_sha}

    with open_catalog(str(first), PROVISIONAL) as one:
        one.attach_source(str(original), proof)
    with open_catalog(str(second), OTHER_PROVISIONAL) as two:
        with pytest.raises(CatalogError, match="already"):
            two.attach_source(str(original), proof)
        assert two.source_sha256 is None


def test_bytes_that_already_have_a_target_are_not_adopted_by_another(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # The case an operator meets: the binary was prepared on its own, and the
    # database-only analysis is proven to come from it. Merging two histories
    # is not something this store invents, so it says so instead.
    original = tmp_path / "firmware"
    original_sha = _write_binary(original, b"\x7fELF" + b"prepared first" * 512)
    with open_catalog(str(original)) as by_bytes:
        by_bytes.record_pass("analysis-bytes", _pass_result())
    database = tmp_path / "firmware.i64"
    database.write_bytes(b"IDA2\x00 packed")

    with open_catalog(str(database), PROVISIONAL) as provisional:
        with pytest.raises(CatalogError, match="already belongs to target"):
            provisional.attach_source(
                str(original), {"kind": "input_fingerprint", "sha256": original_sha}
            )
        assert provisional.source_sha256 is None
    with open_catalog(str(original)) as unchanged:
        assert unchanged.target_key == f"sha256:{original_sha}"
        assert unchanged.page_candidates("analysis-bytes", 0, 10)["total"] == 2


# -- absence, emptiness, and read-only reads --------------------------------


def test_missing_catalog_reports_unavailable(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELF" + b"never prepared" * 64)

    assert get_catalog(str(binary)) is None
    # A read may not bring the store, or its directory, into existence.
    assert not managed_data_dir.exists()
    assert not catalog_path().exists()


def test_an_empty_catalog_is_not_a_missing_one(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELF" + b"prepared, found nothing" * 64)

    with open_catalog(str(binary)) as writer:
        writer.record_pass("analysis-empty", _pass_result(candidates=[]))

    catalog = get_catalog(str(binary))
    assert catalog is not None
    with catalog:
        page = catalog.page_candidates("analysis-empty", 0, 10)
        assert page["available"] is True
        assert page["total"] == 0
        assert page["loaded"] == 0
        assert page["candidates"] == []


def test_a_read_only_catalog_writes_nothing(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELF" + b"already prepared" * 64)
    with open_catalog(str(binary)) as writer:
        writer.record_pass("analysis-ro", _pass_result())
    store = catalog_path()
    before = store.read_bytes()
    neighbours = sorted(p.name for p in store.parent.iterdir())

    catalog = get_catalog(str(binary))
    assert catalog is not None
    with catalog:
        assert catalog.page_candidates("analysis-ro", 0, 10)["total"] == 2
        with pytest.raises(ReadOnlyCatalogError):
            catalog.record_pass("analysis-ro", _pass_result("functions"))
        with pytest.raises(ReadOnlyCatalogError):
            catalog.attach_source(str(binary), {"kind": "input_fingerprint"})
    assert store.read_bytes() == before
    assert sorted(p.name for p in store.parent.iterdir()) == neighbours


def test_an_unknown_target_reads_as_empty_without_being_recorded(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    known = tmp_path / "known"
    _write_binary(known, b"\x7fELFknown")
    stranger = tmp_path / "stranger"
    _write_binary(stranger, b"\x7fELFstranger")
    with open_catalog(str(known)) as writer:
        writer.record_pass("analysis-known", _pass_result())

    catalog = get_catalog(str(stranger))
    assert catalog is not None
    with catalog:
        # The store exists; this target is simply not in it, which is not the
        # same as the store being gone, and reading may not add it.
        assert catalog.target_key.startswith("sha256:")
        with pytest.raises(UnknownAnalysisError):
            catalog.page_candidates("analysis-known", 0, 10)
    assert len(_targets(catalog_path())) == 1


# -- schema version ---------------------------------------------------------


def test_the_schema_is_versioned_and_carries_every_planned_table(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFversioned")
    with open_catalog(str(binary)):
        pass

    connection = sqlite3.connect(f"file:{catalog_path()}?mode=ro", uri=True)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {
            "targets",
            "analyses",
            "passes",
            "candidates",
            "proposals",
            "external_scopes",
            "external_findings",
            "links",
            "sync_events",
        } <= names
        # Plans 3 and 4 fill these; this task creates them and invents no rows.
        for table in (
            "proposals",
            "external_scopes",
            "external_findings",
            "links",
            "sync_events",
        ):
            count = connection.execute(f"SELECT count(*) FROM {table}").fetchone()
            assert count[0] == 0
    finally:
        connection.close()


def test_a_future_schema_version_is_refused_not_migrated(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFfuture")
    with open_catalog(str(binary)) as writer:
        writer.record_pass("analysis-future", _pass_result())
    store = catalog_path()
    connection = sqlite3.connect(store)
    try:
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        connection.commit()
    finally:
        connection.close()
    before = store.read_bytes()

    with pytest.raises(CatalogSchemaError, match="version"):
        open_catalog(str(binary))
    with pytest.raises(CatalogSchemaError, match="version"):
        get_catalog(str(binary))
    assert store.read_bytes() == before


def test_a_file_that_is_not_a_catalog_is_not_written_over(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFforeign")
    store = catalog_path()
    store.parent.mkdir(parents=True)
    connection = sqlite3.connect(store)
    try:
        connection.execute("CREATE TABLE targets (whatever TEXT)")
        connection.execute("INSERT INTO targets VALUES ('someone else''s data')")
        connection.commit()
    finally:
        connection.close()
    before = store.read_bytes()

    with pytest.raises(CatalogSchemaError, match="not a VulFi catalog"):
        open_catalog(str(binary))
    assert store.read_bytes() == before


# -- recording passes and paging candidates ---------------------------------


def test_record_pass_round_trips_candidate_evidence(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    binary_sha = _write_binary(binary, b"\x7fELFevidence")
    with open_catalog(str(binary)) as writer:
        writer.record_pass("analysis-1", _pass_result())

    catalog = get_catalog(str(binary))
    assert catalog is not None
    with catalog:
        page = catalog.page_candidates("analysis-1", 0, 100)
    assert page["analysis_id"] == "analysis-1"
    assert page["target_key"] == f"sha256:{binary_sha}"
    assert page["source_sha256"] == binary_sha
    assert page["managed_idb_id"] is None
    assert page["offset"] == 0
    assert page["limit"] == 100
    assert page["total"] == 2
    assert page["loaded"] == 2
    first, second = page["candidates"]
    assert first == {
        "candidate_id": "cand-1",
        "pass": "strings",
        "kind": "string",
        "backend": "ida",
        "address_space": "image",
        "address": 0x401000,
        "evidence": {"bytes": "68656c6c6f", "encoding": "ascii"},
        "confidence": 0.9,
        "state": "candidate",
        "reason": None,
    }
    assert second["candidate_id"] == "cand-2"
    assert second["reason"] == "decoding is ambiguous"
    # The whole page is JSON, because it crosses the MCP boundary verbatim.
    assert json.loads(json.dumps(page)) == page


def test_pages_are_ordered_and_windowed(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFpaging")
    rows = [
        {
            "candidate_id": f"cand-{index:02d}",
            "kind": "function",
            "backend": "ida",
            "address_space": "image",
            "address": 0x400000 + index * 0x10,
            "evidence": {"xrefs": [index]},
            "confidence": 0.5,
            "state": "candidate",
            "reason": None,
        }
        for index in range(7)
    ]
    with open_catalog(str(binary)) as writer:
        writer.record_pass("analysis-1", _pass_result("functions", candidates=rows))
        page = writer.page_candidates("analysis-1", 2, 3)
        assert page["total"] == 7
        assert page["loaded"] == 3
        assert [row["candidate_id"] for row in page["candidates"]] == [
            "cand-02",
            "cand-03",
            "cand-04",
        ]
        tail = writer.page_candidates("analysis-1", 6, 100)
        assert [row["candidate_id"] for row in tail["candidates"]] == ["cand-06"]
        past_end = writer.page_candidates("analysis-1", 99, 10)
        assert past_end["candidates"] == []
        assert past_end["total"] == 7


@pytest.mark.parametrize(
    "offset, limit",
    [(-1, 10), (0, 0), (0, 201), (0, True), (False, 10), ("0", 10), (0, 1.5)],
)
def test_page_bounds_are_enforced_before_any_query(
    tmp_path: Path, managed_data_dir: Path, offset: object, limit: object
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFbounds")
    with open_catalog(str(binary)) as catalog:
        # The analysis does not exist either; the window is still what is
        # refused, which is only possible if the bounds are checked first.
        with pytest.raises(CatalogError) as refusal:
            catalog.page_candidates("no-such-analysis", offset, limit)
    assert not isinstance(refusal.value, UnknownAnalysisError)
    assert "offset" in str(refusal.value) or "limit" in str(refusal.value)


def test_re_recording_a_pass_replaces_only_its_own_candidates(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFrerun")
    other = [
        {
            "candidate_id": "fn-1",
            "kind": "function",
            "backend": "ida",
            "address_space": "image",
            "address": 0x402000,
            "evidence": {"xrefs": [1]},
            "confidence": 0.8,
            "state": "candidate",
            "reason": None,
        }
    ]
    with open_catalog(str(binary)) as catalog:
        catalog.record_pass("analysis-1", _pass_result("strings"))
        catalog.record_pass("analysis-1", _pass_result("functions", candidates=other))
        assert catalog.page_candidates("analysis-1", 0, 100)["total"] == 3

        catalog.record_pass(
            "analysis-1",
            _pass_result(
                "strings",
                candidates=[
                    {
                        "candidate_id": "cand-1",
                        "kind": "string",
                        "backend": "ida",
                        "address_space": "image",
                        "address": 0x401000,
                        "evidence": {"bytes": "68656c6c6f", "encoding": "ascii"},
                        "confidence": 0.95,
                        "state": "applied",
                        "reason": None,
                    }
                ],
                coverage="partial",
            ),
        )
        page = catalog.page_candidates("analysis-1", 0, 100)
        assert [row["candidate_id"] for row in page["candidates"]] == ["fn-1", "cand-1"]
        assert page["total"] == 2
        applied = next(
            row for row in page["candidates"] if row["candidate_id"] == "cand-1"
        )
        assert applied["state"] == "applied"
        assert applied["confidence"] == 0.95


def _record_proposal(store: Path, analysis_id: str, candidate_id: str) -> None:
    """One approved proposal, of the shape Plan 4 will write."""
    connection = sqlite3.connect(store)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO proposals (proposal_id, analysis_id, candidate_id,"
            " kind, address_space, address, value, rationale, state,"
            " expected_revision, decided_at, decided_by, decision_reason,"
            " created_at) VALUES (?, ?, ?, 'rename', 'image', 4198400,"
            " 'parse_header', 'the string at 0x401000 names it', 'approved',"
            " 1, '2026-01-01T00:00:00Z', 'operator', 'looks right',"
            " '2026-01-01T00:00:00Z')",
            (f"prop-{candidate_id}", analysis_id, candidate_id),
        )
        connection.commit()
    finally:
        connection.close()


def _proposals(store: Path) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
    try:
        return sorted(
            connection.execute(
                "SELECT proposal_id, candidate_id, state FROM proposals"
            ).fetchall()
        )
    finally:
        connection.close()


def test_re_recording_a_pass_keeps_decisions_on_candidates_it_still_names(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # proposals cascade from candidates. A pass that is re-run with the same
    # candidate must update that row, not delete and recreate it, or every
    # decision an operator recorded against it is destroyed in silence.
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFrerun decisions")
    with open_catalog(str(binary)) as catalog:
        catalog.record_pass("analysis-1", _pass_result("strings"))
    _record_proposal(catalog_path(), "analysis-1", "cand-1")
    _record_proposal(catalog_path(), "analysis-1", "cand-2")
    assert len(_proposals(catalog_path())) == 2

    with open_catalog(str(binary)) as catalog:
        # The second run keeps cand-1 with a new confidence and drops cand-2.
        catalog.record_pass(
            "analysis-1",
            _pass_result(
                "strings",
                candidates=[
                    {
                        "candidate_id": "cand-1",
                        "kind": "string",
                        "backend": "ida",
                        "address_space": "image",
                        "address": 0x401000,
                        "evidence": {"bytes": "68656c6c6f", "encoding": "ascii"},
                        "confidence": 0.95,
                        "state": "applied",
                        "reason": None,
                    }
                ],
            ),
        )
        page = catalog.page_candidates("analysis-1", 0, 100)
        assert [row["candidate_id"] for row in page["candidates"]] == ["cand-1"]
        assert page["candidates"][0]["confidence"] == 0.95
        assert page["candidates"][0]["state"] == "applied"

    # The surviving candidate keeps its decision; the dropped one takes its
    # own with it, which is what dropping a finding means.
    assert _proposals(catalog_path()) == [("prop-cand-1", "cand-1", "approved")]


def test_a_candidate_id_held_by_one_pass_is_not_taken_over_by_another(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFownership")
    with open_catalog(str(binary)) as catalog:
        catalog.record_pass("analysis-1", _pass_result("strings"))
        with pytest.raises(CatalogError, match="already held by"):
            catalog.record_pass(
                "analysis-1",
                _pass_result(
                    "functions",
                    candidates=[
                        {
                            "candidate_id": "cand-1",
                            "kind": "function",
                            "backend": "ida",
                            "address_space": "image",
                            "address": 0x402000,
                            "evidence": {"xrefs": [1]},
                            "confidence": 0.8,
                            "state": "candidate",
                            "reason": None,
                        }
                    ],
                ),
            )
        page = catalog.page_candidates("analysis-1", 0, 100)
        assert [row["candidate_id"] for row in page["candidates"]] == [
            "cand-1",
            "cand-2",
        ]
        assert all(row["pass"] == "strings" for row in page["candidates"])


def test_a_rejected_pass_leaves_no_half_written_rows(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFatomic")
    broken = [
        {
            "candidate_id": "good-1",
            "kind": "string",
            "backend": "ida",
            "address_space": "image",
            "address": 0x401000,
            "evidence": {"bytes": "41"},
            "confidence": 0.5,
            "state": "candidate",
            "reason": None,
        },
        {
            "candidate_id": "bad-1",
            "kind": "string",
            "backend": "ida",
            "address_space": "image",
            "address": 0x401010,
            "evidence": {"bytes": "42"},
            "confidence": 0.5,
            "state": "guessed",  # not one of candidate|applied|rejected
            "reason": None,
        },
    ]
    with open_catalog(str(binary)) as catalog:
        with pytest.raises(CatalogError, match="state"):
            catalog.record_pass("analysis-1", _pass_result(candidates=broken))
        # Neither the accepted row before the bad one nor the pass itself
        # survived: the write was one transaction.
        with pytest.raises(UnknownAnalysisError):
            catalog.page_candidates("analysis-1", 0, 10)

        catalog.record_pass("analysis-1", _pass_result())
        with pytest.raises(CatalogError, match="coverage"):
            catalog.record_pass(
                "analysis-1", _pass_result("functions", coverage="probably")
            )
        with pytest.raises(CatalogError, match="pass"):
            catalog.record_pass("analysis-1", _pass_result("decompile_everything"))
        assert catalog.page_candidates("analysis-1", 0, 10)["total"] == 2


def test_a_pass_may_only_claim_candidates_the_catalog_holds(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    binary = tmp_path / "service"
    _write_binary(binary, b"\x7fELFdeclared")
    result = _pass_result()
    result["candidate_ids"] = ["cand-1", "cand-9"]
    with open_catalog(str(binary)) as catalog:
        with pytest.raises(CatalogError, match="candidate_ids"):
            catalog.record_pass("analysis-1", result)
        result["candidate_ids"] = ["cand-1", "cand-2"]
        catalog.record_pass("analysis-1", result)
        assert catalog.page_candidates("analysis-1", 0, 10)["total"] == 2

        # The bare PassResult shape — ids, no candidate objects — restates a
        # pass whose rows are already stored, and leaves them alone.
        restated = _pass_result(coverage="partial")
        del restated["candidates"]
        restated["candidate_ids"] = ["cand-1", "cand-2"]
        catalog.record_pass("analysis-1", restated)
        assert catalog.page_candidates("analysis-1", 0, 10)["total"] == 2

        # The same shape for a pass nothing has recorded names candidates this
        # catalog cannot show, so it is refused rather than written down.
        unbacked = _pass_result("structures")
        del unbacked["candidates"]
        unbacked["candidate_ids"] = ["struct-1"]
        with pytest.raises(CatalogError, match="candidate_ids"):
            catalog.record_pass("analysis-1", unbacked)
        assert catalog.page_candidates("analysis-1", 0, 10)["total"] == 2


def test_an_analysis_id_cannot_be_reused_across_targets(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    first = tmp_path / "a" / "service"
    second = tmp_path / "b" / "service"
    _write_binary(first, b"\x7fELFa")
    _write_binary(second, b"\x7fELFb")
    with open_catalog(str(first)) as one:
        one.record_pass("analysis-shared", _pass_result())
    with open_catalog(str(second)) as two:
        with pytest.raises(CatalogError, match="another target"):
            two.record_pass("analysis-shared", _pass_result())
