"""The preparation catalog: what was recovered, about which exact target.

One SQLite database, in the operator's application data directory and nowhere
else, holds every target this server has prepared. Three rules shape it.

**Identity is the bytes, not the name.** A target whose original binary is in
hand is keyed by the SHA-256 of those bytes, streamed in bounded chunks. A
target supplied as a database only has no original bytes to hash, so it is
keyed by the provisional ``managed_idb_id`` :mod:`vulfi_mcp.ida_runtime` mints
once on the first netnode write, and its ``source_sha256`` stays ``NULL``. That
provisional identity may not be joined to raw bytes until
:meth:`Catalog.attach_source` verifies the relationship against a stored input
fingerprint or a segment-byte association. A matching file name is not
evidence, and this module refuses to treat it as evidence through either
entry point.

The reverse join — a caller presenting raw bytes and the database it just
built from them — is accepted, because that is how preparation works, but it
is recorded as :data:`ASSOCIATION_ASSERTED` rather than as proof, and
``Catalog.source_association`` says so. A later database-only read inherits
that identity knowing nobody compared any bytes, and
:meth:`Catalog.attach_source` can still upgrade it to
:data:`ASSOCIATION_VERIFIED`.

**Creating is not reading.** :func:`open_catalog` is the mutation path and may
bring the database into existence. :func:`get_catalog` is read-only, opens
SQLite in ``mode=ro``, and never creates a file or a directory; when there is
no catalog it answers ``None``, which callers must report as *unavailable*.
A catalog that exists and holds no candidates is a different answer, and this
module keeps the two apart.

**The schema is versioned, and a newer one is refused.** ``PRAGMA
user_version`` carries :data:`SCHEMA_VERSION`; a database written by a later
build is rejected rather than migrated or overwritten. The tables Plans 3 and 4
own are created here, empty, and this module stores no row in them.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Any, Final

from vulfi_mcp.ida_adapter import IDB_SUFFIXES, data_dir
from vulfi_mcp.ida_runtime import (
    PROPOSAL_KINDS,
    PROPOSAL_STATES,
    OperationError,
    utc_now,
    validate_page,
)

__all__ = [
    "ASSOCIATION_ASSERTED",
    "ASSOCIATION_VERIFIED",
    "CATALOG_NAME",
    "CATALOG_UNAVAILABLE_REASON",
    "MIN_SEGMENT_PROOF_BYTES",
    "PROPOSAL_KINDS",
    "PROPOSAL_STATES",
    "SCHEMA_VERSION",
    "Catalog",
    "CatalogError",
    "CatalogSchemaError",
    "ReadOnlyCatalogError",
    "UnknownAnalysisError",
    "UnverifiedAssociationError",
    "catalog_path",
    "get_catalog",
    "open_catalog",
]

#: File name of the one shared catalog under the managed data directory.
CATALOG_NAME: Final = "catalog.sqlite3"

#: Version of the schema below. Bumped only with a migration, never to paper
#: over a database some other build wrote.
SCHEMA_VERSION: Final = 1

#: Why a read reports the catalog unavailable. It is deliberately not phrased
#: as "no candidates": nothing has been prepared *and recorded here*, which a
#: caller must not render as a prepared target that yielded nothing.
CATALOG_UNAVAILABLE_REASON: Final = (
    "there is no preparation catalog yet, and only vulfi_prepare creates one:"
    " there is no store to answer from, which is not the same as a target"
    " whose preparation found no candidates"
)

#: Bytes read per hashing step. Original binaries run to hundreds of megabytes
#: and nothing here needs them resident, so the digest is streamed.
HASH_CHUNK: Final = 1 << 20

#: Smallest segment-byte association this module will accept as proof that a
#: database and a file describe the same image, counted over *distinct* file
#: offsets. A handful of matching bytes is a coincidence; a quarter of a
#: kilobyte landing exactly where the database says it does is not — but only
#: if the spans are distinct, since one span repeated proves only itself.
MIN_SEGMENT_PROOF_BYTES: Final = 256

#: Bounds on a supplied association, so a "proof" cannot become a denial of
#: service or an unbounded blob in the store.
MAX_SEGMENT_PROOF_SPANS: Final = 64
MAX_SEGMENT_PROOF_BYTES: Final = 1 << 16

#: Largest JSON evidence blob one candidate may carry.
MAX_EVIDENCE_BYTES: Final = 1 << 16

#: Longest identifier this store accepts, for ids it did not mint itself.
MAX_ID_LENGTH: Final = 200

#: Longest filesystem path this store records. A managed artifact's path is
#: not an identifier and is not bounded like one: it inherits whatever depth
#: the operator's configured data directory has, and refusing a perfectly
#: good workspace for being nested would be this module's mistake, not the
#: caller's. This is the platform's own ceiling, not a design limit.
MAX_PATH_LENGTH: Final = 4096

#: The passes this design defines. A name outside this set is a mistake in the
#: caller, not a new kind of evidence, so it is refused rather than stored.
PASS_NAMES: Final = frozenset({"strings", "functions", "structures", "pointer_tables"})

#: What a pass may claim about a range. There is no fourth answer.
COVERAGES: Final = frozenset({"complete", "partial", "unavailable"})

#: A candidate is not a fact until something applies it, and a rejection is
#: recorded rather than deleted.
CANDIDATE_STATES: Final = frozenset({"candidate", "applied", "rejected"})

#: Backends that may author a row, matching ``contracts.Backend``.
BACKENDS: Final = frozenset({"ida", "ghidra", "r2"})

#: Characters a ``managed_idb_id`` may use: ``uuid.uuid4().hex`` as minted, and
#: the dashed spelling of the same value.
_ID_CHARACTERS: Final = frozenset("0123456789abcdefABCDEF-")

#: How a target's database and its original bytes came to be joined.
#: ``verified`` means :meth:`Catalog.attach_source` checked the bytes on disk
#: against a proof read out of the database. ``asserted`` means a caller handed
#: both identities to :func:`open_catalog` in one breath and this module took
#: its word for it, which is right for the flow that just built the database
#: from those very bytes and is nothing at all for a caller that merely says
#: so. The distinction is stored, so a later database-only read can tell them
#: apart instead of inheriting an identity it cannot check.
ASSOCIATION_VERIFIED: Final = "verified"
ASSOCIATION_ASSERTED: Final = "asserted"

#: Proof kinds the spec names for joining a provisional target to raw bytes.
_FINGERPRINT: Final = "input_fingerprint"
_SEGMENT_BYTES: Final = "segment_bytes"

#: What is written to ``targets.source_proof`` for an asserted join. It is not
#: a proof and does not pretend to be one: it records that the join rests on
#: the caller's say-so, and when.
_ASSERTED_KIND: Final = "asserted_by_caller"

# The five kinds a proposal may ask for and the five states one may be in are
# imported from `ida_runtime` above, next to the validators that enforce
# them: one vocabulary, not a copy of it in the store.

#: Where a decision may go from where it is. A review records ``approved``
#: before the write it authorizes, so a decision that never became durable is
#: still visible afterwards; ``pending`` is how it comes back when the write
#: did not land, and ``stale`` is how it ends when the artifact moved out
#: from under it. ``rejected`` and ``applied`` are final: a second decision
#: would overwrite one an operator really made.
_PROPOSAL_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "pending": frozenset({"approved", "rejected", "stale"}),
    "approved": frozenset({"applied", "pending", "stale"}),
    "rejected": frozenset(),
    "applied": frozenset(),
    "stale": frozenset(),
}

#: One schema, created once, in one transaction. The last five tables belong to
#: Plans 3 and 4; they are created here so there is one versioned schema rather
#: than a sequence of silent additions, and this module writes none of them.
_SCHEMA: Final = (
    """
    CREATE TABLE IF NOT EXISTS targets (
        target_key      TEXT PRIMARY KEY,
        source_sha256   TEXT UNIQUE,
        managed_idb_id  TEXT UNIQUE,
        source_proof    TEXT,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        CHECK (source_sha256 IS NOT NULL OR managed_idb_id IS NOT NULL),
        CHECK (source_sha256 IS NULL OR length(source_sha256) = 64)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS analyses (
        analysis_id            TEXT PRIMARY KEY,
        target_key             TEXT NOT NULL
                               REFERENCES targets(target_key) ON DELETE CASCADE,
        requested_backend      TEXT,
        artifact_path          TEXT,
        capability_fingerprint TEXT,
        revision               INTEGER NOT NULL DEFAULT 0,
        created_at             TEXT NOT NULL,
        updated_at             TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS analyses_by_target ON analyses(target_key)",
    """
    CREATE TABLE IF NOT EXISTS passes (
        analysis_id       TEXT NOT NULL
                          REFERENCES analyses(analysis_id) ON DELETE CASCADE,
        name              TEXT NOT NULL,
        backend           TEXT NOT NULL,
        coverage          TEXT NOT NULL
                          CHECK (coverage IN ('complete', 'partial', 'unavailable')),
        ranges            TEXT NOT NULL,
        applied_ids       TEXT NOT NULL,
        candidate_ids     TEXT NOT NULL,
        warnings          TEXT NOT NULL,
        artifact_revision INTEGER,
        recorded_at       TEXT NOT NULL,
        PRIMARY KEY (analysis_id, name, backend)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS candidates (
        analysis_id   TEXT NOT NULL,
        candidate_id  TEXT NOT NULL,
        pass_name     TEXT NOT NULL,
        backend       TEXT NOT NULL,
        kind          TEXT NOT NULL,
        address_space TEXT NOT NULL,
        address       INTEGER,
        evidence      TEXT NOT NULL,
        confidence    REAL NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
        state         TEXT NOT NULL
                      CHECK (state IN ('candidate', 'applied', 'rejected')),
        reason        TEXT,
        recorded_at   TEXT NOT NULL,
        PRIMARY KEY (analysis_id, candidate_id),
        FOREIGN KEY (analysis_id, pass_name, backend)
            REFERENCES passes(analysis_id, name, backend) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS proposals (
        proposal_id       TEXT PRIMARY KEY,
        analysis_id       TEXT NOT NULL,
        candidate_id      TEXT NOT NULL,
        kind              TEXT NOT NULL,
        address_space     TEXT NOT NULL,
        address           INTEGER,
        value             TEXT NOT NULL,
        rationale         TEXT NOT NULL,
        state             TEXT NOT NULL
                          CHECK (state IN ('pending', 'approved', 'rejected',
                                           'applied', 'stale')),
        expected_revision INTEGER,
        decided_at        TEXT,
        decided_by        TEXT,
        decision_reason   TEXT,
        created_at        TEXT NOT NULL,
        FOREIGN KEY (analysis_id, candidate_id)
            REFERENCES candidates(analysis_id, candidate_id) ON DELETE CASCADE
    )
    """,
    """
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
    """,
    """
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
    """,
    """
    CREATE TABLE IF NOT EXISTS links (
        link_id             TEXT PRIMARY KEY,
        target_key          TEXT NOT NULL
                            REFERENCES targets(target_key) ON DELETE CASCADE,
        ida_finding_id      TEXT NOT NULL UNIQUE,
        external_finding_id TEXT NOT NULL UNIQUE
                            REFERENCES external_findings(finding_id)
                            ON DELETE RESTRICT,
        proof               TEXT NOT NULL,
        chosen_source       TEXT NOT NULL,
        status              TEXT NOT NULL,
        rationale           TEXT,
        link_revision       INTEGER NOT NULL DEFAULT 1,
        sync_state          TEXT NOT NULL
                            CHECK (sync_state IN ('unlinked', 'pending',
                                                  'synchronized', 'conflict',
                                                  'paused')),
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sync_events (
        event_id               TEXT PRIMARY KEY,
        link_id                TEXT NOT NULL
                               REFERENCES links(link_id) ON DELETE CASCADE,
        kind                   TEXT NOT NULL,
        state                  TEXT NOT NULL
                               CHECK (state IN ('pending', 'confirmed', 'failed')),
        expected_link_revision INTEGER NOT NULL,
        intended_ida_revision  INTEGER,
        observed_ida_revision  INTEGER,
        payload                TEXT NOT NULL,
        created_at             TEXT NOT NULL,
        confirmed_at           TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS sync_events_by_state ON sync_events(state)",
)

#: Page order. Fully derived from stored values, so the same rows page the same
#: way in every process: by pass, then by address with the unprovable ones
#: last, then by id.
_PAGE_ORDER: Final = (
    "ORDER BY pass_name ASC, address IS NULL ASC, address ASC, candidate_id ASC"
)


class CatalogError(ValueError):
    """The catalog refused a request before it changed anything.

    ``ValueError`` for the same reason :class:`vulfi_mcp.ida_runtime.
    OperationError` is: every refusal below is about the values a caller
    supplied, and a caller that cannot tell a rejection from a backend failure
    cannot report either one honestly.
    """


class CatalogSchemaError(CatalogError):
    """The stored catalog is a schema version this build must not touch."""


class ReadOnlyCatalogError(CatalogError):
    """A mutation was asked of a catalog opened for reading."""


class UnknownAnalysisError(CatalogError):
    """No analysis of this target carries the requested id.

    Distinct from an analysis with no candidates: that is an empty page.
    """


class UnverifiedAssociationError(CatalogError):
    """Raw bytes were offered for a target whose relationship is unproven."""


def catalog_path() -> Path:
    """The one catalog file, under the operator's configured data directory.

    The directory comes from :func:`vulfi_mcp.ida_adapter.data_dir`, which is
    the single place ``VULFI_MCP_DATA_DIR`` is read, so the catalog can never
    end up somewhere the managed databases are not: never in this repository,
    never beside the binary, never beside the user's IDB.
    """
    return data_dir() / CATALOG_NAME


def open_catalog(path: str, managed_idb_id: str | None = None) -> Catalog:
    """Open the catalog for ``path``, creating the database if it is not there.

    This is the mutation path: it may create the data directory, the SQLite
    file and the schema, and it records the target row so later writes have
    something to point at. ``managed_idb_id`` is the provisional identity read
    from the netnode; it is required when ``path`` is a database, because a
    database's bytes are not the bytes being analyzed.
    """
    source_sha256, idb_id = _identity(path, managed_idb_id)
    store = catalog_path()
    store.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(store, writable=True)
    try:
        _apply_schema(connection)
        target = _resolve_target(connection, source_sha256, idb_id, create=True)
    except BaseException:
        connection.close()
        raise
    return Catalog(connection, store, target, writable=True)


def get_catalog(path: str, managed_idb_id: str | None = None) -> Catalog | None:
    """The catalog for ``path``, read-only, or ``None`` when there is not one.

    Nothing here creates a file or a directory, and the SQLite connection is
    opened ``mode=ro`` so that remains true however this object is used. A
    ``None`` answer means *unavailable* — see
    :data:`CATALOG_UNAVAILABLE_REASON` — and a caller must not render it as a
    target whose preparation found nothing. A catalog that exists but holds no
    row for this target is the empty case, and comes back as a ``Catalog``.
    """
    store = catalog_path()
    if not store.is_file():
        # The target is still checked, because an unreadable path is a caller
        # error either way; it is not hashed, because a read may not spend
        # minutes on a large binary to arrive at the same "unavailable".
        _target_input(path, managed_idb_id)
        return None
    source_sha256, idb_id = _identity(path, managed_idb_id)
    connection = _connect(store, writable=False)
    try:
        _require_known_version(connection)
        target = _resolve_target(connection, source_sha256, idb_id, create=False)
    except BaseException:
        connection.close()
        raise
    return Catalog(connection, store, target, writable=False)


class _Target:
    """The identity a :class:`Catalog` answers for."""

    __slots__ = (
        "association",
        "key",
        "managed_idb_id",
        "present",
        "source_sha256",
    )

    def __init__(
        self,
        key: str,
        source_sha256: str | None,
        managed_idb_id: str | None,
        *,
        present: bool,
        association: str | None = None,
    ) -> None:
        self.key = key
        self.source_sha256 = source_sha256
        self.managed_idb_id = managed_idb_id
        #: ``verified``, ``asserted`` or ``None`` when there is no join between
        #: a database and raw bytes to describe.
        self.association = association
        #: Whether a row for this target is actually stored. A read of a target
        #: nothing has prepared is an empty catalog, not a missing one, and
        #: must not write the row it did not find.
        self.present = present


class Catalog:
    """One target's view of the preparation catalog.

    Instances are bound to one target identity and one connection. Use as a
    context manager, or call :meth:`close`; a writable instance holds a SQLite
    file handle that other processes must be able to lock.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        database_path: Path,
        target: _Target,
        *,
        writable: bool,
    ) -> None:
        self._connection = connection
        self._database_path = database_path
        self._target = target
        self._writable = writable

    # -- identity -----------------------------------------------------------

    @property
    def database_path(self) -> Path:
        """Where this catalog lives on disk."""
        return self._database_path

    @property
    def target_key(self) -> str:
        """The stable key every row of this target hangs from.

        ``sha256:<digest>`` when the original bytes were hashed, ``idb:<uuid>``
        for a provisional database-only target. It does not change when
        :meth:`attach_source` later proves which bytes that database came from:
        re-keying would orphan the rows already recorded under it.
        """
        return self._target.key

    @property
    def source_sha256(self) -> str | None:
        """The original binary's digest, or ``None`` while it is unproven."""
        return self._target.source_sha256

    @property
    def managed_idb_id(self) -> str | None:
        """The provisional identity minted in the managed database's netnode."""
        return self._target.managed_idb_id

    @property
    def source_association(self) -> str | None:
        """How the database and the original bytes came to be joined.

        :data:`ASSOCIATION_VERIFIED` when :meth:`attach_source` checked bytes
        on disk against a proof read out of the database,
        :data:`ASSOCIATION_ASSERTED` when a caller presented both identities
        together and this store took its word for it, and ``None`` when the
        target carries only one of the two identities and so has no join to
        describe. A caller that reports a database-only target's
        ``source_sha256`` as established fact must look here first.
        """
        return self._target.association

    @property
    def writable(self) -> bool:
        """Whether this instance may change anything."""
        return self._writable

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Catalog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -- verified association ----------------------------------------------

    def attach_source(
        self, binary_path: str, proof: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Record the original bytes of a provisional, database-only target.

        ``proof`` is the only thing that makes this legal, and it is checked
        against the file on disk:

        ``{"kind": "input_fingerprint", "sha256": ...}``
            the input-file digest the database itself stores, which must equal
            the digest of ``binary_path``. The caller is responsible for having
            read that fingerprint out of the database — this module can verify
            the bytes against the claim, not the provenance of the claim.

        ``{"kind": "segment_bytes", "spans": [{"address", "file_offset",
        "bytes"}, ...]}``
            bytes read from the database's mapped segments, which must appear
            byte for byte at the claimed file offsets, over at least
            :data:`MIN_SEGMENT_PROOF_BYTES`.

        Anything else — no proof, a mismatched digest, bytes that are not where
        the association says they are — raises
        :class:`UnverifiedAssociationError` and leaves the target provisional.
        """
        self._require_writable()
        source = _canonical_target(binary_path)
        if source.suffix.lower() in IDB_SUFFIXES:
            raise CatalogError(
                f"{source} is a database, not the original bytes it was built"
                " from, so it cannot prove this target's source"
            )
        verified = _verify_association(source, proof)
        stored_proof = _dump_json(verified["proof"])
        sha256 = str(verified["sha256"])

        if self._target.source_sha256 == sha256:
            if self._target.association == ASSOCIATION_ASSERTED:
                # The bytes were already joined to this database on a caller's
                # word; the same bytes now carry proof, so the record stops
                # being an assertion.
                with self._transaction() as connection:
                    self._ensure_target(connection)
                    connection.execute(
                        "UPDATE targets SET source_proof = ?, updated_at = ?"
                        " WHERE target_key = ?",
                        (stored_proof, utc_now(), self._target.key),
                    )
                self._target.association = ASSOCIATION_VERIFIED
            return self._identity_payload()
        if self._target.source_sha256 is not None:
            raise CatalogError(
                "this target is already attached to"
                f" {self._target.source_sha256}, and {sha256} is a different"
                " binary; one target describes one image"
            )
        with self._transaction() as connection:
            self._ensure_target(connection)
            owner = connection.execute(
                "SELECT target_key FROM targets WHERE source_sha256 = ?", (sha256,)
            ).fetchone()
            if owner is not None:
                raise CatalogError(
                    f"{sha256} already belongs to target {owner[0]}; two"
                    " targets cannot claim the same original bytes"
                )
            connection.execute(
                "UPDATE targets SET source_sha256 = ?, source_proof = ?,"
                " updated_at = ? WHERE target_key = ?",
                (sha256, stored_proof, utc_now(), self._target.key),
            )
        self._target.source_sha256 = sha256
        self._target.association = (
            ASSOCIATION_VERIFIED if self._target.managed_idb_id else None
        )
        return self._identity_payload()

    # -- writes -------------------------------------------------------------

    def record_pass(self, analysis_id: str, pass_result: dict[str, object]) -> None:
        """Store one pass result, and the candidates it produced, atomically.

        The whole result is validated before the transaction opens, so a
        rejected pass leaves no row at all — not the analysis, not the pass,
        not the candidates it had already described.

        Re-running a pass replaces that pass's own candidates and nothing else:
        a second run of ``strings`` does not retire what ``functions`` found,
        and a candidate the new run still names is updated in place rather than
        deleted and recreated. That distinction is load-bearing: ``proposals``
        cascade from ``candidates``, so a re-run that recreated an unchanged
        candidate would destroy every decision recorded against it. Only the
        candidates the new result no longer names are deleted, and their
        proposals go with them. A result that carries no ``candidates`` list
        restates the pass without restating its findings, and the rows it
        recorded earlier stay as they are. Either way the stored
        ``candidate_ids`` names the candidate rows this store actually holds,
        so a declared list that does not match them is refused rather than
        written down as a claim nothing backs.
        """
        self._require_writable()
        identifier = _validate_id(analysis_id, "analysis_id")
        parsed = _parse_pass_result(pass_result)
        rows = parsed["candidates"]
        now = utc_now()
        with self._transaction() as connection:
            self._ensure_target(connection)
            self._ensure_analysis(connection, identifier, now)
            if parsed["replaces_candidates"]:
                stored_ids = [row["candidate_id"] for row in rows]
            else:
                stored_ids = [
                    row[0]
                    for row in connection.execute(
                        "SELECT candidate_id FROM candidates WHERE analysis_id"
                        " = ? AND pass_name = ? AND backend = ?"
                        " ORDER BY candidate_id",
                        (identifier, parsed["pass"], parsed["backend"]),
                    )
                ]
            declared = parsed["candidate_ids"]
            if declared is not None and sorted(declared) != sorted(stored_ids):
                raise CatalogError(
                    f"candidate_ids names {sorted(declared)}, and this pass"
                    f" stores {sorted(stored_ids)}: send the candidates"
                    " themselves, because a pass may not claim candidates this"
                    " catalog does not hold"
                )
            connection.execute(
                "INSERT INTO passes (analysis_id, name, backend, coverage,"
                " ranges, applied_ids, candidate_ids, warnings,"
                " artifact_revision, recorded_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(analysis_id, name, backend) DO UPDATE SET"
                " coverage = excluded.coverage, ranges = excluded.ranges,"
                " applied_ids = excluded.applied_ids,"
                " candidate_ids = excluded.candidate_ids,"
                " warnings = excluded.warnings,"
                " artifact_revision = excluded.artifact_revision,"
                " recorded_at = excluded.recorded_at",
                (
                    identifier,
                    parsed["pass"],
                    parsed["backend"],
                    parsed["coverage"],
                    parsed["ranges"],
                    parsed["applied_ids"],
                    _dump_json(stored_ids),
                    parsed["warnings"],
                    parsed["artifact_revision"],
                    now,
                ),
            )
            if parsed["replaces_candidates"]:
                keep = set(stored_ids)
                held = [
                    row[0]
                    for row in connection.execute(
                        "SELECT candidate_id FROM candidates WHERE analysis_id"
                        " = ? AND pass_name = ? AND backend = ?"
                        " ORDER BY candidate_id",
                        (identifier, parsed["pass"], parsed["backend"]),
                    )
                ]
                for candidate_id in held:
                    if candidate_id in keep:
                        continue
                    connection.execute(
                        "DELETE FROM candidates WHERE analysis_id = ?"
                        " AND candidate_id = ?",
                        (identifier, candidate_id),
                    )
            for row in rows:
                owner = connection.execute(
                    "SELECT pass_name, backend FROM candidates WHERE"
                    " analysis_id = ? AND candidate_id = ?",
                    (identifier, row["candidate_id"]),
                ).fetchone()
                if owner is not None and tuple(owner) != (
                    parsed["pass"],
                    parsed["backend"],
                ):
                    raise CatalogError(
                        f"candidate {row['candidate_id']!r} is already held by"
                        f" pass {owner[0]!r} on backend {owner[1]!r} of this"
                        f" analysis, so a {parsed['pass']!r} result may not"
                        " take it over: one candidate id names one finding"
                    )
                connection.execute(
                    "INSERT INTO candidates (analysis_id, candidate_id,"
                    " pass_name, backend, kind, address_space, address,"
                    " evidence, confidence, state, reason, recorded_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(analysis_id, candidate_id) DO UPDATE SET"
                    " kind = excluded.kind,"
                    " address_space = excluded.address_space,"
                    " address = excluded.address,"
                    " evidence = excluded.evidence,"
                    " confidence = excluded.confidence,"
                    " state = excluded.state, reason = excluded.reason,"
                    " recorded_at = excluded.recorded_at",
                    (
                        identifier,
                        row["candidate_id"],
                        parsed["pass"],
                        parsed["backend"],
                        row["kind"],
                        row["address_space"],
                        row["address"],
                        row["evidence_json"],
                        row["confidence"],
                        row["state"],
                        row["reason"],
                        now,
                    ),
                )

    def record_analysis(
        self,
        analysis_id: str,
        *,
        requested_backend: str,
        artifact_path: str,
        capability_fingerprint: str,
        revision: int,
    ) -> dict[str, object]:
        """Describe the analysis revision later passes will be recorded under.

        These four columns are the whole of what makes a revision reusable
        besides the target identity this catalog is already bound to: which
        backend was asked for, which managed artifact answered, what that
        backend could do at the time, and which revision of the artifact the
        passes describe. A reader that cannot match all four re-runs
        preparation rather than reusing a result that was produced by
        something else.

        Returns the stored row, so a caller reports what the catalog holds
        rather than what it sent.
        """
        self._require_writable()
        identifier = _validate_id(analysis_id, "analysis_id")
        backend = _validate_backend(requested_backend)
        artifact = _validate_path(artifact_path, "artifact_path")
        fingerprint = _validate_id(capability_fingerprint, "capability_fingerprint")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise CatalogError(f"revision must be an integer >= 0, got {revision!r}")
        now = utc_now()
        with self._transaction() as connection:
            self._ensure_target(connection)
            self._ensure_analysis(connection, identifier, now)
            connection.execute(
                "UPDATE analyses SET requested_backend = ?, artifact_path = ?,"
                " capability_fingerprint = ?, revision = ?, updated_at = ?"
                " WHERE analysis_id = ?",
                (backend, artifact, fingerprint, revision, now, identifier),
            )
        stored = self.analysis(identifier)
        if stored is None:  # pragma: no cover - the transaction just wrote it
            raise CatalogError(
                f"analysis {identifier!r} was written and cannot be read back"
            )
        return stored

    def record_proposal(
        self,
        analysis_id: str,
        *,
        proposal_id: str,
        candidate_id: str,
        kind: str,
        address_space: str,
        address: int | None,
        value: dict[str, object],
        evidence: dict[str, object],
        rationale: str,
    ) -> dict[str, object]:
        """Store one agent-authored proposal, pending an operator's decision.

        A row is always born ``pending``. There is deliberately no way to
        create a decided one: the whole control this table exists for is that
        the party who writes a proposal is not the party who approves it, and
        a caller able to insert ``applied`` would be both.

        The proposal has to name a candidate this analysis really holds. The
        foreign key would catch it too, but it would catch it as a constraint
        failure; a proposal about a candidate that is not there is an agent
        naming something that does not exist, and is told so.

        Nothing here touches the managed artifact, and nothing here can:
        this module has no IDA path at all.
        """
        self._require_writable()
        analysis = _validate_id(analysis_id, "analysis_id")
        identifier = _validate_id(proposal_id, "proposal_id")
        candidate = _validate_id(candidate_id, "candidate_id")
        if kind not in PROPOSAL_KINDS:
            raise CatalogError(
                f"kind must be one of {', '.join(PROPOSAL_KINDS)}, got {kind!r}"
            )
        space = _validate_id(address_space, "address_space")
        if address is not None and (
            isinstance(address, bool) or not isinstance(address, int) or address < 0
        ):
            raise CatalogError(f"address must be an integer >= 0, got {address!r}")
        if not isinstance(value, dict) or not value:
            raise CatalogError(f"value must be a non-empty object, got {value!r}")
        if not isinstance(evidence, dict) or not evidence:
            raise CatalogError(
                f"evidence must be a non-empty object, got {evidence!r}"
            )
        if not isinstance(rationale, str) or not rationale.strip():
            raise CatalogError("rationale must be a non-empty string")
        # One column, one canonical document. The schema this build owns has
        # one place for the proposal's own content, and splitting it across a
        # column the schema does not have is not an option open to this task;
        # packing both halves of it into that column as canonical JSON is,
        # and :meth:`proposal` is the only reader of the packing.
        body = _dump_json({"value": dict(value), "evidence": dict(evidence)})
        if len(body) > MAX_EVIDENCE_BYTES:
            raise CatalogError(
                f"this proposal's value and evidence are {len(body)} bytes of"
                f" JSON; the limit is {MAX_EVIDENCE_BYTES}"
            )
        now = utc_now()
        with self._transaction() as connection:
            held = connection.execute(
                "SELECT 1 FROM candidates WHERE analysis_id = ? AND"
                " candidate_id = ?",
                (analysis, candidate),
            ).fetchone()
            if held is None:
                raise CatalogError(
                    f"no candidate {candidate!r} is recorded under analysis"
                    f" {analysis!r} of this target, so there is nothing for"
                    " this proposal to be about"
                )
            try:
                connection.execute(
                    "INSERT INTO proposals (proposal_id, analysis_id,"
                    " candidate_id, kind, address_space, address, value,"
                    " rationale, state, expected_revision, decided_at,"
                    " decided_by, decision_reason, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL,"
                    " NULL, NULL, ?)",
                    (
                        identifier,
                        analysis,
                        candidate,
                        kind,
                        space,
                        address,
                        body,
                        rationale,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as collided:
                # A proposal's id is derived from its content, so two
                # submissions of one change race for this row. The loser is
                # owed the refusal the winner's caller would have been given,
                # in this module's vocabulary rather than the driver's.
                raise CatalogError(
                    f"proposal {identifier!r} is already recorded for this"
                    " target, so this exact change is already waiting on a"
                    f" decision: {collided}"
                ) from collided
        stored = self.proposal(identifier)
        if stored is None:  # pragma: no cover - the transaction just wrote it
            raise CatalogError(
                f"proposal {identifier!r} was written and cannot be read back"
            )
        return stored

    def decide_proposal(
        self,
        proposal_id: str,
        *,
        state: str,
        decided_by: str,
        reason: str,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        """Record what the review did with one proposal, if it may do it.

        The transitions are the review path's own order, enforced here so
        that no caller can shorten it. ``pending`` may be approved, rejected
        or found stale. ``approved`` is the decision recorded *before* the
        write it authorizes, so it may become ``applied`` when that write is
        durable, fall back to ``pending`` when it was not, or become
        ``stale``. ``pending`` may never become ``applied`` directly: that
        would be a change applied without the approval that is the whole
        control.

        A row already decided stays decided. A second decision would rewrite
        history that an operator made, and a reviewer reading this table
        would have no way to tell which one happened.

        ``expected_revision`` records the artifact revision the operator
        reviewed against, and is kept once set: the state that follows a
        decision does not get to rewrite which database it was made about.
        """
        self._require_writable()
        identifier = _validate_id(proposal_id, "proposal_id")
        if state not in PROPOSAL_STATES:
            raise CatalogError(
                f"state must be one of {', '.join(PROPOSAL_STATES)}, got"
                f" {state!r}"
            )
        who = _validate_id(decided_by, "decided_by")
        if not isinstance(reason, str) or not reason.strip():
            # Every state, including the retreat to ``pending``: a decision
            # with no reason recorded is one nobody can act on later.
            raise CatalogError("reason must be a non-empty string")
        if expected_revision is not None and (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise CatalogError(
                f"expected_revision must be an integer >= 0, got"
                f" {expected_revision!r}"
            )
        now = utc_now()
        with self._transaction() as connection:
            held = self._held_proposal(connection, identifier)
            allowed = _PROPOSAL_TRANSITIONS[str(held["state"])]
            if state not in allowed:
                raise CatalogError(
                    f"proposal {identifier!r} is {held['state']!r} and may not"
                    f" become {state!r}; from {held['state']!r} it may become"
                    + (
                        f" {', '.join(sorted(allowed))}"
                        if allowed
                        else " nothing: it is already decided"
                    )
                )
            connection.execute(
                "UPDATE proposals SET state = ?, decided_at = ?, decided_by = ?,"
                " decision_reason = ?, expected_revision ="
                " COALESCE(?, expected_revision) WHERE proposal_id = ?",
                (state, now, who, reason, expected_revision, identifier),
            )
        stored = self.proposal(identifier)
        if stored is None:  # pragma: no cover - the transaction just wrote it
            raise CatalogError(
                f"proposal {identifier!r} was decided and cannot be read back"
            )
        return stored

    # -- reads --------------------------------------------------------------

    def page_candidates(
        self, analysis_id: str, offset: int, limit: int
    ) -> dict[str, object]:
        """One window of an analysis's candidates, in a stable order.

        ``0 <= offset`` and ``1 <= limit <= 200``, enforced before anything is
        queried, so a bad window is always reported as a bad window rather than
        as an unknown analysis. An analysis this target does not have raises
        :class:`UnknownAnalysisError`; an analysis with no candidates is an
        empty page.
        """
        try:
            offset, limit = validate_page(offset, limit)
        except OperationError as error:
            raise CatalogError(str(error)) from error
        identifier = _validate_id(analysis_id, "analysis_id")
        self._require_analysis(identifier)
        total = self._connection.execute(
            "SELECT count(*) FROM candidates WHERE analysis_id = ?", (identifier,)
        ).fetchone()[0]
        rows = self._connection.execute(
            "SELECT candidate_id, pass_name, kind, backend, address_space,"
            " address, evidence, confidence, state, reason FROM candidates"
            f" WHERE analysis_id = ? {_PAGE_ORDER} LIMIT ? OFFSET ?",
            (identifier, limit, offset),
        ).fetchall()
        candidates = [
            {
                "candidate_id": row[0],
                "pass": row[1],
                "kind": row[2],
                "backend": row[3],
                "address_space": row[4],
                "address": row[5],
                "evidence": json.loads(row[6]),
                "confidence": row[7],
                "state": row[8],
                "reason": row[9],
            }
            for row in rows
        ]
        return {
            "available": True,
            "analysis_id": identifier,
            **self._identity_payload(),
            "offset": offset,
            "limit": limit,
            "total": total,
            "loaded": len(candidates),
            "candidates": candidates,
        }

    def analysis(self, analysis_id: str) -> dict[str, object] | None:
        """One analysis revision of *this* target, or ``None``.

        An id another target owns answers ``None`` rather than that target's
        row: an analysis belongs to the image it was made from, and a caller
        asking about one target may not be handed another's revision.
        """
        identifier = _validate_id(analysis_id, "analysis_id")
        row = self._connection.execute(
            "SELECT analysis_id, target_key, requested_backend, artifact_path,"
            " capability_fingerprint, revision, created_at, updated_at"
            " FROM analyses WHERE analysis_id = ?",
            (identifier,),
        ).fetchone()
        if row is None or row[1] != self._target.key:
            return None
        return {
            "analysis_id": row[0],
            "target_key": row[1],
            "requested_backend": row[2],
            "artifact_path": row[3],
            "capability_fingerprint": row[4],
            "revision": row[5],
            "created_at": row[6],
            "updated_at": row[7],
        }

    def latest_analysis(self) -> str | None:
        """The most recently written analysis of this target, or ``None``."""
        row = self._connection.execute(
            "SELECT analysis_id FROM analyses WHERE target_key = ?"
            " ORDER BY updated_at DESC, analysis_id ASC LIMIT 1",
            (self._target.key,),
        ).fetchone()
        return None if row is None else str(row[0])

    def pass_results(self, analysis_id: str) -> list[dict[str, object]]:
        """Every pass recorded under ``analysis_id``, as it was stored.

        The rows come back in :data:`vulfi_mcp.contracts.PassResult` shape,
        so a reader of a reused revision sees exactly what the run that
        produced it reported — including a ``partial`` range and the warning
        that explains it, which is the ordinary outcome on a real image.
        """
        identifier = _validate_id(analysis_id, "analysis_id")
        self._require_analysis(identifier)
        rows = self._connection.execute(
            "SELECT name, backend, coverage, ranges, applied_ids,"
            " candidate_ids, warnings, artifact_revision FROM passes"
            " WHERE analysis_id = ? ORDER BY name ASC, backend ASC",
            (identifier,),
        ).fetchall()
        return [
            {
                "pass": row[0],
                "backend": row[1],
                "coverage": row[2],
                "ranges": json.loads(row[3]),
                "applied_ids": json.loads(row[4]),
                "candidate_ids": json.loads(row[5]),
                "warnings": json.loads(row[6]),
                "artifact_revision": row[7],
            }
            for row in rows
        ]

    def applied_candidates(self, analysis_id: str) -> list[str]:
        """Every candidate of this analysis the managed artifact carries.

        Read from the candidate rows rather than from a pass's declared
        ``applied_ids``, so this counts what the store actually holds in the
        ``applied`` state and not what a result claimed about it.
        """
        identifier = _validate_id(analysis_id, "analysis_id")
        self._require_analysis(identifier)
        return [
            str(row[0])
            for row in self._connection.execute(
                "SELECT candidate_id FROM candidates WHERE analysis_id = ?"
                " AND state = 'applied' ORDER BY candidate_id ASC",
                (identifier,),
            )
        ]

    def candidate(
        self, analysis_id: str, candidate_id: str
    ) -> dict[str, object] | None:
        """One stored candidate of this target's analysis, or ``None``.

        ``None`` means this analysis does not hold a candidate under that id —
        including when a later run of its pass dropped it, which is the case
        a proposal has to be refused for rather than applied against evidence
        the store no longer has.
        """
        identifier = _validate_id(analysis_id, "analysis_id")
        self._require_analysis(identifier)
        row = self._connection.execute(
            "SELECT candidate_id, pass_name, kind, backend, address_space,"
            " address, evidence, confidence, state, reason FROM candidates"
            " WHERE analysis_id = ? AND candidate_id = ?",
            (identifier, _validate_id(candidate_id, "candidate_id")),
        ).fetchone()
        if row is None:
            return None
        return {
            "candidate_id": row[0],
            "pass": row[1],
            "kind": row[2],
            "backend": row[3],
            "address_space": row[4],
            "address": row[5],
            "evidence": json.loads(row[6]),
            "confidence": row[7],
            "state": row[8],
            "reason": row[9],
        }

    def proposal(self, proposal_id: str) -> dict[str, object] | None:
        """One proposal *of this target*, or ``None``.

        A proposal id another target owns answers ``None`` rather than that
        target's row, for the same reason :meth:`analysis` does: a reviewer
        asking about one image may not be handed, or approve, a decision
        about another.
        """
        row = self._connection.execute(
            "SELECT p.proposal_id, p.analysis_id, p.candidate_id, p.kind,"
            " p.address_space, p.address, p.value, p.rationale, p.state,"
            " p.expected_revision, p.decided_at, p.decided_by,"
            " p.decision_reason, p.created_at FROM proposals p"
            " JOIN analyses a ON a.analysis_id = p.analysis_id"
            " WHERE p.proposal_id = ? AND a.target_key = ?",
            (_validate_id(proposal_id, "proposal_id"), self._target.key),
        ).fetchone()
        return None if row is None else _proposal_row(row)

    def page_proposals(
        self,
        analysis_id: str | None = None,
        *,
        state: str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        """One window of this target's proposals, newest decision last.

        ``analysis_id`` narrows to one revision and ``state`` to one stage of
        review; both default to everything this target holds, because an
        operator opening the review command wants the queue, not a revision
        they would have to know the id of first.
        """
        try:
            offset, limit = validate_page(offset, limit)
        except OperationError as error:
            raise CatalogError(str(error)) from error
        where = ["a.target_key = ?"]
        parameters: list[object] = [self._target.key]
        if analysis_id is not None:
            where.append("p.analysis_id = ?")
            parameters.append(_validate_id(analysis_id, "analysis_id"))
        if state is not None:
            if state not in PROPOSAL_STATES:
                raise CatalogError(
                    f"state must be one of {', '.join(PROPOSAL_STATES)}, got"
                    f" {state!r}"
                )
            where.append("p.state = ?")
            parameters.append(state)
        clause = " AND ".join(where)
        total = self._connection.execute(
            "SELECT count(*) FROM proposals p JOIN analyses a"
            f" ON a.analysis_id = p.analysis_id WHERE {clause}",
            tuple(parameters),
        ).fetchone()[0]
        rows = self._connection.execute(
            "SELECT p.proposal_id, p.analysis_id, p.candidate_id, p.kind,"
            " p.address_space, p.address, p.value, p.rationale, p.state,"
            " p.expected_revision, p.decided_at, p.decided_by,"
            " p.decision_reason, p.created_at FROM proposals p"
            f" JOIN analyses a ON a.analysis_id = p.analysis_id WHERE {clause}"
            " ORDER BY p.created_at ASC, p.proposal_id ASC LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        ).fetchall()
        proposals = [_proposal_row(row) for row in rows]
        return {
            "analysis_id": analysis_id,
            "state": state,
            **self._identity_payload(),
            "offset": offset,
            "limit": limit,
            "total": total,
            "loaded": len(proposals),
            "proposals": proposals,
        }

    def _held_proposal(
        self, connection: sqlite3.Connection, proposal_id: str
    ) -> dict[str, object]:
        """The proposal a decision is about, inside that decision's write."""
        row = connection.execute(
            "SELECT p.proposal_id, p.analysis_id, p.candidate_id, p.kind,"
            " p.address_space, p.address, p.value, p.rationale, p.state,"
            " p.expected_revision, p.decided_at, p.decided_by,"
            " p.decision_reason, p.created_at FROM proposals p"
            " JOIN analyses a ON a.analysis_id = p.analysis_id"
            " WHERE p.proposal_id = ? AND a.target_key = ?",
            (proposal_id, self._target.key),
        ).fetchone()
        if row is None:
            raise CatalogError(
                f"no proposal {proposal_id!r} is recorded for target"
                f" {self._target.key}"
            )
        return _proposal_row(row)

    # -- internals ----------------------------------------------------------

    def _identity_payload(self) -> dict[str, object]:
        return {
            "target_key": self._target.key,
            "source_sha256": self._target.source_sha256,
            "managed_idb_id": self._target.managed_idb_id,
            "source_association": self._target.association,
        }

    def _require_writable(self) -> None:
        if not self._writable:
            raise ReadOnlyCatalogError(
                "this catalog was opened for reading; open_catalog is the only"
                " entry point that may change it"
            )

    def _require_analysis(self, analysis_id: str) -> None:
        row = self._connection.execute(
            "SELECT target_key FROM analyses WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()
        if row is None or row[0] != self._target.key:
            raise UnknownAnalysisError(
                f"no analysis {analysis_id!r} is recorded for target"
                f" {self._target.key}"
            )

    def _ensure_target(self, connection: sqlite3.Connection) -> None:
        if self._target.present:
            return
        now = utc_now()
        proof = (
            _dump_json(
                {
                    "kind": _ASSERTED_KIND,
                    "managed_idb_id": self._target.managed_idb_id,
                    "source_sha256": self._target.source_sha256,
                    "asserted_at": now,
                }
            )
            if self._target.association == ASSOCIATION_ASSERTED
            else None
        )
        connection.execute(
            "INSERT INTO targets (target_key, source_sha256, managed_idb_id,"
            " source_proof, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                self._target.key,
                self._target.source_sha256,
                self._target.managed_idb_id,
                proof,
                now,
                now,
            ),
        )
        self._target.present = True

    def _ensure_analysis(
        self, connection: sqlite3.Connection, analysis_id: str, now: str
    ) -> None:
        row = connection.execute(
            "SELECT target_key FROM analyses WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO analyses (analysis_id, target_key, created_at,"
                " updated_at) VALUES (?, ?, ?, ?)",
                (analysis_id, self._target.key, now, now),
            )
            return
        if row[0] != self._target.key:
            raise CatalogError(
                f"analysis {analysis_id!r} belongs to another target"
                f" ({row[0]}), so this target's passes cannot be recorded"
                " under it"
            )
        connection.execute(
            "UPDATE analyses SET updated_at = ? WHERE analysis_id = ?",
            (now, analysis_id),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """One write, all or nothing, with the lock taken up front."""
        connection = self._connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        connection.commit()


# -- identity ---------------------------------------------------------------


def _canonical_target(path: str) -> Path:
    """The one spelling of a supplied target, or a refusal.

    The rule is :func:`vulfi_mcp.ida_adapter.ensure_managed_idb`'s, down to the
    message; only the exception type differs, because every refusal this module
    makes is a :class:`CatalogError` so one caller can catch one family.
    """
    if not isinstance(path, str) or not path:
        raise CatalogError("path must be a non-empty string")
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise CatalogError(f"no such binary or IDA database: {source}")
    return source


def _target_input(path: str, managed_idb_id: object) -> tuple[Path, bool, str | None]:
    """The canonical target, whether it is a database, and its netnode id."""
    source = _canonical_target(path)
    idb_id = _validate_managed_idb_id(managed_idb_id)
    is_database = source.suffix.lower() in IDB_SUFFIXES
    if is_database and idb_id is None:
        raise CatalogError(
            f"{source} is an IDA database, so its original bytes are unknown:"
            " a managed_idb_id from its netnode is required to identify it"
        )
    return source, is_database, idb_id


def _identity(path: str, managed_idb_id: object) -> tuple[str | None, str | None]:
    """The two halves of a target's identity, as the caller's input allows.

    A binary is hashed. A database is not: its bytes are IDA's, not the
    image's, so the only stable thing about it is the id minted in its netnode.
    """
    source, is_database, idb_id = _target_input(path, managed_idb_id)
    return (None if is_database else _sha256(source)), idb_id


def _validate_managed_idb_id(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CatalogError(f"managed_idb_id must be a non-empty string, got {value!r}")
    if len(value) > 40 or not set(value) <= _ID_CHARACTERS:
        raise CatalogError(
            "managed_idb_id must be the hexadecimal UUID the netnode minted,"
            f" got {value!r}"
        )
    return value


def _sha256(source: Path) -> str:
    """The digest of a file, read in bounded chunks rather than all at once."""
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        while chunk := stream.read(HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_target(
    connection: sqlite3.Connection,
    source_sha256: str | None,
    managed_idb_id: str | None,
    *,
    create: bool,
) -> _Target:
    """Find, or describe, the target these identities name.

    The one join this refuses is the dangerous one: raw bytes arriving for a
    stored target that was never shown to come from them. That is what
    :meth:`Catalog.attach_source` is for, and it wants evidence.

    The other direction — a database id arriving for bytes this store already
    knows — is the flow that just built that database from those very bytes, so
    it is accepted, but nothing here has checked it. It is written down as
    :data:`ASSOCIATION_ASSERTED` rather than as proof, so a later
    database-only read is told the identity it inherits rests on a caller's
    word and not on bytes anyone compared.
    """
    by_sha = (
        connection.execute(
            "SELECT target_key, source_sha256, managed_idb_id, source_proof"
            " FROM targets WHERE source_sha256 = ?",
            (source_sha256,),
        ).fetchone()
        if source_sha256 is not None
        else None
    )
    by_id = (
        connection.execute(
            "SELECT target_key, source_sha256, managed_idb_id, source_proof"
            " FROM targets WHERE managed_idb_id = ?",
            (managed_idb_id,),
        ).fetchone()
        if managed_idb_id is not None
        else None
    )

    if by_sha is not None:
        if by_id is not None and by_id[0] != by_sha[0]:
            raise UnverifiedAssociationError(
                f"managed database {managed_idb_id} answers for target"
                f" {by_id[0]}, but these bytes belong to {by_sha[0]}"
            )
        if by_id is None and managed_idb_id is not None and create:
            if by_sha[2] is not None:
                # by_id is None, so this is a *different* database claiming
                # bytes that already answer for one. Overwriting would re-home
                # every row recorded under the old id without saying so.
                raise UnverifiedAssociationError(
                    f"these bytes answer for managed database {by_sha[2]} as"
                    f" target {by_sha[0]}, and {managed_idb_id} is a different"
                    " database: one target records one managed database"
                )
            now = utc_now()
            asserted = _dump_json(
                {
                    "kind": _ASSERTED_KIND,
                    "managed_idb_id": managed_idb_id,
                    "source_sha256": source_sha256,
                    "asserted_at": now,
                }
            )
            # Written as an assertion, not as proof: nothing here compared the
            # database against the bytes. The guard keeps a verified proof
            # from ever being downgraded to one.
            _write_once(
                connection,
                "UPDATE targets SET managed_idb_id = ?, source_proof = ?,"
                " updated_at = ? WHERE target_key = ?"
                " AND managed_idb_id IS NULL AND source_proof IS NULL",
                (managed_idb_id, asserted, now, by_sha[0]),
            )
            stored = connection.execute(
                "SELECT target_key, source_sha256, managed_idb_id, source_proof"
                " FROM targets WHERE target_key = ?",
                (by_sha[0],),
            ).fetchone()
            return _Target(
                stored[0],
                stored[1],
                stored[2],
                present=True,
                association=_association(stored[1], stored[2], stored[3]),
            )
        return _Target(
            by_sha[0],
            by_sha[1],
            by_sha[2],
            present=True,
            association=_association(by_sha[1], by_sha[2], by_sha[3]),
        )

    if by_id is not None:
        if source_sha256 is not None and by_id[1] != source_sha256:
            known = "unknown" if by_id[1] is None else by_id[1]
            raise UnverifiedAssociationError(
                f"managed database {managed_idb_id} answers for target"
                f" {by_id[0]}, whose original bytes are {known}, not"
                f" {source_sha256}: raw bytes join a database-only target"
                " through attach_source and a verified fingerprint or"
                " segment-byte association, never because a name matches"
            )
        return _Target(
            by_id[0],
            by_id[1],
            by_id[2],
            present=True,
            association=_association(by_id[1], by_id[2], by_id[3]),
        )

    key = f"sha256:{source_sha256}" if source_sha256 else f"idb:{managed_idb_id}"
    now = utc_now()
    proof = (
        _dump_json(
            {
                "kind": _ASSERTED_KIND,
                "managed_idb_id": managed_idb_id,
                "source_sha256": source_sha256,
                "asserted_at": now,
            }
        )
        if source_sha256 is not None and managed_idb_id is not None
        else None
    )
    target = _Target(
        key,
        source_sha256,
        managed_idb_id,
        present=False,
        association=_association(source_sha256, managed_idb_id, proof),
    )
    if create:
        _write_once(
            connection,
            "INSERT INTO targets (target_key, source_sha256, managed_idb_id,"
            " source_proof, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key, source_sha256, managed_idb_id, proof, now, now),
        )
        target.present = True
    return target


def _association(
    source_sha256: str | None, managed_idb_id: str | None, proof: str | None
) -> str | None:
    """How this row's database and its original bytes came to be joined.

    ``None`` when there is no join to describe: a target with only one of the
    two identities has nothing to be right or wrong about. A stored proof of a
    kind :meth:`Catalog.attach_source` checks is ``verified``; anything else,
    including a row that carries both identities and no proof at all, is
    ``asserted``, because absence of evidence is not evidence.
    """
    if source_sha256 is None or managed_idb_id is None:
        return None
    try:
        stored = json.loads(proof) if proof else None
    except ValueError:
        stored = None
    if isinstance(stored, dict) and stored.get("kind") in (
        _FINGERPRINT,
        _SEGMENT_BYTES,
    ):
        return ASSOCIATION_VERIFIED
    return ASSOCIATION_ASSERTED


def _write_once(
    connection: sqlite3.Connection, statement: str, parameters: tuple[object, ...]
) -> None:
    """One statement in its own transaction, rolled back if it fails."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(statement, parameters)
    except BaseException:
        connection.rollback()
        raise
    connection.commit()


def _verify_association(source: Path, proof: object) -> dict[str, object]:
    """Check a claimed relationship against the bytes on disk."""
    if proof is None:
        raise UnverifiedAssociationError(
            "a database-only target cannot adopt raw bytes without proof:"
            f" supply a {_FINGERPRINT!r} or {_SEGMENT_BYTES!r} association"
            " read out of the database — a matching file name is not evidence"
        )
    if not isinstance(proof, dict):
        raise UnverifiedAssociationError(
            f"proof must be an object, got {type(proof).__name__}"
        )
    kind = proof.get("kind")
    if kind == _FINGERPRINT:
        return _verify_fingerprint(source, proof)
    if kind == _SEGMENT_BYTES:
        return _verify_segment_bytes(source, proof)
    raise UnverifiedAssociationError(
        f"proof kind must be {_FINGERPRINT!r} or {_SEGMENT_BYTES!r},"
        f" got {kind!r}"
    )


def _verify_fingerprint(source: Path, proof: dict[str, object]) -> dict[str, object]:
    claimed = proof.get("sha256")
    if not isinstance(claimed, str) or len(claimed) != 64:
        raise UnverifiedAssociationError(
            f"the stored input fingerprint must be a SHA-256 digest, got"
            f" {claimed!r}"
        )
    claimed = claimed.lower()
    actual = _sha256(source)
    if actual != claimed:
        raise UnverifiedAssociationError(
            f"{source} hashes to {actual}, and the database recorded its input"
            f" as {claimed}: these are different files"
        )
    return {
        "sha256": actual,
        "proof": {"kind": _FINGERPRINT, "sha256": actual},
    }


def _verify_segment_bytes(source: Path, proof: dict[str, object]) -> dict[str, object]:
    spans = proof.get("spans")
    if not isinstance(spans, list) or not spans:
        raise UnverifiedAssociationError(
            "a segment-byte association needs a non-empty 'spans' list of"
            " {address, file_offset, bytes} objects"
        )
    if len(spans) > MAX_SEGMENT_PROOF_SPANS:
        raise UnverifiedAssociationError(
            f"a segment-byte association may carry at most"
            f" {MAX_SEGMENT_PROOF_SPANS} spans, got {len(spans)}"
        )
    checked: list[dict[str, object]] = []
    # Every span proved so far, as half-open file ranges. The threshold below
    # only means something if the spans cover distinct bytes: sixty-four copies
    # of the same four bytes of ELF magic are one coincidence repeated, not a
    # quarter of a kilobyte of agreement. At MAX_SEGMENT_PROOF_SPANS spans this
    # comparison is at most a few thousand integer tests.
    proved: list[tuple[int, int, int]] = []
    matched = 0
    with source.open("rb") as stream:
        for index, span in enumerate(spans):
            address, offset, expected = _span(span, index)
            end = offset + len(expected)
            for earlier, start, stop in proved:
                if offset < stop and start < end:
                    raise UnverifiedAssociationError(
                        f"span {index} covers file offsets {max(offset, start)}"
                        f" to {min(end, stop)} of {source}, which span {earlier}"
                        " already proved: a segment-byte association must cover"
                        " distinct file offsets, because repeating one span"
                        " proves nothing beyond that one span"
                    )
            stream.seek(offset)
            actual = stream.read(len(expected))
            if actual != expected:
                raise UnverifiedAssociationError(
                    f"span {index} claims {len(expected)} bytes of {source} at"
                    f" offset {offset} (address {address:#x}), and the file"
                    " does not hold them: this database describes other bytes"
                )
            matched += len(expected)
            proved.append((index, offset, end))
            checked.append(
                {"address": address, "file_offset": offset, "length": len(expected)}
            )
    if matched < MIN_SEGMENT_PROOF_BYTES:
        raise UnverifiedAssociationError(
            f"a segment-byte association proves {matched} distinct bytes; at"
            f" least {MIN_SEGMENT_PROOF_BYTES} must match before a provisional"
            " target adopts a file"
        )
    return {
        "sha256": _sha256(source),
        "proof": {"kind": _SEGMENT_BYTES, "spans": checked, "matched_bytes": matched},
    }


def _span(span: object, index: int) -> tuple[int, int, bytes]:
    if not isinstance(span, dict):
        raise UnverifiedAssociationError(
            f"span {index} must be an object, got {type(span).__name__}"
        )
    address = _whole_number(span.get("address"), f"span {index} address")
    offset = _whole_number(span.get("file_offset"), f"span {index} file_offset")
    raw = span.get("bytes")
    if not isinstance(raw, str) or not raw:
        raise UnverifiedAssociationError(
            f"span {index} must carry its 'bytes' as a hexadecimal string"
        )
    if len(raw) > 2 * MAX_SEGMENT_PROOF_BYTES:
        raise UnverifiedAssociationError(
            f"span {index} is longer than the {MAX_SEGMENT_PROOF_BYTES} bytes"
            " one span may prove"
        )
    try:
        expected = bytes.fromhex(raw)
    except ValueError as error:
        raise UnverifiedAssociationError(
            f"span {index} is not hexadecimal: {error}"
        ) from error
    if not expected:
        raise UnverifiedAssociationError(f"span {index} carries no bytes")
    return address, offset, expected


def _whole_number(value: object, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise UnverifiedAssociationError(
            f"{what} must be an integer >= 0, got {value!r}"
        )
    return value


# -- pass results -----------------------------------------------------------


def _validate_backend(backend: object) -> str:
    if backend not in BACKENDS:
        raise CatalogError(
            f"backend must be one of {sorted(BACKENDS)}, got {backend!r}"
        )
    return str(backend)


def _parse_pass_result(pass_result: object) -> dict[str, Any]:
    """Validate a whole pass result before a single row of it is written."""
    if not isinstance(pass_result, dict):
        raise CatalogError(
            f"a pass result must be an object, got {type(pass_result).__name__}"
        )
    name = pass_result.get("pass")
    if name not in PASS_NAMES:
        raise CatalogError(
            f"pass must be one of {sorted(PASS_NAMES)}, got {name!r}"
        )
    backend = _validate_backend(pass_result.get("backend"))
    coverage = pass_result.get("coverage")
    if coverage not in COVERAGES:
        raise CatalogError(
            f"coverage must be one of {sorted(COVERAGES)}, got {coverage!r}"
        )
    revision = pass_result.get("artifact_revision")
    if revision is not None and (
        isinstance(revision, bool) or not isinstance(revision, int) or revision < 0
    ):
        raise CatalogError(
            f"artifact_revision must be an integer >= 0 or null, got {revision!r}"
        )
    parsed: dict[str, Any] = {
        "pass": name,
        "backend": backend,
        "coverage": coverage,
        "artifact_revision": revision,
        # Already canonical JSON text: validating these means serializing
        # them, and serializing the same list twice to store it once is work
        # nobody asked for.
        "ranges": _json_array(pass_result.get("ranges"), "ranges"),
        "applied_ids": _json_array(pass_result.get("applied_ids"), "applied_ids"),
        "warnings": _json_array(pass_result.get("warnings"), "warnings"),
    }
    # A result that carries no 'candidates' key is reporting the pass, not
    # restating its findings, so the rows it recorded earlier stay put.
    raw = pass_result.get("candidates")
    parsed["replaces_candidates"] = raw is not None
    rows = [] if raw is None else _candidates(raw, str(backend))
    parsed["candidates"] = rows
    declared = pass_result.get("candidate_ids")
    if declared is not None and (
        not isinstance(declared, list)
        or any(not isinstance(item, str) for item in declared)
    ):
        raise CatalogError("candidate_ids must be a list of strings")
    # Compared against the rows the store ends up holding, not against the
    # list that came with them: the point is that the pass cannot name a
    # candidate nothing in this catalog backs.
    parsed["candidate_ids"] = declared
    return parsed


def _candidates(raw: object, backend: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise CatalogError(f"candidates must be a list, got {type(raw).__name__}")
    rows = [_candidate(item, index, backend) for index, item in enumerate(raw)]
    seen = {row["candidate_id"] for row in rows}
    if len(seen) != len(rows):
        raise CatalogError("two candidates in this pass carry the same candidate_id")
    return rows


def _candidate(item: object, index: int, backend: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise CatalogError(
            f"candidate {index} must be an object, got {type(item).__name__}"
        )
    candidate_id = _validate_id(item.get("candidate_id"), f"candidate {index} id")
    kind = item.get("kind")
    if not isinstance(kind, str) or not kind or len(kind) > MAX_ID_LENGTH:
        raise CatalogError(f"candidate {candidate_id!r} needs a kind, got {kind!r}")
    space = item.get("address_space")
    if not isinstance(space, str) or not space or len(space) > MAX_ID_LENGTH:
        raise CatalogError(
            f"candidate {candidate_id!r} needs an address_space, got {space!r}"
        )
    address = item.get("address")
    if address is not None and (
        isinstance(address, bool) or not isinstance(address, int) or address < 0
    ):
        raise CatalogError(
            f"candidate {candidate_id!r} must carry an address >= 0 or null,"
            f" got {address!r}"
        )
    row_backend = item.get("backend", backend)
    if row_backend != backend:
        raise CatalogError(
            f"candidate {candidate_id!r} claims backend {row_backend!r} inside"
            f" a {backend!r} pass"
        )
    confidence = item.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise CatalogError(
            f"candidate {candidate_id!r} needs a numeric confidence, got"
            f" {confidence!r}"
        )
    if not 0.0 <= float(confidence) <= 1.0:
        raise CatalogError(
            f"candidate {candidate_id!r} has confidence {confidence!r};"
            " confidence is a number in 0..1, and it is not proof"
        )
    state = item.get("state")
    if state not in CANDIDATE_STATES:
        raise CatalogError(
            f"candidate {candidate_id!r} has state {state!r}; state must be one"
            f" of {sorted(CANDIDATE_STATES)}"
        )
    reason = item.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise CatalogError(
            f"candidate {candidate_id!r} must give its reason as text or null,"
            f" got {type(reason).__name__}"
        )
    evidence = item.get("evidence")
    if not isinstance(evidence, dict):
        raise CatalogError(
            f"candidate {candidate_id!r} must carry its evidence as an object;"
            " a candidate without evidence is a guess"
        )
    encoded = _dump_json(evidence)
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise CatalogError(
            f"candidate {candidate_id!r} carries more than"
            f" {MAX_EVIDENCE_BYTES} bytes of evidence"
        )
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "address_space": space,
        "address": address,
        "evidence_json": encoded,
        "confidence": float(confidence),
        "state": state,
        "reason": reason,
    }


def _proposal_row(row: tuple[Any, ...]) -> dict[str, object]:
    """One stored proposal, with its packed value and evidence unpacked.

    The column holds one canonical JSON document carrying both halves of the
    proposal's own content; this is the only place that knows that, so every
    reader above sees ``value`` and ``evidence`` as the separate things they
    are.
    """
    body = json.loads(row[6])
    return {
        "proposal_id": row[0],
        "analysis_id": row[1],
        "candidate_id": row[2],
        "kind": row[3],
        "address_space": row[4],
        "address": row[5],
        "value": body.get("value", {}),
        "evidence": body.get("evidence", {}),
        "rationale": row[7],
        "state": row[8],
        "expected_revision": row[9],
        "decided_at": row[10],
        "decided_by": row[11],
        "decision_reason": row[12],
        "created_at": row[13],
    }


def _validate_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{what} must be a non-empty string, got {value!r}")
    if len(value) > MAX_ID_LENGTH:
        raise CatalogError(f"{what} is longer than {MAX_ID_LENGTH} characters")
    return value


def _validate_path(value: object, what: str) -> str:
    """One filesystem path, bounded as a path rather than as an identifier."""
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{what} must be a non-empty string, got {value!r}")
    if len(value) > MAX_PATH_LENGTH:
        raise CatalogError(f"{what} is longer than {MAX_PATH_LENGTH} characters")
    return value


def _json_array(value: object, what: str) -> str:
    """One JSON array, as the text that will be stored."""
    if value is None:
        return "[]"
    if not isinstance(value, list):
        raise CatalogError(f"{what} must be a list, got {type(value).__name__}")
    return _dump_json(value)


def _dump_json(value: object) -> str:
    """Canonical JSON, so the same value is the same bytes in every row."""
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as error:
        raise CatalogError(f"value is not JSON: {error}") from error


# -- connections and schema -------------------------------------------------


def _connect(store: Path, *, writable: bool) -> sqlite3.Connection:
    """One connection, with foreign keys on and transactions left to us."""
    uri = store.as_uri() if writable else f"{store.as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
    except sqlite3.Error as error:
        raise CatalogError(
            f"the catalog at {store} could not be opened: {error}"
        ) from error
    try:
        connection.execute("PRAGMA foreign_keys = ON")
    except sqlite3.Error as error:
        connection.close()
        raise CatalogError(
            f"the catalog at {store} could not be prepared: {error}"
        ) from error
    return connection


def _apply_schema(connection: sqlite3.Connection) -> None:
    """Create the schema once, or refuse a version this build does not own."""
    version = _version(connection)
    if version == SCHEMA_VERSION:
        return
    if version > SCHEMA_VERSION:
        raise CatalogSchemaError(
            f"this catalog is schema version {version}; this build reads and"
            f" writes version {SCHEMA_VERSION} only, and will not migrate or"
            " overwrite a newer one"
        )
    if version != 0:
        raise CatalogSchemaError(
            f"this catalog is schema version {version}, which this build"
            f" (version {SCHEMA_VERSION}) has no migration for"
        )
    connection.execute("BEGIN IMMEDIATE")
    try:
        if _version(connection) != 0:  # Another process won the race.
            connection.rollback()
            _require_known_version(connection)
            return
        if _has_tables(connection):
            raise CatalogSchemaError(
                "this file holds tables but carries no schema version, so it"
                " is not a VulFi catalog and this build will not write over it"
            )
        for statement in _SCHEMA:
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    except BaseException:
        connection.rollback()
        raise
    connection.commit()


def _has_tables(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
    ).fetchone()
    return row is not None


def _require_known_version(connection: sqlite3.Connection) -> None:
    version = _version(connection)
    if version != SCHEMA_VERSION:
        raise CatalogSchemaError(
            f"this catalog is schema version {version}; this build reads"
            f" version {SCHEMA_VERSION} only"
        )


def _version(connection: sqlite3.Connection) -> int:
    return int(connection.execute("PRAGMA user_version").fetchone()[0])
