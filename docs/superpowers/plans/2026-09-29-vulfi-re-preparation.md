# VulFi RE Preparation and Proposal Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Before scanning, recover justified strings, functions, structure fields, and pointer tables in managed IDA artifacts; expose bounded evidence and inert LLM proposals; allow explicit operator review to apply safe changes.

**Architecture:** Build on the [IDA core plan](2026-09-29-vulfi-ida-core.md). `prepare.py` coordinates four evidence passes, a per-target SQLite candidate catalog, and a bounded IDB preparation summary. IDAPython performs deterministic recovery only on managed IDBs; user binaries and supplied IDBs are never overwritten. External backends join the same pass contract in [Plan 3](2026-09-29-vulfi-mcp-fallback.md); linked triage and OMP review arrive in [Plan 4](2026-09-29-vulfi-linked-triage-omp.md). This is an internal milestone, not a final release.

**Tech Stack:** Python >=3.11; IDA >=9.4, official Nexus source-backed IDAPython; stdlib `sqlite3`, `hashlib`, `json`, `pathlib`; `pytest`, `gcc` and fixture ELF binaries.

**Spec:** [RE preparation design](../specs/2026-09-29-vulfi-re-preparation-design.md) and [MCP/storage design](../specs/2026-09-28-vulfi-ida-mcp-design.md).

## Global Constraints

- Reuse Plan 1 `ensure_managed_idb`, `invoke_ida`, `run`, `ScanResult`, `Rule`, and netnode v2; do not fork a second IDA MCP server. `vulfi_prepare`, `vulfi_preparation`, `vulfi_propose_recovery` bring the public VulFi tool count from four to seven.
- A pass has `complete|partial|unavailable` **per address range**, not a numeric discovery target. Discovery is bounded and never promises all hidden data. `Info` and clean negative scan results still require verified arguments.
- Use original binary SHA-256 for catalog identity when raw bytes are available; use stable provisional `managed_idb_id` otherwise. SQLite belongs in operator-configured application data, not source/binary directory. Missing SQLite is unavailable, not an empty set of candidates.
- Normalize original binary and IDB paths, preserve read-only source bytes, checkpoint managed IDB before mutation, and report actual save failures/partial passes. No auto-execution of recovered bytes or generated scripts.
- Agent-authored proposals may only be stored through MCP. Approval/rejection and application live in a separate operator CLI (and later OMP confirmation), with revision revalidation; operators must restrict CLI credentials for enforced human separation.
- Use `uv run --python 3.11`; integration tests exercise real compiled artifacts and actual IDA saves. Never substitute mocked candidate counts, tool echoes, or source-text assertions for recovered facts.

## Review Focus

- An IDB-only analysis cannot be silently attached to unrelated raw bytes because a filename matches; test Task 1's provisional identity and verified-association boundary.
- UTF-16BE/embedded-NUL raw bytes and a constant-built stack string must retain exact byte/operation evidence, not a guessed decoded label; test Task 2.
- A call target overlapping an existing function tail must stay a candidate rather than redefining code; test Task 2.
- Aligned pointer-looking integers without relocation/xref support and conflicting structure fields must never be auto-applied; test Task 3.
- A stale approval, IDB save failure, or catalog failure must not report a durable approved revision; test Task 5.

---

### Task 1: Catalog identity, candidate storage, and unavailable reads

**Files:** Create `src/vulfi_mcp/catalog.py`, `tests/test_catalog.py`; modify `src/vulfi_mcp/contracts.py`, `src/vulfi_mcp/ida_runtime.py` for stable `managed_idb_id` if not already recorded.

**Interfaces:** Produce `open_catalog(path: str, managed_idb_id: str | None = None) -> Catalog` (explicit mutation/create path), `get_catalog(path: str, managed_idb_id: str | None = None) -> Catalog | None` (read-only; never creates files), and `Catalog.record_pass(analysis_id: str, pass_result: dict[str, object]) -> None`/`Catalog.page_candidates(analysis_id: str, offset: int, limit: int) -> dict[str, object]`. `Catalog` owns SQLite `targets`, `analyses`, `passes`, `candidates`, `proposals`, `external_scopes`, `external_findings`, `links`, `sync_events` schema with foreign keys and versioning; Plans 3/4 populate their tables, without inventing placeholder rows. Output `analysis_id`, stable target key and binary SHA when present. Use `VULFI_MCP_DATA_DIR` only as a trusted operator environment setting in tests/deployment.

- [ ] **Step 1: Write failing behavior tests.** `test_binary_sha_namespaces_two_catalogs` writes two different binaries with identical basenames into separate directories and asserts separate SHA keys and no source-tree SQLite; `test_idb_only_keeps_provisional_identity` reopens a managed IDB, checks unchanged provisional UUID, and rejects attachment of unrelated bytes without stored fingerprint/segment-byte proof; `test_missing_catalog_reports_unavailable` calls read-only `get_catalog` and verifies no file was created.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/test_catalog.py -q` must FAIL on missing catalog API.
- [ ] **Step 3: Implement schema-versioned catalog and path/identity rules.** Hash raw bytes in bounded streaming chunks, use transactions, enable foreign keys, reject future schema versions, distinguish absence from zero rows. Persist IDB provisional identity through the netnode while keeping raw binary hash unknown until verifiable association.
- [ ] **Step 4: Run green.** `uv run --python 3.11 pytest tests/test_catalog.py -q` must PASS, including temp application data path and reopens.
- [ ] **Step 5: Commit.** `git add src/vulfi_mcp/catalog.py src/vulfi_mcp/contracts.py src/vulfi_mcp/ida_runtime.py tests/test_catalog.py && git commit -m "feat: catalog preparation evidence by target"` (include only files actually changed).

### Task 2: Find hidden functions and recover source-backed strings

**Files:** Create `src/vulfi_mcp/prepare.py`, `tests/fixtures/vulfi_preparation.c`, `tests/integration/test_prepare_code_strings.py`; modify `src/vulfi_mcp/contracts.py`, `src/vulfi_mcp/ida_runtime.py`, `src/vulfi_mcp/ida_adapter.py`.

**Interfaces:** Produce `run_ida_passes(idb_path: str, passes: tuple[str, ...], limits: dict[str, int]) -> dict[str, object]` in `prepare.py`, delegating to source-backed `run("prepare", payload)` through Plan 1 `invoke_ida`. Define JSON-native `Candidate` with `candidate_id`, `kind`, `backend`, `address_space`, `address`, `evidence`, `confidence`, `state`, `reason` and `PassResult` with `pass`, `backend`, `ranges`, `coverage`, `applied_ids`, `candidate_ids`, `warnings`, `artifact_revision` in `contracts.py` so providers can import types without a `prepare.py` routing import cycle. `functions` must run before instruction-derived `strings` while independent raw mapped-byte string discovery can run first; requested subsets explain skipped prerequisites.

- [ ] **Step 1: Write failing integration tests.** Compile `vulfi_preparation.c` with `gcc -O0 -fno-inline -fPIE -pie`, then prepare a disposable managed IDB with one function deliberately undefined and one raw section's strings untyped at baseline. `test_recover_unmarked_function_and_strings` asserts the justified function boundary exists after preparation, printable/UTF-16LE/UTF-16BE bytes map to exact evidence addresses, and a constant-write stack string cites instruction/value evidence; verify the source's checksum unchanged and original IDB still untyped. `test_overlap_stays_candidate` supplies an overlapping tail target and checks the old function unchanged. `test_budget_and_cancel_are_partial` bounds bytes/candidates or interrupts a pass and checks explicit unvisited ranges/partial coverage.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_prepare_code_strings.py -q` must FAIL before worker pass implementation.
- [ ] **Step 3: Implement evidence-first function/string passes.** Inspect executable gaps/call xrefs, decode reachable instruction boundaries and non-overlap before creating functions. Scan mapped bytes for bounded ASCII/UTF-16 in both orders and recover only provably constant stack writes; do not treat binary text or decompiler prose as an instruction. Checkpoint before safe managed-IDB mutations, report range-level limits and unsupported stack recovery explicitly.
- [ ] **Step 4: Run green and smoke IDA.** `uv run --python 3.11 pytest tests/integration/test_prepare_code_strings.py -q` must PASS; separately reopen disposable managed IDB and inspect the recovered function/string evidence and unchanged original bytes.
- [ ] **Step 5: Commit.** `git add src/vulfi_mcp/prepare.py src/vulfi_mcp/contracts.py src/vulfi_mcp/ida_runtime.py src/vulfi_mcp/ida_adapter.py tests/fixtures/vulfi_preparation.c tests/integration/test_prepare_code_strings.py && git commit -m "feat: recover bounded functions and strings"`.

### Task 3: Structure fields and relocation-backed pointer tables

**Files:** Modify `src/vulfi_mcp/prepare.py`, `src/vulfi_mcp/ida_runtime.py`, `tests/fixtures/vulfi_preparation.c`; create `tests/integration/test_prepare_data.py`.

**Interfaces:** Extend `run_ida_passes(..., passes=("structures", "pointer_tables"), ...)` and `run("prepare", payload)` to return compatible `PassResult`/`Candidate` objects. A structure candidate must cite consistent offset/width/use sites; a pointer-table candidate must cite relocation/access pattern, target pointer width and endianness. Applied changes return managed-artifact revision; conflicts and unsupported extraction return reasons without overwriting existing types.

- [ ] **Step 1: Write failing fixture tests.** `test_consistent_offsets_produce_fields` asserts precise offsets/widths in the managed IDB and unchanged user-defined type on conflict. `test_relocation_table_not_random_integers` distinguishes a genuine relocated function-pointer table from a same-width aligned integer array and leaves ambiguous jump-table entries as candidates. `test_bad_alignment_and_truncated_range_are_partial` checks explicit range warnings rather than full coverage.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_prepare_data.py -q` must FAIL on absent passes.
- [ ] **Step 3: Implement conservative inference.** Derive stride/fields from repeated compatible access evidence, check existing type boundaries, read actual relocation and xref records for pointer tables, verify targets in mapped code/data, and only define conflict-free managed ranges. Candidate creation is not equivalent to an applied type.
- [ ] **Step 4: Run green and inspect artifact.** `uv run --python 3.11 pytest tests/integration/test_prepare_data.py tests/integration/test_prepare_code_strings.py -q` must PASS; reopen managed IDB and confirm only justified definitions persisted.
- [ ] **Step 5: Commit.** `git add src/vulfi_mcp/prepare.py src/vulfi_mcp/ida_runtime.py tests/fixtures/vulfi_preparation.c tests/integration/test_prepare_data.py && git commit -m "feat: infer guarded structures and pointer tables"`.

### Task 4: Public prepare/page tools and automatic scan preparation

**Files:** Modify `src/vulfi_mcp/prepare.py`, `src/vulfi_mcp/catalog.py`, `src/vulfi_mcp/ida_runtime.py`, `src/vulfi_mcp/server.py`, `src/vulfi_mcp/contracts.py`, `tests/integration/test_mcp_ida.py`; create `tests/integration/test_preparation_flow.py`.

**Interfaces:** Produce `prepare_target(path: str, backend: str = "auto", passes: list[str] | None = None) -> dict[str, object]` and `preparation_page(path: str, analysis_id: str | None = None, offset: int = 0, limit: int = 100) -> dict[str, object]` in `prepare.py`, exposed unchanged as `vulfi_prepare`/`vulfi_preparation` through `server.py`. Amend Plan 1 `vulfi_scan(path, rules=None, scan_name="agent", backend="auto", analysis_id=None)` to call `prepare_target` if no matching analysis revision, then scan that managed artifact. A matching revision requires source identity, managed artifact, backend capability fingerprint and requested pass coverage; IDB netnode contains only a bounded summary while catalog stores all candidates.

- [ ] **Step 1: Write failing end-to-end tests.** `test_scan_prepares_once_and_reuses_revision` calls the real MCP prepare and scan on a compiled fixture in separate requests, checks recovered evidence affects a specific finding, then reuses an identical revision without reapplying changes. `test_invalid_passes_and_rules_do_not_mutate` verifies `[]`, unknown pass, and unsafe rule expression fail before IDB/catalog creation. `test_catalog_unavailable_is_not_empty` pages when SQLite is offline and observes unavailable status. `test_failed_save_retains_partial` injects a failed managed-IDB save and verifies no complete pass/scan is claimed; page bounds `offset>=0`, `1<=limit<=200` are enforced.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_preparation_flow.py -q` must FAIL on missing public operations.
- [ ] **Step 3: Implement pass orchestration, revisioning, and public tools.** Store per-range results and candidate evidence transactionally; write bounded IDB summary only after reported save, expose artifact paths and warnings, and retain prior complete results when a later run is cancelled. Reject external backend requests as unavailable until Plan 3 provides real adapters; never claim successful fallback from a nonexistent provider.
- [ ] **Step 4: Run green and client smoke.** `uv run --python 3.11 pytest tests/integration/test_preparation_flow.py tests/integration/test_mcp_ida.py -q` must PASS; invoke both new tools and a scan in a real stdio MCP session and inspect the preparation revision.
- [ ] **Step 5: Commit.** `git add src/vulfi_mcp/prepare.py src/vulfi_mcp/catalog.py src/vulfi_mcp/ida_runtime.py src/vulfi_mcp/server.py src/vulfi_mcp/contracts.py tests/integration/test_mcp_ida.py tests/integration/test_preparation_flow.py && git commit -m "feat: prepare managed analysis before scanning"`.

### Task 5: Evidence-linked proposals and operator CLI review

**Files:** Modify `src/vulfi_mcp/prepare.py`, `src/vulfi_mcp/catalog.py`, `src/vulfi_mcp/ida_runtime.py`, `src/vulfi_mcp/server.py`, `README.md`; create `src/vulfi_mcp/operator.py`, `tests/test_proposals.py`, `tests/integration/test_review_cli.py`.

**Interfaces:** Produce `propose_recovery(path: str, analysis_id: str, proposals: list[dict[str, object]]) -> dict[str, object]` in `prepare.py` and expose only this mutation through MCP `vulfi_propose_recovery`. Produce `review_proposal(path: str, proposal_id: str, decision: Literal["approve", "reject"], expected_revision: int) -> dict[str, object]` in `operator.py`, reachable only from `vulfi-mcp review` CLI. `run("apply_reviewed_proposal", payload)` revalidates evidence/conflicts against the managed IDB; checkpoint, apply, save, then update catalog approval/revision. Review of a Ghidra/r2 candidate without safe provider write support remains rejected/unavailable with reason, not a fake apply.

- [ ] **Step 1: Write failing tests.** `test_proposal_is_inert_until_review` submits a valid function-boundary proposal, checks IDB unchanged and candidate paged as pending, then runs real CLI approval and verifies changed IDB/revision and subsequent scan uses that revision. `test_each_permitted_kind_applies_only_with_proof` uses separate candidate-only fixture ranges for name, string decode, structure field, and pointer table; each approval changes exactly the justified managed definition after current-evidence revalidation and leaves original bytes untouched. `test_scripts_missing_evidence_and_type_conflicts_rejected` covers three distinct invalid proposals. `test_stale_and_failed_review_do_not_confirm` changes artifact revision between proposal/approval and separately forces IDB save/catalog failure; neither may return an approved durable state. Exercise actual CLI rejection and show operator evidence before the confirmation prompt.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/test_proposals.py tests/integration/test_review_cli.py -q` must FAIL before proposal/review APIs.
- [ ] **Step 3: Implement proposal validation and separate operator path.** Accept only name, function boundary, string decode, structure field, pointer-table kinds with exact candidate IDs, evidence, address range, value, rationale; reject executable content. Recheck original bytes/types/current artifact revision under review, checkpoint managed IDB, and make saved state observable before confirming catalog approval. A post-save catalog error must expose pending/reconciliation state and recover from the checkpoint/event rather than silently claiming completion. Document that shell privileges can run the CLI even when MCP tools cannot.
- [ ] **Step 4: Run green and operator smoke.** `uv run --python 3.11 pytest tests/test_proposals.py tests/integration/test_review_cli.py tests/integration/test_preparation_flow.py -q` must PASS; use a disposable artifact, call MCP proposal, reject one in CLI, approve another, reopen IDB/catalog and inspect revision.
- [ ] **Step 5: Commit.** `git add src/vulfi_mcp/prepare.py src/vulfi_mcp/catalog.py src/vulfi_mcp/ida_runtime.py src/vulfi_mcp/server.py src/vulfi_mcp/operator.py tests/test_proposals.py tests/integration/test_review_cli.py README.md && git commit -m "feat: review evidence-linked recovery proposals"`.

**Handoff to Plan 3:** Seven VulFi tools now exist and work for IDA, but `auto` has not yet passed a real external-provider gate. Do not release the all-backend design until provider and linked-triage plans pass.
