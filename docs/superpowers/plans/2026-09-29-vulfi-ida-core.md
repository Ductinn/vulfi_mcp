# VulFi IDA Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working headless IDA MCP extension that evaluates the 24 stock VulFi rules and custom rules, persists distinct findings/triage in a managed IDB, and retains all six official IDA tools.

**Architecture:** This is the first, IDA-only internal milestone; it is not the complete approved multi-backend release. Keep rule validation and the restricted interpreter importable without IDA, send a self-contained source-backed runtime through Nexus, and save a versioned netnode in a managed IDB. The [preparation](2026-09-29-vulfi-re-preparation.md), [provider](2026-09-29-vulfi-mcp-fallback.md), and [linked-triage](2026-09-29-vulfi-linked-triage-omp.md) plans add the remaining approved behavior in that order; do not publish a release before all four gates pass.

**Tech Stack:** Python >=3.11; `uv`, `pytest`; official `ida-mcp`/`ida-nexus`/`ida-domain`; IDAPython `idalib` and Hex-Rays; stdlib `ast`/`hashlib`/`json`.

**Spec:** [MCP and storage design](../specs/2026-09-28-vulfi-ida-mcp-design.md) and [RE preparation design](../specs/2026-09-29-vulfi-re-preparation-design.md).

## Global Constraints

- Python >=3.11 and IDA >=9.4 for this path; run host tests with `uv run --python 3.11`, not the workstation's default Python 3.9.
- Start dependency locking with `ida-mcp==20260924.0.3`, `ida-nexus==0.13.0`, `ida-domain==0.5.1`; re-lock only after an actual compatibility smoke. No GUI provider plugin during integration; isolate `IDAUSR` without removing user plugins.
- Keep one agent-facing `vulfi-mcp` process with six stock IDA tools; use exported `ida_mcp.mcp.tool`/`serve_stdio` and `ida_nexus.DatabaseHandle`/`RemoteModule`, not private managers or GUI APIs.
- Remote code is a self-contained `src/vulfi_mcp/ida_runtime.py` source module with `codec="json"`; import IDA APIs inside worker functions. Validate untrusted rules before opening or modifying an IDB; no Python `eval`/`exec`.
- Copy a saved, unlocked user IDB before VulFi mutations; source binaries are read-only. IDA netnode `vulfi_mcp.v2`, blob `(1,"S")`, is authoritative for IDA findings and unlinked assessments. Preserve Apache-2.0 license/attribution for copied VulFi rules/prototypes.
- Deliver this as an internal milestone only: `vulfi_scan` gains automatic preparation in Plan 2, external MCP fallback in Plan 3, and linked sync/OMP in Plan 4. Do not claim final release parity from these IDA-only checks.
- Mark licensed integrations explicitly: ordinary contributor suites may skip them with a named prerequisite reason, but `VULFI_REQUIRE_LIVE=1` makes any missing IDA/provider prerequisite a failure. Release verification runs with this flag and checks zero skips.

## Review Focus

- A valid rule with unavailable arguments must report unsupported/partial rather than emit `Info` or a clean negative; pin in Task 4's decompiler-failure test.
- Duplicate-named rules and two distinct call sites must keep separate finding IDs/assessments; pin in Task 5's rescan/reopen test.
- A GUI-locked input IDB must not be copied while stale or bypassed; pin in Task 3's lock test.
- A partial rescan must retain and mark older assessed rows stale; pin in Task 5's partial-to-complete test.
- Malformed agent rules must fail before a raw binary opens or a netnode is written; pin in Task 6's MCP integration test.

---

### Task 1: Rule contracts, pinned data, and template

**Files:** Create `pyproject.toml`, `uv.lock`, `src/vulfi_mcp/__init__.py`, `src/vulfi_mcp/contracts.py`, `src/vulfi_mcp/rules.py`, `src/vulfi_mcp/data/rules.json`, `src/vulfi_mcp/data/prototypes.json`, `THIRD_PARTY_LICENSES/Accenture-VulFi-LICENSE`, `tests/test_rules.py`.

**Interfaces:** Produce `Rule` TypedDict in `rules.py` with exactly `name`, `function_names`, `wrappers`, `mark_if.{High,Medium,Low}`; `Finding`, `RuleCoverage`, `ScanResult` JSON-native TypedDicts in `contracts.py`; `load_stock_rules() -> tuple[Rule, ...]`, `validate_rules(raw: object) -> tuple[Rule, ...]`, `canonical_rule_digest(rule: Rule) -> str`, and `rule_template() -> dict[str, object]` in `rules.py`. Copy `vulfi_rules.json` and `vulfi_prototypes.json` from Accenture/VulFi commit `0bb7fdf8ccb906600cc209c35daf05774172acc8`, not the unshipped template. Later tasks use these exact names. Ensure the package loads its JSON resources after wheel installation.

- [ ] **Step 1: Write failing behavior tests.** In `tests/test_rules.py`, `test_stock_rules_validate_and_duplicate_names_keep_distinct_digests` asserts `len(load_stock_rules()) == 24`, accepts two rules with the same `name` but different definitions, and checks their canonical digests differ; `test_invalid_mark_if_rejected` rejects a missing priority branch and an empty `function_names` list with a rule-indexed error. `test_rule_template_example_roundtrips` validates a returned example rule, verifies `mark_if` has exactly `High`, `Medium`, `Low`, and checks that allowed predicates and unsupported-evidence limits are included. Include an installed-wheel resource test using `importlib.resources` rather than reading source text.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/test_rules.py -q`; expected FAIL because package/contracts are absent.
- [ ] **Step 3: Implement the listed functions and package metadata.** Lock the three exact IDA dependencies plus `pytest` (dev). Use canonical JSON `sort_keys=True`, compact separators, `ensure_ascii=False`, UTF-8 SHA-256; preserve Apache-2.0 attribution. Do not deduplicate by rule name.
- [ ] **Step 4: Run green.** `uv run --python 3.11 pytest tests/test_rules.py -q` must PASS.
- [ ] **Step 5: Commit.** Commit `feat: package validated VulFi rules` with only Task 1 files.

### Task 2: Restricted stock-compatible expression evaluator

**Files:** Create `src/vulfi_mcp/ida_runtime.py`, `tests/test_rule_eval.py`; modify `src/vulfi_mcp/rules.py` for preflight if needed.

**Interfaces:** Produce pure `Param` and `FunctionCall` fact types, `RuleContext(params: tuple[Param, ...], call: FunctionCall)`, `validate_expression(expr: str) -> None`, and `evaluate_rule(rule: Rule, context: RuleContext) -> Literal["High","Medium","Low"] | None` in `ida_runtime.py`. Use postponed annotations and a `TYPE_CHECKING`-only `Rule` import; the source-backed module must execute without importing the installed package or IDA at module load. Host passes validated rules as JSON. Later IDA extraction and external adapters populate the same fact types; `None` means a fully evaluated rule had no matched branch, never an extraction failure.

- [ ] **Step 1: Write failing tests.** `test_priority_and_bounded_comprehensions` uses a variable `strcpy` argument and a `%s` format-string case to assert expected High/Medium/Low precedence and bounded iteration; `test_all_stock_expressions_validate` walks all 24 rules through each nonempty `mark_if` expression; `test_rejects_python_escape_before_ida` rejects import, dunder, attribute chains, arbitrary calls, mutation, and an over-budget comprehension. Test a verified zero-argument context separately from an unavailable argument sentinel.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/test_rule_eval.py -q`; expected FAIL on missing interpreter.
- [ ] **Step 3: Implement only approved AST nodes and receiver methods.** Support the spec's `param[i]`, `param_count`, `function_call`, boolean/arithmetic/comparison/index/list-comprehension forms, bounded `any`/`len`/`range`, `lower`/`split`/`startswith`, and stock `Param`/`FunctionCall` predicates. Refuse unknown facts rather than manufacture constants; no `eval`/`exec` and no IDA imports at module load.
- [ ] **Step 4: Run green.** `uv run --python 3.11 pytest tests/test_rule_eval.py tests/test_rules.py -q` must PASS.
- [ ] **Step 5: Commit.** Commit `feat: evaluate bounded VulFi rule expressions` with only Task 2 files.

### Task 3: Managed IDA analysis and Nexus lease

**Files:** Create `src/vulfi_mcp/ida_adapter.py`, `tests/fixtures/vulfi_calls.c`, `tests/conftest.py`, `tests/integration/test_ida_adapter.py`; modify `src/vulfi_mcp/ida_runtime.py`.

**Interfaces:** Produce `ensure_managed_idb(path: str) -> str` (canonical managed IDB path; saved input IDB is cloned only when unlocked), `invoke_ida(idb_path: str, operation: str, payload: dict[str, object]) -> dict[str, object]` in `ida_adapter.py`, and `run(operation: str, payload: dict[str, object]) -> dict[str, object]` in the source-backed worker module. The adapter opens a `DatabaseHandle`, invokes `RemoteModule(..., codec="json")`, saves after mutations, and closes only its own lease. `tests/conftest.py` supplies `compiled_calls` by compiling `vulfi_calls.c` into `tmp_path` with `gcc -O0 -fno-builtin -fno-inline`.

- [ ] **Step 1: Write failing integration tests.** `test_managed_copy_opens_saves_reopens` checks that IDA enumerates functions in the compiled binary, saves/reopens the managed `.i64`, and source bytes/any supplied original IDB remain unchanged. `test_busy_source_idb_is_not_copied` holds an unregistered GUI lock when available and expects `DatabaseBusyError` without a managed clone; use a controlled lock probe if GUI setup is unavailable, not a skip of the release gate.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_ida_adapter.py -q`; expected FAIL before the adapter exists (licensed IDA integration is required here).
- [ ] **Step 3: Implement the public Nexus path.** Avoid private MCP `DATABASE_MANAGER` or stock `instance_id`. Normalize JSON only, check source IDB save/lock before copying, and keep worker imports inside `run` operations. Return managed path via Nexus `instance.idb_path`, not `db.path`.
- [ ] **Step 4: Run green plus actual smoke.** `uv run --python 3.11 pytest tests/integration/test_ida_adapter.py -q` must PASS; independently invoke `ensure_managed_idb()` on a disposable compiled binary and inspect worker function count and persisted IDB after reopen.
- [ ] **Step 5: Commit.** Commit `feat: open managed IDA databases through Nexus` with only Task 3 files.

### Task 4: IDA call-site, wrapper, array, and loop evidence

**Files:** Modify `src/vulfi_mcp/ida_runtime.py`, `src/vulfi_mcp/ida_adapter.py`; add `tests/fixtures/vulfi_shapes.c`, `tests/integration/test_ida_scan.py`.

**Interfaces:** Produce `scan_ida(idb_path: str, rules: tuple[Rule, ...], scope: str) -> ScanResult` in `ida_adapter.py`, backed by worker `run("scan", payload)` returning JSON-native function/call-site evidence and per-rule `evaluated|unsupported|failed` coverage. Record branch/argument extraction, wrappers one level deep, loop/array pseudo-rules, and prototype application provenance. This task consumes Task 2 evaluator and Task 3 managed IDB.

- [ ] **Step 1: Write failing fixture tests.** `test_two_variable_source_calls_are_distinct` compiles two `strcpy` sites, asserts both are found at different addresses and each has evidence for the matched rule/branch. `test_wrapper_loop_and_array_fact_detection` uses a wrapper, indexed access, and loop fixture to assert specific structured facts, not nonempty pseudocode. `test_verified_zero_arguments_get_info` checks an actual zero-argument call receives `Info`; `test_decompiler_unavailable_is_partial` forces a controlled decompiler-unavailable case and asserts `coverage="partial"`, an unsupported reason, and no `Info`/clean negative from missing arguments.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_ida_scan.py -q`; expected FAIL on absent scan operation.
- [ ] **Step 3: Implement evidence extraction and evaluation.** Traverse IDA xrefs and ctree/disassembly on a managed IDB; only populate `Param`/`FunctionCall` when backend facts justify them. Apply stock prototypes sent in the validated worker payload only within the scan operation and disclose `SetType`; bound wrapper discovery and ctree work. Don't use GUI/plugin objects.
- [ ] **Step 4: Run green.** `uv run --python 3.11 pytest tests/integration/test_ida_scan.py tests/test_rule_eval.py -q` must PASS.
- [ ] **Step 5: Commit.** Commit `feat: scan IDA call sites with VulFi rules` with only Task 4 files.

### Task 5: Versioned netnode, triage, and scoped rescans

**Files:** Modify `src/vulfi_mcp/ida_runtime.py`, `src/vulfi_mcp/ida_adapter.py`, `src/vulfi_mcp/contracts.py`; create `tests/integration/test_ida_findings.py`.

**Interfaces:** Produce `findings_ida(idb_path: str, offset: int, limit: int) -> dict[str, object]` and `triage_ida(idb_path: str, finding_id: str, status: str, rationale: str) -> dict[str, object]` in `ida_adapter.py`. Worker owns netnode v2 read/modify/write and `managed_idb_id`; finding keys include backend/scope/rule digest/address space/address/ordinal. Save IDB after successful mutation, not on a failed validation. `last_seen_scan_id` marks retained stale rows; `triage_revision` increments only on an accepted update.

- [ ] **Step 1: Write failing persistence tests.** `test_independent_assessments_survive_reopen` scans two sites and duplicate-named rules, assigns different statuses with Unicode rationales, closes/reopens, and checks exact IDs plus unchanged other scope. `test_partial_rescan_keeps_stale_until_complete` removes observable evidence in a managed test copy, forces partial coverage, checks old assessed row is stale, then completes a rescan that retires it. `test_unknown_id_bad_status_empty_rationale_and_bad_page_do_not_write` checks precise errors and unchanged netnode for unknown IDs, invalid statuses, empty rationale, or out-of-bounds pages.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_ida_findings.py -q`; expected FAIL on missing persistence/triage.
- [ ] **Step 3: Implement exact-ID carry-forward, complete/partial scope semantics, stable JSON record, and pagination.** Use a single remote IDA operation for each read/modify/write; reject unknown schema versions. Preserve independent assessments at one address; do not reattach on changed rule/ctree occurrence ordering.
- [ ] **Step 4: Run green.** `uv run --python 3.11 pytest tests/integration/test_ida_findings.py tests/integration/test_ida_scan.py -q` must PASS.
- [ ] **Step 5: Commit.** Commit `feat: persist independent findings in IDB` with only Task 5 files.

### Task 6: One public MCP entry point for IDA tools

**Files:** Create `src/vulfi_mcp/server.py`, `tests/integration/test_mcp_ida.py`; modify `pyproject.toml`, `README.md` (only installation/use details now verified).

**Interfaces:** Export `vulfi_rule_template() -> dict[str, object]`, `vulfi_scan(path: str, rules: list[Rule] | None = None, scan_name: str = "agent", backend: str = "auto", analysis_id: str | None = None) -> ScanResult`, `vulfi_findings(path: str, binary_path: str | None = None, offset: int = 0, limit: int = 100) -> dict[str, object]`, and `vulfi_triage(path: str, finding_id: str, status: str, rationale: str, binary_path: str | None = None) -> dict[str, object]` through official `@tool`; `main() -> None` invokes `serve_stdio`. Reserve `backend`/`analysis_id` and `binary_path` for Plans 2/3; this IDA-only milestone accepts `ida` or `auto` when IDA is capable and otherwise reports explicitly incomplete capability, never an empty success. Validate rules before `ensure_managed_idb`. Do not implement fake provider/preparation stubs.

- [ ] **Step 1: Write failing end-to-end behavior test.** `test_stdio_scan_then_triage_survives_restart` launches `vulfi-mcp` as a real MCP child, sends a custom nested rule and compiled-binary path, observes two distinct findings, triages one, reconnects and reads persisted status. `test_invalid_custom_rule_or_scan_name_leaves_no_idb` submits a malicious AST rule and an invalid `custom:<scan_name>` identifier separately, asserting indexed/parameter errors and no new managed IDB/netnode. Stock six plus four new tool discovery is a throwaway integration assertion, not a permanent wiring-only unit test.
- [ ] **Step 2: Run red.** `uv run --python 3.11 pytest tests/integration/test_mcp_ida.py -q`; expected FAIL before entry-point registration.
- [ ] **Step 3: Register tools on official IDA MCP and package the CLI.** Shape JSON results per `contracts.py`, use `backend="idalib"` for successful IDA analysis while individual findings use `backend="ida"`, preserve error/partial statuses and OMP origin metadata, keep stdio clean of logs, and document the IDA-only internal milestone honestly.
- [ ] **Step 4: Run green and MCP smoke.** `uv run --python 3.11 pytest tests/test_rules.py tests/test_rule_eval.py tests/integration -q` must PASS; run `uv run --python 3.11 vulfi-mcp` through a disposable MCP client and observe one stock and one VulFi tool call.
- [ ] **Step 5: Commit.** Commit `feat: expose IDA VulFi scanning on official MCP` with only Task 6 files.

**Handoff to Plan 2:** The IDA worker and public tools function end to end, but the approved full design still requires preparation, external providers, and linked triage. Keep this milestone internal; no release claim yet.
