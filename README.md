# VulFi MCP

VulFi-style vulnerability-hunting rules, evidence-first analysis preparation, and operator-reviewed recovery for the official Hex-Rays IDA MCP server. Importing this package's entry point registers seven VulFi tools on the server `ida-mcp` already owns, so one stdio connection serves the six stock IDA tools and the seven VulFi tools from a single process. It is not a second MCP server and not a fork of the official one.

**Status: internal IDA-only milestone, not a release.** Everything below works end to end against real IDA. The external Ghidra/radare2 providers and reviewer-linked triage described in the design documents are **not implemented**, and the tools refuse the parameters that would need them instead of answering as if they existed.

## What works today

- **`vulfi_rule_template`** — the rule schema, worked examples, the restricted expression language a `mark_if` branch may use, and its limits.
- **`vulfi_scan`** — scans a binary or a saved `.i64`/`.idb`. The target is copied into a managed workspace and only the copy is ever analyzed or written; the supplied file is left untouched. Every rule is validated in full *before* any database is created, and expressions are interpreted from a restricted syntax tree — never with Python `eval` or `exec`. The target is prepared first (below) unless a recorded preparation revision already matches the request, and the result names the revision it read. Omitting `rules` runs the 24 stock VulFi rules in scope `default`; a nonempty list runs only those rules in scope `custom:<scan_name>`. Each rule comes back `evaluated`, `unsupported`, or `failed` with a reason, so a rule whose facts IDA could not establish is never reported as a clean negative.
- **`vulfi_prepare`** — recovers what the managed analysis can justify before it is scanned: functions in executable bytes nothing references, strings in mapped bytes and in the instructions that assemble them, structure layouts proven from consistent sized accesses, and pointer tables every slot of which carries a relocation. Every recovery carries the bytes, instructions, accesses or relocation records it rests on; anything that cannot be justified stays a candidate with the reason, and `state` is `applied` only where the managed database really changed. Coverage is reported *per address range*: `partial` is the ordinary answer on a real image and means some range was not reached, not that the pass failed. Re-running an unchanged target reuses the recorded revision and applies nothing.
- **`vulfi_preparation`** — pages the candidates a preparation recorded, with their evidence and each pass's per-range coverage, without re-running or applying anything. A target nothing has prepared has no managed database, which is reported as an unavailable store with a reason — never as a preparation that recovered nothing.
- **`vulfi_propose_recovery`** — stores an agent's evidence-linked proposals for an operator to review. **It changes nothing.** A proposal names a candidate the catalog holds, quotes that candidate's own evidence back, and asks for one of five changes — a name, a function boundary, a string decode, a structure's fields, or a pointer table — in a closed vocabulary where every name is an ASCII identifier and no field can carry a script, a command or an expression. One that cites no evidence, cites evidence its candidate does not carry, sits at an address that is not its candidate's, or asks for something already defined is refused with that reason and is not stored.
- **`vulfi_findings`** — pages stored rows in one stable order across every scope of the IDA backend. It evaluates no rule, rewrites no row, and never analyzes a binary or creates a database: a target no `vulfi_scan` has run against has no managed database and therefore no store, which is reported as an unavailable IDA store with a reason and zero rows — not as a target without findings.
- **`vulfi_triage`** — records one assessment (`Not Checked`, `False Positive`, `Suspicious`, `Vulnerable`) against a finding's exact id, with a nonempty rationale. A refused update writes nothing, and an id against a target that was never scanned is refused without analyzing or creating anything.

Findings and assessments live in the managed IDB's own netnode, so they survive closing and reopening the database and restarting the server. Rescanning a scope preserves earlier assessments by exact finding id. Preparation candidates and proposals live in one SQLite catalog under the managed data directory, keyed by the original binary's SHA-256 where it is in hand and by a provisional per-database identity otherwise; the IDB keeps a bounded summary and the revision, so findings stay interpretable if that catalog is unavailable.

## Reviewing a proposal: `vulfi-mcp review`

**No MCP tool approves anything.** Applying a proposal is a separate command, run by a person at a shell:

```sh
vulfi-mcp review list    --path ./target
vulfi-mcp review show    --path ./target --proposal-id prop-...
vulfi-mcp review approve --path ./target --proposal-id prop-... --expected-revision 3
vulfi-mcp review reject  --path ./target --proposal-id prop-... --expected-revision 3 --reason "..."
```

`show`, and every `approve`/`reject` before it asks, prints what the managed analysis holds *right now* in the proposed range — the original bytes and their digest, the name, the function, the type and the items already defined there — beside the proposed change, its expected effect, and the candidate evidence the proposal quotes. Then it waits for the decision to be typed out in full; anything else aborts and writes nothing.

An approval is not a promise about a database the reviewer can no longer see. Before anything is applied it revalidates against the **current** artifact: the candidate must still be in the catalog and still carry the quoted evidence, the artifact must still be at `--expected-revision`, the bytes must still be the ones the candidate recorded, and nothing may have been defined over the range. A failure of any of those marks the proposal `stale`, applies nothing, and the proposal has to be made again. A conflict is always a refusal and never an overwrite.

The order is checkpoint, apply, save, observe, record. The decision is written to the catalog *before* the write it authorizes, so a decision that never became durable is still visible afterwards; the change goes through the one lease that saves and that keeps the bytes it replaces. A durable approved revision is reported only when both stores hold it — a stale approval, a failed save, and a catalog that could not record the approval all answer `approved_revision: null`, and the last of those also takes the change back off the artifact from the checkpoint so the two stores are not left disagreeing.

**The separation is procedural.** This is an ordinary program on an ordinary PATH, so anything running with the operator's own OS permissions — including a shell-capable agent — can run it. What the split prevents is an MCP client applying its own proposals through the protocol it is already talking. An installation that needs enforced human separation has to enforce it with credentials: run the MCP server as a principal that cannot execute `vulfi-mcp review` and cannot write the managed data directory, and give the reviewer a different one.

## Not implemented in this milestone

- **External backends.** `backend` accepts `ida` or `auto`; `ghidra` and `r2` are refused by name. No Ghidra or radare2 provider is built, and nothing falls back to IDA in their place. A proposal against a candidate some other backend recovered is refused by name too, because there is no safe way to write it back yet.
- **Linked triage and the external catalog.** `binary_path` is refused on `vulfi_findings` and `vulfi_triage`. Every stored row reports `sync_state: "unlinked"`, and `target_total_complete` is `false` because the second store is absent — absent, not empty.
- **OMP confirmation UI.** The design also describes reviewing proposals through an explicit OMP confirmation surface. The local command above is the review path this milestone ships.

### A save IDA 9.4.260714 cannot read back

IDA 9.4.260714 has an open Hex-Rays defect where a database it has just packed cannot be opened again: `idapro.open_database` answers `rc 4` with "Database is empty" while the file still probes as `packed`, and the damage is permanent for that file ([Hex-Rays community: *Inaccurate "database is empty" error (9.4)*](https://community.hex-rays.com/t/inaccurate-database-is-empty-error-9-4/763)). Measured on this build, in a loop that did nothing but save and reopen one managed database, **7 of 331 saves — roughly one in fifty — produced a database IDA could not read back.** That is a number for this build and this machine, not a rate promised for any other.

This server does not retry and does not hide it. Every save it makes to a managed database keeps the bytes that save replaces, beside the database. If the next open of that database fails with that exact signature and nothing else holds the file, the kept bytes are put back once and the operation fails with a `ManagedDatabaseError` saying so — so a database is never silently left corrupt, and a caller is never answered from one as if the last save had survived.

Your recourse when it happens: **rescan.** The rolled-back workspace is usable again immediately and is missing only what the failed save changed. If the kept bytes cannot be opened either, the error says the workspace has to be rebuilt, which `vulfi_scan` does by pointing it at the source binary again — the source is never written to, so it is always available to rebuild from.

## Requirements

- Python >= 3.11.
- IDA >= 9.4 with an activated `idalib` license. Analysis runs headless through `ida-nexus`; no IDA GUI session is attached and no database is opened in place.
- Hex-Rays for rules that need argument recovery. Without a decompiler, scans still run against disassembly and report `partial` coverage with the affected rules `unsupported`.
- `gcc` only to build the test fixtures.

## Install and run

```sh
uv sync
uv run --python 3.11 vulfi-mcp
```

`vulfi-mcp` with no arguments speaks MCP over stdio and writes nothing else to stdout — stdout is the transport. `vulfi-mcp review ...` is the operator command above and is never reachable through MCP. Point an MCP client at the server the way you would at any stdio server:

```json
{
  "mcpServers": {
    "vulfi": { "command": "vulfi-mcp", "args": [] }
  }
}
```

## Managed workspace

Everything this server writes lives under one root: `$VULFI_MCP_DATA_DIR` when set, otherwise `$XDG_DATA_HOME/vulfi-mcp` (`~/.local/share/vulfi-mcp` by default). Managed databases are created under `databases/<name>-<hash>/`, one deterministic directory per target, and the same file at the same path always resolves to the same managed database instead of being analyzed again. The preparation catalog — candidates, their evidence, and every proposal and review decision — is the single `catalog.sqlite3` beside them. Nothing is ever written next to the target, and the target itself is never written to at all.

## Tests

```sh
uv run --python 3.11 pytest -q
```

Tests that need IDA, or `gcc`, skip when the prerequisite is missing. Set `VULFI_REQUIRE_LIVE=1` to turn any such skip into a failure, which is how the live coverage is verified.

## Upstream projects

Built on [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp), [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), and [ida-domain](https://github.com/HexRaysSA/ida-domain). The 24 stock rules and the function-prototype table in `src/vulfi_mcp/data/` are derived from [Accenture VulFi](https://github.com/Accenture/VulFi) and are redistributed under its Apache-2.0 licence, a copy of which ships beside them and in `THIRD_PARTY_LICENSES/`. The rule evaluator is an independent implementation: it interprets a restricted syntax tree rather than executing rule expressions as Python.

The full architecture is described in the [MCP, fallback, and data design](docs/superpowers/specs/2026-09-28-vulfi-ida-mcp-design.md) and the [RE preparation design](docs/superpowers/specs/2026-09-29-vulfi-re-preparation-design.md). The parts those documents describe that are listed above as not implemented are proposed contracts, not available commands.
