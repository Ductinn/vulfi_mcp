# VulFi MCP

VulFi-style vulnerability-hunting rules for the official Hex-Rays IDA MCP server. Importing this package's entry point registers four VulFi tools on the server `ida-mcp` already owns, so one stdio connection serves the six stock IDA tools and the four VulFi tools from a single process. It is not a second MCP server and not a fork of the official one.

**Status: internal IDA-only milestone, not a release.** The tools below work end to end against real IDA; the preparation pass, the external Ghidra/radare2 providers, and reviewer-linked triage described in the design documents are **not implemented**, and the tools refuse the parameters that would need them instead of answering as if they existed.

## What works today

- **`vulfi_rule_template`** — the rule schema, worked examples, the restricted expression language a `mark_if` branch may use, and its limits.
- **`vulfi_scan`** — scans a binary or a saved `.i64`/`.idb`. The target is copied into a managed workspace and only the copy is ever analyzed or written; the supplied file is left untouched. Omitting `rules` runs the 24 stock VulFi rules in scope `default`; a nonempty list runs only those rules in scope `custom:<scan_name>`. Every rule is validated in full *before* any database is created, and expressions are interpreted from a restricted syntax tree — never with Python `eval` or `exec`. Each rule comes back `evaluated`, `unsupported`, or `failed` with a reason, so a rule whose facts IDA could not establish is never reported as a clean negative.
- **`vulfi_findings`** — pages stored rows in one stable order across every scope of the IDA backend. It evaluates no rule, rewrites no row, and never analyzes a binary or creates a database: a target no `vulfi_scan` has run against has no managed database and therefore no store, which is reported as an unavailable IDA store with a reason and zero rows — not as a target without findings.
- **`vulfi_triage`** — records one assessment (`Not Checked`, `False Positive`, `Suspicious`, `Vulnerable`) against a finding's exact id, with a nonempty rationale. A refused update writes nothing, and an id against a target that was never scanned is refused without analyzing or creating anything.

Findings and assessments live in the managed IDB's own netnode, so they survive closing and reopening the database and restarting the server. Rescanning a scope preserves earlier assessments by exact finding id.

## Not implemented in this milestone

- **Preparation.** There is no hidden-string/function/structure recovery pass, so `vulfi_scan`'s `analysis_id` is refused: no revision exists to reuse.
- **External backends.** `backend` accepts `ida` or `auto`; `ghidra` and `r2` are refused by name. No Ghidra or radare2 provider is built.
- **Linked triage and the external catalog.** `binary_path` is refused on `vulfi_findings` and `vulfi_triage`. Every stored row reports `sync_state: "unlinked"`, and `target_total_complete` is `false` because the second store is absent — absent, not empty.

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

`vulfi-mcp` speaks MCP over stdio and writes nothing else to stdout — stdout is the transport. Point an MCP client at it the way you would at any stdio server:

```json
{
  "mcpServers": {
    "vulfi": { "command": "vulfi-mcp", "args": [] }
  }
}
```

## Managed workspace

Everything this server writes lives under one root: `$VULFI_MCP_DATA_DIR` when set, otherwise `$XDG_DATA_HOME/vulfi-mcp` (`~/.local/share/vulfi-mcp` by default). Managed databases are created under `databases/<name>-<hash>/`, one deterministic directory per target, and the same file at the same path always resolves to the same managed database instead of being analyzed again.

## Tests

```sh
uv run --python 3.11 pytest -q
```

Tests that need IDA, or `gcc`, skip when the prerequisite is missing. Set `VULFI_REQUIRE_LIVE=1` to turn any such skip into a failure, which is how the live coverage is verified.

## Upstream projects

Built on [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp), [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), and [ida-domain](https://github.com/HexRaysSA/ida-domain). The 24 stock rules and the function-prototype table in `src/vulfi_mcp/data/` are derived from [Accenture VulFi](https://github.com/Accenture/VulFi) and are redistributed under its Apache-2.0 licence, a copy of which ships beside them and in `THIRD_PARTY_LICENSES/`. The rule evaluator is an independent implementation: it interprets a restricted syntax tree rather than executing rule expressions as Python.

The full architecture, including the parts this milestone does not implement, is described in the [MCP, fallback, and data design](docs/superpowers/specs/2026-09-28-vulfi-ida-mcp-design.md) and the [RE preparation design](docs/superpowers/specs/2026-09-29-vulfi-re-preparation-design.md). Both describe proposed contracts, not available commands.
