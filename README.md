# VulFi MCP

VulFi-style vulnerability-hunting rules, evidence-first analysis preparation, and operator-reviewed recovery for the official Hex-Rays IDA MCP server. Importing this package's entry point registers seven VulFi tools on the server `ida-mcp` already owns, so one stdio connection serves the six stock IDA tools and the seven VulFi tools from a single process. It is not a second MCP server and not a fork of the official one.

**Status: measured release of the surface below.** The operator surface is implemented, and the limits below are the ones this build measured. `VULFI_REQUIRE_LIVE=1 uv run --python 3.11 pytest -q --tb=line` passed: 428 passed, 1 skipped in 831.27s, exit 0. The skip is `test_the_previous_build_refuses_this_builds_catalog_by_name` because HEAD already carries schema version 2; it is not a licensed IDA, live Ghidra, or live r2 skip. `bun test omp/extension.test.ts` passed (8 pass, 0 fail). A cell that says unavailable is not a clean negative. A refused IDA save is the operator's failure and is not reported as the next backend being absent.

## Release matrix

Tested on this machine, ELF x86-64 only. No other architecture, OS, or IDA GUI session was exercised. A cell that says unavailable is not a clean negative.

| Surface | Tested pin | What it does here |
| --- | --- | --- |
| Python | 3.11.15 (`requires-python >= 3.11`) | host and IDA worker |
| IDA | 9.4.260714 at `/home/ductin/Applications/ida-pro-9.4`, `idalib` | managed copy, netnode `vulfi_mcp.v2`, six stock tools |
| Official IDA MCP | `ida-mcp==20260924.0.3`, `ida-nexus==0.13.0`, `ida-domain==0.5.1`, `idapro==0.0.10` | `open_database`, `execute_python`, `reference`, `list_databases`, `save_database`, `close_database` |
| MCP client | `mcp==2.2.0` | stdio to providers; protocol the pins were measured at |
| VulFi tools | seven, no eighth | `vulfi_rule_template`, `vulfi_scan`, `vulfi_prepare`, `vulfi_preparation`, `vulfi_propose_recovery`, `vulfi_findings`, `vulfi_triage` |
| Ghidra | 12.1.2_PUBLIC, GhidraMCP 6.0.0, bridge stdio to `http://127.0.0.1:8192` | strings, functions, P-code facts the typed tools state |
| Ghidra JVM | the live process was OpenJDK 25.0.1, not Java 21 | Java 21 (`temurin-21.0.12+101.0.LTS`) is installed; this gate's server was not started with it. Do not claim a Java 21 runtime from this checkout. |
| radare2 | 6.2.2, `radareorg/radare2-mcp` 1.8.8 at `/tmp/vulfi-providers/r2mcp/src/r2mcp` | strings and functions. `LD_LIBRARY_PATH=/tmp/vulfi-providers/r2/lib` |
| OMP board | `@oh-my-pi/pi-coding-agent` 18.3.2 | optional widget. Not a second MCP client. |

Authorities: the managed IDB netnode is authoritative for unlinked IDA assessments. SQLite is authoritative for external rows and for the canonical decision of a reviewer-created link. A linked pair is two findings, not one vulnerability. No public tool was added for approval or linking.


## What works today

- **`vulfi_rule_template`** — the rule schema, worked examples, the restricted expression language a `mark_if` branch may use, and its limits.
- **`vulfi_scan`** — scans a binary or a saved `.i64`/`.idb`. The target is copied into a managed workspace and only the copy is ever analyzed or written; the supplied file is left untouched. Every rule is validated in full *before* any database is created, and expressions are interpreted from a restricted syntax tree — never with Python `eval` or `exec`. The target is prepared first (below) unless a recorded preparation revision already matches the request, and the result names the revision it read. Omitting `rules` runs the 24 stock VulFi rules in scope `default`; a nonempty list runs only those rules in scope `custom:<scan_name>`. Each rule comes back `evaluated`, `unsupported`, or `failed` with a reason, so a rule whose facts IDA could not establish is never reported as a clean negative.
- **`vulfi_prepare`** — recovers what the managed analysis can justify before it is scanned: functions in executable bytes nothing references, strings in mapped bytes and in the instructions that assemble them, structure layouts proven from consistent sized accesses, and pointer tables every slot of which carries a relocation. Every recovery carries the bytes, instructions, accesses or relocation records it rests on; anything that cannot be justified stays a candidate with the reason, and `state` is `applied` only where the managed database really changed. Coverage is reported *per address range*: `partial` is the ordinary answer on a real image and means some range was not reached, not that the pass failed. Re-running an unchanged target reuses the recorded revision and applies nothing.
- **`vulfi_preparation`** — pages the candidates a preparation recorded, with their evidence and each pass's per-range coverage, without re-running or applying anything. A target nothing has prepared has no managed database, which is reported as an unavailable store with a reason — never as a preparation that recovered nothing.
- **`vulfi_propose_recovery`** — stores an agent's evidence-linked proposals for an operator to review. **It changes nothing.** A proposal names a candidate the catalog holds, quotes that candidate's own evidence back, and asks for one of five changes — a name, a function boundary, a string decode, a structure's fields, or a pointer table — in a closed vocabulary where every name is an ASCII identifier and no field can carry a script, a command or an expression. One that cites no evidence, cites evidence its candidate does not carry, sits at an address that is not its candidate's, or asks for something already defined is refused with that reason and is not stored.
- **`vulfi_findings`** — pages stored rows in one stable order across every scope of every backend. It evaluates no rule, rewrites no row, and never analyzes a binary or creates a database: a target no `vulfi_scan` has run against has no managed database and therefore no store, which is reported as an unavailable IDA store with a reason and zero rows — not as a target without findings.
- **`vulfi_triage`** — records one assessment (`Not Checked`, `False Positive`, `Suspicious`, `Vulnerable`) against a finding's exact id, with a nonempty rationale. A refused update writes nothing, and an id against a target that was never scanned is refused without analyzing or creating anything.

Findings and assessments live in the managed IDB's own netnode, so they survive closing and reopening the database and restarting the server. Rescanning a scope preserves earlier assessments by exact finding id. Preparation candidates and proposals live in one SQLite catalog under the managed data directory, keyed by the original binary's SHA-256 where it is in hand and by a provisional per-database identity otherwise; the IDB keeps a bounded summary and the revision, so findings stay interpretable if that catalog is unavailable.

## Reviewing a proposal: `vulfi-mcp review`

**No MCP tool approves anything.** Applying a proposal is a separate command, run by a person at a shell:

```sh
vulfi-mcp review list    --path ./target
vulfi-mcp review show    --path ./target --proposal-id prop-...
vulfi-mcp review approve --path ./target --proposal-id prop-... --expected-revision 3
vulfi-mcp review reject  --path ./target --proposal-id prop-... --expected-revision 3 --reason "..."
vulfi-mcp review reopen  --path ./target --proposal-id prop-... --reason "..."
```

`show`, and every `approve`/`reject` before it asks, prints what the managed analysis holds *right now* in the proposed range — the original bytes and their digest, the name, the function, the type and the items already defined there — beside the proposed change, its expected effect, and the candidate evidence the proposal quotes. Then it waits for the decision to be typed out in full; anything else aborts and writes nothing.

An approval is not a promise about a database the reviewer can no longer see. Before anything is applied it revalidates against the **current** artifact: the candidate must still be in the catalog and still carry the quoted evidence, the artifact must still be at `--expected-revision`, the bytes must still be the ones the candidate recorded, and nothing may have been defined over the range. A failure of any of those marks the proposal `stale`, applies nothing, and the proposal has to be made again. A conflict is always a refusal and never an overwrite.

The order is checkpoint, apply, save, observe, record. The decision is written to the catalog *before* the write it authorizes, so a decision that never became durable is still visible afterwards; the change goes through the one lease that saves and that keeps the bytes it replaces. A durable approved revision is reported only when both stores hold it — a stale approval, a failed save, and a catalog that could not record the approval all answer `approved_revision: null`, and the last of those also takes the change back off the artifact from the checkpoint so the two stores are not left disagreeing.

`reopen` is the way back from the last of those. The row it leaves behind says `approved` with no change behind it: nothing can decide it, and re-submitting the identical change is refused as a duplicate because a proposal's id is derived from its content. `reopen` returns such a row to `pending` — after reading the managed artifact again and finding that what the proposal asks for really is not there. A proposal whose change *is* there is left alone and said so, and one whose candidate no longer carries its evidence is marked `stale` instead. It approves nothing itself: the operator decides it afterwards the usual way.

**The separation is procedural.** This is an ordinary program on an ordinary PATH, so anything running with the operator's own OS permissions — including a shell-capable agent — can run `vulfi-mcp review`, `vulfi-mcp link`, and `vulfi-mcp resolve`, and can pass `--confirmed`. What the split prevents is an MCP client applying its own proposals or links through the protocol it is already talking. `--confirmed` is not an MCP tool. An installation that needs enforced human separation has to enforce it with credentials: run the MCP server as a principal that cannot execute those commands and cannot write the managed data directory, and give the reviewer a different one.

## Linking findings: `vulfi-mcp link` and `vulfi-mcp resolve`

These are local commands, not MCP tools. A link is created only after the operator has seen both assessments and the mapping evidence: both image bases, the RVA, the original bytes, and the xref proof. A pair the machine has already rejected is printed as a refusal and is not prompted.

```sh
vulfi-mcp link --path ./target --ida-id ida:... --external-id ghidra:... \
  --binary ./target --source new --status Suspicious \
  --rationale "same call site, reviewed"
vulfi-mcp resolve --path ./target --link-id L-... --source ida \
  --status "False Positive" --rationale "reviewer chose the IDA assessment"
```

`--source` is `ida`, `external`, or `new`. `--status` is one of `Not Checked`, `False Positive`, `Suspicious`, `Vulnerable`. The command waits for that source to be typed out in full. `--confirmed <token>` skips that stdin read only when the token is the decision already given; a missing or disagreeing token writes nothing. `--confirmed` is a CLI flag, not an MCP tool. A shell that can already run `vulfi-mcp` can pass it. That is the credential risk, not a second protocol.

Link proof is original-binary SHA-256, the full rule digest, a verified address-space mapping to the same call site (RVA, bytes, and a code xref), and the live finding ids. `function_name` is not an identity. External rules that name more than one function store an empty `function_name`. Name matching is not supported. Equal numeric addresses with different image bases do not link. A provisional IDB without verified source proof does not link.

A later triage of either finding id journals one decision. `pending` is the crash window. `synchronized` is only after the IDB save is observed. `conflict` is an unexpected revision; the next update does not overwrite. `paused` is a stale or missing member. `unavailable` is a store that did not answer. `vulfi-mcp resolve` writes a new guarded event after the operator sees the evidence again. It is not last-write-wins, and it does not unpause a link.

## Status meanings

| Word | Where | Meaning |
| --- | --- | --- |
| `Not Checked`, `False Positive`, `Suspicious`, `Vulnerable` | finding assessment | the four triage states. A new row is `Not Checked`. |
| `pending`, `approved`, `rejected`, `applied`, `stale` | proposal | `approved` is the decision recorded before the write. `applied` is the only state that claims the artifact changed. `stale` means the candidate or the bytes moved; nothing was applied. |
| `evaluated`, `unsupported`, `failed` | rule | facts were established, the backend states it cannot establish them, or the call did not finish. None of those is a clean "no finding" unless the rule was `evaluated` and matched nothing. |
| `answered`, `unsupported`, `failed`, `unavailable`, `unverified` | routing attempt | see the routing table below. They are not interchangeable. |
| `complete`, `partial`, `unavailable` | pass coverage | `partial` is ordinary. `unavailable` means that pass was not established, not that the image had nothing. |
| `pending`, `synchronized`, `conflict`, `paused`, `unavailable` | link | crash window, confirmed mirror, unexpected revision, member not reconfirmed or gone, store did not answer. |
| `stale` on a row | finding | the catalog sets this bit when a later scan did not observe the row. It is not, by itself, a paused link. |

A `stale` bit set by a scope whose stored state is `failed` and that observed no findings is not "not reconfirmed." The server does not pause a link for that bit. A partial scan that saw other rows and did not reconfirm the member does pause. The catalog still sets the bit in both cases. The distinction is the scope state plus whether that scan observed other rows.


## Routing across backends

`backend` is `auto`, `ida`, `ghidra` or `r2`, and the decision is made **per preparation pass and per rule**, never per scan. `auto` is the chain IDA → Ghidra → radare2: IDA answers what its evidence supports, each pass or rule it could not establish is asked of a configured Ghidra MCP, and each one still unanswered is asked of a configured radare2 MCP. Naming a backend runs exactly that one with no fallback — a result produced by IDA is not a Ghidra result.

Every pass and every rule reports what each backend said, in five words that are deliberately not interchangeable:

| Outcome | What happened | What the chain did |
| --- | --- | --- |
| `answered` | the backend established it | stored; no other backend is asked |
| `unsupported` | a session opened and the backend states it cannot establish this fact | chain advances |
| `failed` | a session opened and the call did not finish | chain advances, and the failure is **kept**: it stays in the attempts, it keeps the pass or scan from ever being `complete`, and a later backend's answer is reported *beside* it, never instead of it |
| `unavailable` | nobody looked — no configuration, no session | chain advances |
| `unverified` | the backend could not be shown to be reading the same bytes | chain **stops**; no other backend may stand in for an unprovable identity |

Nothing upgrades a coverage. A bounded or truncated read makes a pass `partial` whatever its geometry, an `unavailable` range is never raised, and a pass no backend could run is named in `routing` with each backend's reason rather than left out as though it had run and found nothing.

What each backend can actually do here was measured, not assumed. Ghidra answers `strings` and `functions` and establishes argument and return-check facts from high P-code only. `structures` and `pointer_tables` are `unavailable` on this Ghidra build: it exposes no typed tool that proves a field width or a relocation. Stock Buffer Overflow is `unsupported` on this Ghidra build because it needs `calls_before`, and GhidraMCP 6.0.0 states no argument flow across a call. radare2 answers the same two passes and establishes exactly one rule fact — which functions a call site is reached from — so a stock rule that needs argument structure, including Buffer Overflow, is `unsupported` on it. Its contribution is preparation evidence, not rule coverage. radare2 has no safe writer: no project, no save, and a proposal against one of its candidates is refused by name. **No backend turns decompiled C into a structural fact**; a provider that has only pseudocode has no contexts and says so.

Findings are scoped by backend **and** by `default`/`custom:<scan_name>`, in independent stores. A scan may retire a row only when it really ran, covered the whole image and was asked every rule in the scan; anything less keeps the rows it did not observe and marks them `stale`. A complete Ghidra scan of `default` therefore cannot touch Ghidra's `custom:nightly`, radare2's scopes, or the IDA netnode. External rows belong to the original binary's SHA-256 namespace: a database-only target must supply `binary_path`, which is proved against the input digest the database itself records, and an unrelated binary is refused rather than guessed at.

`vulfi-mcp review approve` can apply a reviewed change to Ghidra's managed project, through its own safe writer, which revalidates the overlap and the project revision at the moment it applies. radare2 has no project and no save, so a mutation would not outlive the session that made it: a proposal against one of its candidates is refused by name.

## External identity

Provider configuration is one TOML file: `$VULFI_MCP_PROVIDER_CONFIG`, or `providers.toml` under the managed data directory. No MCP argument, rule, or provider response chooses the executable or the URL. A stdio `command` must be an absolute path. `[[ghidra.binaries]]` and `[[r2.binaries]]` map a local directory to the path that provider sees. A binary outside that map is not sent. The client hashes the mapped file when it can read it; it does not take the provider's word for bytes it can hash itself. An unverified identity stops the chain. External finding ids include the original binary's SHA-256. Two binaries do not share an id. An IDB-only request does not join external rows until `binary_path` is proved against the digest the database records.

```toml
[ghidra]
transport = "stdio"
command = "/absolute/path/to/bridge-mcp-ghidra"
args = []

[ghidra.env]
GHIDRA_MCP_URL = "http://127.0.0.1:8192"

[[ghidra.binaries]]
local = "/work/samples"
remote = "/work/samples"

[r2]
transport = "stdio"
command = "/tmp/vulfi-providers/r2mcp/src/r2mcp"
args = []

[r2.env]
PATH = "/tmp/vulfi-providers/r2/bin:/usr/bin:/bin"
LD_LIBRARY_PATH = "/tmp/vulfi-providers/r2/lib"

[[r2.binaries]]
local = "/work/samples"
remote = "/work/samples"
```

The paths above are the pins this checkout measured, not a portable install. A loopback endpoint needs the operator's own authentication; this file is the only place a token is read, and it is not echoed in errors.


## Limits

- **Automatic links.** No link is created by a matching address, a matching RVA alone, or a matching name. A reviewer creates one with `vulfi-mcp link`.
- **A recovered IDA function is not a Ghidra finding.** Defining a function over unreferenced bytes in the managed IDB does not make Ghidra disassemble those bytes. On this build an unreferenced executable section is loaded and no function is created over it, so there is no xref at that call and nothing to link. The `strcpy` in `main` is a different site. Do not link them.
- **Empty `function_name`.** External multi-name rules store an empty `function_name`. Links do not read that field.
- **Ghidra `structures` and `pointer_tables`.** Unavailable. No typed tool. radare2 has no safe writer. Stock Buffer Overflow is unsupported on this Ghidra build because it needs `calls_before`.
- **Stale is not pause.** See the status table. A failed scope with no findings does not pause a link. A partial scan that saw other rows does.

### A save IDA 9.4.260714 cannot read back

IDA 9.4.260714 has an open Hex-Rays defect where a database it has just packed cannot be opened again: `idapro.open_database` answers `rc 4` with "Database is empty" while the file still probes as `packed`, and the damage is permanent for that file ([Hex-Rays community: *Inaccurate "database is empty" error (9.4)*](https://community.hex-rays.com/t/inaccurate-database-is-empty-error-9-4/763)). Measured on this build, in a loop that did nothing but save and reopen one managed database, **7 of 331 saves — roughly one in fifty — produced a database IDA could not read back.** That is a number for this build and this machine, not a rate promised for any other.

This server does not retry and does not hide it. Every save it makes to a managed database keeps the bytes that save replaces, beside the database. If the next open of that database fails with that exact signature and nothing else holds the file, the kept bytes are put back once and the operation fails with a `ManagedDatabaseError` saying so — so a database is never silently left corrupt, and a caller is never answered from one as if the last save had survived.

Your recourse when it happens: **rescan.** The rolled-back workspace is usable again immediately and is missing only what the failed save changed. If the kept bytes cannot be opened either, the error says the workspace has to be rebuilt, which `vulfi_scan` does by pointing it at the source binary again — the source is never written to, so it is always available to rebuild from.

A rolled-back mirror can leave SQLite at a revision the IDB no longer has. The next linked update conflicts instead of overwriting. Rescan does not invent a synchronized state for that window. `resolve` is how an operator chooses again, after the evidence is on screen.


## Requirements

- Python >= 3.11. This checkout was run with 3.11.15.
- IDA >= 9.4 with an activated `idalib` license. Measured: 9.4.260714. Analysis runs headless through `ida-nexus`; no IDA GUI session is attached and no database is opened in place. ELF x86-64 is the only architecture these gates exercised.
- Hex-Rays for rules that need argument recovery. Without a decompiler, scans still run against disassembly and report `partial` coverage with the affected rules `unsupported`.
- Java for the Ghidra headless server. The live process in this gate was OpenJDK 25.0.1 with Ghidra 12.1.2_PUBLIC and GhidraMCP 6.0.0. Java 21 (`temurin-21.0.12+101.0.LTS`) is installed here and was not the JVM that answered. Do not treat that install path as a tested runtime.
- radare2 6.2.2 and radare2-mcp 1.8.8, with `LD_LIBRARY_PATH` pointing at that radare2's `lib`. The measured binary is `/tmp/vulfi-providers/r2mcp/src/r2mcp`.
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

## Optional OMP board

The board is an OMP extension, not another MCP client and not part of OMP's native todo list. It does not create, edit, or complete todo tasks. It keeps a session-local cache of validated VulFi tool results and draws that cache under the editor. Without the extension, `vulfi-mcp` and the local review commands work as before.

Install is opt-in. From a checkout:

```sh
omp --no-extensions -e ./omp/extension.ts
```

The MCP server entry is trusted only when its configured command is `vulfi-mcp`. The name `vulfi` alone is not enough. An unrelated server that returns VulFi-shaped JSON does not update the board. The extension reads `tool_result` events from OMP's existing bridge. It does not open its own MCP session and it does not page tools on its own.

`/vulfi-board` shows the cache. `/vulfi-review` and `/vulfi-link` show the evidence and, only after a confirmation in the TUI, run a fixed argv:

```text
vulfi-mcp review ...
vulfi-mcp link ...
vulfi-mcp resolve ...
```

Declining the confirmation does not spawn the command. Headless and print modes do not treat a missing dialog as approval and do not spawn it either. The arguments are a list, not a shell string. After the TUI confirmation, the extension passes `--confirmed` with the token the operator already gave, so the CLI does not read stdin for that same decision. That flag is not an MCP tool. A shell that can already run `vulfi-mcp` can pass it; that is the credential risk below, not a second protocol.

**The confirmation is not a credential boundary.** `vulfi-mcp` is an ordinary program. Anything that already has the operator's OS permissions, including a shell-capable agent, can run `vulfi-mcp review`, `vulfi-mcp link`, and `vulfi-mcp resolve` without the board. An installation that needs enforced human separation has to enforce it with credentials: the MCP server principal must not be able to execute those commands or write the managed data directory.

The board is stale until the agent calls `vulfi_findings` or `vulfi_preparation` again. It shows the last refresh time and `loaded / target_total`. A store that did not answer is an offline warning, not a zero count. A linked pair stays two rows. A finding is identified by its id; an empty `function_name` is not an identity. A stale flag on a row is not a paused link. Pause is the link state `paused`.


## Managed workspace

Everything this server writes lives under one root: `$VULFI_MCP_DATA_DIR` when set, otherwise `$XDG_DATA_HOME/vulfi-mcp` (`~/.local/share/vulfi-mcp` by default). Managed databases are created under `databases/<name>-<hash>/`, one deterministic directory per target, and the same file at the same path always resolves to the same managed database instead of being analyzed again. The preparation catalog — candidates, their evidence, proposals, review decisions, external findings, and link events — is the single `catalog.sqlite3` beside them. Nothing is ever written next to the target, and the target itself is never written to at all.

There is no second catalog generation. An operator who wants a catalog backup copies `catalog.sqlite3` themselves; this server does not. Each mutating save of a published managed IDB keeps the bytes it replaces in `<database>.pre-save` beside that database, for the bad-pack rollback above. That spare is not an operator snapshot tool, and it is dropped once a later open proves the new bytes readable. The staging save that first publishes a database has no spare.

## Tests

```sh
uv run --python 3.11 pytest -q
```

Tests that need IDA, Ghidra, radare2, or `gcc` skip when the prerequisite is missing. Set `VULFI_REQUIRE_LIVE=1` to turn any such skip into a failure. A skip of a licensed IDA, live Ghidra, or live r2 integration under that flag is a failed release gate, not a pass. `bun test omp/extension.test.ts` is the OMP gate. Do not wrap pytest in an outer flock on the Ghidra lock: the suite takes `/tmp/vulfi-ghidra-<host>-<port>.lock` itself, and an outer flock makes every provider test wait out and skip.

## Upstream projects

Built on [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp), [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), and [ida-domain](https://github.com/HexRaysSA/ida-domain). The 24 stock rules and the function-prototype table in `src/vulfi_mcp/data/` are derived from [Accenture VulFi](https://github.com/Accenture/VulFi) and are redistributed under its Apache-2.0 licence, a copy of which ships beside them and in `THIRD_PARTY_LICENSES/`. The rule evaluator is an independent implementation: it interprets a restricted syntax tree rather than executing rule expressions as Python.

The full architecture is described in the [MCP, fallback, and data design](docs/superpowers/specs/2026-09-28-vulfi-ida-mcp-design.md) and the [RE preparation design](docs/superpowers/specs/2026-09-29-vulfi-re-preparation-design.md). Where those documents describe a pass, a rule, or a link this README lists as unavailable, that description is not a command.
