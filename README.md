# VulFi MCP

A design-stage project for preparing binaries, running VulFi-style vulnerability rules through the official Hex-Rays IDA MCP or a configured Ghidra/radare2 MCP fallback, and triaging findings across backends.

**Status:** Architecture specification only. There is no runnable MCP server, scanner, extension, or packaged rule set in this repository yet. The tool contracts below describe planned behavior, not available commands.

## Proposed architecture

- A Python 3.11+ entry point extends the official `ida-mcp` registry without forking it; its six stock IDA tools remain available.
- Preparation discovers candidate hidden strings/functions, recovers safe functions, and infers data structures and pointer tables **before** rule scans. It records evidence and gaps rather than claiming to find every hidden object.
- IDA analysis uses headless `idalib` through `ida-nexus`. When IDA cannot decompile or open a target, vetted Ghidra/radare2 MCP adapters provide supported preparation and rule evidence. Unsupported rules are listed explicitly; no decompiler-text guess is counted as a structural match.
- The 24 stock VulFi rules and agent-supplied rules use a restricted expression interpreter, not Python `eval` or `exec`. The existing agent may propose RE improvements, but an operator must review them before they change managed analysis artifacts.
- IDA findings and assessments persist in a managed IDB netnode; fallback findings and preparation records persist in SQLite outside the repository. Reviewer-linked matching findings synchronize assessments with a durable, conflict-aware journal.
- An optional OMP TypeScript extension presents preparation, per-backend triage, and human review without changing OMP's native todo list.

The seven planned VulFi tools are `vulfi_rule_template`, `vulfi_prepare`, `vulfi_preparation`, `vulfi_propose_recovery`, `vulfi_scan`, `vulfi_findings`, and `vulfi_triage`. Local operator review/link commands are separate from agent-callable MCP tools.

Read the [MCP, fallback, and data design](docs/superpowers/specs/2026-09-28-vulfi-ida-mcp-design.md) and the [RE preparation design](docs/superpowers/specs/2026-09-29-vulfi-re-preparation-design.md). Both describe proposed contracts and verification gates, not available commands. Implementation and installation instructions will follow when the software exists.

## Upstream projects

This proposal builds on [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp), [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), [Accenture VulFi](https://github.com/Accenture/VulFi), the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), [radareorg radare2-mcp](https://github.com/radareorg/radare2-mcp), a [headless-capable Ghidra MCP candidate](https://github.com/bethington/ghidra-mcp), and [Oh My Pi](https://github.com/can1357/oh-my-pi). No upstream source code or rules are distributed in this design-stage repository. The official IDA MCP still requires an IDA installation; IDA's decompiler-dependent rules require an appropriate license, while fallback providers have their own prerequisites.
