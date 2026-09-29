# VulFi MCP

A design-stage project for running VulFi-style vulnerability rules through the official Hex-Rays IDA MCP, with persistent per-finding triage and an optional Oh My Pi (OMP) board.

**Status:** Architecture specification only. There is no runnable MCP server, scanner, extension, or packaged rule set in this repository yet. The tool contracts below describe planned behavior, not available commands.

## Proposed architecture

- A Python 3.11+ MCP entry point extends the official `ida-mcp` tool registry without forking it or replacing its six stock tools.
- `ida-nexus` leases a headless `idalib` worker; scanning runs in IDAPython through `RemoteModule`. There is no GUI plugin or additional MCP/HTTP server.
- The 24 stock VulFi rules and agent-supplied rules use a restricted expression interpreter, not Python `eval` or `exec`.
- Findings, rule snapshots, coverage, and independent assessments for each rule/call site are stored as versioned JSON in the IDB's netnode. Partial scans retain and identify stale findings.
- An OMP TypeScript extension presents MCP findings in its own triage widget; the IDB remains authoritative, and OMP's built-in todo list is untouched.

The four planned tools are `vulfi_rule_template`, `vulfi_scan`, `vulfi_findings`, and `vulfi_triage`.

Read the [full design and data contracts](docs/superpowers/specs/2026-09-28-vulfi-ida-mcp-design.md), including scope boundaries, failure behavior, dependency baseline, and the integration test gate. Implementation and installation instructions will follow when the software exists.

## Upstream projects

This proposal builds on [Hex-Rays IDA MCP](https://github.com/HexRaysSA/ida-mcp), [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), [Accenture VulFi](https://github.com/Accenture/VulFi), and [Oh My Pi](https://github.com/can1357/oh-my-pi). No upstream source code or rules are distributed in this design-stage repository. Running the proposed decompiler-dependent rules will require an IDA license with headless Hex-Rays decompilation support.
