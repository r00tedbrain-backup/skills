# tools/ — Bundled utilities for the reverse-engineering skill

> Original works — MIT-licensed — part of `r00tedbrain-backup/skills`.
> See LICENSE in the repo root.

This directory ships small, self-contained utilities that work alongside the methodology files in `references/`. Everything here is original code we wrote. Nothing in this directory is copied or derived from third-party projects without explicit license — we link to upstream MCP servers and plugins instead of redistributing them.

## What's here

| File | Purpose | Counterpart in the wider ecosystem |
|---|---|---|
| [`ida_export_plugin.py`](./ida_export_plugin.py) | IDA Pro plugin (Ctrl-Shift-E) that exports the current IDB into a `decompile/` directory of plain-text files an AI agent can read directly. | Same output layout as community plugins like `P4nda0s/IDA-NO-MCP`, written from scratch with a clear MIT license. |
| [`dex_memory_dumper.js`](./dex_memory_dumper.js) | Frida agent (JavaScript) that dumps DEX files from a running Android app — both via raw memory scan and via `ClassLoader` traversal. | Equivalent functionality to `panda-dex-dumper`, but as portable Frida JS instead of a native binary. |
| [`mcp/`](./mcp/) | Setup notes and JSON config snippets for connecting AI agents to **upstream MCP servers** (ida-pro-mcp, GhidraMCP, r2mcp). The MCP servers themselves are installed from their original repos. | Mirrors P4nda0s' "Option A — IDA Pro MCP (preferred)" workflow. |

## Quick start by task

### "I have IDA Pro and want the agent to read my analysis"
**Two equivalent options — pick whichever fits:**

1. **Live (MCP)** — install [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp), follow [`mcp/ida-pro-mcp.md`](./mcp/ida-pro-mcp.md). Agent queries IDA in real time.
2. **File-based (export)** — drop [`ida_export_plugin.py`](./ida_export_plugin.py) in your IDA `plugins/` directory, press **Ctrl-Shift-E**, point the agent at the resulting directory.

Both produce the same analytical surface. The methodology files (`references/symbol-recovery.md`, `references/struct-recovery.md`, `references/idapython.md`) work with either.

### "I have Ghidra and want the agent to read my analysis"
Install [`LaurieWired/GhidraMCP`](https://github.com/LaurieWired/GhidraMCP), follow [`mcp/ghidra-mcp.md`](./mcp/ghidra-mcp.md). Methodology in `references/ghidra-scripting.md` applies.

### "I want to dump DEX from a packed Android app"
Use [`dex_memory_dumper.js`](./dex_memory_dumper.js) with Frida — see the header comment of the file for usage. Pulls into `/data/local/tmp/<package>/`, then `adb pull`.

### "I want to set up multiple disassembler MCP servers at once"
Open [`mcp/claude-config-snippets.json`](./mcp/claude-config-snippets.json) (or the Cursor equivalent), copy the entries you want into your agent's MCP config, restart the agent.

## Authorization reminder

Every tool here is for **authorized analysis only** — applications you own, programs under written-permission bug-bounty scope, your own QA / interoperability research, malware in isolated lab environments, and CTF challenges.

Hooking an AI agent up to a live disassembler or to a Frida session inside a running app gives it broad read/write capability over your analysis. Treat it as a privileged user:

- Use **read-only** MCP modes when the upstream supports them.
- Snapshot or copy IDBs/Ghidra projects before exposing them.
- Never enable any of these on systems or applications you don't have explicit permission to analyze.

## License

All original code in this directory is MIT-licensed. Third-party MCP servers and plugins are governed by their own upstream licenses (linked from each `mcp/*.md` file). We do not modify or redistribute that upstream code.
