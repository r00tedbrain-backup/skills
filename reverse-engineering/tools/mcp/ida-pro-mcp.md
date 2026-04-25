# Setting up `ida-pro-mcp` for AI agents

> Reference notes for the third-party server `mrexodia/ida-pro-mcp` (MIT-licensed). We do not redistribute its code — these are install instructions plus client configuration we wrote ourselves.

## What it does
Exposes IDA Pro to MCP clients so an AI agent can:

- List, search, and decompile functions (Hex-Rays)
- Read and write names, comments, types
- Walk xrefs and the call graph
- Inspect strings, imports, exports
- Read/patch bytes when authorized

This is the **live-query alternative** to the file-based `decompile/` export workflow — both produce the same analytical capabilities, this one just doesn't need a pre-export step.

## Prerequisites

1. **IDA Pro 7.7+** with the Hex-Rays decompiler license (the server falls back gracefully if Hex-Rays is absent, but most useful tools require it).
2. **Python 3.10+** in the IDA Python environment (`idapyswitch` makes this easy).
3. An **MCP-capable agent** (Claude Code, Cursor, Continue, Cline, OpenCode, etc.).

## Install (upstream — MIT)

Always install from the canonical upstream repo:

```bash
# Clone the MIT-licensed upstream
git clone https://github.com/mrexodia/ida-pro-mcp.git
cd ida-pro-mcp

# Install per the upstream README. As of writing, the documented flow is:
pip install -e .
# or, in IDA's bundled python:
"<IDA install dir>/python3" -m pip install -e .
```

Then load the server inside IDA: `File → Script File…` → choose `ida_pro_mcp/server.py` from the cloned repo (path may have changed — follow upstream README).

The server prints something like:
```
[ida-pro-mcp] listening on http://127.0.0.1:13338
```

Take that URL — you'll point your agent at it.

## Configure clients

### Claude Code
Edit `~/.config/claude/mcp.json` (or `~/Library/Application Support/Claude/mcp.json` on macOS). Add this block — adapt the URL to whatever the server printed:

```json
{
  "mcpServers": {
    "ida-pro": {
      "transport": "sse",
      "url": "http://127.0.0.1:13338/sse"
    }
  }
}
```

Restart Claude Code. You should see the `ida-pro` server in the MCP panel and tool calls like `ida_pro_decompile_function`, `ida_pro_get_xrefs`, etc.

### Cursor
Add the same block to Cursor's MCP config (`Settings → MCP → Edit JSON`).

### Continue, Cline, etc.
Each agent's MCP config is slightly different but takes the same `url`/`transport` keys. Copy the snippets from `claude-config-snippets.json` and `cursor-config-snippets.json` in this directory and adapt.

## Verify the connection
With IDA open and the server running, ask your agent:

> List the first 10 functions in the IDB and show the decompilation of the largest one.

The agent should respond with live data — not generic descriptions. If you see "I cannot access IDA," the MCP connection isn't established yet.

## How this complements our skill
- The skill's reference files (`references/idapython.md`, `references/symbol-recovery.md`, `references/struct-recovery.md`) tell the agent **what to look for**.
- `ida-pro-mcp` gives the agent **a way to look for it** in real time.
- When MCP is unavailable, our `tools/ida_export_plugin.py` produces the same analytical surface as a directory of plain-text files.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Agent says "no MCP servers connected" | Server not started, or wrong URL/port in config |
| Tool calls hang indefinitely | IDA is busy with auto-analysis — wait for it to finish |
| `ImportError` when loading server.py | Python version mismatch; use `idapyswitch` to align IDA's Python |
| Hex-Rays calls fail | Decompiler license missing or expired |
| "Permission denied" when patching bytes | Some upstream builds default to read-only — check the server's `--write` flag |
