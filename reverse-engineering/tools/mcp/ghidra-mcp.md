# Setting up `GhidraMCP` for AI agents

> Reference notes for the third-party server `LaurieWired/GhidraMCP` (Apache 2.0). We do not redistribute its code — these are install instructions plus client configuration we wrote ourselves.

## What it does
Exposes a running Ghidra instance to MCP clients so an AI agent can:

- List programs and functions
- Decompile functions on demand
- Read symbols, references, comments
- Run Ghidra scripts headlessly via the agent

Equivalent capability to `ida-pro-mcp` but for the free, open-source disassembler.

## Prerequisites
1. **Ghidra 11.x or newer** installed locally
2. **Java 17+** (Ghidra ships with bundled JDK on most platforms)
3. An **MCP-capable agent**

## Install (upstream — Apache 2.0)

```bash
git clone https://github.com/LaurieWired/GhidraMCP.git
cd GhidraMCP
# Follow upstream README — typically a Gradle build that produces a Ghidra
# extension .zip you install through Ghidra's "File → Install Extensions…"
```

Once installed, the extension adds an MCP server endpoint that starts when Ghidra opens. Default port is usually `8080` or `13339` — check the upstream README.

## Configure Claude Code

Add to `~/.config/claude/mcp.json` (or the macOS path):

```json
{
  "mcpServers": {
    "ghidra": {
      "transport": "sse",
      "url": "http://127.0.0.1:8080/sse"
    }
  }
}
```

Adapt the port to whatever the extension prints in Ghidra's console.

## Configure Cursor / Continue / Cline
Same JSON block, dropped into the agent's MCP config file.

## Verify
With Ghidra open and a project loaded, ask your agent:

> Decompile the function `entry` in the currently active program.

You should see live decompilation — not a generic explanation.

## When to use this vs ida-pro-mcp
| Use `ghidra-mcp` when… | Use `ida-pro-mcp` when… |
|---|---|
| You don't have IDA Pro license | You have IDA Pro |
| You're working with open-source RE tools end-to-end | You need the best Hex-Rays decompiler |
| You want to leverage Ghidra Scripts headlessly | You want full IDA scripting via IDAPython |

Both are fully supported by our skill (`references/ghidra-scripting.md` and `references/idapython.md`).

## Authorization reminder
Same caveats as IDA: the agent gets the same write capabilities as a Ghidra user. Only attach to projects you have explicit permission to analyze.
