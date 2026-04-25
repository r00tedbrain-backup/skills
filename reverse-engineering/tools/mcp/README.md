# MCP servers for reverse engineering

> Authorized use only. These are setup notes for **MIT/Apache-licensed third-party MCP servers** plus our own configuration snippets. We do NOT redistribute the upstream code — every server below is installed from its original repository.

## What is MCP?
The Model Context Protocol (MCP) lets an AI agent (Claude Code, Cursor, Continue, etc.) call out to local servers that expose structured tools. For reverse engineering, the most useful servers are:

| Server | What it exposes | License | Repo |
|---|---|---|---|
| `ida-pro-mcp`           | IDA Pro: functions, decompilation, types, names, xrefs, comments | MIT     | [`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) |
| `ghidra-mcp`            | Ghidra: programs, decompiled functions, symbols, scripts         | Apache  | [`LaurieWired/GhidraMCP`](https://github.com/LaurieWired/GhidraMCP) |
| `r2mcp`                 | radare2: r2 commands as tools                                    | LGPL    | [`radareorg/r2mcp`](https://github.com/radareorg/r2mcp) |
| `binja-mcp` (community) | Binary Ninja: similar surface to ida-pro-mcp                     | varies  | search "binary ninja mcp" — multiple forks |

When MCP is connected, the agent uses live queries instead of relying on pre-exported files (the `decompile/` directory pattern). Both modes are valid — use whichever fits your workflow.

## How this directory is organized

**Server install guides:**
- [`ida-pro-mcp.md`](./ida-pro-mcp.md) — install + configure `mrexodia/ida-pro-mcp` (MIT)
- [`ghidra-mcp.md`](./ghidra-mcp.md) — install + configure `LaurieWired/GhidraMCP` (Apache)

**Drop-in client config snippets** (one per agent):
| Agent | File | Config location |
|---|---|---|
| Claude Code | [`claude-config-snippets.json`](./claude-config-snippets.json) | `~/.config/claude/mcp.json` (Linux) / `~/Library/Application Support/Claude/mcp.json` (macOS) |
| Cursor | [`cursor-config-snippets.json`](./cursor-config-snippets.json) | Cursor → Settings → MCP → Edit JSON |
| OpenCode | [`opencode-config-snippets.json`](./opencode-config-snippets.json) | `opencode.json` at project root, or `~/.config/opencode/config.json` |
| Continue | [`continue-config-snippets.json`](./continue-config-snippets.json) | `~/.continue/config.yaml` (newer) or `config.json` (legacy) |
| Cline | [`cline-config-snippets.json`](./cline-config-snippets.json) | VS Code globalStorage path (per OS, see file) |
| Windsurf | [`windsurf-config-snippets.json`](./windsurf-config-snippets.json) | `~/.codeium/windsurf/mcp_config.json` |

For other agents (Codex, Gemini CLI, Qwen Code, Roo Code, Kilo Code, Trae, Zencoder, Continue, Junie, Kiro CLI, Pi, Antigravity, Mux, OpenHands, Pochi, etc.), the format is almost always one of these three patterns:

```jsonc
// Pattern A — Claude-Desktop style (most common)
{ "mcpServers": { "<name>": { "transport": "sse", "url": "..." } } }

// Pattern B — OpenCode style
{ "mcp": { "<name>": { "type": "remote", "url": "..." } } }

// Pattern C — array style (Continue legacy)
{ "modelContextProtocolServers": [ { "name": "...", "transport": {...} } ] }
```

If your agent isn't listed, copy the pattern that matches its docs and adapt the URLs from any of the snippets above.

## Quick decision: MCP or file-based export?

| Use MCP when… | Use file-based export when… |
|---|---|
| You have IDA/Ghidra open and a long interactive session | You want to share state with an agent without giving live access |
| You need live updates as you rename/retype | You're doing a one-shot batch analysis |
| The binary fits in a single project the agent can stay attached to | You're analyzing dozens of binaries and want offline queryability |
| You're on the same machine as the agent | You're shipping context to a sandboxed/remote agent |

Our skill supports **both** modes — see `references/idapython.md` §0 ("Pre-check: How is the agent accessing IDA?") for the full decision tree.

## Authorization reminder
Hooking your AI agent up to a live disassembler is powerful — it lets the agent rename functions, change types, even patch bytes. Only enable MCP for binaries you have explicit permission to analyze, and prefer **read-only MCP modes** when available.
