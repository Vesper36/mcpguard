# MCPGuard

Local security gateway for MCP servers and AI coding agents.

Use Cursor, Claude Desktop, and other MCP clients with real repositories without exposing `.env`, private keys, tokens, or destructive tool calls.

## Quickstart

```bash
npm install -g mcpguard
mcpguard setup cursor filesystem --root . --install
```

This creates:

- `mcpguard.yaml`: safe default policy.
- `mcpguard.tests.yaml`: policy tests for secret blocking.
- `.mcpguard/cursor-filesystem.mcp.json`: generated MCP config block.
- `.cursor/mcp.json`: Cursor project MCP config when `--install` is used.

## Common Commands

```bash
# Generate a policy from a preset
mcpguard init --preset filesystem-safe

# Generate Cursor/Claude/generic MCP config
mcpguard config generate --client cursor --name filesystem -- npx @modelcontextprotocol/server-filesystem .

# Check your setup
mcpguard doctor --policy mcpguard.yaml --test mcpguard.tests.yaml -- npx @modelcontextprotocol/server-filesystem .

# Simulate a blocked secret read
mcpguard policy simulate --tool read_file --args '{"path":".env"}'

# Review audit logs
mcpguard logs
```

## What It Does

MCPGuard sits between an AI client and an MCP server:

```text
Cursor / Claude / Agent -> MCPGuard -> MCP Server -> Files, shell, APIs
```

It can:

- Block reads of `.env`, private keys, and token files.
- Redact secrets before responses reach the AI model.
- Ask before unknown or risky tool calls.
- Write JSONL audit logs for every decision.
- Generate MCP client config for Cursor, Claude Desktop, and generic clients.

## Repository

https://github.com/Vesper36/mcpguard
