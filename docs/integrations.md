# Integrations

MCPGuard wraps MCP servers that use stdio transport.

## Filesystem Server

```bash
mcpguard run -- npx @modelcontextprotocol/server-filesystem .
```

## Custom Server

```bash
mcpguard run -- node ./server.js
```

## Client Configuration

Where a client expects an MCP server command, set:

```json
{
  "command": "mcpguard",
  "args": [
    "run",
    "--policy",
    "mcpguard.yaml",
    "--",
    "npx",
    "@modelcontextprotocol/server-filesystem",
    "."
  ]
}
```

## CI

CI usually has no TTY. Keep the fallback explicit:

```bash
mcpguard run --non-interactive deny -- npx your-mcp-server
```

Use `mcpguard logs --json` to export redacted audit records.
