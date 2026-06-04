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

The fastest path is `setup`, which creates a policy, a policy test file, and a portable `mcpServers` config block:

```bash
mcpguard setup cursor filesystem --root .
```

For an existing policy, generate a config block without writing setup files:

```bash
mcpguard config generate \
  --client cursor \
  --name filesystem \
  --policy mcpguard.yaml \
  --cwd . \
  -- npx @modelcontextprotocol/server-filesystem .
```

The generated JSON uses the common `mcpServers` shape:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpguard",
      "args": [
        "run",
        "--policy",
        "/absolute/path/mcpguard.yaml",
        "--cwd",
        "/absolute/path/project",
        "--",
        "npx",
        "@modelcontextprotocol/server-filesystem",
        "."
      ]
    }
  }
}
```

`--client` accepts `claude-desktop`, `cursor`, or `generic`. The emitted block is intentionally portable; paste it into the MCP server configuration area for that client.

Run a local setup check after wiring the config:

```bash
mcpguard doctor --policy mcpguard.yaml --test mcpguard.tests.yaml -- npx @modelcontextprotocol/server-filesystem .
```

## CI

CI usually has no TTY. Keep the fallback explicit:

```bash
mcpguard run --non-interactive deny -- npx your-mcp-server
```

Use `mcpguard logs --json` to export redacted audit records.
