# Quickstart

Install dependencies for local development:

```bash
pnpm install
pnpm build
```

Create a policy:

```bash
pnpm --filter mcpguard dev -- init
```

Proxy an MCP server:

```bash
pnpm --filter mcpguard dev -- run -- npx @modelcontextprotocol/server-filesystem .
```

When a client sends `tools/call`, MCPGuard evaluates `mcpguard.yaml`.

Useful commands:

```bash
pnpm --filter mcpguard dev -- logs
pnpm --filter mcpguard dev -- logs --json
pnpm --filter mcpguard dev -- policy generate --out mcpguard.generated.yaml
```

For a global install after publishing:

```bash
pnpm add -g mcpguard
mcpguard init
mcpguard run -- npx @modelcontextprotocol/server-filesystem .
```
