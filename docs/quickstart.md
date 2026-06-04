# Quickstart

Install dependencies for local development:

```bash
pnpm install
pnpm build
```

Create a policy:

```bash
pnpm --filter mcpguard dev -- init --preset filesystem-safe
```

Generate policy, policy tests, and a ready-to-paste MCP client config for the current repository:

```bash
pnpm --filter mcpguard dev -- setup cursor filesystem --root .
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
pnpm --filter mcpguard dev -- doctor --policy examples/filesystem/mcpguard.yaml --test examples/filesystem/mcpguard.tests.yaml -- node examples/demo-server.mjs
pnpm --filter mcpguard dev -- policy validate
pnpm --filter mcpguard dev -- policy simulate --tool read_file --args '{"path":".env"}'
pnpm --filter mcpguard dev -- policy test --file examples/filesystem/mcpguard.tests.yaml
pnpm --filter mcpguard dev -- policy generate --out mcpguard.generated.yaml
```

For a global install after publishing:

```bash
pnpm add -g mcpguard
mcpguard setup cursor filesystem --root .
mcpguard run -- npx @modelcontextprotocol/server-filesystem .
```
