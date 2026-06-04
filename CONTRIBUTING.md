# Contributing

Thanks for helping improve MCPGuard.

## Development

```bash
pnpm install
pnpm check
```

Run the CLI locally:

```bash
pnpm --filter mcpguard dev -- --help
```

## Pull Requests

Before opening a pull request:

- Add or update tests for policy, redaction, proxy, or CLI behavior.
- Run `pnpm check`.
- Keep new dependencies small and security-relevant.
- Avoid logging secrets or raw MCP responses in tests.

## Design Principles

- Local-first by default.
- No telemetry.
- stdout remains MCP-only when proxying stdio.
- stderr is for human-readable status and diagnostics.
- Deny by default in non-interactive mode when a policy asks for approval.
