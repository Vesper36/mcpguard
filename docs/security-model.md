# Security Model

MCPGuard is a local mediation layer, not a sandbox.

## Guarantees

MCPGuard can:

- Deny matching MCP `tools/call` requests before they reach the server.
- Redact matching secrets from server responses.
- Keep an audit trail of decisions and responses.
- Keep human diagnostics out of MCP stdout.

## Non-Guarantees

MCPGuard cannot:

- Fix vulnerabilities in an upstream MCP server.
- Prevent side effects from calls that policy allowed.
- Inspect encrypted network traffic initiated by an MCP server.
- Guarantee that every possible secret format is redacted.
- Replace OS sandboxing, container isolation, or least-privilege credentials.

## Recommended Setup

- Run MCP servers with least-privilege filesystem and API credentials.
- Start with `defaults.action: ask`.
- Put deny rules before broad allow rules.
- Keep `.mcpguard/audit.jsonl` out of git.
- Use custom redaction patterns for organization-specific tokens.
- Prefer read-only tokens for GitHub, cloud, database, and browser MCP servers.

## Protocol Cleanliness

MCPGuard uses stdout only for MCP JSON-RPC messages. Prompts and diagnostics are written to stderr or `/dev/tty`. This matters because MCP clients expect server stdout to contain only protocol messages.
