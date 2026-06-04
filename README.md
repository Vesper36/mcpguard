# MCPGuard

Local security gateway for MCP servers and AI coding agents.

```bash
pnpm add -g mcpguard
mcpguard run --policy mcpguard.yaml -- npx @modelcontextprotocol/server-filesystem .
```

MCPGuard sits between an AI client and an MCP server. It proxies stdio JSON-RPC traffic, blocks risky tool calls before they reach the server, redacts secrets from responses, and writes an audit trail you can review later.

## Why

AI coding agents can read files, call APIs, browse repositories, run shell commands, and touch production systems through MCP servers. That power needs a local permission layer that is simple enough to use every day.

MCPGuard is built for:

- Teams trying MCP servers with real repositories.
- Security-conscious developers using local AI coding agents.
- Open-source maintainers who want agent activity to be reviewable.
- CI pipelines that need policy checks and sanitized audit logs.

## Features

- **MCP stdio proxy**: Transparent newline-delimited JSON-RPC forwarding.
- **Policy engine**: `allow`, `deny`, and `ask` decisions for `tools/call`.
- **Path controls**: Glob allowlists and denylists for file-like arguments.
- **Command controls**: Regex denylists for shell-like arguments.
- **Secret redaction**: Masks API keys, GitHub tokens, JWTs, AWS keys, private keys, and custom patterns.
- **Interactive approval**: Uses `/dev/tty` so MCP stdin/stdout stays protocol-clean.
- **Audit logs**: JSONL events for decisions, responses, lifecycle, and errors.
- **Policy generation**: Creates allow-rule drafts from real approved sessions.
- **No telemetry**: Runs locally and does not send prompts, code, or logs anywhere.

## Quickstart

Create a policy:

```bash
mcpguard init
```

Run an MCP server behind MCPGuard:

```bash
mcpguard run -- npx @modelcontextprotocol/server-filesystem .
```

Review recent decisions:

```bash
mcpguard logs
```

Generate a policy draft from allowed calls:

```bash
mcpguard policy generate --out mcpguard.generated.yaml
```

Validate and simulate policy decisions without starting an MCP server:

```bash
mcpguard policy validate
mcpguard policy simulate --tool read_file --args '{"path":".env"}'
```

## Policy Example

```yaml
version: 1

defaults:
  action: ask
  reason: No policy rule matched this tool call.

redaction:
  enabled: true
  mask: "****"

audit:
  enabled: true
  path: ".mcpguard/audit.jsonl"

approval:
  nonInteractive: deny
  rememberByDefault: false

rules:
  - id: block-secret-files
    match:
      method: tools/call
      args:
        path:
          deny:
            - ".env"
            - ".env.*"
            - "**/*.pem"
            - "**/id_rsa"
            - "**/id_ed25519"
    action: deny
    reason: Secret-bearing files are blocked by default.

  - id: block-destructive-shell
    match:
      method: tools/call
      args:
        command:
          denyRegex:
            - "(^|\\s)rm\\s+-rf(\\s|$)"
            - "git\\s+reset\\s+--hard"
            - "DROP\\s+DATABASE"
    action: deny
    reason: Destructive commands require an explicit exception.

  - id: allow-project-reads
    match:
      method: tools/call
      tool:
        - read_file
        - list_directory
      args:
        path:
          allow:
            - "src/**"
            - "packages/**"
            - "README.md"
            - "package.json"
    action: allow
```

Rules are evaluated top to bottom. The first matching rule wins. If no rule matches, `defaults.action` is used.

## CLI

```bash
mcpguard init [--out mcpguard.yaml] [--force]
mcpguard run [--policy mcpguard.yaml] [--audit-log .mcpguard/audit.jsonl] [--non-interactive deny|allow] -- <server command>
mcpguard logs [--audit-log .mcpguard/audit.jsonl] [--limit 20] [--json]
mcpguard policy generate [--audit-log .mcpguard/audit.jsonl] [--out mcpguard.generated.yaml]
mcpguard policy validate [--policy mcpguard.yaml] [--json]
mcpguard policy simulate [--policy mcpguard.yaml] --tool read_file --args '{"path":"README.md"}' [--json] [--fail-on-deny]
```

## How It Works

The MCP stdio transport uses UTF-8 JSON-RPC messages separated by newlines. MCPGuard keeps stdout reserved for valid MCP messages and writes diagnostics to stderr. For each `tools/call` request, MCPGuard:

1. Extracts the tool name and arguments.
2. Evaluates the YAML policy.
3. Allows, denies, or asks for approval.
4. Redacts server responses before returning them to the client.
5. Writes redacted audit events to JSONL.

Non-tool MCP messages such as initialization and tool listing are forwarded transparently.

## Development

```bash
pnpm install
pnpm check
pnpm --filter mcpguard dev -- --help
```

Project layout:

```text
packages/core   policy engine, redaction, audit logger, stdio proxy
packages/cli    mcpguard command line
docs            usage and security model
examples        starter policies and demos
```

## Roadmap

- Web UI for browsing sessions and decisions.
- MCP Registry scanner for risky tool surfaces.
- VS Code and Cursor configuration helpers.
- Signed audit log mode.
- Policy packs for filesystem, GitHub, shell, database, browser, and cloud MCP servers.

## License

MIT
