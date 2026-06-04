# Policy

MCPGuard policies are YAML files.

```yaml
version: 1
defaults:
  action: ask
rules: []
```

## Actions

- `allow`: Forward the tool call to the MCP server.
- `deny`: Return a JSON-RPC error to the MCP client.
- `ask`: Ask the operator through `/dev/tty`.

In non-interactive environments, `ask` uses `approval.nonInteractive`.

```yaml
approval:
  nonInteractive: deny
```

## Matching

Rules are evaluated from top to bottom. The first matching rule wins.

```yaml
rules:
  - id: allow-src-reads
    match:
      method: tools/call
      tool: read_file
      args:
        path:
          allow:
            - "src/**"
    action: allow
```

Supported match fields:

- `method`: JSON-RPC method, usually `tools/call`.
- `tool`: Tool name from `params.name`.
- `toolRegex`: Regex for tool names.
- `rawJsonContains`: Literal substring in the raw request.
- `rawJsonRegex`: Regex over the raw request.
- `args`: Matchers for nested argument keys.

Argument matcher fields:

- `equals`
- `contains`
- `regex`
- `allow`
- `deny`
- `allowRegex`
- `denyRegex`

`allow` and `deny` are glob triggers. They do not mean "everything except". For a deny rule, use `deny` patterns with `action: deny`. For an allow rule, use `allow` patterns with `action: allow`.

## Redaction

```yaml
redaction:
  enabled: true
  mask: "****"
  extraPatterns:
    - "xox[baprs]-[A-Za-z0-9-]+"
```

Built-in redaction covers common API tokens, GitHub tokens, JWTs, AWS access keys, private keys, and key-value secrets such as `password=...`.

## Audit

```yaml
audit:
  enabled: true
  path: ".mcpguard/audit.jsonl"
```

Audit logs are JSONL. Sensitive values are redacted before logging.
