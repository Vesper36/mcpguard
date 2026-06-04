# Policy

MCPGuard policies are YAML files.

```yaml
version: 1
defaults:
  action: ask
rules: []
```

Generate a preset instead of starting from scratch:

```bash
mcpguard init --preset filesystem-safe
mcpguard init --preset shell-safe --out shell.mcpguard.yaml
mcpguard init --preset github-readonly --out github.mcpguard.yaml
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

## Validation

Validate policy syntax and schema:

```bash
mcpguard policy validate --policy mcpguard.yaml
```

Simulate a tool call without starting an MCP server:

```bash
mcpguard policy simulate \
  --policy mcpguard.yaml \
  --tool read_file \
  --args '{"path":".env"}'
```

Machine-readable output:

```bash
mcpguard policy simulate --tool read_file --args '{"path":"README.md"}' --json
```

Use `--fail-on-deny` in CI when a denied decision should fail the job.

## Policy Tests

For repeatable checks, keep expected decisions in a YAML test file:

```yaml
version: 1
policy: mcpguard.yaml

cases:
  - name: block dotenv read
    tool: read_file
    args:
      path: .env
    expect:
      action: deny
      ruleId: block-secrets
```

Run the suite:

```bash
mcpguard policy test --file mcpguard.tests.yaml
```

`policy` inside the test file is resolved relative to the test file. `--policy` overrides it.

Supported expectations:

- `action`: `allow`, `deny`, or `ask`.
- `ruleId`: expected matched rule, or `null` for the default decision.
- `reasonContains`: substring that must appear in the decision reason.

CI-friendly output:

```bash
mcpguard policy test --file mcpguard.tests.yaml --json
```
