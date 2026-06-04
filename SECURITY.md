# Security Policy

MCPGuard is security tooling, so reports should be handled privately first.

## Reporting A Vulnerability

Please open a private vulnerability report through GitHub Security Advisories.

Include:

- The affected MCPGuard version or commit.
- A minimal reproduction.
- Whether secrets, filesystem access, shell execution, or audit logs are involved.
- Expected and observed behavior.

Do not include live credentials, production tokens, or private keys in the report.

## Scope

In scope:

- Policy bypasses.
- Secret redaction bypasses.
- Audit log leaks.
- Unsafe defaults that allow unexpected tool execution.
- MCP JSON-RPC handling bugs that change security decisions.

Out of scope:

- Vulnerabilities in an upstream MCP server.
- Vulnerabilities in an AI model or client.
- Social engineering against repository maintainers.
