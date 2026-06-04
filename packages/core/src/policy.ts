import { readFile } from "node:fs/promises";
import { minimatch } from "minimatch";
import { parse as parseYaml } from "yaml";
import {
  type McpGuardPolicy,
  type McpGuardRule,
  policySchema,
  type ScalarMatcher,
} from "./policy-schema.js";
import type {
  JsonObject,
  JsonRpcMessage,
  PolicyDecision,
  ProxyRequestContext,
} from "./types.js";

export const DEFAULT_POLICY_TEXT = `version: 1

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
    description: Block common secret-bearing files.
    match:
      method: tools/call
      args:
        path:
          deny:
            - ".env"
            - ".env.*"
            - "**/.env"
            - "**/.env.*"
            - "**/*.pem"
            - "**/*.key"
            - "**/id_rsa"
            - "**/id_ed25519"
    action: deny
    reason: Secret-bearing files are blocked by default.

  - id: block-destructive-shell
    description: Block destructive shell commands.
    match:
      method: tools/call
      args:
        command:
          denyRegex:
            - "(^|\\\\s)rm\\\\s+-rf(\\\\s|$)"
            - "git\\\\s+reset\\\\s+--hard"
            - "DROP\\\\s+DATABASE"
            - "truncate\\\\s+table"
    action: deny
    reason: Destructive shell commands require an explicit policy exception.

  - id: allow-project-reads
    description: Allow common read-only project inspection tools.
    match:
      method: tools/call
      tool:
        - read_file
        - list_directory
        - search_files
      args:
        path:
          allow:
            - "src/**"
            - "packages/**"
            - "docs/**"
            - "examples/**"
            - "README.md"
            - "package.json"
            - "pnpm-workspace.yaml"
            - "tsconfig*.json"
    action: allow
    reason: Read-only project inspection is allowed for non-secret paths.
`;

export async function loadPolicyFile(path: string): Promise<McpGuardPolicy> {
  const source = await readFile(path, "utf8");
  return parsePolicy(source, path);
}

export function parsePolicy(
  source: string,
  sourceName = "policy",
): McpGuardPolicy {
  try {
    const parsed = parseYaml(source);
    return policySchema.parse(parsed);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid MCPGuard policy at ${sourceName}: ${detail}`);
  }
}

export function requestContextFromMessage(
  message: JsonRpcMessage,
): ProxyRequestContext {
  const params = asObject(message.params);
  const toolName = typeof params?.name === "string" ? params.name : undefined;
  const args =
    asObject(params?.arguments) ?? asObject(params?.args) ?? undefined;

  return {
    id: message.id,
    method: message.method,
    toolName,
    args,
    raw: message,
  };
}

export function evaluatePolicy(
  policy: McpGuardPolicy,
  context: ProxyRequestContext,
): PolicyDecision {
  for (const rule of policy.rules) {
    if (ruleMatches(rule, context)) {
      return {
        action: rule.action,
        ruleId: rule.id,
        reason: rule.reason ?? rule.description ?? `Matched rule ${rule.id}.`,
      };
    }
  }

  return {
    action: policy.defaults.action,
    reason: policy.defaults.reason ?? "No policy rule matched this tool call.",
  };
}

export function ruleMatches(
  rule: McpGuardRule,
  context: ProxyRequestContext,
): boolean {
  const match = rule.match;

  if (match.method && !matchesStringList(context.method, match.method)) {
    return false;
  }

  if (match.tool && !matchesStringList(context.toolName, match.tool)) {
    return false;
  }

  if (match.toolRegex && !matchesRegex(context.toolName, match.toolRegex)) {
    return false;
  }

  if (match.rawJsonContains || match.rawJsonRegex) {
    const raw = JSON.stringify(context.raw);

    if (match.rawJsonContains && !raw.includes(match.rawJsonContains)) {
      return false;
    }

    if (match.rawJsonRegex && !new RegExp(match.rawJsonRegex, "iu").test(raw)) {
      return false;
    }
  }

  if (match.args) {
    for (const [key, matcher] of Object.entries(match.args)) {
      const values = collectArgumentValues(context.args, key);
      if (!scalarMatcherMatches(values, matcher)) {
        return false;
      }
    }
  }

  return true;
}

function asObject(value: unknown): JsonObject | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as JsonObject;
  }

  return undefined;
}

function matchesStringList(
  value: string | undefined,
  expected: string | string[],
): boolean {
  if (!value) {
    return false;
  }

  return Array.isArray(expected)
    ? expected.includes(value)
    : expected === value;
}

function matchesRegex(value: string | undefined, pattern: string): boolean {
  return typeof value === "string" && new RegExp(pattern, "iu").test(value);
}

function scalarMatcherMatches(
  values: unknown[],
  matcher: ScalarMatcher,
): boolean {
  if (values.length === 0) {
    return false;
  }

  const asStrings = values.map((value) => String(value));

  if (
    matcher.equals !== undefined &&
    !values.some((value) => value === matcher.equals)
  ) {
    return false;
  }

  if (
    matcher.contains !== undefined &&
    !asStrings.some((value) => value.includes(matcher.contains ?? ""))
  ) {
    return false;
  }

  if (
    matcher.regex !== undefined &&
    !asStrings.some((value) =>
      new RegExp(matcher.regex ?? "", "iu").test(value),
    )
  ) {
    return false;
  }

  if (
    matcher.allow !== undefined &&
    !asStrings.some((value) =>
      matcher.allow?.some((pattern) => globMatches(value, pattern)),
    )
  ) {
    return false;
  }

  if (
    matcher.allowRegex !== undefined &&
    !asStrings.some((value) =>
      matcher.allowRegex?.some((pattern) =>
        new RegExp(pattern, "iu").test(value),
      ),
    )
  ) {
    return false;
  }

  if (
    matcher.deny !== undefined &&
    !asStrings.some((value) =>
      matcher.deny?.some((pattern) => globMatches(value, pattern)),
    )
  ) {
    return false;
  }

  if (
    matcher.denyRegex !== undefined &&
    !asStrings.some((value) =>
      matcher.denyRegex?.some((pattern) =>
        new RegExp(pattern, "iu").test(value),
      ),
    )
  ) {
    return false;
  }

  return true;
}

function globMatches(value: string, pattern: string): boolean {
  const normalizedValue = normalizeSlashes(value);
  const normalizedPattern = normalizeSlashes(pattern);
  return minimatch(normalizedValue, normalizedPattern, {
    dot: true,
    nocase: process.platform === "win32",
  });
}

function normalizeSlashes(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\//, "");
}

function collectArgumentValues(
  args: JsonObject | undefined,
  key: string,
): unknown[] {
  if (!args) {
    return [];
  }

  const values: unknown[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item);
      }
      return;
    }

    if (!value || typeof value !== "object") {
      return;
    }

    for (const [entryKey, entryValue] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (entryKey === key) {
        if (Array.isArray(entryValue)) {
          values.push(...entryValue);
        } else {
          values.push(entryValue);
        }
      }

      visit(entryValue);
    }
  };

  visit(args);
  return values.filter((value) =>
    ["string", "number", "boolean"].includes(typeof value),
  );
}
