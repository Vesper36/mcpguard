#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_POLICY_TEXT,
  parsePolicy,
  Redactor,
  runStdioProxy,
  type AuditEvent,
  type JsonObject,
  type McpGuardPolicy,
} from "@mcpguard/core";
import { stringify as stringifyYaml } from "yaml";

const DEFAULT_POLICY_PATH = "mcpguard.yaml";

interface RunOptions {
  policyPath: string;
  auditLog?: string;
  noRedaction: boolean;
  nonInteractive?: "deny" | "allow";
  command: string[];
}

interface LogsOptions {
  auditLog: string;
  json: boolean;
  limit: number;
}

interface GenerateOptions {
  auditLog: string;
  out?: string;
}

async function main(argv = process.argv.slice(2)): Promise<number> {
  const [command, ...rest] = argv;

  try {
    switch (command) {
      case undefined:
      case "-h":
      case "--help":
      case "help":
        printHelp();
        return 0;
      case "-v":
      case "--version":
      case "version":
        console.log("mcpguard 0.1.0");
        return 0;
      case "init":
        return await initCommand(rest);
      case "run":
        return await runCommand(rest);
      case "logs":
        return await logsCommand(rest);
      case "policy":
        return await policyCommand(rest);
      default:
        throw new CliError(`Unknown command: ${command}`, 1);
    }
  } catch (error) {
    if (error instanceof CliError) {
      console.error(`mcpguard: ${error.message}`);
      if (error.showHelp) {
        printHelp();
      }
      return error.exitCode;
    }

    const message = error instanceof Error ? error.message : String(error);
    console.error(`mcpguard: ${message}`);
    return 1;
  }
}

async function initCommand(args: string[]): Promise<number> {
  const force = args.includes("--force") || args.includes("-f");
  const path = readStringOption(args, ["--out", "-o"], DEFAULT_POLICY_PATH);

  if (existsSync(path) && !force) {
    throw new CliError(`${path} already exists. Use --force to overwrite.`, 1);
  }

  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, DEFAULT_POLICY_TEXT, "utf8");
  console.log(`Created ${path}`);
  return 0;
}

async function runCommand(args: string[]): Promise<number> {
  const options = parseRunOptions(args);
  const policy = await loadAndOverridePolicy(options);
  const [command, ...commandArgs] = options.command;

  if (!command) {
    throw new CliError(
      "Missing MCP server command. Use: mcpguard run -- <server command>",
      1,
    );
  }

  return await runStdioProxy({
    command,
    args: commandArgs,
    policy,
  });
}

async function logsCommand(args: string[]): Promise<number> {
  const options: LogsOptions = {
    auditLog: readStringOption(
      args,
      ["--audit-log", "--log"],
      ".mcpguard/audit.jsonl",
    ),
    json: args.includes("--json"),
    limit: Number(readStringOption(args, ["--limit", "-n"], "20")),
  };

  const events = await readAuditEvents(options.auditLog);
  const selected = events.slice(Math.max(0, events.length - options.limit));

  if (options.json) {
    for (const event of selected) {
      console.log(JSON.stringify(event));
    }
    return 0;
  }

  for (const event of selected) {
    console.log(formatAuditEvent(event));
  }

  return 0;
}

async function policyCommand(args: string[]): Promise<number> {
  const [subcommand, ...rest] = args;
  if (subcommand !== "generate") {
    throw new CliError(
      "Use: mcpguard policy generate [--audit-log path] [--out path]",
      1,
    );
  }

  const options: GenerateOptions = {
    auditLog: readStringOption(
      rest,
      ["--audit-log", "--log"],
      ".mcpguard/audit.jsonl",
    ),
    out: readOptionalStringOption(rest, ["--out", "-o"]),
  };

  const events = await readAuditEvents(options.auditLog);
  const generated = generatePolicyFromAudit(events);

  if (options.out) {
    await mkdir(dirname(resolve(options.out)), { recursive: true });
    await writeFile(options.out, generated, "utf8");
    console.log(`Created ${options.out}`);
  } else {
    console.log(generated);
  }

  return 0;
}

export function parseRunOptions(args: string[]): RunOptions {
  const splitIndex = args.indexOf("--");
  if (splitIndex === -1) {
    throw new CliError(
      "Missing -- separator. Use: mcpguard run [options] -- <server command>",
      1,
    );
  }

  const optionArgs = args.slice(0, splitIndex);
  const command = args.slice(splitIndex + 1);
  const nonInteractive = readOptionalStringOption(optionArgs, [
    "--non-interactive",
  ]);

  if (
    nonInteractive &&
    nonInteractive !== "deny" &&
    nonInteractive !== "allow"
  ) {
    throw new CliError("--non-interactive must be either deny or allow", 1);
  }

  const parsedNonInteractive = nonInteractive as "deny" | "allow" | undefined;

  return {
    policyPath: readStringOption(
      optionArgs,
      ["--policy", "-p"],
      DEFAULT_POLICY_PATH,
    ),
    auditLog: readOptionalStringOption(optionArgs, ["--audit-log", "--log"]),
    noRedaction: optionArgs.includes("--no-redaction"),
    nonInteractive: parsedNonInteractive,
    command,
  };
}

async function loadAndOverridePolicy(
  options: RunOptions,
): Promise<McpGuardPolicy> {
  const source = existsSync(options.policyPath)
    ? await readFile(options.policyPath, "utf8")
    : DEFAULT_POLICY_TEXT;
  const policy = parsePolicy(source, options.policyPath);

  if (options.auditLog) {
    policy.audit.path = options.auditLog;
  }

  if (options.noRedaction) {
    policy.redaction.enabled = false;
  }

  if (options.nonInteractive) {
    policy.approval.nonInteractive = options.nonInteractive;
  }

  return policy;
}

async function readAuditEvents(path: string): Promise<AuditEvent[]> {
  if (!existsSync(path)) {
    return [];
  }

  const source = await readFile(path, "utf8");
  return source
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as AuditEvent);
}

function generatePolicyFromAudit(events: AuditEvent[]): string {
  const allowed = events.filter(
    (event) => event.type === "decision" && event.allowed && event.toolName,
  );
  const grouped = new Map<string, Set<string>>();

  for (const event of allowed) {
    const toolName = event.toolName;
    if (!toolName) {
      continue;
    }

    const paths = collectPaths(event.data);
    const key = toolName;
    const group = grouped.get(key) ?? new Set<string>();

    for (const path of paths) {
      group.add(path);
    }

    grouped.set(key, group);
  }

  const rules = [...grouped.entries()].map(([toolName, paths]) => {
    const rule: JsonObject = {
      id: `allow-${slugify(toolName)}`,
      match: {
        method: "tools/call",
        tool: toolName,
      },
      action: "allow",
      reason: "Generated from allowed audit events.",
    };

    if (paths.size > 0) {
      rule.match = {
        ...(rule.match as JsonObject),
        args: {
          path: {
            allow: [...paths].sort(),
          },
        },
      };
    }

    return rule;
  });

  const policy = {
    version: 1,
    defaults: {
      action: "ask",
      reason: "No generated rule matched this tool call.",
    },
    redaction: {
      enabled: true,
      mask: "****",
    },
    audit: {
      enabled: true,
      path: ".mcpguard/audit.jsonl",
    },
    approval: {
      nonInteractive: "deny",
      rememberByDefault: false,
    },
    rules,
  };

  return stringifyYaml(policy);
}

function collectPaths(value: unknown): string[] {
  const paths = new Set<string>();
  const visit = (entry: unknown): void => {
    if (Array.isArray(entry)) {
      for (const item of entry) {
        visit(item);
      }
      return;
    }

    if (!entry || typeof entry !== "object") {
      return;
    }

    for (const [key, child] of Object.entries(
      entry as Record<string, unknown>,
    )) {
      if (key === "path" && typeof child === "string") {
        paths.add(child);
      }
      visit(child);
    }
  };

  visit(value);
  return [...paths];
}

function formatAuditEvent(event: AuditEvent): string {
  const time = event.timestamp;
  if (event.type === "decision") {
    const state = event.allowed ? "ALLOW" : "DENY";
    return `${time} ${state} ${event.toolName ?? "(unknown)"} rule=${event.ruleId ?? "default"} reason=${event.reason ?? ""}`;
  }

  if (event.type === "response") {
    return `${time} RESPONSE request=${String(event.requestId ?? "")}`;
  }

  return `${time} ${event.type.toUpperCase()} ${event.reason ?? JSON.stringify(event.data ?? {})}`;
}

function readStringOption(
  args: string[],
  names: string[],
  defaultValue: string,
): string {
  return readOptionalStringOption(args, names) ?? defaultValue;
}

function readOptionalStringOption(
  args: string[],
  names: string[],
): string | undefined {
  for (const name of names) {
    const index = args.indexOf(name);
    if (index !== -1) {
      const value = args[index + 1];
      if (!value || value.startsWith("-")) {
        throw new CliError(`${name} requires a value`, 1);
      }
      return value;
    }
  }

  return undefined;
}

function slugify(value: string): string {
  return new Redactor({ enabled: false })
    .redactString(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-|-$/gu, "");
}

function printHelp(): void {
  console.log(`MCPGuard

A local security gateway for MCP servers and AI coding agents.

Usage:
  mcpguard init [--out mcpguard.yaml] [--force]
  mcpguard run [--policy mcpguard.yaml] [--audit-log .mcpguard/audit.jsonl] [--non-interactive deny|allow] -- <server command>
  mcpguard logs [--audit-log .mcpguard/audit.jsonl] [--limit 20] [--json]
  mcpguard policy generate [--audit-log .mcpguard/audit.jsonl] [--out mcpguard.generated.yaml]

Examples:
  mcpguard init
  mcpguard run -- npx @modelcontextprotocol/server-filesystem .
  mcpguard logs
`);
}

class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number,
    readonly showHelp = false,
  ) {
    super(message);
  }
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const exitCode = await main();
  process.exitCode = exitCode;
}
