#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_POLICY_TEXT,
  evaluatePolicy,
  parsePolicy,
  Redactor,
  requestContextFromMessage,
  runStdioProxy,
  type AuditEvent,
  type JsonObject,
  type JsonValue,
  type McpGuardPolicy,
  type PolicyAction,
} from "@mcpguard/core";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

const DEFAULT_POLICY_PATH = "mcpguard.yaml";
const DEFAULT_POLICY_TEST_PATH = "mcpguard.tests.yaml";

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

interface SimulateOptions {
  policyPath: string;
  method: string;
  tool: string;
  args: JsonObject;
  json: boolean;
  failOnDeny: boolean;
}

interface PolicyTestOptions {
  file: string;
  policyPath?: string;
  json: boolean;
  failFast: boolean;
}

interface PolicyTestFile {
  version?: number;
  policy?: string;
  cases: PolicyTestCase[];
}

interface PolicyTestCase {
  name: string;
  method: string;
  tool: string;
  args: JsonObject;
  expect: {
    action?: PolicyAction;
    ruleId?: string | null;
    reasonContains?: string;
  };
}

interface PolicyTestResult {
  name: string;
  ok: boolean;
  method: string;
  tool: string;
  actual: {
    action: PolicyAction;
    ruleId?: string;
    reason: string;
  };
  expected: PolicyTestCase["expect"];
  message?: string;
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

  switch (subcommand) {
    case "generate":
      return await policyGenerateCommand(rest);
    case "validate":
      return await policyValidateCommand(rest);
    case "simulate":
      return await policySimulateCommand(rest);
    case "test":
      return await policyTestCommand(rest);
    default:
      throw new CliError(
        "Use: mcpguard policy <generate|validate|simulate|test>",
        1,
      );
  }
}

async function policyGenerateCommand(args: string[]): Promise<number> {
  const options: GenerateOptions = {
    auditLog: readStringOption(
      args,
      ["--audit-log", "--log"],
      ".mcpguard/audit.jsonl",
    ),
    out: readOptionalStringOption(args, ["--out", "-o"]),
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

async function policyValidateCommand(args: string[]): Promise<number> {
  const policyPath = readStringOption(
    args,
    ["--policy", "-p"],
    DEFAULT_POLICY_PATH,
  );
  const json = args.includes("--json");
  const policy = await loadPolicy(policyPath);

  if (json) {
    console.log(
      JSON.stringify({
        ok: true,
        policy: policyPath,
        rules: policy.rules.length,
        defaults: policy.defaults,
      }),
    );
  } else {
    console.log(
      `Policy OK: ${policyPath} (${policy.rules.length} rule${policy.rules.length === 1 ? "" : "s"})`,
    );
  }

  return 0;
}

async function policySimulateCommand(args: string[]): Promise<number> {
  const options = parseSimulateOptions(args);
  const policy = await loadPolicy(options.policyPath);
  const context = requestContextFromMessage({
    jsonrpc: "2.0",
    id: "simulate",
    method: options.method,
    params: {
      name: options.tool,
      arguments: options.args,
    },
  });
  const decision = evaluatePolicy(policy, context);
  const redactor = new Redactor({
    enabled: policy.redaction.enabled,
    mask: policy.redaction.mask,
    extraPatterns: policy.redaction.extraPatterns,
  });
  const result = {
    method: options.method,
    tool: options.tool,
    args: redactor.redactValue(options.args) as JsonValue,
    decision,
  };

  if (options.json) {
    console.log(JSON.stringify(result));
  } else {
    const state = decision.action.toUpperCase();
    console.log(
      `${state} ${options.tool} rule=${decision.ruleId ?? "default"} reason=${decision.reason}`,
    );
  }

  if (options.failOnDeny && decision.action === "deny") {
    return 2;
  }

  return 0;
}

async function policyTestCommand(args: string[]): Promise<number> {
  const options = parsePolicyTestOptions(args);
  const source = await readFile(options.file, "utf8");
  const testFile = parsePolicyTestFile(source, options.file);
  const policyPath = options.policyPath
    ? options.policyPath
    : resolvePathFromBaseFile(
        options.file,
        testFile.policy ?? DEFAULT_POLICY_PATH,
      );
  const policy = await loadPolicy(policyPath);
  const results: PolicyTestResult[] = [];

  for (const testCase of testFile.cases) {
    const result = evaluatePolicyTestCase(policy, testCase);
    results.push(result);

    if (options.failFast && !result.ok) {
      break;
    }
  }

  const passed = results.filter((result) => result.ok).length;
  const failed = results.length - passed;

  if (options.json) {
    console.log(
      JSON.stringify({
        ok: failed === 0,
        file: options.file,
        policy: policyPath,
        passed,
        failed,
        results,
      }),
    );
  } else {
    for (const result of results) {
      const state = result.ok ? "PASS" : "FAIL";
      console.log(
        `${state} ${result.name} actual=${result.actual.action} rule=${result.actual.ruleId ?? "default"}`,
      );
      if (!result.ok && result.message) {
        console.log(`  ${result.message}`);
      }
    }

    console.log(
      `Policy tests: ${passed} passed, ${failed} failed (${options.file})`,
    );
  }

  return failed === 0 ? 0 : 1;
}

export function parseSimulateOptions(args: string[]): SimulateOptions {
  const policyPath = readStringOption(
    args,
    ["--policy", "-p"],
    DEFAULT_POLICY_PATH,
  );
  const method = readStringOption(args, ["--method"], "tools/call");
  const tool = readOptionalStringOption(args, ["--tool"]);
  const argsJson = readStringOption(args, ["--args"], "{}");

  if (!tool) {
    throw new CliError(
      'Missing --tool. Use: mcpguard policy simulate --tool read_file --args \'{"path":"README.md"}\'',
      1,
    );
  }

  let parsedArgs: unknown;
  try {
    parsedArgs = JSON.parse(argsJson);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliError(`--args must be valid JSON: ${message}`, 1);
  }

  if (
    !parsedArgs ||
    typeof parsedArgs !== "object" ||
    Array.isArray(parsedArgs)
  ) {
    throw new CliError("--args must be a JSON object", 1);
  }

  return {
    policyPath,
    method,
    tool,
    args: parsedArgs as JsonObject,
    json: args.includes("--json"),
    failOnDeny: args.includes("--fail-on-deny"),
  };
}

export function parsePolicyTestOptions(args: string[]): PolicyTestOptions {
  return {
    file: readStringOption(args, ["--file", "-f"], DEFAULT_POLICY_TEST_PATH),
    policyPath: readOptionalStringOption(args, ["--policy", "-p"]),
    json: args.includes("--json"),
    failFast: args.includes("--fail-fast"),
  };
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
  const policy = await loadPolicy(options.policyPath, true);

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

async function loadPolicy(
  policyPath: string,
  useDefaultWhenMissing = false,
): Promise<McpGuardPolicy> {
  const source =
    useDefaultWhenMissing && !existsSync(policyPath)
      ? DEFAULT_POLICY_TEXT
      : await readFile(policyPath, "utf8");
  return parsePolicy(source, policyPath);
}

function parsePolicyTestFile(
  source: string,
  sourceName: string,
): PolicyTestFile {
  let parsed: unknown;
  try {
    parsed = parseYaml(source);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new CliError(
      `Invalid policy test YAML at ${sourceName}: ${message}`,
      1,
    );
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CliError(
      `Invalid policy test file at ${sourceName}: expected an object`,
      1,
    );
  }

  const object = parsed as Record<string, unknown>;
  const version = object.version;
  if (version !== undefined && version !== 1) {
    throw new CliError(
      `Invalid policy test file at ${sourceName}: version must be 1`,
      1,
    );
  }

  if (object.policy !== undefined && typeof object.policy !== "string") {
    throw new CliError(
      `Invalid policy test file at ${sourceName}: policy must be a string`,
      1,
    );
  }

  if (!Array.isArray(object.cases)) {
    throw new CliError(
      `Invalid policy test file at ${sourceName}: cases must be an array`,
      1,
    );
  }

  return {
    version: version as number | undefined,
    policy: object.policy,
    cases: object.cases.map((entry, index) =>
      parsePolicyTestCase(entry, index, sourceName),
    ),
  };
}

function parsePolicyTestCase(
  value: unknown,
  index: number,
  sourceName: string,
): PolicyTestCase {
  const prefix = `Invalid policy test case ${index + 1} at ${sourceName}`;

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CliError(`${prefix}: expected an object`, 1);
  }

  const object = value as Record<string, unknown>;
  const name =
    typeof object.name === "string" ? object.name : `case ${index + 1}`;
  const method =
    typeof object.method === "string" ? object.method : "tools/call";
  const tool = object.tool;
  const args = object.args ?? {};
  const expect = object.expect;

  if (typeof tool !== "string" || tool.length === 0) {
    throw new CliError(`${prefix}: tool is required`, 1);
  }

  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new CliError(`${prefix}: args must be a JSON object`, 1);
  }

  if (!expect || typeof expect !== "object" || Array.isArray(expect)) {
    throw new CliError(`${prefix}: expect must be an object`, 1);
  }

  const expected = expect as Record<string, unknown>;
  if (
    expected.action !== undefined &&
    expected.action !== "allow" &&
    expected.action !== "deny" &&
    expected.action !== "ask"
  ) {
    throw new CliError(
      `${prefix}: expect.action must be allow, deny, or ask`,
      1,
    );
  }

  if (
    expected.ruleId !== undefined &&
    expected.ruleId !== null &&
    typeof expected.ruleId !== "string"
  ) {
    throw new CliError(`${prefix}: expect.ruleId must be a string or null`, 1);
  }

  if (
    expected.reasonContains !== undefined &&
    typeof expected.reasonContains !== "string"
  ) {
    throw new CliError(`${prefix}: expect.reasonContains must be a string`, 1);
  }

  return {
    name,
    method,
    tool,
    args: args as JsonObject,
    expect: {
      action: expected.action as PolicyAction | undefined,
      ruleId: expected.ruleId as string | null | undefined,
      reasonContains: expected.reasonContains as string | undefined,
    },
  };
}

function evaluatePolicyTestCase(
  policy: McpGuardPolicy,
  testCase: PolicyTestCase,
): PolicyTestResult {
  const context = requestContextFromMessage({
    jsonrpc: "2.0",
    id: "test",
    method: testCase.method,
    params: {
      name: testCase.tool,
      arguments: testCase.args,
    },
  });
  const decision = evaluatePolicy(policy, context);
  const failures: string[] = [];

  if (testCase.expect.action && decision.action !== testCase.expect.action) {
    failures.push(
      `expected action ${testCase.expect.action}, got ${decision.action}`,
    );
  }

  if (testCase.expect.ruleId !== undefined) {
    const actualRuleId = decision.ruleId ?? null;
    if (actualRuleId !== testCase.expect.ruleId) {
      failures.push(
        `expected rule ${testCase.expect.ruleId ?? "default"}, got ${actualRuleId ?? "default"}`,
      );
    }
  }

  if (
    testCase.expect.reasonContains &&
    !decision.reason.includes(testCase.expect.reasonContains)
  ) {
    failures.push(
      `expected reason to contain ${JSON.stringify(testCase.expect.reasonContains)}, got ${JSON.stringify(decision.reason)}`,
    );
  }

  return {
    name: testCase.name,
    ok: failures.length === 0,
    method: testCase.method,
    tool: testCase.tool,
    actual: {
      action: decision.action,
      ruleId: decision.ruleId,
      reason: decision.reason,
    },
    expected: testCase.expect,
    message: failures.join("; ") || undefined,
  };
}

function resolvePathFromBaseFile(baseFile: string, candidate: string): string {
  if (candidate.startsWith("/") || /^[A-Za-z]:[\\/]/u.test(candidate)) {
    return candidate;
  }

  return resolve(dirname(resolve(baseFile)), candidate);
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
  mcpguard policy validate [--policy mcpguard.yaml] [--json]
  mcpguard policy simulate [--policy mcpguard.yaml] --tool read_file --args '{"path":"README.md"}' [--json] [--fail-on-deny]
  mcpguard policy test [--file mcpguard.tests.yaml] [--policy mcpguard.yaml] [--json] [--fail-fast]

Examples:
  mcpguard init
  mcpguard run -- npx @modelcontextprotocol/server-filesystem .
  mcpguard logs
  mcpguard policy simulate --tool read_file --args '{"path":".env"}'
  mcpguard policy test --file examples/filesystem/mcpguard.tests.yaml
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
