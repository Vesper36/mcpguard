#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { delimiter, dirname, isAbsolute, resolve } from "node:path";
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

type PolicyPreset =
  | "default"
  | "filesystem-safe"
  | "shell-safe"
  | "github-readonly";
type SetupClient = "claude-desktop" | "cursor" | "generic";
type SetupTarget = "filesystem";

interface RunOptions {
  policyPath: string;
  auditLog?: string;
  cwd?: string;
  noRedaction: boolean;
  nonInteractive?: "deny" | "allow";
  command: string[];
}

interface InitOptions {
  path: string;
  force: boolean;
  preset: PolicyPreset;
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

interface ConfigGenerateOptions {
  client: "claude-desktop" | "cursor" | "generic";
  name: string;
  policyPath: string;
  cwd: string;
  out?: string;
  command: string[];
}

interface DoctorOptions {
  policyPath: string;
  testFile?: string;
  json: boolean;
  command: string[];
}

interface DoctorCheck {
  name: string;
  status: "pass" | "warn" | "fail";
  message: string;
}

interface SetupOptions {
  client: SetupClient;
  target: SetupTarget;
  root: string;
  name: string;
  policyPath: string;
  testsPath: string;
  configPath: string;
  force: boolean;
  command: string[];
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
      case "setup":
        return await setupCommand(rest);
      case "policy":
        return await policyCommand(rest);
      case "config":
        return await configCommand(rest);
      case "doctor":
        return await doctorCommand(rest);
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
  const options = parseInitOptions(args);

  if (existsSync(options.path) && !options.force) {
    throw new CliError(
      `${options.path} already exists. Use --force to overwrite.`,
      1,
    );
  }

  await mkdir(dirname(resolve(options.path)), { recursive: true });
  await writeFile(options.path, policyPresetText(options.preset), "utf8");
  console.log(`Created ${options.path}`);
  return 0;
}

async function setupCommand(args: string[]): Promise<number> {
  const options = parseSetupOptions(args);
  const policyText = policyPresetText("filesystem-safe");
  const testText = filesystemPolicyTestsText(options.policyPath);
  const config = buildMcpClientConfig({
    client: options.client,
    name: options.name,
    policyPath: options.policyPath,
    cwd: options.root,
    command: options.command,
  });
  const configText = `${JSON.stringify(config, null, 2)}\n`;

  await writeSetupFile(options.policyPath, policyText, options.force);
  await writeSetupFile(options.testsPath, testText, options.force);
  await writeSetupFile(options.configPath, configText, options.force);

  console.log(`Created ${options.policyPath}`);
  console.log(`Created ${options.testsPath}`);
  console.log(`Created ${options.configPath}`);
  console.log("");
  console.log("Paste this mcpServers block into your MCP client:");
  console.log(configText.trimEnd());
  console.log("");

  const checks = await runDoctorChecks({
    policyPath: options.policyPath,
    testFile: options.testsPath,
    json: false,
    command: options.command,
  });

  for (const check of checks) {
    console.log(
      `${check.status.toUpperCase()} ${check.name}: ${check.message}`,
    );
  }

  return checks.some((check) => check.status === "fail") ? 1 : 0;
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
    cwd: options.cwd,
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
  const results = runPolicyTestSuite(policy, testFile.cases, options.failFast);

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

async function configCommand(args: string[]): Promise<number> {
  const [subcommand, ...rest] = args;
  if (subcommand !== "generate") {
    throw new CliError(
      "Use: mcpguard config generate [options] -- <server command>",
      1,
    );
  }

  const options = parseConfigGenerateOptions(rest);
  const config = buildMcpClientConfig(options);
  const json = `${JSON.stringify(config, null, 2)}\n`;

  if (options.out) {
    await mkdir(dirname(resolve(options.out)), { recursive: true });
    await writeFile(options.out, json, "utf8");
    console.log(`Created ${options.out}`);
  } else {
    console.log(json.trimEnd());
  }

  return 0;
}

async function doctorCommand(args: string[]): Promise<number> {
  const options = parseDoctorOptions(args);
  const checks = await runDoctorChecks(options);
  const failed = checks.filter((check) => check.status === "fail").length;

  if (options.json) {
    console.log(
      JSON.stringify({
        ok: failed === 0,
        checks,
      }),
    );
    return failed === 0 ? 0 : 1;
  }

  for (const check of checks) {
    console.log(
      `${check.status.toUpperCase()} ${check.name}: ${check.message}`,
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

export function parseConfigGenerateOptions(
  args: string[],
): ConfigGenerateOptions {
  const splitIndex = args.indexOf("--");
  if (splitIndex === -1) {
    throw new CliError(
      "Missing -- separator. Use: mcpguard config generate [options] -- <server command>",
      1,
    );
  }

  const optionArgs = args.slice(0, splitIndex);
  const command = args.slice(splitIndex + 1);
  const client = readStringOption(optionArgs, ["--client"], "generic");

  if (
    client !== "claude-desktop" &&
    client !== "cursor" &&
    client !== "generic"
  ) {
    throw new CliError(
      "--client must be claude-desktop, cursor, or generic",
      1,
    );
  }

  if (command.length === 0) {
    throw new CliError("Missing MCP server command after --", 1);
  }

  return {
    client,
    name: readStringOption(optionArgs, ["--name"], "default"),
    policyPath: readStringOption(
      optionArgs,
      ["--policy", "-p"],
      DEFAULT_POLICY_PATH,
    ),
    cwd: readStringOption(optionArgs, ["--cwd"], process.cwd()),
    out: readOptionalStringOption(optionArgs, ["--out", "-o"]),
    command,
  };
}

export function parseDoctorOptions(args: string[]): DoctorOptions {
  const splitIndex = args.indexOf("--");
  const optionArgs = splitIndex === -1 ? args : args.slice(0, splitIndex);
  const command = splitIndex === -1 ? [] : args.slice(splitIndex + 1);

  return {
    policyPath: readStringOption(
      optionArgs,
      ["--policy", "-p"],
      DEFAULT_POLICY_PATH,
    ),
    testFile: readOptionalStringOption(optionArgs, ["--test"]),
    json: optionArgs.includes("--json"),
    command,
  };
}

export function parseInitOptions(args: string[]): InitOptions {
  const preset = readStringOption(args, ["--preset"], "default");

  if (!isPolicyPreset(preset)) {
    throw new CliError(
      "--preset must be default, filesystem-safe, shell-safe, or github-readonly",
      1,
    );
  }

  return {
    path: readStringOption(args, ["--out", "-o"], DEFAULT_POLICY_PATH),
    force: args.includes("--force") || args.includes("-f"),
    preset,
  };
}

export function parseSetupOptions(args: string[]): SetupOptions {
  const [clientInput, targetInput, ...rest] = args;
  const client = normalizeSetupClient(clientInput);

  if (!client) {
    throw new CliError(
      "Use: mcpguard setup <cursor|claude|generic> filesystem [--root .]",
      1,
    );
  }

  if (targetInput !== "filesystem") {
    throw new CliError(
      "Only the filesystem setup target is currently supported",
      1,
    );
  }

  const splitIndex = rest.indexOf("--");
  const optionArgs = splitIndex === -1 ? rest : rest.slice(0, splitIndex);
  const commandOverride = splitIndex === -1 ? [] : rest.slice(splitIndex + 1);
  const root = resolve(readStringOption(optionArgs, ["--root"], "."));
  const name = readStringOption(optionArgs, ["--name"], "filesystem");
  const policyPath = resolvePathFromBaseFile(
    `${root}/setup`,
    readStringOption(optionArgs, ["--policy", "-p"], DEFAULT_POLICY_PATH),
  );
  const testsPath = resolvePathFromBaseFile(
    `${root}/setup`,
    readStringOption(optionArgs, ["--tests"], DEFAULT_POLICY_TEST_PATH),
  );
  const configPath = resolvePathFromBaseFile(
    `${root}/setup`,
    readStringOption(
      optionArgs,
      ["--config-out"],
      `.mcpguard/${client}-filesystem.mcp.json`,
    ),
  );

  return {
    client,
    target: "filesystem",
    root,
    name,
    policyPath,
    testsPath,
    configPath,
    force: optionArgs.includes("--force") || optionArgs.includes("-f"),
    command:
      commandOverride.length > 0
        ? commandOverride
        : ["npx", "@modelcontextprotocol/server-filesystem", "."],
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
    cwd: readOptionalStringOption(optionArgs, ["--cwd"]),
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

function buildMcpClientConfig(options: ConfigGenerateOptions): JsonObject {
  return {
    mcpServers: {
      [options.name]: {
        command: "mcpguard",
        args: [
          "run",
          "--policy",
          resolve(options.policyPath),
          "--cwd",
          resolve(options.cwd),
          "--",
          ...options.command,
        ],
      },
    },
  };
}

async function writeSetupFile(
  path: string,
  content: string,
  force: boolean,
): Promise<void> {
  if (existsSync(path) && !force) {
    throw new CliError(`${path} already exists. Use --force to overwrite.`, 1);
  }

  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, content, "utf8");
}

function policyPresetText(preset: PolicyPreset): string {
  switch (preset) {
    case "default":
      return DEFAULT_POLICY_TEXT;
    case "filesystem-safe":
      return `version: 1

defaults:
  action: ask
  reason: Review filesystem access before allowing it.

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
            - "**/*.p12"
            - "**/*.pfx"
            - "**/id_rsa"
            - "**/id_ed25519"
            - "**/credentials"
            - "**/secrets.*"
    action: deny
    reason: Secret-bearing files are blocked by default.

  - id: block-heavy-and-generated-folders
    description: Block large or generated folders that are rarely useful for agent context.
    match:
      method: tools/call
      args:
        path:
          deny:
            - "node_modules/**"
            - ".git/**"
            - "dist/**"
            - "build/**"
            - "coverage/**"
            - ".next/**"
            - ".turbo/**"
    action: deny
    reason: Generated and dependency folders are blocked by default.

  - id: allow-project-context
    description: Allow normal source, docs, and project metadata reads.
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
            - "app/**"
            - "components/**"
            - "packages/**"
            - "docs/**"
            - "examples/**"
            - "README.md"
            - "CONTRIBUTING.md"
            - "SECURITY.md"
            - "LICENSE"
            - "package.json"
            - "pnpm-workspace.yaml"
            - "tsconfig*.json"
            - "vite.config.*"
            - "next.config.*"
    action: allow
    reason: Read-only project context is allowed for non-secret paths.
`;
    case "shell-safe":
      return `version: 1

defaults:
  action: ask
  reason: Review shell commands before allowing them.

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
  - id: block-destructive-shell
    match:
      method: tools/call
      args:
        command:
          denyRegex:
            - "(^|\\\\s)rm\\\\s+-rf(\\\\s|$)"
            - "git\\\\s+reset\\\\s+--hard"
            - "git\\\\s+clean\\\\s+-fd"
            - "DROP\\\\s+DATABASE"
            - "truncate\\\\s+table"
            - "curl\\\\s+[^|]+\\\\|\\\\s*(sh|bash)"
    action: deny
    reason: Destructive shell commands are blocked by default.
`;
    case "github-readonly":
      return `version: 1

defaults:
  action: ask
  reason: Review GitHub MCP operations before allowing them.

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
  - id: block-github-mutating-tools
    match:
      method: tools/call
      toolRegex: "(create|update|delete|merge|close|reopen|comment|review|approve|request|invite|add|remove)"
    action: deny
    reason: Mutating GitHub tools are blocked by the readonly preset.

  - id: allow-github-read-tools
    match:
      method: tools/call
      toolRegex: "(get|list|search|read|fetch)"
    action: allow
    reason: Read-only GitHub tools are allowed.
`;
  }
}

function filesystemPolicyTestsText(policyPath: string): string {
  return `version: 1
policy: ${JSON.stringify(policyPath)}

cases:
  - name: allow source read
    tool: read_file
    args:
      path: src/index.ts
    expect:
      action: allow
      ruleId: allow-project-context

  - name: block dotenv read
    tool: read_file
    args:
      path: .env
    expect:
      action: deny
      ruleId: block-secret-files

  - name: block private key read
    tool: read_file
    args:
      path: id_ed25519
    expect:
      action: deny
      ruleId: block-secret-files

  - name: ask before unknown write
    tool: write_file
    args:
      path: src/index.ts
      content: hello
    expect:
      action: ask
      ruleId: null
`;
}

function isPolicyPreset(value: string): value is PolicyPreset {
  return (
    value === "default" ||
    value === "filesystem-safe" ||
    value === "shell-safe" ||
    value === "github-readonly"
  );
}

function normalizeSetupClient(
  value: string | undefined,
): SetupClient | undefined {
  if (value === "claude") {
    return "claude-desktop";
  }

  if (value === "claude-desktop" || value === "cursor" || value === "generic") {
    return value;
  }

  return undefined;
}

async function runDoctorChecks(options: DoctorOptions): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  const nodeMajor = Number(process.versions.node.split(".")[0]);

  checks.push({
    name: "node",
    status: nodeMajor >= 20 ? "pass" : "fail",
    message: `Node.js ${process.versions.node}${nodeMajor >= 20 ? "" : " is below the required 20.x"}`,
  });

  let policy: McpGuardPolicy | undefined;
  try {
    policy = await loadPolicy(options.policyPath);
    checks.push({
      name: "policy",
      status: "pass",
      message: `${options.policyPath} is valid with ${policy.rules.length} rule${policy.rules.length === 1 ? "" : "s"}`,
    });
  } catch (error) {
    checks.push({
      name: "policy",
      status: "fail",
      message: error instanceof Error ? error.message : String(error),
    });
  }

  if (policy) {
    checks.push({
      name: "redaction",
      status: policy.redaction.enabled ? "pass" : "warn",
      message: policy.redaction.enabled
        ? "response redaction is enabled"
        : "response redaction is disabled",
    });
    checks.push({
      name: "audit",
      status: policy.audit.enabled ? "pass" : "warn",
      message: policy.audit.enabled
        ? `audit log enabled at ${policy.audit.path}`
        : "audit logging is disabled",
    });
    checks.push({
      name: "approval",
      status: policy.approval.nonInteractive === "allow" ? "warn" : "pass",
      message:
        policy.approval.nonInteractive === "allow"
          ? "non-interactive ask fallback allows calls"
          : "non-interactive ask fallback denies calls",
    });
  }

  if (options.testFile && policy) {
    try {
      const source = await readFile(options.testFile, "utf8");
      const testFile = parsePolicyTestFile(source, options.testFile);
      const results = runPolicyTestSuite(policy, testFile.cases, false);
      const failed = results.filter((result) => !result.ok);
      checks.push({
        name: "policy-tests",
        status: failed.length === 0 ? "pass" : "fail",
        message:
          failed.length === 0
            ? `${results.length} policy test${results.length === 1 ? "" : "s"} passed`
            : `${failed.length} of ${results.length} policy tests failed`,
      });
    } catch (error) {
      checks.push({
        name: "policy-tests",
        status: "fail",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (options.command.length > 0) {
    const executable = options.command[0];
    checks.push({
      name: "server-command",
      status: executable && commandExists(executable) ? "pass" : "fail",
      message: executable
        ? commandExists(executable)
          ? `${executable} was found`
          : `${executable} was not found on PATH`
        : "no server command provided",
    });
  }

  return checks;
}

function commandExists(command: string): boolean {
  if (command.includes("/") || command.includes("\\")) {
    return existsSync(isAbsolute(command) ? command : resolve(command));
  }

  for (const directory of (process.env.PATH ?? "").split(delimiter)) {
    if (!directory) {
      continue;
    }

    if (existsSync(resolve(directory, command))) {
      return true;
    }

    if (
      process.platform === "win32" &&
      existsSync(resolve(directory, `${command}.cmd`))
    ) {
      return true;
    }
  }

  return false;
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

function runPolicyTestSuite(
  policy: McpGuardPolicy,
  cases: PolicyTestCase[],
  failFast: boolean,
): PolicyTestResult[] {
  const results: PolicyTestResult[] = [];

  for (const testCase of cases) {
    const result = evaluatePolicyTestCase(policy, testCase);
    results.push(result);

    if (failFast && !result.ok) {
      break;
    }
  }

  return results;
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
  mcpguard setup <cursor|claude|generic> filesystem [--root .] [--force]
  mcpguard run [--policy mcpguard.yaml] [--cwd .] [--audit-log .mcpguard/audit.jsonl] [--non-interactive deny|allow] -- <server command>
  mcpguard logs [--audit-log .mcpguard/audit.jsonl] [--limit 20] [--json]
  mcpguard config generate --client cursor --name filesystem --policy mcpguard.yaml -- npx @modelcontextprotocol/server-filesystem .
  mcpguard doctor [--policy mcpguard.yaml] [--test mcpguard.tests.yaml] [--json] [-- <server command>]
  mcpguard policy generate [--audit-log .mcpguard/audit.jsonl] [--out mcpguard.generated.yaml]
  mcpguard policy validate [--policy mcpguard.yaml] [--json]
  mcpguard policy simulate [--policy mcpguard.yaml] --tool read_file --args '{"path":"README.md"}' [--json] [--fail-on-deny]
  mcpguard policy test [--file mcpguard.tests.yaml] [--policy mcpguard.yaml] [--json] [--fail-fast]

Examples:
  mcpguard init --preset filesystem-safe
  mcpguard setup cursor filesystem --root .
  mcpguard config generate --client cursor --name filesystem -- npx @modelcontextprotocol/server-filesystem .
  mcpguard doctor --policy examples/filesystem/mcpguard.yaml --test examples/filesystem/mcpguard.tests.yaml -- node examples/demo-server.mjs
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
