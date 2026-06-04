import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import {
  hasResponseId,
  makeErrorResponse,
  MCPGUARD_DENIED_CODE,
  MCPGUARD_INTERNAL_CODE,
  parseJsonRpcLine,
  stringifyJsonRpc,
} from "./json-rpc.js";
import { AuditLogger } from "./audit.js";
import { TerminalApprover } from "./approval.js";
import { evaluatePolicy, requestContextFromMessage } from "./policy.js";
import { Redactor } from "./redactor.js";
import type { Approver, JsonRpcMessage, JsonValue } from "./types.js";
import type { McpGuardPolicy } from "./policy-schema.js";

export interface StdioProxyOptions {
  command: string;
  args: string[];
  policy: McpGuardPolicy;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  auditLogger?: AuditLogger;
  redactor?: Redactor;
  approver?: Approver;
}

export async function runStdioProxy(
  options: StdioProxyOptions,
): Promise<number> {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const redactor =
    options.redactor ??
    new Redactor({
      enabled: options.policy.redaction.enabled,
      mask: options.policy.redaction.mask,
      extraPatterns: options.policy.redaction.extraPatterns,
    });
  const auditLogger =
    options.auditLogger ??
    new AuditLogger({
      enabled: options.policy.audit.enabled,
      path: options.policy.audit.path,
    });
  const approver =
    options.approver ??
    new TerminalApprover({
      nonInteractive: options.policy.approval.nonInteractive,
      rememberByDefault: options.policy.approval.rememberByDefault,
      redactor,
    });

  const child = spawn(options.command, options.args, {
    cwd: options.cwd ?? process.cwd(),
    env: options.env ?? process.env,
    stdio: ["pipe", "pipe", "pipe"],
  });

  await auditLogger.write({
    type: "lifecycle",
    data: {
      event: "proxy_started",
      command: [options.command, ...options.args].join(" "),
    },
  });

  child.on("error", async (error) => {
    stderr.write(`[mcpguard] failed to start server: ${error.message}\n`);
    await auditLogger.write({
      type: "error",
      reason: error.message,
      data: { event: "spawn_error" },
    });
  });

  child.stderr?.on("data", (chunk: Buffer) => {
    stderr.write(chunk);
  });

  const clientLines = createInterface({ input: stdin, crlfDelay: Infinity });
  const serverLines = createInterface({
    input: child.stdout,
    crlfDelay: Infinity,
  });

  const clientPump = (async (): Promise<void> => {
    for await (const line of clientLines) {
      await handleClientLine(
        line,
        child.stdin,
        stdout,
        stderr,
        options.policy,
        auditLogger,
        redactor,
        approver,
      );
    }

    child.stdin?.end();
  })();

  const serverPump = (async (): Promise<void> => {
    for await (const line of serverLines) {
      await handleServerLine(line, stdout, stderr, auditLogger, redactor);
    }
  })();

  const [exitCode] = (await once(child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  clientLines.close();
  serverLines.close();
  await Promise.allSettled([clientPump, serverPump]);

  const code = exitCode ?? 1;
  await auditLogger.write({
    type: "lifecycle",
    data: {
      event: "proxy_stopped",
      exitCode: code,
    },
  });

  return code;
}

async function handleClientLine(
  line: string,
  childStdin: NodeJS.WritableStream | null,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
  policy: McpGuardPolicy,
  auditLogger: AuditLogger,
  redactor: Redactor,
  approver: Approver,
): Promise<void> {
  if (!line.trim()) {
    return;
  }

  let message: JsonRpcMessage;
  try {
    message = parseJsonRpcLine(line);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    stdout.write(
      stringifyJsonRpc(
        makeErrorResponse(
          null,
          MCPGUARD_INTERNAL_CODE,
          "MCPGuard could not parse client JSON-RPC.",
          { reason },
        ),
      ),
    );
    await auditLogger.write({
      type: "error",
      reason,
      data: { direction: "client_to_server" },
    });
    return;
  }

  if (message.method !== "tools/call") {
    await writeToChild(childStdin, line);
    return;
  }

  const context = requestContextFromMessage(message);
  const decision = evaluatePolicy(policy, context);
  let allowed = decision.action === "allow";
  let reason = decision.reason;

  if (decision.action === "ask") {
    const approval = await approver.approve(context, decision);
    allowed = approval.allowed;
    reason = approval.reason;
  }

  await auditLogger.write({
    type: "decision",
    requestId: context.id,
    method: context.method,
    toolName: context.toolName,
    action: decision.action,
    allowed,
    ruleId: decision.ruleId,
    reason,
    data: redactor.redactValue(context.args ?? {}),
  });

  if (allowed) {
    await writeToChild(childStdin, line);
    return;
  }

  stderr.write(
    `[mcpguard] denied ${context.toolName ?? "tools/call"}: ${reason}\n`,
  );

  if (hasResponseId(message)) {
    stdout.write(
      stringifyJsonRpc(
        makeErrorResponse(
          message.id,
          MCPGUARD_DENIED_CODE,
          "MCPGuard denied this tool call.",
          {
            ruleId: decision.ruleId ?? null,
            reason,
          },
        ),
      ),
    );
  }
}

async function handleServerLine(
  line: string,
  stdout: NodeJS.WritableStream,
  stderr: NodeJS.WritableStream,
  auditLogger: AuditLogger,
  redactor: Redactor,
): Promise<void> {
  if (!line.trim()) {
    return;
  }

  let message: JsonRpcMessage;
  try {
    message = parseJsonRpcLine(line);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    stderr.write(`[mcpguard] blocked non-MCP stdout from server: ${reason}\n`);
    await auditLogger.write({
      type: "error",
      reason,
      data: { direction: "server_to_client" },
    });
    return;
  }

  const redacted = redactor.redactValue(message);
  stdout.write(stringifyJsonRpc(redacted));

  if (hasResponseId(redacted)) {
    await auditLogger.write({
      type: "response",
      requestId: redacted.id,
      data: redacted as unknown as JsonValue,
    });
  }
}

async function writeToChild(
  childStdin: NodeJS.WritableStream | null,
  line: string,
): Promise<void> {
  const streamState = childStdin as
    | (NodeJS.WritableStream & { destroyed?: boolean })
    | null;
  if (!streamState || streamState.destroyed) {
    return;
  }

  if (!streamState.write(`${line}\n`)) {
    await once(streamState, "drain");
  }
}
