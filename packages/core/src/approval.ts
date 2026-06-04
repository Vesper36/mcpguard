import { createReadStream, createWriteStream } from "node:fs";
import { createInterface } from "node:readline/promises";
import type {
  ApprovalResult,
  Approver,
  PolicyDecision,
  ProxyRequestContext,
} from "./types.js";
import { Redactor } from "./redactor.js";

export interface TerminalApproverOptions {
  nonInteractive?: "deny" | "allow";
  rememberByDefault?: boolean;
  redactor?: Redactor;
}

export class TerminalApprover implements Approver {
  private readonly nonInteractive: "deny" | "allow";
  private readonly rememberByDefault: boolean;
  private readonly redactor: Redactor;
  private readonly remembered = new Map<string, ApprovalResult>();

  constructor(options: TerminalApproverOptions = {}) {
    this.nonInteractive = options.nonInteractive ?? "deny";
    this.rememberByDefault = options.rememberByDefault ?? false;
    this.redactor = options.redactor ?? new Redactor();
  }

  async approve(
    context: ProxyRequestContext,
    decision: PolicyDecision,
  ): Promise<ApprovalResult> {
    const key = this.rememberKey(context, decision);
    const remembered = this.remembered.get(key);
    if (remembered) {
      return remembered;
    }

    const interactive = await this.askTerminal(context, decision);
    if (interactive.remember) {
      this.remembered.set(key, interactive);
    }
    return interactive;
  }

  private async askTerminal(
    context: ProxyRequestContext,
    decision: PolicyDecision,
  ): Promise<ApprovalResult> {
    try {
      const input = createReadStream("/dev/tty", { encoding: "utf8" });
      const output = createWriteStream("/dev/tty");
      const rl = createInterface({ input, output });
      const args = this.redactor.redactValue(context.args ?? {});

      output.write("\nMCPGuard approval required\n");
      output.write(`tool: ${context.toolName ?? "(unknown)"}\n`);
      output.write(`rule: ${decision.ruleId ?? "(default)"}\n`);
      output.write(`reason: ${decision.reason}\n`);
      output.write(`arguments: ${JSON.stringify(args, null, 2)}\n`);

      const suffix = this.rememberByDefault ? " [Y/n/a/d] " : " [y/N/a/d] ";
      const answer = (
        await rl.question(
          `Allow this call? yes, no, allow-session, deny-session${suffix}`,
        )
      )
        .trim()
        .toLowerCase();
      rl.close();

      if (answer === "a" || answer === "allow-session") {
        return {
          allowed: true,
          remember: true,
          reason: "Approved for this session.",
        };
      }

      if (answer === "d" || answer === "deny-session") {
        return {
          allowed: false,
          remember: true,
          reason: "Denied for this session.",
        };
      }

      if (
        answer === "y" ||
        answer === "yes" ||
        (this.rememberByDefault && answer === "")
      ) {
        return { allowed: true, remember: false, reason: "Approved once." };
      }

      return { allowed: false, remember: false, reason: "Denied by operator." };
    } catch {
      const allowed = this.nonInteractive === "allow";
      return {
        allowed,
        remember: false,
        reason: allowed
          ? "Allowed by non-interactive fallback."
          : "Denied by non-interactive fallback.",
      };
    }
  }

  private rememberKey(
    context: ProxyRequestContext,
    decision: PolicyDecision,
  ): string {
    return JSON.stringify({
      ruleId: decision.ruleId,
      method: context.method,
      toolName: context.toolName,
      args: context.args,
    });
  }
}
