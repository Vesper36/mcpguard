import { mkdir, appendFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { AuditEvent, JsonValue } from "./types.js";

export interface AuditLoggerOptions {
  enabled?: boolean;
  path?: string;
  sessionId?: string;
}

export class AuditLogger {
  readonly sessionId: string;
  private readonly enabled: boolean;
  private readonly path: string;

  constructor(options: AuditLoggerOptions = {}) {
    this.enabled = options.enabled ?? true;
    this.path = resolve(options.path ?? ".mcpguard/audit.jsonl");
    this.sessionId = options.sessionId ?? createSessionId();
  }

  async write(
    event: Omit<AuditEvent, "timestamp" | "sessionId">,
  ): Promise<void> {
    if (!this.enabled) {
      return;
    }

    const fullEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      ...event,
      data: event.data === undefined ? undefined : compactJson(event.data),
    };

    await mkdir(dirname(this.path), { recursive: true });
    await appendFile(this.path, `${JSON.stringify(fullEvent)}\n`, "utf8");
  }
}

export function createSessionId(): string {
  return `mg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function compactJson(value: JsonValue): JsonValue {
  const serialized = JSON.stringify(value);
  if (serialized.length <= 20000) {
    return value;
  }

  return {
    truncated: true,
    originalBytes: Buffer.byteLength(serialized),
    preview: serialized.slice(0, 20000),
  };
}
