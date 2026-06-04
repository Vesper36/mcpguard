import type { JsonObject } from "./types.js";

export interface RedactorOptions {
  enabled?: boolean;
  mask?: string;
  extraPatterns?: string[];
}

export class Redactor {
  private readonly enabled: boolean;
  private readonly mask: string;
  private readonly patterns: RegExp[];

  constructor(options: RedactorOptions = {}) {
    this.enabled = options.enabled ?? true;
    this.mask = options.mask ?? "****";
    this.patterns = [
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
      /\bAKIA[0-9A-Z]{16}\b/gu,
      /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/gu,
      /\bgithub_pat_[A-Za-z0-9_]{60,}\b/gu,
      /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/gu,
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu,
      /\b(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|private[_-]?key)\b\s*[:=]\s*["']?[^"',\s}]+/giu,
      ...(options.extraPatterns ?? []).map(
        (pattern) => new RegExp(pattern, "gu"),
      ),
    ];
  }

  redactString(value: string): string {
    if (!this.enabled) {
      return value;
    }

    let redacted = value;
    for (const pattern of this.patterns) {
      redacted = redacted.replace(pattern, (match) => this.maskMatch(match));
    }
    return redacted;
  }

  redactValue<T>(value: T): T {
    if (!this.enabled) {
      return value;
    }

    if (typeof value === "string") {
      return this.redactString(value) as T;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.redactValue(item)) as T;
    }

    if (value && typeof value === "object") {
      const output: JsonObject = {};
      for (const [key, entryValue] of Object.entries(value)) {
        if (entryValue === undefined) {
          continue;
        }
        output[key] = this.redactValue(entryValue);
      }
      return output as T;
    }

    return value;
  }

  private maskMatch(match: string): string {
    if (match.includes("=") || match.includes(":")) {
      return match.replace(/([:=]\s*["']?)([^"',\s}]+)/u, `$1${this.mask}`);
    }

    return this.mask;
  }
}
