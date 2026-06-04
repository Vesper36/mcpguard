import { describe, expect, it } from "vitest";
import {
  evaluatePolicy,
  parsePolicy,
  requestContextFromMessage,
} from "../src/index.js";

describe("policy engine", () => {
  it("denies secret paths before broad read rules", () => {
    const policy = parsePolicy(`version: 1
defaults:
  action: ask
rules:
  - id: block-env
    match:
      method: tools/call
      args:
        path:
          deny:
            - ".env"
            - "**/.env"
    action: deny
  - id: allow-read
    match:
      method: tools/call
      tool: read_file
      args:
        path:
          allow:
            - "**/*"
    action: allow
`);

    const context = requestContextFromMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "read_file",
        arguments: {
          path: ".env",
        },
      },
    });

    expect(evaluatePolicy(policy, context)).toMatchObject({
      action: "deny",
      ruleId: "block-env",
    });
  });

  it("allows matching non-secret read paths", () => {
    const policy = parsePolicy(`version: 1
defaults:
  action: ask
rules:
  - id: allow-src
    match:
      method: tools/call
      tool: read_file
      args:
        path:
          allow:
            - "src/**"
    action: allow
`);

    const context = requestContextFromMessage({
      jsonrpc: "2.0",
      id: "req-1",
      method: "tools/call",
      params: {
        name: "read_file",
        arguments: {
          path: "src/index.ts",
        },
      },
    });

    expect(evaluatePolicy(policy, context)).toMatchObject({
      action: "allow",
      ruleId: "allow-src",
    });
  });

  it("uses the default decision when no rule matches", () => {
    const policy = parsePolicy(`version: 1
defaults:
  action: ask
  reason: review required
rules: []
`);

    const context = requestContextFromMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "write_file",
        arguments: {
          path: "src/index.ts",
        },
      },
    });

    expect(evaluatePolicy(policy, context)).toMatchObject({
      action: "ask",
      reason: "review required",
    });
  });
});
