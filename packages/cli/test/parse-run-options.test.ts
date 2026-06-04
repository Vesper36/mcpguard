import { describe, expect, it } from "vitest";
import { parseRunOptions, parseSimulateOptions } from "../src/index.js";

describe("parseRunOptions", () => {
  it("parses policy and command after separator", () => {
    expect(
      parseRunOptions(["--policy", "custom.yaml", "--", "npx", "server", "."]),
    ).toEqual({
      policyPath: "custom.yaml",
      auditLog: undefined,
      noRedaction: false,
      nonInteractive: undefined,
      command: ["npx", "server", "."],
    });
  });

  it("requires the command separator", () => {
    expect(() => parseRunOptions(["npx", "server"])).toThrow(
      "Missing -- separator",
    );
  });
});

describe("parseSimulateOptions", () => {
  it("parses a simulated tool call", () => {
    expect(
      parseSimulateOptions([
        "--policy",
        "custom.yaml",
        "--tool",
        "read_file",
        "--args",
        '{"path":"README.md"}',
        "--json",
      ]),
    ).toEqual({
      policyPath: "custom.yaml",
      method: "tools/call",
      tool: "read_file",
      args: { path: "README.md" },
      json: true,
      failOnDeny: false,
    });
  });

  it("requires JSON object arguments", () => {
    expect(() =>
      parseSimulateOptions(["--tool", "read_file", "--args", '"README.md"']),
    ).toThrow("--args must be a JSON object");
  });
});
