import { describe, expect, it } from "vitest";
import {
  parseConfigGenerateOptions,
  parseDoctorOptions,
  parseInitOptions,
  parsePolicyTestOptions,
  parseRunOptions,
  parseSetupOptions,
  parseSimulateOptions,
} from "../src/index.js";

describe("parseRunOptions", () => {
  it("parses policy and command after separator", () => {
    expect(
      parseRunOptions(["--policy", "custom.yaml", "--", "npx", "server", "."]),
    ).toEqual({
      policyPath: "custom.yaml",
      auditLog: undefined,
      cwd: undefined,
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

describe("parseInitOptions", () => {
  it("parses preset init options", () => {
    expect(
      parseInitOptions([
        "--preset",
        "filesystem-safe",
        "--out",
        "safe.yaml",
        "--force",
      ]),
    ).toEqual({
      path: "safe.yaml",
      force: true,
      preset: "filesystem-safe",
    });
  });
});

describe("parseSetupOptions", () => {
  it("parses cursor filesystem setup with defaults", () => {
    const options = parseSetupOptions([
      "cursor",
      "filesystem",
      "--root",
      ".",
      "--name",
      "repo",
    ]);

    expect(options).toMatchObject({
      client: "cursor",
      target: "filesystem",
      name: "repo",
      force: false,
      command: ["npx", "@modelcontextprotocol/server-filesystem", "."],
    });
    expect(options.policyPath.endsWith("/mcpguard.yaml")).toBe(true);
    expect(options.testsPath.endsWith("/mcpguard.tests.yaml")).toBe(true);
    expect(
      options.configPath.endsWith("/.mcpguard/cursor-filesystem.mcp.json"),
    ).toBe(true);
  });

  it("accepts claude as an alias for claude-desktop", () => {
    expect(parseSetupOptions(["claude", "filesystem"]).client).toBe(
      "claude-desktop",
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

describe("parsePolicyTestOptions", () => {
  it("parses policy test options", () => {
    expect(
      parsePolicyTestOptions([
        "--file",
        "examples/filesystem/mcpguard.tests.yaml",
        "--policy",
        "examples/filesystem/mcpguard.yaml",
        "--json",
        "--fail-fast",
      ]),
    ).toEqual({
      file: "examples/filesystem/mcpguard.tests.yaml",
      policyPath: "examples/filesystem/mcpguard.yaml",
      json: true,
      failFast: true,
    });
  });
});

describe("parseConfigGenerateOptions", () => {
  it("parses config generation options and wrapped command", () => {
    expect(
      parseConfigGenerateOptions([
        "--client",
        "cursor",
        "--name",
        "filesystem",
        "--policy",
        "mcpguard.yaml",
        "--cwd",
        ".",
        "--",
        "npx",
        "@modelcontextprotocol/server-filesystem",
        ".",
      ]),
    ).toEqual({
      client: "cursor",
      name: "filesystem",
      policyPath: "mcpguard.yaml",
      cwd: ".",
      out: undefined,
      command: ["npx", "@modelcontextprotocol/server-filesystem", "."],
    });
  });
});

describe("parseDoctorOptions", () => {
  it("parses doctor checks with optional server command", () => {
    expect(
      parseDoctorOptions([
        "--policy",
        "examples/filesystem/mcpguard.yaml",
        "--test",
        "examples/filesystem/mcpguard.tests.yaml",
        "--json",
        "--",
        "node",
        "examples/demo-server.mjs",
      ]),
    ).toEqual({
      policyPath: "examples/filesystem/mcpguard.yaml",
      testFile: "examples/filesystem/mcpguard.tests.yaml",
      json: true,
      command: ["node", "examples/demo-server.mjs"],
    });
  });
});
