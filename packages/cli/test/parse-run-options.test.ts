import { describe, expect, it } from "vitest";
import { parseRunOptions } from "../src/index.js";

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
