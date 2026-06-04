import { describe, expect, it } from "vitest";
import { Redactor } from "../src/index.js";

describe("redactor", () => {
  it("masks common API tokens inside strings", () => {
    const redactor = new Redactor({ mask: "[MASKED]" });
    const value = redactor.redactString(
      "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
    );

    expect(value).toBe("OPENAI_API_KEY=[MASKED]");
  });

  it("redacts nested JSON values", () => {
    const redactor = new Redactor();
    const value = redactor.redactValue({
      content: "token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH123456",
      safe: "hello",
    });

    expect(value).toEqual({
      content: "token: ****",
      safe: "hello",
    });
  });
});
