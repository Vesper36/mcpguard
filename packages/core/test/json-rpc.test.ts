import { describe, expect, it } from "vitest";
import {
  makeErrorResponse,
  MCPGUARD_DENIED_CODE,
  parseJsonRpcLine,
  stringifyJsonRpc,
} from "../src/index.js";

describe("json-rpc helpers", () => {
  it("parses and stringifies newline-delimited messages", () => {
    const parsed = parseJsonRpcLine(
      '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    );
    expect(parsed).toMatchObject({ id: 1, method: "tools/list" });
    expect(stringifyJsonRpc(parsed)).toBe(
      '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
    );
  });

  it("creates MCPGuard denial responses", () => {
    expect(makeErrorResponse("abc", MCPGUARD_DENIED_CODE, "Denied")).toEqual({
      jsonrpc: "2.0",
      id: "abc",
      error: {
        code: MCPGUARD_DENIED_CODE,
        message: "Denied",
      },
    });
  });
});
