import type { JsonRpcId, JsonRpcMessage, JsonValue } from "./types.js";

export const MCPGUARD_DENIED_CODE = -32001;
export const MCPGUARD_INTERNAL_CODE = -32002;

export function parseJsonRpcLine(line: string): JsonRpcMessage {
  const parsed = JSON.parse(line) as unknown;
  if (!isJsonRpcMessage(parsed)) {
    throw new Error("Line is not a JSON-RPC message");
  }
  return parsed;
}

export function stringifyJsonRpc(message: JsonRpcMessage): string {
  return `${JSON.stringify(message)}\n`;
}

export function isJsonRpcMessage(value: unknown): value is JsonRpcMessage {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const object = value as Record<string, unknown>;
  return object.jsonrpc === undefined || object.jsonrpc === "2.0";
}

export function hasResponseId(
  message: JsonRpcMessage,
): message is JsonRpcMessage & { id: JsonRpcId } {
  return Object.prototype.hasOwnProperty.call(message, "id");
}

export function makeErrorResponse(
  id: JsonRpcId,
  code: number,
  message: string,
  data?: JsonValue,
): JsonRpcMessage {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      ...(data === undefined ? {} : { data }),
    },
  };
}
