export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue | undefined };

export type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc?: "2.0";
  id?: JsonRpcId;
  method?: string;
  params?: JsonValue;
  result?: JsonValue;
  error?: {
    code: number;
    message: string;
    data?: JsonValue;
  };
}

export type PolicyAction = "allow" | "deny" | "ask";

export interface PolicyDecision {
  action: PolicyAction;
  ruleId?: string;
  reason: string;
}

export interface ProxyRequestContext {
  id?: JsonRpcId;
  method?: string;
  toolName?: string;
  args?: JsonObject;
  raw: JsonRpcMessage;
}

export interface ApprovalResult {
  allowed: boolean;
  remember?: boolean;
  reason: string;
}

export interface Approver {
  approve(
    context: ProxyRequestContext,
    decision: PolicyDecision,
  ): Promise<ApprovalResult>;
}

export interface AuditEvent {
  timestamp: string;
  sessionId: string;
  type: "lifecycle" | "decision" | "response" | "error";
  requestId?: JsonRpcId;
  method?: string;
  toolName?: string;
  action?: PolicyAction;
  allowed?: boolean;
  ruleId?: string;
  reason?: string;
  data?: JsonValue;
}
