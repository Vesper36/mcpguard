import { z } from "zod";

const actionSchema = z.enum(["allow", "deny", "ask"]);

const scalarMatcherSchema = z
  .object({
    equals: z.union([z.string(), z.number(), z.boolean()]).optional(),
    contains: z.string().optional(),
    regex: z.string().optional(),
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
    allowRegex: z.array(z.string()).optional(),
    denyRegex: z.array(z.string()).optional(),
  })
  .strict();

const ruleSchema = z
  .object({
    id: z.string().min(1),
    description: z.string().optional(),
    match: z
      .object({
        method: z.union([z.string(), z.array(z.string())]).optional(),
        tool: z.union([z.string(), z.array(z.string())]).optional(),
        toolRegex: z.string().optional(),
        args: z.record(z.string(), scalarMatcherSchema).optional(),
        rawJsonContains: z.string().optional(),
        rawJsonRegex: z.string().optional(),
      })
      .strict(),
    action: actionSchema,
    reason: z.string().optional(),
  })
  .strict();

export const policySchema = z
  .object({
    version: z.literal(1),
    defaults: z
      .object({
        action: actionSchema.default("ask"),
        reason: z.string().optional(),
      })
      .strict()
      .default({ action: "ask" }),
    redaction: z
      .object({
        enabled: z.boolean().default(true),
        mask: z.string().min(1).default("****"),
        extraPatterns: z.array(z.string()).default([]),
      })
      .strict()
      .default({ enabled: true, mask: "****", extraPatterns: [] }),
    audit: z
      .object({
        enabled: z.boolean().default(true),
        path: z.string().min(1).default(".mcpguard/audit.jsonl"),
      })
      .strict()
      .default({ enabled: true, path: ".mcpguard/audit.jsonl" }),
    approval: z
      .object({
        nonInteractive: z.enum(["deny", "allow"]).default("deny"),
        rememberByDefault: z.boolean().default(false),
      })
      .strict()
      .default({ nonInteractive: "deny", rememberByDefault: false }),
    rules: z.array(ruleSchema).default([]),
  })
  .strict();

export type McpGuardPolicy = z.infer<typeof policySchema>;
export type McpGuardRule = McpGuardPolicy["rules"][number];
export type ScalarMatcher = z.infer<typeof scalarMatcherSchema>;
