#!/usr/bin/env node
import readline from "node:readline";

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

for await (const line of rl) {
  if (!line.trim()) {
    continue;
  }

  const message = JSON.parse(line);

  if (message.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: "mcpguard-demo-server",
          version: "0.1.0",
        },
      },
    });
    continue;
  }

  if (message.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        tools: [
          {
            name: "read_file",
            description: "Demo read tool.",
            inputSchema: {
              type: "object",
              properties: {
                path: {
                  type: "string",
                },
              },
              required: ["path"],
            },
          },
        ],
      },
    });
    continue;
  }

  if (message.method === "tools/call") {
    send({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        content: [
          {
            type: "text",
            text: `read ${message.params?.arguments?.path ?? "(unknown)"} with token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH123456`,
          },
        ],
      },
    });
    continue;
  }

  send({
    jsonrpc: "2.0",
    id: message.id,
    error: {
      code: -32601,
      message: `Unknown method: ${message.method}`,
    },
  });
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
