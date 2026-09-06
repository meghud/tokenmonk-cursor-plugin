"use strict";

// src/config-mcp.ts
var import_node_fs2 = require("node:fs");
var import_node_path3 = require("node:path");

// src/lib/config.ts
var import_node_os = require("node:os");
var import_node_path = require("node:path");
function configFilePath() {
  return process.env.TOKENMONK_CONFIG_FILE ?? (0, import_node_path.join)((0, import_node_os.homedir)(), ".tokenmonk", "cursor.config.json");
}

// src/lib/hook-log.ts
var import_node_fs = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path2 = require("node:path");
var MAX_BYTES = 256 * 1024;
function logPath() {
  return process.env.TOKENMONK_HOOK_LOG ?? (0, import_node_path2.join)((0, import_node_os2.homedir)(), ".tokenmonk-hooks.log");
}
function logHook(hook, event) {
  try {
    const path = logPath();
    try {
      if ((0, import_node_fs.statSync)(path).size > MAX_BYTES) (0, import_node_fs.renameSync)(path, `${path}.1`);
    } catch {
    }
    (0, import_node_fs.appendFileSync)(path, JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), hook, ...event }) + "\n");
  } catch {
  }
}

// src/config-mcp.ts
function persistConfig() {
  const endpoint = process.env.CAPTURE_ENDPOINT;
  const token = process.env.CAPTURE_TOKEN;
  if (!endpoint || !token) return { wrote: false, hasToken: Boolean(token) };
  const path = configFilePath();
  (0, import_node_fs2.mkdirSync)((0, import_node_path3.dirname)(path), { recursive: true });
  (0, import_node_fs2.writeFileSync)(
    path,
    JSON.stringify(
      { endpoint, orgToken: token, redactMode: process.env.REDACT_MODE === "content" ? "content" : "default", writtenAt: (/* @__PURE__ */ new Date()).toISOString() },
      null,
      2
    ) + "\n",
    { mode: 384 }
  );
  return { wrote: true, hasToken: true };
}
try {
  const result = persistConfig();
  logHook("config-mcp", { event: "start", ...result });
} catch (err) {
  logHook("config-mcp", { event: "error", message: err instanceof Error ? err.message : String(err) });
}
var send = (msg) => {
  process.stdout.write(JSON.stringify(msg) + "\n");
};
var buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.id === void 0) continue;
    if (msg.method === "initialize") {
      send({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "tokenmonk-config", version: "0.1.0" }
        }
      });
    } else if (msg.method === "tools/list") {
      send({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } });
    } else {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
    }
  }
});
process.stdin.on("end", () => process.exit(0));
