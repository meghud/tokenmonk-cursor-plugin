"use strict";

// src/flush-spool.ts
var import_node_os2 = require("node:os");
var import_node_path4 = require("node:path");
var import_node_fs2 = require("node:fs");

// src/lib/hook-log.ts
var import_node_fs = require("node:fs");
var import_node_os = require("node:os");
var import_node_path = require("node:path");
var MAX_BYTES = 256 * 1024;
function logPath() {
  return process.env.TOKENMONK_HOOK_LOG ?? (0, import_node_path.join)((0, import_node_os.homedir)(), ".tokenmonk-hooks.log");
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
async function runHook(hook, fn) {
  const started = Date.now();
  logHook(hook, { event: "start" });
  try {
    await fn();
    logHook(hook, { event: "end", ms: Date.now() - started });
  } catch (err) {
    logHook(hook, { event: "error", ms: Date.now() - started, message: err instanceof Error ? err.message : String(err) });
  }
}

// src/lib/hook-io.ts
var import_node_child_process = require("node:child_process");
var import_node_path3 = require("node:path");

// src/lib/plugin-root.ts
var import_node_path2 = require("node:path");
function pluginRoot() {
  return process.env.TOKENMONK_PLUGIN_ROOT ?? (0, import_node_path2.join)(__dirname, "..");
}

// src/lib/hook-io.ts
function readStdinJson(timeoutMs = 1500) {
  return new Promise((resolve) => {
    let raw = "";
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      const stripped = raw.replace(/^﻿/, "");
      try {
        const parsed = JSON.parse(stripped);
        resolve(typeof parsed === "object" && parsed !== null ? parsed : {});
      } catch {
        resolve({});
      }
    };
    const guard = setTimeout(done, timeoutMs);
    guard.unref?.();
    try {
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => raw += chunk);
      process.stdin.on("end", done);
      process.stdin.on("error", done);
    } catch {
      done();
    }
  });
}
function spawnUploader() {
  try {
    const child = (0, import_node_child_process.spawn)(process.execPath, [(0, import_node_path3.join)(pluginRoot(), "dist", "uploader.js")], {
      detached: true,
      stdio: "ignore"
    });
    child.unref();
  } catch {
  }
}

// src/flush-spool.ts
var THOUGHT_GATE_MS = 6e4;
function markerDir() {
  return process.env.TOKENMONK_DRAIN_DIR ?? (0, import_node_path4.join)((0, import_node_os2.homedir)(), ".tokenmonk", "drain");
}
function gateOpen(conversationId) {
  const safe = conversationId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 128) || "unknown";
  const marker = (0, import_node_path4.join)(markerDir(), safe);
  try {
    const last = Number((0, import_node_fs2.readFileSync)(marker, "utf8"));
    if (Number.isFinite(last) && Date.now() - last < THOUGHT_GATE_MS) return false;
  } catch {
  }
  try {
    (0, import_node_fs2.mkdirSync)(markerDir(), { recursive: true });
    (0, import_node_fs2.writeFileSync)(marker, String(Date.now()));
  } catch {
  }
  return true;
}
async function main() {
  const payload = await readStdinJson();
  process.stdout.write(JSON.stringify({}));
  const event = typeof payload.hook_event_name === "string" ? payload.hook_event_name : "unknown";
  const conversationId = typeof payload.conversation_id === "string" ? payload.conversation_id : "unknown";
  if (event === "afterAgentThought" && !gateOpen(conversationId)) {
    logHook("flush-spool", { event: "gated", hook: event });
    return;
  }
  logHook("flush-spool", { event: "drain_requested", hook: event });
  spawnUploader();
}
void runHook("flush-spool", main).then(() => process.exit(0));
