"use strict";

// src/lib/http.ts
var TIMEOUT_MS = 3e3;
async function postJsonOk(url, token, body) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

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

// src/lib/config.ts
var import_node_fs2 = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path3 = require("node:path");

// src/lib/plugin-root.ts
var import_node_path2 = require("node:path");
function pluginRoot() {
  return process.env.TOKENMONK_PLUGIN_ROOT ?? (0, import_node_path2.join)(__dirname, "..");
}

// src/lib/config.ts
function configFilePath() {
  return process.env.TOKENMONK_CONFIG_FILE ?? (0, import_node_path3.join)((0, import_node_os2.homedir)(), ".tokenmonk", "cursor.config.json");
}
function readJson(path) {
  try {
    const parsed = JSON.parse((0, import_node_fs2.readFileSync)(path, "utf8"));
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}
function str(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function loadConfig() {
  const redactMode = process.env.REDACT_MODE === "content" ? "content" : "default";
  const envEndpoint = str(process.env.CAPTURE_ENDPOINT);
  const envToken = str(process.env.CAPTURE_TOKEN);
  if (envEndpoint && envToken) return { endpoint: envEndpoint, orgToken: envToken, redactMode };
  for (const path of [configFilePath(), (0, import_node_path3.resolve)(pluginRoot(), "tokenmonk.config.json")]) {
    const cfg = readJson(path);
    if (!cfg) continue;
    const endpoint = str(cfg.endpoint) ?? str(cfg.capture_endpoint);
    const orgToken = str(cfg.orgToken) ?? str(cfg.capture_token);
    if (endpoint && orgToken) {
      const fileMode = cfg.redactMode === "content" || cfg.redact_mode === "content" ? "content" : redactMode;
      return { endpoint, orgToken, redactMode: fileMode };
    }
  }
  return null;
}

// src/lib/drain.ts
async function drainEntries(entries, send, budget) {
  let i = 0;
  let sent = 0;
  let failed = false;
  for (; i < entries.length; i++) {
    if (sent >= budget) break;
    if (!await send(entries[i])) {
      failed = true;
      break;
    }
    sent++;
  }
  return { sent, failed, remaining: entries.slice(i) };
}

// src/lib/spool.ts
var import_node_fs3 = require("node:fs");
var import_node_os3 = require("node:os");
var import_node_path4 = require("node:path");
var MAX_TOTAL_BYTES = 50 * 1024 * 1024;
var MAX_AGE_MS = 24 * 60 * 60 * 1e3;
var LOCK_TTL_MS = 60 * 1e3;
function spoolDir() {
  return process.env.TOKENMONK_SPOOL_DIR ?? (0, import_node_path4.join)((0, import_node_os3.homedir)(), ".tokenmonk", "spool");
}
function spoolFiles() {
  try {
    return (0, import_node_fs3.readdirSync)(spoolDir()).filter((f) => f.endsWith(".jsonl")).sort().map((f) => (0, import_node_path4.join)(spoolDir(), f));
  } catch {
    return [];
  }
}
function readEntries(file) {
  try {
    return (0, import_node_fs3.readFileSync)(file, "utf8").split("\n").filter((l) => l.trim()).flatMap((l) => {
      try {
        return [JSON.parse(l)];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}
function writeRemaining(file, entries, consumed) {
  try {
    const tail = (0, import_node_fs3.existsSync)(file) ? (0, import_node_fs3.readFileSync)(file, "utf8").split("\n").filter(Boolean).slice(consumed) : [];
    const kept = [...entries.map((e) => JSON.stringify(e)), ...tail];
    if (kept.length === 0) (0, import_node_fs3.rmSync)(file, { force: true });
    else (0, import_node_fs3.writeFileSync)(file, kept.join("\n") + "\n");
  } catch {
  }
}
function prune(now = /* @__PURE__ */ new Date()) {
  let expired = 0;
  let overflowed = 0;
  const files = spoolFiles();
  for (const f of files) {
    try {
      if (now.getTime() - (0, import_node_fs3.statSync)(f).mtimeMs > MAX_AGE_MS) {
        (0, import_node_fs3.rmSync)(f, { force: true });
        expired++;
      }
    } catch {
    }
  }
  let total = 0;
  const remaining = spoolFiles().map((f) => {
    let size = 0;
    try {
      size = (0, import_node_fs3.statSync)(f).size;
    } catch {
      size = 0;
    }
    total += size;
    return { file: f, size };
  });
  for (const entry of remaining) {
    if (total <= MAX_TOTAL_BYTES) break;
    try {
      (0, import_node_fs3.rmSync)(entry.file, { force: true });
      total -= entry.size;
      overflowed++;
    } catch {
      break;
    }
  }
  return { expired, overflowed };
}
function lockPath() {
  return (0, import_node_path4.join)(spoolDir(), ".uploader.lock");
}
function acquireLock(now = /* @__PURE__ */ new Date()) {
  try {
    (0, import_node_fs3.mkdirSync)(spoolDir(), { recursive: true });
    const path = lockPath();
    if ((0, import_node_fs3.existsSync)(path) && now.getTime() - (0, import_node_fs3.statSync)(path).mtimeMs < LOCK_TTL_MS) return false;
    (0, import_node_fs3.writeFileSync)(path, String(process.pid));
    return true;
  } catch {
    return false;
  }
}
function releaseLock() {
  try {
    (0, import_node_fs3.rmSync)(lockPath(), { force: true });
  } catch {
  }
}

// src/uploader.ts
var MAX_PER_RUN = 200;
async function main() {
  if (!acquireLock()) return;
  try {
    const { expired, overflowed } = prune();
    if (expired || overflowed) logHook("uploader", { event: "pruned", expired, overflowed });
    const config = loadConfig();
    if (!config) {
      logHook("uploader", { event: "unconfigured", pending: spoolFiles().length });
      return;
    }
    let sent = 0;
    let stopped = false;
    for (const file of spoolFiles()) {
      if (stopped) break;
      const entries = readEntries(file);
      const result = await drainEntries(
        entries,
        (entry) => postJsonOk(config.endpoint, config.orgToken, entry),
        MAX_PER_RUN - sent
      );
      writeRemaining(file, result.remaining, entries.length);
      sent += result.sent;
      if (result.failed || sent >= MAX_PER_RUN) stopped = true;
    }
    logHook("uploader", { event: "drained", sent, stopped });
  } finally {
    releaseLock();
  }
}
void main().then(
  () => process.exit(0),
  () => process.exit(0)
);
