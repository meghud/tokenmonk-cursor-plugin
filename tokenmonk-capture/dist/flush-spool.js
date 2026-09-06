"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// ../../packages/redact/dist/redact.js
var require_redact = __commonJS({
  "../../packages/redact/dist/redact.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.redact = redact2;
    var PATTERNS = [
      { category: "private_key_block", regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/g },
      { category: "aws_access_key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
      { category: "github_token", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
      { category: "slack_token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
      { category: "google_api_key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
      { category: "stripe_key", regex: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
      { category: "anthropic_api_key", regex: /\bsk-ant-[A-Za-z0-9-_]{20,}\b/g },
      { category: "openai_api_key", regex: /\bsk-[A-Za-z0-9]{20,}\b/g },
      { category: "bearer_token", regex: /\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*/g },
      { category: "email", regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
      { category: "credit_card", regex: /\b(?:\d{4}[ -]){3}\d{1,4}\b|\b\d{13,16}\b/g },
      { category: "ssn", regex: /\b\d{3}-\d{2}-\d{4}\b/g },
      { category: "phone", regex: /\b(?:\(\d{3}\)\s?|\d{3}-)\d{3}-\d{4}\b/g }
    ];
    function redact2(text) {
      let redactedText = text;
      const findings = [];
      for (const { category, regex } of PATTERNS) {
        const matches = redactedText.match(regex);
        if (!matches || matches.length === 0)
          continue;
        redactedText = redactedText.replace(regex, `[REDACTED:${category}]`);
        findings.push({ category, count: matches.length });
      }
      return { redactedText, findings };
    }
  }
});

// ../../packages/redact/dist/index.js
var require_dist = __commonJS({
  "../../packages/redact/dist/index.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    } : function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    });
    var __exportStar = exports2 && exports2.__exportStar || function(m, exports3) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports3, p)) __createBinding(exports3, m, p);
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    __exportStar(require_redact(), exports2);
  }
});

// src/flush-spool.ts
var import_node_os5 = require("node:os");
var import_node_path6 = require("node:path");
var import_node_fs4 = require("node:fs");

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

// src/lib/spool.ts
var import_node_fs2 = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path4 = require("node:path");
var MAX_TOTAL_BYTES = 50 * 1024 * 1024;
var MAX_AGE_MS = 24 * 60 * 60 * 1e3;
var LOCK_TTL_MS = 60 * 1e3;
function spoolDir() {
  return process.env.TOKENMONK_SPOOL_DIR ?? (0, import_node_path4.join)((0, import_node_os2.homedir)(), ".tokenmonk", "spool");
}
function dayStamp(now = /* @__PURE__ */ new Date()) {
  return now.toISOString().slice(0, 10).replace(/-/g, "");
}
function appendRecord(record, now = /* @__PURE__ */ new Date()) {
  try {
    const dir = spoolDir();
    (0, import_node_fs2.mkdirSync)(dir, { recursive: true });
    (0, import_node_fs2.appendFileSync)((0, import_node_path4.join)(dir, `${dayStamp(now)}.jsonl`), JSON.stringify(record) + "\n");
  } catch {
  }
}

// src/lib/record.ts
var import_node_child_process3 = require("node:child_process");
var import_node_os3 = require("node:os");

// src/lib/git-context.ts
var import_node_child_process2 = require("node:child_process");
function run(cmd, cwd) {
  try {
    return (0, import_node_child_process2.execSync)(cmd, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
}
function getGitContext(cwd) {
  if (!cwd) return { gitRemote: null, gitBranch: null };
  return {
    gitRemote: run("git remote get-url origin", cwd),
    gitBranch: run("git rev-parse --abbrev-ref HEAD", cwd)
  };
}

// src/lib/ticket-keys.ts
var TICKET_PATTERN = /\b[A-Z][A-Z0-9]{1,9}-\d+\b/g;
function detectTicketKeys(...sources) {
  const found = /* @__PURE__ */ new Set();
  for (const source of sources) {
    if (!source) continue;
    for (const match of source.matchAll(TICKET_PATTERN)) {
      found.add(match[0]);
    }
  }
  return [...found];
}

// src/lib/surface.ts
function detectSurface(input = {}) {
  const override = process.env.TOKENMONK_SURFACE;
  if (override === "ide" || override === "cli" || override === "agent") return override;
  if (process.env.CURSOR_AGENT) return "agent";
  if (input.is_background_agent === true) return "agent";
  if (typeof input.conversation_id === "string" && input.conversation_id.startsWith("bc-")) return "agent";
  return process.env.VSCODE_PID ? "ide" : "cli";
}

// src/lib/record.ts
function str(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function isAttributableEmail(email) {
  if (!email || !email.includes("@")) return false;
  const e = email.toLowerCase();
  if (e === "noreply@anthropic.com" || e === "noreply@github.com") return false;
  return !e.endsWith(".noreply.github.com");
}
function identityHint(payload) {
  const payloadEmail = str(payload.user_email) ?? str(process.env.CURSOR_USER_EMAIL);
  let gitUser = null;
  try {
    gitUser = (0, import_node_child_process3.execSync)("git config user.name", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    gitUser = null;
  }
  let osUser = null;
  try {
    osUser = (0, import_node_os3.userInfo)().username || null;
  } catch {
    osUser = null;
  }
  return {
    email: isAttributableEmail(payloadEmail) ? payloadEmail : null,
    os_user: osUser,
    git_user: gitUser
  };
}
function resolveCwd(payload) {
  const roots = Array.isArray(payload.workspace_roots) ? payload.workspace_roots : [];
  const firstRoot = roots.length > 0 ? str(roots[0]) : null;
  return firstRoot ?? str(process.env.CURSOR_PROJECT_DIR) ?? str(payload.cwd);
}
function baseRecord(payload, opts) {
  const conversationId = str(payload.conversation_id) ?? str(payload.session_id) ?? "unknown";
  const cwd = resolveCwd(payload);
  const git = getGitContext(cwd);
  const identity = identityHint(payload);
  return {
    session_id: conversationId,
    turn_id: opts.turnId,
    raw_actor_id: identity.email ?? identity.os_user ?? "unknown",
    identity_hint: identity,
    harness: "cursor",
    surface: detectSurface(payload),
    event_timestamp_utc: (/* @__PURE__ */ new Date()).toISOString(),
    cwd,
    git_remote: git.gitRemote,
    git_branch: git.gitBranch,
    ticket_keys: detectTicketKeys(git.gitBranch, cwd),
    tool_names: [],
    file_paths_touched: [],
    skills_invoked: opts.skillsInvoked ?? [],
    prompt_text: opts.promptText,
    source_side_classification: null,
    ...str(payload.model) ? { model_name: str(payload.model) } : {},
    ...str(payload.generation_id) ? { generation_id: str(payload.generation_id) } : {}
  };
}

// src/lib/tool-traffic.ts
var import_redact = __toESM(require_dist());
function sanitizeId(raw) {
  return typeof raw === "string" ? raw.replace(/[^A-Za-z0-9._:-]/g, "") : "";
}

// src/lib/turn-aggregate.ts
var import_node_fs3 = require("node:fs");
var import_node_os4 = require("node:os");
var import_node_path5 = require("node:path");
function turnsDir() {
  return process.env.TOKENMONK_TURNS_DIR ?? (0, import_node_path5.join)((0, import_node_os4.homedir)(), ".tokenmonk", "turns");
}
function turnFile(conversationId, generationId) {
  const safeConv = conversationId || "unknown";
  return (0, import_node_path5.join)(turnsDir(), `${safeConv}${generationId ? `-${generationId}` : ""}.jsonl`);
}
function readTurnAggregate(conversationId, generationId) {
  const out = { turnId: null, toolNames: [], filePaths: [] };
  const tools = /* @__PURE__ */ new Set();
  const paths = /* @__PURE__ */ new Set();
  try {
    const file = turnFile(conversationId, generationId);
    if (!(0, import_node_fs3.existsSync)(file)) return out;
    for (const line of (0, import_node_fs3.readFileSync)(file, "utf8").split("\n")) {
      if (!line) continue;
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue;
      }
      if (entry.turn_id && !out.turnId) out.turnId = entry.turn_id;
      if (entry.tool && !tools.has(entry.tool)) {
        tools.add(entry.tool);
        out.toolNames.push(entry.tool);
      }
      if (entry.path && !paths.has(entry.path)) {
        paths.add(entry.path);
        out.filePaths.push(entry.path);
      }
    }
  } catch {
  }
  return out;
}
function clearTurn(conversationId, generationId) {
  try {
    (0, import_node_fs3.rmSync)(turnFile(conversationId, generationId), { force: true });
  } catch {
  }
}
var MAX_AGE_MS2 = 6 * 60 * 60 * 1e3;
function pruneTurns(now = Date.now()) {
  let removed = 0;
  try {
    const dir = turnsDir();
    if (!(0, import_node_fs3.existsSync)(dir)) return 0;
    for (const name of (0, import_node_fs3.readdirSync)(dir)) {
      if (!name.endsWith(".jsonl")) continue;
      const file = (0, import_node_path5.join)(dir, name);
      try {
        if (now - (0, import_node_fs3.statSync)(file).mtimeMs > MAX_AGE_MS2) {
          (0, import_node_fs3.rmSync)(file, { force: true });
          removed++;
        }
      } catch {
      }
    }
  } catch {
  }
  return removed;
}

// src/flush-spool.ts
var THOUGHT_GATE_MS = 6e4;
function markerDir() {
  return process.env.TOKENMONK_DRAIN_DIR ?? (0, import_node_path6.join)((0, import_node_os5.homedir)(), ".tokenmonk", "drain");
}
function gateOpen(conversationId) {
  const safe = conversationId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 128) || "unknown";
  const marker = (0, import_node_path6.join)(markerDir(), safe);
  try {
    const last = Number((0, import_node_fs4.readFileSync)(marker, "utf8"));
    if (Number.isFinite(last) && Date.now() - last < THOUGHT_GATE_MS) return false;
  } catch {
  }
  try {
    (0, import_node_fs4.mkdirSync)(markerDir(), { recursive: true });
    (0, import_node_fs4.writeFileSync)(marker, String(Date.now()));
  } catch {
  }
  return true;
}
function flushTurn(payload) {
  const conversationId = sanitizeId(payload.conversation_id ?? payload.session_id);
  const generationId = sanitizeId(payload.generation_id);
  const agg = readTurnAggregate(conversationId, generationId);
  if (agg.toolNames.length === 0 && agg.filePaths.length === 0) return;
  const turnId = agg.turnId ?? `cursor:tools:${conversationId || "unknown"}${generationId ? `:${generationId}` : ""}`;
  appendRecord({
    ...baseRecord(payload, { turnId, promptText: null }),
    tool_names: agg.toolNames,
    file_paths_touched: agg.filePaths
  });
  clearTurn(conversationId, generationId);
  logHook("flush-spool", {
    event: "turn_flushed",
    tools: agg.toolNames.length,
    paths: agg.filePaths.length,
    merged: agg.turnId != null
  });
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
  if (event === "stop" || event === "afterAgentResponse") {
    flushTurn(payload);
    pruneTurns();
  }
  logHook("flush-spool", { event: "drain_requested", hook: event });
  spawnUploader();
}
void runHook("flush-spool", main).then(() => process.exit(0));
