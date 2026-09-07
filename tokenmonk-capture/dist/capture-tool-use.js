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
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

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

// src/capture-tool-use.ts
var capture_tool_use_exports = {};
__export(capture_tool_use_exports, {
  contractFor: () => contractFor,
  shouldEmitTraffic: () => shouldEmitTraffic
});
module.exports = __toCommonJS(capture_tool_use_exports);

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

// src/lib/turn-aggregate.ts
var import_node_fs2 = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path2 = require("node:path");
function turnsDir() {
  return process.env.TOKENMONK_TURNS_DIR ?? (0, import_node_path2.join)((0, import_node_os2.homedir)(), ".tokenmonk", "turns");
}
function turnFile(conversationId, generationId) {
  const safeConv = conversationId || "unknown";
  return (0, import_node_path2.join)(turnsDir(), `${safeConv}${generationId ? `-${generationId}` : ""}.jsonl`);
}
function appendTurnEntry(conversationId, generationId, entry) {
  try {
    const dir = turnsDir();
    if (!(0, import_node_fs2.existsSync)(dir)) (0, import_node_fs2.mkdirSync)(dir, { recursive: true });
    (0, import_node_fs2.appendFileSync)(turnFile(conversationId, generationId), JSON.stringify(entry) + "\n");
  } catch {
  }
}
var MAX_AGE_MS = 6 * 60 * 60 * 1e3;

// src/lib/spool.ts
var import_node_fs3 = require("node:fs");
var import_node_os3 = require("node:os");
var import_node_path3 = require("node:path");
var MAX_TOTAL_BYTES = 50 * 1024 * 1024;
var MAX_AGE_MS2 = 24 * 60 * 60 * 1e3;
var LOCK_TTL_MS = 60 * 1e3;
function spoolDir() {
  return process.env.TOKENMONK_SPOOL_DIR ?? (0, import_node_path3.join)((0, import_node_os3.homedir)(), ".tokenmonk", "spool");
}
function dayStamp(now = /* @__PURE__ */ new Date()) {
  return now.toISOString().slice(0, 10).replace(/-/g, "");
}
function appendRecord(record, now = /* @__PURE__ */ new Date()) {
  try {
    const dir = spoolDir();
    (0, import_node_fs3.mkdirSync)(dir, { recursive: true });
    (0, import_node_fs3.appendFileSync)((0, import_node_path3.join)(dir, `${dayStamp(now)}.jsonl`), JSON.stringify(record) + "\n");
  } catch {
  }
}

// src/lib/record.ts
var import_node_child_process2 = require("node:child_process");
var import_node_os4 = require("node:os");

// src/lib/git-context.ts
var import_node_child_process = require("node:child_process");
function run(cmd, cwd) {
  try {
    return (0, import_node_child_process.execSync)(cmd, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
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
    gitUser = (0, import_node_child_process2.execSync)("git config user.name", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    gitUser = null;
  }
  let osUser = null;
  try {
    osUser = (0, import_node_os4.userInfo)().username || null;
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
var import_node_crypto = require("node:crypto");
var import_node_fs4 = require("node:fs");
var import_node_os5 = require("node:os");
var import_node_path4 = require("node:path");
var import_redact = __toESM(require_dist());
function normalizeToolName(raw) {
  const name = typeof raw === "string" ? raw.trim() : "";
  if (name.startsWith("MCP:")) return { isMcp: true, tool: name.slice("MCP:".length) };
  return { isMcp: false, tool: name };
}
function sanitizeId(raw) {
  return typeof raw === "string" ? raw.replace(/[^A-Za-z0-9._:-]/g, "") : "";
}
function parseMaybeJson(value) {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}
var DEFAULT_MAX_DEPTH = 4;
var MAX_PATHS = 256;
var ROOT = "$";
function typeOf(v) {
  if (v === null) return "null";
  if (v === void 0) return "undefined";
  if (Array.isArray(v)) return "array";
  const t = typeof v;
  if (t === "string" || t === "number" || t === "boolean") return t;
  return "object";
}
function sha256(s) {
  return (0, import_node_crypto.createHash)("sha256").update(s).digest("hex");
}
function schemaSignature(value, maxDepth = DEFAULT_MAX_DEPTH) {
  const paths = [];
  let truncated = false;
  const push = (p, t) => {
    if (paths.length >= MAX_PATHS) {
      truncated = true;
      return;
    }
    paths.push(`${p || ROOT}:${t}`);
  };
  const walk = (v, p, depth) => {
    if (paths.length >= MAX_PATHS) {
      truncated = true;
      return;
    }
    const t = typeOf(v);
    if (t === "array") {
      const arr = v;
      if (arr.length === 0) return push(p, "empty");
      if (depth >= maxDepth) {
        truncated = true;
        return push(p, "\u2026");
      }
      walk(arr[0], `${p}[]`, depth + 1);
      return;
    }
    if (t === "object") {
      const obj = v;
      const keys = Object.keys(obj).sort();
      if (keys.length === 0) return push(p, "object{}");
      if (depth >= maxDepth) {
        truncated = true;
        return push(p, "\u2026");
      }
      for (const k of keys) walk(obj[k], p ? `${p}.${k}` : k, depth + 1);
      return;
    }
    push(p, t);
  };
  walk(value, "", 0);
  paths.sort();
  return { paths, sig: sha256(paths.join("\n")).slice(0, 16), truncated };
}
var DEFAULT_TRAFFIC_CONFIG = {
  enabled: true,
  fullPerSession: 20,
  sampleRate: 5
};
function decideSample(count, cfg = DEFAULT_TRAFFIC_CONFIG) {
  if (!cfg.enabled) return { emit: false, sampled: false, count };
  if (count <= cfg.fullPerSession) return { emit: true, sampled: false, count };
  const over = count - cfg.fullPerSession;
  const rate = cfg.sampleRate > 0 ? cfg.sampleRate : 1;
  return { emit: over % rate === 0, sampled: true, count };
}
function loadTrafficConfig() {
  const cfg = { ...DEFAULT_TRAFFIC_CONFIG };
  const envEnabled = process.env.TOKENMONK_TRAFFIC_ENABLED ?? process.env.TRAFFIC_ENABLED;
  if (envEnabled != null) cfg.enabled = !(envEnabled === "0" || envEnabled.toLowerCase() === "false");
  const envFull = Number(process.env.TOKENMONK_TRAFFIC_FULL_PER_SESSION);
  if (Number.isFinite(envFull) && envFull >= 0) cfg.fullPerSession = envFull;
  const envRate = Number(process.env.TOKENMONK_TRAFFIC_SAMPLE_RATE);
  if (Number.isFinite(envRate) && envRate >= 1) cfg.sampleRate = envRate;
  return cfg;
}
function trafficDir() {
  return process.env.TOKENMONK_TRAFFIC_DIR ?? (0, import_node_path4.join)((0, import_node_os5.tmpdir)(), "tokenmonk-traffic");
}
function nextTrafficCount(conversationId, server, dir = trafficDir()) {
  try {
    if (!(0, import_node_fs4.existsSync)(dir)) (0, import_node_fs4.mkdirSync)(dir, { recursive: true });
    const file = (0, import_node_path4.join)(dir, `${sha256(conversationId).slice(0, 24)}.json`);
    let counts = {};
    if ((0, import_node_fs4.existsSync)(file)) {
      try {
        counts = JSON.parse((0, import_node_fs4.readFileSync)(file, "utf8"));
      } catch {
        counts = {};
      }
    }
    const next = (typeof counts[server] === "number" ? counts[server] : 0) + 1;
    counts[server] = next;
    (0, import_node_fs4.writeFileSync)(file, JSON.stringify(counts));
    return next;
  } catch {
    return 1;
  }
}
var MAX_ERROR_CHARS = 240;
function latencyMs(duration) {
  return typeof duration === "number" && Number.isFinite(duration) ? Math.round(duration) : null;
}
function extractError(payload) {
  const raw = typeof payload.error_message === "string" ? payload.error_message : null;
  const failed = raw != null || payload.failure_type != null || payload.is_interrupt === true;
  if (!failed) return null;
  const { redactedText } = (0, import_redact.redact)(raw ?? String(payload.failure_type ?? "error"));
  const prefixed = payload.is_interrupt === true ? `interrupt: ${redactedText}` : redactedText;
  return prefixed.length > MAX_ERROR_CHARS ? prefixed.slice(0, MAX_ERROR_CHARS) + "\u2026" : prefixed;
}
function buildToolTraffic(input) {
  const depth = input.maxDepth ?? DEFAULT_MAX_DEPTH;
  const parsedInput = parseMaybeJson(input.toolInput);
  const parsedResponse = parseMaybeJson(input.response);
  return {
    server_name: input.serverName,
    tool_name: input.toolName,
    phase: "post",
    input_schema_sig: parsedInput === void 0 ? null : schemaSignature(parsedInput, depth),
    response_schema_sig: parsedResponse === void 0 || parsedResponse === null ? null : schemaSignature(parsedResponse, depth),
    error: extractError(input.payload),
    latency_ms: latencyMs(input.payload.duration),
    sampled: input.sampled
  };
}
function trafficTurnId(conversationId, generationId, tt) {
  const seed = JSON.stringify({ s: tt.server_name, t: tt.tool_name, i: tt.input_schema_sig?.sig ?? "" });
  const gen = sanitizeId(generationId);
  const genSegment = gen ? `:${gen}` : "";
  return `cursor:traffic:post:${sanitizeId(conversationId) || "unknown"}${genSegment}:${tt.server_name}.${tt.tool_name}:${sha256(seed).slice(0, 12)}`;
}

// src/capture-tool-use.ts
var ALLOW = '{"permission":"allow"}';
var EMPTY = "{}";
function contractFor(event) {
  return event === "preToolUse" ? ALLOW : EMPTY;
}
function shouldEmitTraffic(event, toolName) {
  if (event === "afterMCPExecution") return true;
  if (event === "postToolUseFailure") return normalizeToolName(toolName).isMcp;
  return false;
}
var PATH_KEYS = ["path", "file_path", "filePath", "target_file"];
function filePathFrom(toolInput) {
  if (!toolInput || typeof toolInput !== "object") return null;
  const obj = toolInput;
  for (const k of PATH_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return null;
}
async function main() {
  const payload = await readStdinJson();
  const event = typeof payload.hook_event_name === "string" ? payload.hook_event_name : "";
  process.stdout.write(contractFor(event));
  const conversationId = sanitizeId(payload.conversation_id ?? payload.session_id);
  const generationId = sanitizeId(payload.generation_id);
  const { tool } = normalizeToolName(payload.tool_name);
  if (tool) appendTurnEntry(conversationId, generationId, { tool });
  const path = filePathFrom(payload.tool_input);
  if (path) appendTurnEntry(conversationId, generationId, { path });
  if (!shouldEmitTraffic(event, payload.tool_name)) return;
  const config = loadTrafficConfig();
  if (!config.enabled) return;
  const serverName = typeof payload.mcp_server_name === "string" && payload.mcp_server_name.length > 0 ? payload.mcp_server_name : "unknown";
  const decision = decideSample(nextTrafficCount(conversationId, serverName), config);
  if (!decision.emit) {
    logHook("capture-tool-use", { event: "sampled_out", cursor_event: event, server: serverName, count: decision.count });
    return;
  }
  const traffic = buildToolTraffic({
    serverName,
    toolName: tool,
    toolInput: payload.tool_input,
    response: payload.result_json ?? payload.tool_output ?? null,
    payload,
    sampled: decision.sampled
  });
  const record = {
    ...baseRecord(payload, {
      turnId: trafficTurnId(conversationId, generationId, traffic),
      promptText: null
    }),
    tool_names: tool ? [tool] : [],
    tool_traffic: traffic
  };
  appendRecord(record);
  logHook("capture-tool-use", {
    event: "spooled",
    cursor_event: event,
    server: traffic.server_name,
    tool: traffic.tool_name,
    latency_ms: latencyMs(payload.duration),
    sampled: decision.sampled
  });
}
if (require.main === module) {
  void runHook("capture-tool-use", main).then(() => process.exit(0));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  contractFor,
  shouldEmitTraffic
});
