"use strict";

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

// src/lib/plugin-root.ts
var import_node_path2 = require("node:path");
function pluginRoot() {
  return process.env.TOKENMONK_PLUGIN_ROOT ?? (0, import_node_path2.join)(__dirname, "..");
}

// src/lib/hook-io.ts
function readStdinJson(timeoutMs = 1500) {
  return new Promise((resolve2) => {
    let raw = "";
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      const stripped = raw.replace(/^﻿/, "");
      try {
        const parsed = JSON.parse(stripped);
        resolve2(typeof parsed === "object" && parsed !== null ? parsed : {});
      } catch {
        resolve2({});
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

// src/lib/automation-sync.ts
var import_node_fs4 = require("node:fs");
var import_node_os5 = require("node:os");
var import_node_path5 = require("node:path");

// src/lib/config.ts
var import_node_fs2 = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path3 = require("node:path");
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

// src/lib/record.ts
var import_node_child_process = require("node:child_process");
var import_node_os4 = require("node:os");

// src/lib/identity-store.ts
var import_node_fs3 = require("node:fs");
var import_node_os3 = require("node:os");
var import_node_path4 = require("node:path");
function storePath() {
  return process.env.TOKENMONK_IDENTITY_STORE ?? (0, import_node_path4.join)((0, import_node_os3.homedir)(), ".tokenmonk", "cursor-identity.json");
}
function rememberEmail(email) {
  if (!email) return;
  try {
    if (readEmail() === email) return;
    (0, import_node_fs3.mkdirSync)((0, import_node_path4.join)(storePath(), ".."), { recursive: true });
    (0, import_node_fs3.writeFileSync)(storePath(), JSON.stringify({ email, updatedAt: (/* @__PURE__ */ new Date()).toISOString() }));
  } catch {
  }
}
function readEmail() {
  try {
    const s = JSON.parse((0, import_node_fs3.readFileSync)(storePath(), "utf8"));
    return typeof s.email === "string" && s.email.length > 0 ? s.email : null;
  } catch {
    return null;
  }
}

// src/lib/record.ts
function str2(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function isAttributableEmail(email) {
  if (!email || !email.includes("@")) return false;
  const e = email.toLowerCase();
  if (e === "noreply@anthropic.com" || e === "noreply@github.com") return false;
  return !e.endsWith(".noreply.github.com");
}
function identityHint(payload) {
  const observed = str2(payload.user_email) ?? str2(process.env.CURSOR_USER_EMAIL);
  if (isAttributableEmail(observed)) rememberEmail(observed);
  const payloadEmail = observed ?? readEmail();
  let gitUser = null;
  try {
    gitUser = (0, import_node_child_process.execSync)("git config user.name", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
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

// src/lib/automation-sync.ts
var FETCH_TIMEOUT_MS = 8e3;
var CHECK_INTERVAL_MS = 24 * 60 * 60 * 1e3;
function distributionDir() {
  return process.env.TOKENMONK_DISTRIBUTION_DIR ?? (0, import_node_path5.join)((0, import_node_os5.homedir)(), ".tokenmonk", "distribution");
}
function stagedPath() {
  return (0, import_node_path5.join)(distributionDir(), "cursor-automations.json");
}
function manifestPath() {
  return (0, import_node_path5.join)(distributionDir(), ".cursor-automations-manifest.json");
}
function readJson2(path) {
  try {
    return JSON.parse((0, import_node_fs4.readFileSync)(path, "utf8"));
  } catch {
    return null;
  }
}
function writeJson(path, value) {
  try {
    (0, import_node_fs4.mkdirSync)(distributionDir(), { recursive: true });
    (0, import_node_fs4.writeFileSync)(path, JSON.stringify(value, null, 2));
  } catch (err) {
    logHook("cursor-automations", { event: "write-failed", message: String(err) });
  }
}
function readStaged() {
  return readJson2(stagedPath()) ?? { scheduled_jobs: [], skipped_artifacts: 0 };
}
async function syncAutomations(force = false) {
  const none = { pending: [], staged: [], skippedArtifacts: 0 };
  const config = loadConfig();
  if (!config) return { status: "unconfigured", ...none };
  const identity = identityHint({});
  if (!identity.email) return { status: "unidentified", ...none };
  const manifest = readJson2(manifestPath());
  if (!force && manifest && Date.now() - manifest.lastCheckedAt < CHECK_INTERVAL_MS) {
    const staged = readStaged();
    return { status: "unchanged", pending: [], staged: staged.scheduled_jobs, skippedArtifacts: staged.skipped_artifacts };
  }
  const headers = { Authorization: `Bearer ${config.orgToken}` };
  headers["X-TM-Email"] = identity.email;
  if (identity.os_user) headers["X-TM-Os-User"] = identity.os_user;
  if (identity.git_user) headers["X-TM-Git-User"] = identity.git_user;
  if (manifest?.etag && !force) headers["If-None-Match"] = manifest.etag;
  const base = config.endpoint.replace(/\/v1\/capture\/?$/, "");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let jobs;
  let artifactCount;
  let etag;
  try {
    const res = await fetch(`${base}/v1/automations/distribution`, { headers, signal: controller.signal });
    etag = res.headers.get("ETag") ?? res.headers.get("etag") ?? manifest?.etag ?? "";
    if (res.status === 304) {
      const staged = readStaged();
      writeJson(manifestPath(), { ...manifest, lastCheckedAt: Date.now() });
      return { status: "unchanged", pending: [], staged: staged.scheduled_jobs, skippedArtifacts: staged.skipped_artifacts };
    }
    if (!res.ok) return { status: "unreachable", ...none };
    const data = await res.json();
    jobs = data.scheduled_jobs ?? [];
    artifactCount = (data.artifacts ?? []).length;
  } catch {
    return { status: "unreachable", ...none };
  } finally {
    clearTimeout(timeout);
  }
  const prev = manifest?.versions ?? {};
  const pending = jobs.filter((j) => prev[j.name] !== j.version);
  writeJson(stagedPath(), { scheduled_jobs: jobs, skipped_artifacts: artifactCount });
  writeJson(manifestPath(), {
    etag,
    lastCheckedAt: Date.now(),
    versions: Object.fromEntries(jobs.map((j) => [j.name, j.version])),
    skippedArtifacts: artifactCount
  });
  if (artifactCount > 0) {
    logHook("cursor-automations", { event: "artifacts-skipped", count: artifactCount });
  }
  return { status: "updated", pending, staged: jobs, skippedArtifacts: artifactCount };
}

// src/sync-automations.ts
async function main() {
  await readStdinJson();
  process.stdout.write("{}");
  const result = await syncAutomations(false);
  logHook("cursor-automations", {
    event: "sync",
    status: result.status,
    staged: result.staged.length,
    pending: result.pending.length,
    skipped_artifacts: result.skippedArtifacts
  });
}
if (require.main === module) {
  void runHook("cursor-automations", main).then(() => process.exit(0));
}
