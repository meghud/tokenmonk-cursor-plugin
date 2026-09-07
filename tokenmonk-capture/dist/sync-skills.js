"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/sync-skills.ts
var sync_skills_exports = {};
__export(sync_skills_exports, {
  isDue: () => isDue,
  markChecked: () => markChecked
});
module.exports = __toCommonJS(sync_skills_exports);
var import_node_fs4 = require("node:fs");
var import_node_os5 = require("node:os");
var import_node_path5 = require("node:path");

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

// src/lib/user-skills.ts
var import_node_fs3 = require("node:fs");
var import_node_os4 = require("node:os");
var import_node_path4 = require("node:path");

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
var import_node_os3 = require("node:os");
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
  const payloadEmail = str2(payload.user_email) ?? str2(process.env.CURSOR_USER_EMAIL);
  let gitUser = null;
  try {
    gitUser = (0, import_node_child_process.execSync)("git config user.name", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
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

// src/lib/skill-bundle.ts
function ensureFrontmatter(name, description, body) {
  if (body.trimStart().startsWith("---")) return body;
  return `---
name: ${name}
description: ${JSON.stringify(description)}
---

${body}`;
}
function skillSlug(name) {
  const slug = name.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "");
  return slug || "skill";
}

// src/lib/user-skills.ts
var FETCH_TIMEOUT_MS = 8e3;
var TM_PREFIX = "tm-";
function skillsDir() {
  return process.env.TOKENMONK_CURSOR_SKILLS_DIR ?? (0, import_node_path4.join)((0, import_node_os4.homedir)(), ".cursor", "skills");
}
function manifestPath() {
  return process.env.TOKENMONK_CURSOR_SKILLS_MANIFEST ?? (0, import_node_path4.join)((0, import_node_os4.homedir)(), ".tokenmonk", "cursor-skills.json");
}
function readManifest() {
  try {
    const raw = JSON.parse((0, import_node_fs3.readFileSync)(manifestPath(), "utf8"));
    return raw && Array.isArray(raw.slugs) ? raw : null;
  } catch {
    return null;
  }
}
function saveManifest(m) {
  try {
    (0, import_node_fs3.mkdirSync)((0, import_node_path4.join)(manifestPath(), ".."), { recursive: true });
    (0, import_node_fs3.writeFileSync)(manifestPath(), JSON.stringify(m, null, 2));
  } catch (err) {
    logHook("cursor-skills", { event: "manifest-write-failed", message: String(err) });
  }
}
function dirFor(slug) {
  return (0, import_node_path4.join)(skillsDir(), `${TM_PREFIX}${slug}`);
}
async function fetchEntitled(baseUrl, orgToken, etag, force) {
  const headers = { Authorization: `Bearer ${orgToken}` };
  const identity = identityHint({});
  if (identity.email) headers["X-TM-Email"] = identity.email;
  if (identity.os_user) headers["X-TM-Os-User"] = identity.os_user;
  if (identity.git_user) headers["X-TM-Git-User"] = identity.git_user;
  if (etag && !force) headers["If-None-Match"] = etag;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${baseUrl}/v1/skills/distribution`, { headers, signal: controller.signal });
    const responseEtag = res.headers.get("ETag") ?? res.headers.get("etag") ?? etag ?? "";
    if (res.status === 304) return { status: 304, skills: [], etag: responseEtag, identityStatus: "unknown" };
    if (!res.ok) return { status: res.status, skills: [], etag: responseEtag, identityStatus: "unknown" };
    const data = await res.json();
    return {
      status: 200,
      skills: data.skills ?? [],
      etag: responseEtag,
      identityStatus: data.identity?.status === "identified" ? "identified" : "unknown"
    };
  } finally {
    clearTimeout(timeout);
  }
}
async function syncSkills(force = false) {
  const empty = { installed: [], removed: [], skills: [], identityStatus: "unknown" };
  const config = loadConfig();
  if (!config) return { status: "unconfigured", ...empty };
  const manifest = readManifest();
  const baseUrl = config.endpoint.replace(/\/v1\/capture\/?$/, "");
  let result;
  try {
    result = await fetchEntitled(baseUrl, config.orgToken, manifest?.etag, force);
  } catch {
    return { status: "unreachable", ...empty };
  }
  if (result.status === 304) {
    return {
      status: "unchanged",
      installed: [],
      removed: [],
      skills: manifest?.entries ?? [],
      identityStatus: manifest?.identityStatus ?? "unknown"
    };
  }
  if (result.status !== 200) {
    return { status: "error", ...empty, httpStatus: result.status };
  }
  if (result.identityStatus === "unknown" && result.skills.length === 0) {
    return {
      status: "unchanged",
      installed: [],
      removed: [],
      skills: manifest?.entries ?? [],
      identityStatus: "unknown"
    };
  }
  const prevVersions = manifest?.versions ?? {};
  const installed = [];
  const newSlugs = [];
  const newVersions = {};
  const entries = [];
  const failed = [];
  let allWritten = true;
  try {
    (0, import_node_fs3.mkdirSync)(skillsDir(), { recursive: true });
  } catch {
    return { status: "error", ...empty };
  }
  for (const skill of result.skills) {
    const slug = skillSlug(skill.name);
    newSlugs.push(slug);
    newVersions[slug] = skill.version;
    entries.push({ slug, name: skill.name, version: skill.version, description: skill.description });
    if (prevVersions[slug] === skill.version && !force) continue;
    try {
      (0, import_node_fs3.mkdirSync)(dirFor(slug), { recursive: true });
      (0, import_node_fs3.writeFileSync)(
        (0, import_node_path4.join)(dirFor(slug), "SKILL.md"),
        ensureFrontmatter(skill.name, skill.description, skill.bodyContent),
        "utf8"
      );
      installed.push(slug);
    } catch (err) {
      newVersions[slug] = "";
      allWritten = false;
      failed.push(slug);
      logHook("cursor-skills", { event: "skill-write-failed", slug, message: String(err) });
    }
  }
  const entitled = new Set(newSlugs);
  const removed = [];
  for (const slug of manifest?.slugs ?? []) {
    if (entitled.has(slug)) continue;
    try {
      (0, import_node_fs3.rmSync)(dirFor(slug), { recursive: true, force: true });
      removed.push(slug);
    } catch (err) {
      logHook("cursor-skills", { event: "prune-failed", slug, message: String(err) });
    }
  }
  saveManifest({
    version: 1,
    slugs: newSlugs,
    versions: newVersions,
    entries,
    identityStatus: result.identityStatus,
    // RAIL 3. Never advance the ETag past a partial write: persisting the new one would make the
    // next request 304 and short-circuit before the per-skill retry could run, stranding the failed
    // skill until the server's set changes again.
    etag: allWritten ? result.etag : "",
    updatedAt: (/* @__PURE__ */ new Date()).toISOString()
  });
  return {
    status: "ok",
    installed,
    removed,
    skills: entries,
    identityStatus: result.identityStatus,
    partial: failed.length > 0 ? failed : void 0
  };
}

// src/sync-skills.ts
var CHECK_INTERVAL_MS = 24 * 60 * 60 * 1e3;
function checkFile() {
  return process.env.TOKENMONK_SKILLS_CHECK ?? (0, import_node_path5.join)((0, import_node_os5.homedir)(), ".tokenmonk", "cursor-skills-check.json");
}
function isDue(force) {
  if (force) return true;
  try {
    const at = JSON.parse((0, import_node_fs4.readFileSync)(checkFile(), "utf8")).at ?? 0;
    return Date.now() - at > CHECK_INTERVAL_MS;
  } catch {
    return true;
  }
}
function markChecked() {
  try {
    (0, import_node_fs4.mkdirSync)((0, import_node_path5.join)(checkFile(), ".."), { recursive: true });
    (0, import_node_fs4.writeFileSync)(checkFile(), JSON.stringify({ at: Date.now() }));
  } catch {
  }
}
async function main() {
  const argv = process.argv.slice(2);
  const force = argv.includes("--force") || process.env.TOKENMONK_FORCE_SYNC === "1";
  const caller = argv.find((a) => a.startsWith("--caller="))?.slice("--caller=".length) ?? "unknown";
  if (!process.stdin.isTTY) await readStdinJson();
  process.stdout.write("{}");
  if (!isDue(force)) {
    logHook("cursor-skills", { event: "throttled", caller });
    return;
  }
  const result = await syncSkills(force);
  logHook("cursor-skills", {
    event: "sync",
    caller,
    status: result.status,
    installed: result.installed.length,
    removed: result.removed.length,
    skills: result.skills.length,
    identity: result.identityStatus,
    partial: result.partial?.length ?? 0
  });
  if (result.status === "ok" || result.status === "unchanged") markChecked();
}
if (require.main === module) {
  void runHook("cursor-skills", main).then(() => process.exit(0));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  isDue,
  markChecked
});
