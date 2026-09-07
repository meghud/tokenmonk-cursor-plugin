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

// src/announce.ts
var announce_exports = {};
__export(announce_exports, {
  buildSkillsText: () => buildSkillsText,
  changedSkills: () => changedSkills,
  pickTopic: () => pickTopic
});
module.exports = __toCommonJS(announce_exports);
var import_node_fs4 = require("node:fs");
var import_node_os5 = require("node:os");
var import_node_path6 = require("node:path");

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

// src/lib/user-skills.ts
var import_node_fs3 = require("node:fs");
var import_node_os4 = require("node:os");
var import_node_path4 = require("node:path");

// src/lib/skill-bundle.ts
function parseSkillFrontmatter(md) {
  const block = /^\s*---\r?\n([\s\S]*?)\r?\n---/.exec(md)?.[1];
  if (!block) return {};
  const out = {};
  for (const line of block.split(/\r?\n/)) {
    const kv = /^(name|description)\s*:\s*(.*)$/.exec(line);
    const key = kv?.[1];
    if (!kv || !key) continue;
    const raw = (kv[2] ?? "").trim();
    let value = raw;
    if (raw.startsWith('"')) {
      try {
        value = JSON.parse(raw);
      } catch {
        value = raw.replace(/^"|"$/g, "");
      }
    } else if (raw.startsWith("'")) {
      value = raw.replace(/^'|'$/g, "");
    }
    if (value) out[key] = value;
  }
  return out;
}

// src/lib/user-skills.ts
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
function readInstalledSkills() {
  const manifest = readManifest();
  if (manifest?.entries?.length) return manifest.entries;
  try {
    return (0, import_node_fs3.readdirSync)(skillsDir()).filter((d) => d.startsWith(TM_PREFIX)).flatMap((d) => {
      const file = (0, import_node_path4.join)(skillsDir(), d, "SKILL.md");
      if (!(0, import_node_fs3.existsSync)(file)) return [];
      const fm = parseSkillFrontmatter((0, import_node_fs3.readFileSync)(file, "utf8"));
      const slug = d.slice(TM_PREFIX.length);
      return [{ slug, name: fm.name ?? slug, version: "", description: fm.description ?? "" }];
    });
  } catch {
    return [];
  }
}

// src/lib/skills-resync.ts
var import_node_child_process2 = require("node:child_process");
var import_node_path5 = require("node:path");
function spawnSkillsSync(opts) {
  try {
    const args = [(0, import_node_path5.join)(pluginRoot(), "dist", "sync-skills.js"), `--caller=${opts.caller}`];
    if (opts.force) args.push("--force");
    const child = (0, import_node_child_process2.spawn)(process.execPath, args, { detached: true, stdio: "ignore" });
    child.unref();
  } catch {
  }
}

// src/announce.ts
var EMPTY_NUDGE_INTERVAL_MS = Math.floor(7 * 24 * 60 * 60 * 1e3 / 2);
var IDENTITY_NUDGE_INTERVAL_MS = 7 * 24 * 60 * 60 * 1e3;
var BOOTSTRAP_INTERVAL_MS = 10 * 60 * 1e3;
function stateFile() {
  return process.env.TOKENMONK_ANNOUNCE_STATE ?? (0, import_node_path6.join)((0, import_node_os5.homedir)(), ".tokenmonk", "announce.json");
}
function readState() {
  try {
    return JSON.parse((0, import_node_fs4.readFileSync)(stateFile(), "utf8"));
  } catch {
    return {};
  }
}
function writeState(s) {
  try {
    (0, import_node_fs4.mkdirSync)((0, import_node_path6.join)(stateFile(), ".."), { recursive: true });
    (0, import_node_fs4.writeFileSync)(stateFile(), JSON.stringify(s));
  } catch {
  }
}
function changedSkills(installed, announced) {
  return installed.filter((s) => announced[s.slug] !== s.version);
}
function buildSkillsText(changed, dir) {
  const list = changed.map((s) => `  - ${s.name}: ${s.description}`).join("\n");
  return [
    `TokenMonk: ${changed.length} skill${changed.length === 1 ? "" : "s"} your organisation shares ${changed.length === 1 ? "is" : "are"} now on this machine, under ${dir}:`,
    list,
    `Cursor loads skills from that directory itself, so there is nothing for you to install and no file to hand over. Mention this to the user in your own words if it is a natural moment \u2014 if they are mid-task it can wait, and this notice returns.`
  ].join("\n");
}
function pickTopic(args) {
  const { installed, state, dir, hasEmail, now } = args;
  const changed = changedSkills(installed, state.announcedSkills ?? {});
  if (changed.length > 0) {
    return {
      kind: "skills",
      text: buildSkillsText(changed, dir),
      commit: (s) => ({
        ...s,
        announcedSkills: { ...s.announcedSkills ?? {}, ...Object.fromEntries(installed.map((k) => [k.slug, k.version])) }
      })
    };
  }
  if (installed.length === 0 && now - (state.emptyNudgedAt ?? 0) > EMPTY_NUDGE_INTERVAL_MS) {
    return {
      kind: "empty",
      text: `TokenMonk: no shared skills have synced to this machine yet (they would appear under ${dir}). If the user asks about TokenMonk skills, that is the current state \u2014 do not raise it otherwise.`,
      commit: (s) => ({ ...s, emptyNudgedAt: now })
    };
  }
  if (!hasEmail && now - (state.identityNudgedAt ?? 0) > IDENTITY_NUDGE_INTERVAL_MS) {
    return {
      kind: "identity",
      text: `TokenMonk: this session reports no account email, so its usage attributes to the organisation rather than to a person, and shared skills scoped to a team will not reach it. Mention it only if the user asks why their TokenMonk activity looks unattributed.`,
      commit: (s) => ({ ...s, identityNudgedAt: now })
    };
  }
  return null;
}
async function main() {
  const payload = await readStdinJson();
  const config = loadConfig();
  if (!config) {
    process.stdout.write(JSON.stringify({ continue: true }));
    return;
  }
  const state = readState();
  const installed = readInstalledSkills();
  const now = Date.now();
  if (installed.length === 0 && now - (state.bootstrappedAt ?? 0) > BOOTSTRAP_INTERVAL_MS) {
    spawnSkillsSync({ caller: "announce-bootstrap" });
    writeState({ ...state, bootstrappedAt: now });
  }
  const topic = pickTopic({
    installed,
    state,
    dir: skillsDir(),
    hasEmail: Boolean(identityHint(payload).email),
    now
  });
  if (!topic) {
    process.stdout.write(JSON.stringify({ continue: true }));
    return;
  }
  process.stdout.write(JSON.stringify({ continue: true, additional_context: topic.text }));
  writeState(topic.commit(readState()));
  logHook("announce", { event: "announced", kind: topic.kind });
}
if (require.main === module) {
  void runHook("announce", main).then(() => process.exit(0));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  buildSkillsText,
  changedSkills,
  pickTopic
});
