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

// src/provision.ts
var provision_exports = {};
__export(provision_exports, {
  contentField: () => contentField,
  describe: () => describe
});
module.exports = __toCommonJS(provision_exports);
var import_node_crypto = require("node:crypto");

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

// src/lib/spool.ts
var import_node_fs2 = require("node:fs");
var import_node_os2 = require("node:os");
var import_node_path2 = require("node:path");
var MAX_TOTAL_BYTES = 50 * 1024 * 1024;
var MAX_AGE_MS = 24 * 60 * 60 * 1e3;
var LOCK_TTL_MS = 60 * 1e3;
function spoolDir() {
  return process.env.TOKENMONK_SPOOL_DIR ?? (0, import_node_path2.join)((0, import_node_os2.homedir)(), ".tokenmonk", "spool");
}
function dayStamp(now = /* @__PURE__ */ new Date()) {
  return now.toISOString().slice(0, 10).replace(/-/g, "");
}
function appendRecord(record, now = /* @__PURE__ */ new Date()) {
  try {
    const dir = spoolDir();
    (0, import_node_fs2.mkdirSync)(dir, { recursive: true });
    (0, import_node_fs2.appendFileSync)((0, import_node_path2.join)(dir, `${dayStamp(now)}.jsonl`), JSON.stringify(record) + "\n");
  } catch {
  }
}

// src/lib/hook-io.ts
var import_node_child_process = require("node:child_process");
var import_node_path4 = require("node:path");

// src/lib/plugin-root.ts
var import_node_path3 = require("node:path");
function pluginRoot() {
  return process.env.TOKENMONK_PLUGIN_ROOT ?? (0, import_node_path3.join)(__dirname, "..");
}

// src/lib/hook-io.ts
function spawnUploader() {
  try {
    const child = (0, import_node_child_process.spawn)(process.execPath, [(0, import_node_path4.join)(pluginRoot(), "dist", "uploader.js")], {
      detached: true,
      stdio: "ignore"
    });
    child.unref();
  } catch {
  }
}

// src/lib/record.ts
var import_node_child_process3 = require("node:child_process");
var import_node_os4 = require("node:os");

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

// src/lib/identity-store.ts
var import_node_fs3 = require("node:fs");
var import_node_os3 = require("node:os");
var import_node_path5 = require("node:path");
function storePath() {
  return process.env.TOKENMONK_IDENTITY_STORE ?? (0, import_node_path5.join)((0, import_node_os3.homedir)(), ".tokenmonk", "cursor-identity.json");
}
function rememberEmail(email) {
  if (!email) return;
  try {
    if (readEmail() === email) return;
    (0, import_node_fs3.mkdirSync)((0, import_node_path5.join)(storePath(), ".."), { recursive: true });
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
  const observed = str(payload.user_email) ?? str(process.env.CURSOR_USER_EMAIL);
  if (isAttributableEmail(observed)) rememberEmail(observed);
  const payloadEmail = observed ?? readEmail();
  let gitUser = null;
  try {
    gitUser = (0, import_node_child_process3.execSync)("git config user.name", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
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

// src/lib/automation-sync.ts
var import_node_fs5 = require("node:fs");
var import_node_os6 = require("node:os");
var import_node_path7 = require("node:path");

// src/lib/config.ts
var import_node_fs4 = require("node:fs");
var import_node_os5 = require("node:os");
var import_node_path6 = require("node:path");
function configFilePath() {
  return process.env.TOKENMONK_CONFIG_FILE ?? (0, import_node_path6.join)((0, import_node_os5.homedir)(), ".tokenmonk", "cursor.config.json");
}
function readJson(path) {
  try {
    const parsed = JSON.parse((0, import_node_fs4.readFileSync)(path, "utf8"));
    return typeof parsed === "object" && parsed !== null ? parsed : null;
  } catch {
    return null;
  }
}
function str2(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function loadConfig() {
  const redactMode = process.env.REDACT_MODE === "content" ? "content" : "default";
  const envEndpoint = str2(process.env.CAPTURE_ENDPOINT);
  const envToken = str2(process.env.CAPTURE_TOKEN);
  if (envEndpoint && envToken) return { endpoint: envEndpoint, orgToken: envToken, redactMode };
  for (const path of [configFilePath(), (0, import_node_path6.resolve)(pluginRoot(), "tokenmonk.config.json")]) {
    const cfg = readJson(path);
    if (!cfg) continue;
    const endpoint = str2(cfg.endpoint) ?? str2(cfg.capture_endpoint);
    const orgToken = str2(cfg.orgToken) ?? str2(cfg.capture_token);
    if (endpoint && orgToken) {
      const fileMode = cfg.redactMode === "content" || cfg.redact_mode === "content" ? "content" : redactMode;
      return { endpoint, orgToken, redactMode: fileMode };
    }
  }
  return null;
}

// src/lib/automation-sync.ts
var FETCH_TIMEOUT_MS = 8e3;
var CHECK_INTERVAL_MS = 24 * 60 * 60 * 1e3;
function distributionDir() {
  return process.env.TOKENMONK_DISTRIBUTION_DIR ?? (0, import_node_path7.join)((0, import_node_os6.homedir)(), ".tokenmonk", "distribution");
}
function stagedPath() {
  return (0, import_node_path7.join)(distributionDir(), "cursor-automations.json");
}
function manifestPath() {
  return (0, import_node_path7.join)(distributionDir(), ".cursor-automations-manifest.json");
}
function readJson2(path) {
  try {
    return JSON.parse((0, import_node_fs5.readFileSync)(path, "utf8"));
  } catch {
    return null;
  }
}
function writeJson(path, value) {
  try {
    (0, import_node_fs5.mkdirSync)(distributionDir(), { recursive: true });
    (0, import_node_fs5.writeFileSync)(path, JSON.stringify(value, null, 2));
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
function describeSchedule(job) {
  if (job.cron_expression) return `cron ${job.cron_expression}`;
  if (job.run_once_at) return `once at ${job.run_once_at}`;
  return "no schedule set";
}

// src/provision.ts
function contentField(text) {
  return { text, chars: text.length, hash: (0, import_node_crypto.createHash)("sha256").update(text).digest("hex").slice(0, 16) };
}
function describe(job) {
  const parts = [
    `- ${job.name} (v${job.version})`,
    `    schedule: ${describeSchedule(job)}`,
    job.model ? `    model: ${job.model}` : null,
    job.required_connectors?.length ? `    connectors: ${job.required_connectors.join(", ")}` : null,
    job.est_cost_band ? `    cost band: ${job.est_cost_band}` : null,
    job.depends_on_skill ? `    depends on skill: ${job.depends_on_skill}` : null,
    `    prompt: ${JSON.stringify(job.prompt)}`
  ];
  return parts.filter(Boolean).join("\n");
}
function list() {
  const staged = readStaged();
  if (staged.scheduled_jobs.length === 0) {
    process.stdout.write("No scheduled jobs are currently offered to this account.\n");
  } else {
    process.stdout.write(
      `${staged.scheduled_jobs.length} scheduled job(s) offered:
${staged.scheduled_jobs.map(describe).join("\n")}
`
    );
  }
  if (staged.skipped_artifacts > 0) {
    process.stdout.write(
      `
${staged.skipped_artifacts} live artifact template(s) were skipped \u2014 artifacts are a Claude-only feature and Cursor has no runtime for them.
`
    );
  }
  process.stdout.write(
    `
To create one, use Cursor's own /automate with the schedule and prompt above, then run this with --accepted "<name>" so TokenMonk can reconcile it.
`
  );
}
function recordAccepted(name) {
  const staged = readStaged();
  const job = staged.scheduled_jobs.find((j) => j.name === name);
  if (!job) {
    process.stdout.write(`No offered job named ${JSON.stringify(name)}. Run this without arguments to see what is available.
`);
    return;
  }
  const record = {
    ...baseRecord({}, {
      // Idempotent per template: accepting the same job twice is the same fact, and the server's
      // (orgId, turnId) merge collapses it rather than logging a second intent.
      turnId: `cursor:schedule:provision:${job.name}`,
      promptText: null
    }),
    tool_event: {
      object_kind: "scheduled_job",
      action: "provision_requested",
      phase: "post",
      natural_key: job.name,
      connector_names: job.required_connectors ?? [],
      schedule: {
        name: job.name,
        prompt: contentField(job.prompt),
        cron_expression: job.cron_expression ?? null,
        run_once_at: job.run_once_at ?? null,
        model: job.model ?? null
      }
    }
  };
  appendRecord(record);
  spawnUploader();
  logHook("cursor-automations", { event: "provision_requested", name: job.name, version: job.version });
  process.stdout.write(
    `Recorded that ${job.name} was accepted. Create it in Cursor with /automate if you have not already \u2014 TokenMonk reconciles it by name once it runs.
`
  );
}
async function main() {
  const argv = process.argv.slice(2);
  const acceptedIdx = argv.indexOf("--accepted");
  if (acceptedIdx !== -1) {
    const name = argv[acceptedIdx + 1];
    if (!name) {
      process.stdout.write('Usage: --accepted "<job name>"\n');
      return;
    }
    recordAccepted(name);
    return;
  }
  const result = await syncAutomations(true);
  if (result.status === "unconfigured") {
    process.stdout.write("TokenMonk is not configured on this machine, so no automations can be fetched.\n");
    return;
  }
  if (result.status === "unidentified") {
    process.stdout.write("Could not establish which account this session belongs to, so no automations were fetched.\n");
    return;
  }
  if (result.status === "unreachable") {
    process.stdout.write("Could not reach TokenMonk. Showing whatever was staged previously.\n");
  }
  list();
}
if (require.main === module) {
  void runHook("provision", main).then(() => process.exit(0));
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  contentField,
  describe
});
