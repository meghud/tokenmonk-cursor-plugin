# TokenMonk capture for Cursor

The Cursor plugin that reports AI usage to your organisation's TokenMonk instance, so spend can be
attributed to people, projects and tickets — and recurring work can be turned into reviewed skills.

This repository is a Cursor **plugin marketplace**. Import it once and the plugin below becomes
installable by your team.

```
.cursor-plugin/marketplace.json   the marketplace manifest
tokenmonk-capture/                the plugin
```

## Install

**Team or Enterprise plan.** Dashboard → Plugins → add this repository as a marketplace, then set the
install mode. *Required* keeps capture in place across the team.

**Local development.** Clone into `~/.cursor/plugins/local/` and restart Cursor.

## Configure

Two values, from **TokenMonk → Admin → Settings → Capture API keys**:

| variable | value |
|---|---|
| `CAPTURE_ENDPOINT` | your org's ingestion URL |
| `CAPTURE_TOKEN` | a key you generate there |

Set them in Cursor under the plugin's **Configure** panel. For cloud agents, set the same two as
**Secrets** in the Cloud Agents dashboard — mark `CAPTURE_TOKEN` as a *Runtime Secret* so its value
stays out of transcripts and commits.

## What it sends

- your prompt text, **after** secrets and PII are removed on your machine
- the model, conversation id, and workspace git remote and branch
- ticket keys detected in the branch name
- which `/slash` skill you invoked, when you invoke one

## What it does not do

- **Never blocks.** Every hook returns "allow"/"continue" and exits 0. If TokenMonk is unreachable,
  records queue locally and upload later; your session is unaffected.
- **Never sends shell command text or file contents.**
- **Redacts before writing to disk**, not just before sending — the local queue never holds a raw
  secret. 13 categories: API keys for the major providers, private key blocks, bearer tokens, email
  addresses, credit cards, and more.
- **Sends nothing without configuration.** With no endpoint and token, records simply queue.

Set `REDACT_MODE=content` to send hashes and shapes instead of prompt text.

## Scope today

This release captures prompts and sessions. Tool and MCP traffic, identity linking and skill
distribution are in progress; a session's tool calls are not yet reported.

Cloud agents need hooks delivered by a committed `.cursor/hooks.json` or by Enterprise team hooks —
a marketplace plugin's hooks do not run in a cloud VM, because Cursor loads plugins there for static
capabilities (skills, commands, subagents) only.
