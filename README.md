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

- your prompt text, **after** secrets, payment-card data, personal data and your organisation's own
  redaction rules are removed on your machine — each removed value becomes a marker such as
  `[REDACTED:email]`
- the model, conversation id, and workspace git remote and branch
- ticket keys detected in the branch name
- which `/slash` skill you invoked, when you invoke one

## What it does not do

- **Never blocks.** Every hook returns "allow"/"continue" and exits 0. If TokenMonk is unreachable,
  records queue locally and upload later; your session is unaffected.
- **Never sends shell command text or file contents.**
- **Redacts before writing to disk**, not just before sending — the local queue never holds a raw
  secret. 17 built-in categories: API keys for the major providers, private key blocks and bearer
  tokens (always on); card numbers, security codes, expiry dates and IBANs; email addresses, phone
  numbers, US SSNs and IP addresses. Your admin can turn individual card and personal-data categories
  off and add patterns of their own (TokenMonk → Admin → Privacy & Redaction).
- **Sends nothing without configuration.** With no endpoint and token, records simply queue.

Set `REDACT_MODE=content` to send hashes and shapes instead of prompt text.

### Instruction rules

Admins can also write redaction rules in plain language ("internal project codenames", "customer
account numbers"). These are applied **on your machine** by the Cursor CLI, `cursor-agent`, using
your own Cursor login — your prompt is never sent to TokenMonk to be redacted. While such rules are
active:

- a prompt's text is held back until the rules have been applied, then uploaded a few seconds after
  the turn (one small model call per prompt; results are cached);
- if it can't be redacted — `cursor-agent` isn't installed, or the model changed anything other than
  the sensitive spans — the prompt text is **never sent**, only its metadata;
- tool payloads are not model-redacted, so their content is withheld too.

Install the CLI with `curl https://cursor.com/install -fsS | bash` if your organisation uses
instruction rules. `TOKENMONK_SCRUB_MODEL` picks the model `cursor-agent` uses.

## Scope today

This release captures prompts and sessions. Tool and MCP traffic, identity linking and skill
distribution are in progress; a session's tool calls are not yet reported.

Cloud agents need hooks delivered by a committed `.cursor/hooks.json` or by Enterprise team hooks —
a marketplace plugin's hooks do not run in a cloud VM, because Cursor loads plugins there for static
capabilities (skills, commands, subagents) only.
