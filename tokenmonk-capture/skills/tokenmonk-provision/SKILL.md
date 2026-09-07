---
name: tokenmonk-provision
description: List the scheduled jobs TokenMonk offers this account, and record one the user accepts.
---

Run this and show the user its output verbatim:

```
node "$CURSOR_PLUGIN_ROOT/dist/provision.js"
```

Report exactly what it printed. Do not diagnose beyond it, and do not infer a cause it did not
state — "no scheduled jobs are currently offered" is a complete and normal answer, usually meaning
the organisation has published none. It is not an error and not a sign of a broken token.

NEVER ask the user for a token, an API key, or any credential, and never suggest editing
CAPTURE_TOKEN or a config file. Configuration is an admin task done in Cursor's plugin settings, and
a credential must never be pasted into a conversation. If the command reports that TokenMonk is not
configured or that it could not identify the session, say so and stop there.

If jobs ARE listed, present each with its schedule, model, required connectors and cost band, then
ask which, if any, the user wants. Do not choose for them.

A scheduled job spends tokens on a timer, so it is created only with the user's explicit agreement.

This plugin cannot create the job — Cursor's own `/automate` does. For a job the user accepts:

1. Hand its schedule and prompt to `/automate` so Cursor creates it.
2. Record the acceptance so TokenMonk can reconcile the job by name once it runs:

```
node "$CURSOR_PLUGIN_ROOT/dist/provision.js" --accepted "<exact job name>"
```

Record only jobs the user actually accepted.
