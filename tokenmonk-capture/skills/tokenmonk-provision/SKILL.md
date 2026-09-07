---
name: tokenmonk-provision
description: List the scheduled jobs TokenMonk offers this account, and record one the user accepts.
---

First, list what is offered and show the user the result:

```
node "$CURSOR_PLUGIN_ROOT/dist/provision.js"
```

Present each job with its schedule, model, required connectors and estimated cost band. Then stop and
ask which, if any, they want. Do not choose for them.

A scheduled job spends tokens on a timer, so it is created only with the user's explicit agreement.

This plugin cannot create the job. Cursor's own `/automate` does that. For a job the user accepts:

1. Hand the job's schedule and prompt to `/automate` so Cursor creates it.
2. Then record the acceptance so TokenMonk can reconcile the job by name once it runs:

```
node "$CURSOR_PLUGIN_ROOT/dist/provision.js" --accepted "<exact job name>"
```

Record only jobs the user actually accepted. Recording one they declined would put a job in
TokenMonk's timeline that nobody asked for.

If the listing mentions skipped artifact templates, that is expected — live artifacts are a
Claude-only feature and Cursor has no runtime for them.
