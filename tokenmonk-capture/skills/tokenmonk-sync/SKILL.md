---
name: tokenmonk-sync
description: Pull the TokenMonk skills this account is entitled to onto this machine, and report what changed.
---

Run this exactly, from the plugin directory, and report its output:

```
node "$CURSOR_PLUGIN_ROOT/dist/sync-skills.js" --force --caller=skill
```

Then tell the user, in your own words, what changed — how many skills were installed or removed, and
their names. Skills land under their own directory, which the command's log line names; Cursor loads
them from there itself, so there is nothing further to install and no file to hand over.

Never ask the user for a token or credential, and never suggest editing CAPTURE_TOKEN or a config
file — configuration is an admin task in Cursor's plugin settings.

If the command reports `unidentified`, say so plainly: it means this session could not establish
which account it belongs to, and it deliberately syncs nothing rather than risk installing another
person's skills. That usually resolves itself on the next Cursor session, which records the account
email. Do not work around it by editing files.
