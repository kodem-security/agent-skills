---
description: "Kodem Security: `scan` your current changes (default), `fix` your existing backlog, or get a `report`."
---

Route the developer's request by its first word:

- `scan` (or no subcommand): use the **kodem-security** skill to scan the current
  changes against the repo's Kodem policies now.
- `fix`: use the **kodem-backlog-fix** skill on the rest of the request. It works
  through the **existing** Kodem backlog, not the diff they just wrote: pull the
  prioritized issues, show the plan, confirm, apply Kodem's fixes, re-scan. With
  nothing after `fix`, the ask is "fix my issues": the top 10 open issues by Kodem
  Score — SCA issues that have a fix, and code issues Kai confirmed real. If the
  request is read-only ("what's my posture?", "show me everything"), use
  **kodem-report** instead.
- `report`: use the **kodem-report** skill: full report, or the short posture
  summary if they asked for posture. It makes no changes.

Their request: $ARGUMENTS

For `fix`, state the inference you made and confirm before applying anything.
Never commit or push.
