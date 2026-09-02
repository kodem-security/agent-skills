---
description: Fix your repo's existing Kodem security backlog (open SCA/SAST issues), prioritized by Kodem Score. Say what you want in plain language.
allowed-tools: Bash(kodem-cli:*), Bash(git remote:*), Bash(git config:*), Bash(git rev-parse:*), Read, Edit
---

The developer wants to work through their **existing** Kodem security backlog —
the open issues already in the Kodem platform — not the diff they just wrote.

Handle their request using the **kodem-backlog-fix** skill: follow its flow
(identify the repo → pull the prioritized backlog → orient and show the plan →
confirm → apply Kodem's computed fixes → re-scan and hand back), and its
Supported-requests table for mapping what they said to the right scope.

One exception: if the request is **read-only** — "full report", "show me
everything", "what's my posture?", "what should I prioritize?", or any ask to
*see* the state rather than fix it — use the **kodem-report** skill instead. It
builds the report (or short posture summary) from the same data, makes zero
changes, and ends by offering to hand back to backlog-fix.

Their request: $ARGUMENTS

If `$ARGUMENTS` is empty, treat it as the default ask ("fix my issues"): the top
10 open issues by Kodem Score — SCA (dependency) issues that have a fix, and code
(SAST) issues confirmed real by Kai, Kodem's AI code-analysis verdict (i.e. not a
false positive). Always state the inference you made and confirm before applying
anything, and never commit or push automatically.
