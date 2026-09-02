---
name: kodem-report
description: "Read-only security report of a repo's Kodem state — full report or short posture summary. Makes ZERO changes to the repo: no fixes, no edits, no commits. Use this whenever someone wants to SEE their security state rather than fix it: 'full report', 'show me everything', 'security report', 'what's my posture?', 'what should I prioritize?', 'how bad is my backlog?', 'are we breaching any policies?', 'what would CI block?', 'give me an overview before we fix anything', or an AppSec manager asking for project status. This is DIFFERENT from kodem-backlog-fix (which applies fixes) and from the prevention scan (which checks the diff you just wrote). If the user asks to fix their security issues or backlog, use kodem-backlog-fix instead."
allowed-tools:
  - Bash(${CLAUDE_SKILL_DIR}/scripts/build-report.sh:*)
  - Bash(kodem-cli:*)
  - Bash(git remote:*)
  - Bash(git config:*)
  - Bash(git rev-parse:*)
  - Bash(git status:*)
  - Read
  - Grep
  - Glob
---

# Kodem Report

Turn a repo's Kodem triage data into a structured, read-only report: issues
ranked by **Kodem Score** (runtime reachability weighted most, then
exploitability and severity), computed fixes, Quick Wins, Kai verdicts, and
policies. The audience is an AppSec manager checking project state, or a
developer deciding what's worth fixing before touching anything.

Two outputs:
- **Full report** — overview, findings summary, policies & breaches, the complete
  findings list with platform context, recommended next steps.
- **Posture summary** — counts, policies & breaches, top priorities, next steps.

Both end the same way: offer to hand straight to `kodem-backlog-fix`.

## The read-only contract

This skill makes **zero changes** on every run. No file edits, no dependency
bumps, no commits, no pushes, no code rewrites — even if a fix looks trivial.
The person running a report is often *deciding whether to trust the tooling*;
an unexpected write, however helpful, breaks that trust permanently.

- Run only read commands: `git remote`/`config`/`rev-parse`/`status`, `kodem-cli`
  reads, the report script below, and the policy-aware scan (which reads the
  repo and reports — it changes nothing).
- Report files are written to a **temp directory**, never into the repo. Only
  save a copy inside the repo if the user explicitly asks for one there.
- If the user asks you to fix something mid-report, finish the report, then hand
  off to the `kodem-backlog-fix` skill **scoped to exactly what they asked** —
  its supported-requests table maps specific asks ("fix CVE-…", "fix the lodash
  one", "fix the top 3"). Don't fix inline, and don't widen their ask into
  backlog-fix's default top-10 set.
- Never mark issues resolved (runtime resolution earns that, not a report).

## Step 0 — Check platform access

```bash
kodem-cli auth status
```

- **CLI not installed** → the report needs `kodem-cli`. Install it with this skill's
  own installer:
  `${CLAUDE_SKILL_DIR}/scripts/install.sh` (the same script
  updates an existing CLI). Running it needs the developer's approval — if they
  decline, say the report needs the CLI and stop rather than retrying. If the
  installer isn't present (skills delivered as separate files), ask the user to
  install `kodem-cli` from their Kodem onboarding, and stop until it's available.
- **Not authenticated** → you're in the **no-platform-access tier**: no triage
  data, Kodem Score, runtime, verdicts, or policies. Don't stop — build a
  **local-only report** from a CLI scan instead (see Fallback tiers), and say
  plainly *why* the platform isn't available (no OAuth or API key — quote the
  CLI's own error) and that `kodem-cli auth login` unlocks the full report.
- **Authenticated** → next step.

## Step 1 — Identify the repo

Derive the repository name Kodem knows it by — usually the `org/repo` from:

```bash
git remote get-url origin
```

Normalize to `org/repo` (strip host and `.git`). If the pull later reports
"code repository not found", **ask the user once** for the Kodem repo name and
re-run with their answer (`--repo-name`). If the repo genuinely isn't in Kodem,
fall back to a local scan (see Fallback tiers) and offer to connect it.

Monorepos can span several Kodem projects; the report script detects and names
each project. Report them together.

## Step 2 — Build the report (one script run)

The script does the whole deterministic part: pulls the data (every read
tagged `--skill-trigger` for usage attribution), computes exact counts, parses
the policy verdicts, and renders a **complete, user-friendly report**. Your
numbers come from it — never recompute or restate counts from memory.

```bash
${CLAUDE_SKILL_DIR}/scripts/build-report.sh <repo-root> --view full
${CLAUDE_SKILL_DIR}/scripts/build-report.sh <repo-root> --view posture
```

Options you'll actually use:
- `--repo-name org/repo` — when the git remote isn't the name Kodem knows.
- `--view full|posture` — full report vs short posture summary (default: full).
- `--format md|json|csv` — output format (default: `md`, the user-friendly one).
- `--inline-limit N` — above N findings (default 50), stdout shows a preview and
  the complete list stays in the report file (`0` prints everything).
- Scoping, pushed to the CLI (say the report is scoped when you use these):
  `--severity CRITICAL,HIGH` · `--type sca|sast` · `--runtime` ·
  `--package <name>` · `--cve <id>`.

The rendered report prints to stdout and is also written (with `report.json`, the
canonical structured data) to a temp directory — the `BUILD_REPORT_FILES:` trailer
names it, and `BUILD_REPORT_RESULT: ok` confirms a clean run. If a
`KODEM_UPDATE_AVAILABLE:` trailer appears, finish the report first, then offer
the CLI update once — never loop on it.

**Large backlogs** print a `BUILD_REPORT_INLINE: elided` trailer: stdout carried
only the top of each severity group, and the complete report is in the file. Tell
the user that plainly (count + file path) and offer the choices: print the full
list here anyway, copy the report file somewhere they pick, or narrow the scope.
Don't paste the full file into the chat unprompted — the point of the preview is
saving the user tokens.

**Exit codes → what to do:**

| Exit | Meaning | Your move |
| --- | --- | --- |
| 0 | report built | Step 3 |
| 2 | kodem-cli missing | Step 0 installer |
| 3 | not authenticated | no-platform tier (Fallback tiers) |
| 4 | repo not mapped | ask once for the Kodem name, retry with `--repo-name`; else not-mapped tier |
| 5 | not authorized (key scope) | no-scope tier — don't retry, it won't help |
| 6 | CLI too old for the read commands | update via the Step 0 installer, retry once; else local-scan report |
| 7 | python3 missing | do the manual pull (see Fallback: manual pull) |
| 1 | anything else | retry once, then report the script's error to the user |

## Step 3 — Present and enrich

Pick the view from the ask: "full report" / "show me everything" → `--view full`;
"what's my posture?" / "what should I prioritize?" → `--view posture`; ambiguous →
posture, then offer the full report.

The script's output **is** the report — complete and correct on its own. Present
it, then add the judgment a script can't:

- Sharpen the overview: 2–3 plain sentences on what actually matters (real risk
  vs raw count, the one thing to do first).
- Phrase the next steps for this user's context; keep the script's ordering.
- Narrate the missing signals the script flagged (see Missing signals).
- **Never alter the script's numbers, list, or ranking.** If something looks
  wrong, say so — don't silently "fix" it. That includes the counts: the script
  already excludes findings in this tool's own installed files (under
  `.claude/skills/` and `.claude/plugins/`) and reports how many via
  `signals.excluded_tool_own_files` — relay that number, don't re-derive it or
  adjust the totals yourself. Findings elsewhere under `.claude/` are the
  developer's own code and are included, as they should be.
- If the user compares this report to an earlier one: counts can change between
  runs — the platform recomputes fixability and scores continuously. That's
  normal, not a scan error; say so rather than reconciling by hand.
- **Call out the base image when it dominates.** On a containerised repo the base
  image is often most of the backlog, and that changes the answer to "what should I
  prioritize?" from a list of packages to a single `FROM` bump. The script counts
  this for you — read it from `report.json`, don't re-derive it:
  `signals.base_image_findings` (findings with `from_base_image: true`) and
  `signals.base_image_fix_known` (how many carry a computed target). If the share is
  substantial, say so with the number, and name the target from a finding's
  `base_image_fix` (`image` plus a `tags` entry, or `image@digest`).
  `base_image_fix.tags` are aliases of one digest, not alternative fixes.
  `base_image_fix_count` > 1 means the fix varies across images and only the first
  is shown; **it is never 1**, so `0` means "zero *or exactly one*".
  **Never invent an image, tag or digest.** `base_image_fix` is often absent for
  ordinary reasons — a container-image project id never triggers the lookup that
  populates it — so when `base_image_fix_known` is 0, report the count and say the
  target was not returned rather than guessing one.

**Custom formats:** if the user asks for a format the flags cover (`json`, `csv`,
posture), use the flag. For bespoke asks ("group by team", "one-pager for my
exec"), transform from `report.json` — never from memory — so every number stays
traceable to the data.

## Close every report the same way

1. **Offer the hand-off**: "Want me to fix these? Say the word and I'll run the
   backlog fix (`kodem-backlog-fix`) — e.g. 'fix the top 10' or 'fix the
   runtime-reachable ones'." A report that ends in a dead end is a wasted read.
2. **State the runtime-resolution expectation** plainly: issues resolve in Kodem
   once a fix is *deployed* and the sensor stops seeing the vulnerable component
   — not the moment code is committed.

(The script's render includes both as static lines; keep them, and make the
hand-off offer conversationally too.)

## Missing signals — degrade, state it, don't break

A report with a gap is still a report. The script detects the gaps and prints
them under **Missing signals**; your job is to make sure they land:

- **No runtime signal** (no sensor, or code repo and image not correlated) →
  priorities are best-effort, ranked by the remaining Kodem Score inputs.
- **Kai not enabled** → SAST confirmed-vs-false-positive can't be shown;
  recommend review before fixing.
- **No policies configured** → say so; don't relabel high-score issues as
  "policy breaches".
- **Empty backlog** → it's clean; policy state still shows; skip the fix offer.
- **No lockfile for an npm/pnpm/yarn manifest** → the script detects this and
  emits it under **Missing signals**; relay that note, don't re-derive it. The
  consequence is stronger than stale data: the platform reads the resolved tree
  out of the lockfile, so those JavaScript dependencies are **not scanned at all**
  and the manifest contributes **zero findings**. Never present that as clean —
  say the manifest was not scanned, and recommend committing a lockfile
  (`npm install --package-lock-only`, or the ecosystem's install command) and
  re-running. A repo whose only manifest is unresolved can show a clean report
  while being entirely unscanned.

Never fabricate a value the platform didn't return.

## Fallback tiers — always name the tier you're in

- **Full**: connected, mapped, correlated, Kai on, policies set → everything above.
- **No runtime / no correlation**: full report minus runtime — see Missing signals.
- **Repo not mapped** (exit 4): ask once; if it isn't in Kodem, do the
  **local-only report** below and offer to connect the repo.
- **Not authorized** (exit 5 — 403 / insufficient scope): the CLI can't read this
  repo's triage data and retrying won't help. Do a best-effort **agent-native
  read-only overview**: read the manifests and lockfiles yourself, list the
  dependencies you recognize as risky, and say plainly this is **best-effort with
  no Kodem context**. Still zero changes.
  **Be precise about what would actually unblock them: this report needs
  all-resources access.** It reads the tenant unscoped and never passes
  `--scope-id`, so being granted an individual scope — or every scope in the tenant —
  would still return nothing. Don't tell them to ask for "scope access"; that sends
  them to request something that cannot help. Say they need all-resources access,
  and that **`kodem-backlog-fix` does work for a restricted caller** — it resolves
  scopes and fans out per scope — so if what they want is to see and fix their own
  issues, point them there instead of leaving them stuck here.
- **No platform access** (exit 3 / not authenticated): build the **local-only
  report** from the CLI's local scans:

  ```bash
  kodem-cli scan code-repository open-source <repo-root> --skill-trigger \
    --description "report: local-only (no platform access)"
  kodem-cli scan code-repository code <repo-root> --skill-trigger \
    --description "report: local-only (no platform access)"
  ```

  Report findings by severity (package/version/CVE/fixed-in; file/CWE for code),
  state up front **why** the platform isn't available (quote the CLI's error) and
  that the local view has no Kodem Score, runtime, Kai verdicts, Quick Wins, or
  policies. Offer `kodem-cli auth login`. Some CLI builds refuse to scan without
  credentials at all — if so, say exactly that and fall back to the agent-native
  overview above (clearly labeled).
- **Manual pull** (exit 7 — no python3): do the script's job by hand, keeping the
  same output shape (overview · summary table · policies · complete findings list
  · next steps). The reads:

  ```bash
  kodem-cli issues list --repository-name "<org/repo>" --skill-trigger --json --limit 0
  kodem-cli issues quick-wins --project "<projectId>" --skill-trigger --json
  kodem-cli scan code-repository open-source <repo-root> \
    --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
    --description "report: read-only posture check"
  kodem-cli scan code-repository code <repo-root> \
    --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
    --description "report: read-only posture check"
  ```

  Run **both** policy scans — open-source and code policies are distinct rule
  sets; checking only one reads as a clean bill of health on the other.

  Per issue you get: `kodemScore`, `category` (sca/sast), `severity`, `riskId`,
  `packageName`, `cwe`, `riskInsights` (`runtime`, `exploitMaturity`),
  `fixInsights` + `fixVersions` (the computed fix), `issueKaiAnalysis.isFalsePositive`
  (Kai verdict — SAST only, when enabled), `status`, `uiLink`. An issue with
  `status: "open"` counts as open even if it carries a `dismissReason`. Policy
  verdict lines are prefixed `[CI · …]` / `[SCM · …]` (distinct rule sets — name
  the right one; worst verdict wins) or `NOT FOUND` when none configured.

## Supported requests

| The user says | What you do |
| --- | --- |
| "full report" / "show me everything" | `--view full`, complete findings list. |
| "what's my posture?" / "what should I prioritize?" | `--view posture`. |
| "report on the critical and high" | `--severity CRITICAL,HIGH`; say it's scoped. |
| "just the dependencies" / "only the code issues" | `--type sca` / `--type sast`. |
| "are we breaching any policies?" / "what would CI block?" | Full run; lead with the policies section. |
| "only what's reachable in production" | `--runtime`. |
| "give me JSON / CSV" | `--format json` / `--format csv`. |
| a custom format ("group by team", "exec one-pager") | Transform from `report.json`; keep every number traceable. |
| "fix …" (their security issues) | Not this skill — hand to `kodem-backlog-fix`, scoped to exactly what they asked. |
| "what can you do?" | Explain the plugin's three skills (prevention / backlog-fix / report). No data pull. |

**Ordering rule**: the findings list is grouped by severity with
runtime-reachable first and **Kodem Score** ranking within each group; the
top-priorities list is Kodem Score order, with policy-breaching issues boosted
and Kai false positives demoted. A user's scope is a *filter* on that layout,
never a different sort.
