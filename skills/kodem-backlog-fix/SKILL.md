---
name: kodem-backlog-fix
description: "Fix a repo's EXISTING Kodem security backlog — the open SCA and SAST issues already in the Kodem platform — prioritized by Kodem Score (runtime reachability + exploitability + severity). Use this whenever a developer asks to fix, triage, or work through their security issues/backlog/vulnerabilities: 'fix my issues', 'fix the backlog', 'fix all critical and high', 'fix the runtime-reachable ones', 'just the dependencies', 'fix everything from lodash', 'grab the quick wins', 'fix CVE-2024-3094', a pasted Kodem issue link, or 'fix the issue on <ticket_id>'. This is DIFFERENT from the prevention scan (which only checks the diff you just wrote) — this pulls and fixes issues that already exist in the repo. Requires Kodem platform access (OAuth or API key)."
allowed-tools:
  - Bash(kodem-cli:*)
  - Bash(git remote:*)
  - Bash(git config:*)
  - Bash(git rev-parse:*)
  - Read
  - Edit
---

# Kodem Backlog Fix

Fix the security issues that already exist in a repo's Kodem backlog, in the
order that actually reduces risk. This is the developer-invoked counterpart to
the prevention scan: prevention stops *new* issues in the diff; this clears the
*existing* backlog.

The goal is **real risk reduced**, not findings closed. That's why everything is
ordered by **Kodem Score** — Kodem's ranking that weights runtime reachability
most, then exploitability and severity. You lead with what the platform already
knows (the runtime signal only Kodem's sensor has) instead of re-deriving it.

Default behavior for a bare "fix my issues": the **top 10 by Kodem Score**, with
SCA (open-source) filtered to *fixable* and SAST (code) filtered to *not a false
positive*. Anything more specific (see **Supported requests**) narrows or widens
that set.

## Prerequisite: platform access is the floor

This skill reads a repo's triage data from the Kodem platform, so it needs
platform access (OAuth or an API key). Confirm the CLI is present and
authenticated before anything else:

```bash
kodem-cli auth status
```

- **CLI not installed** → install it with this skill's own installer:
  `${CLAUDE_SKILL_DIR}/scripts/install.sh` (the same script
  updates an existing CLI). Running it needs the developer's approval — if they
  decline, say the backlog can't be read without the CLI and stop rather than
  retrying. Otherwise re-run `kodem-cli auth status` and carry on. Only
  if the installer isn't present — skills delivered as separate files rather than
  together — ask the user to install `kodem-cli` from their Kodem onboarding and
  stop until it's available.
- **Not authenticated** → tell the user to run `kodem-cli auth login` (browser
  OAuth) and stop. Without platform access this skill can't run — say so plainly.
  No Kodem skill can: every scan mode needs a valid token, so an expired one stops
  prevention too.

## Step 1 — Identify the repo

Derive the repository name Kodem knows it by. It's usually the `org/repo` from
the remote:

```bash
git remote get-url origin
```

Normalize to `org/repo` (strip the host and any `.git`, e.g.
`git@github.com:acme/store-api.git` → `acme/store-api`). You'll pass this as
`--repository-name` in the next step; the CLI resolves it for you.

If the CLI later reports the repo can't be mapped ("code repository not found"),
**ask the user once** for the Kodem repo name, then **re-run Step 2 with
`--repository-name "<their answer>"`** and reuse that name for the rest of the
session. If it genuinely isn't in Kodem at all, say so and offer to fall back to a
local scan (the prevention skill) — see **Fallback tiers**.

Monorepos can map to several Kodem projects; the issues you get back each carry
their own `projectId`, so a repo that spans multiple projects simply shows
multiple `projectId` values — handle them together.

## Step 1.5 — Resolve the caller's scope

Triage reads are **scoped**. A user with **All Resources** access reads the whole
tenant with no scope specified; a **restricted** user (the majority in many
tenants) can only read within the scopes they're granted, and an unscoped read
fails for them. Resolve this once, up front, so the developer never has to know
or supply a scope:

```bash
kodem-cli scopes list --json
```

Returns `{ "data": { "count": N, "scopes": [ { "id", "name", "isAllResources" } ] } }`.

- **Any scope has `isAllResources: true`** → the caller has full access. Run Step 2
  **as-is, without `--scope-id`**. Done — skip the fan-out entirely.
- **Every scope has `isAllResources: false`** → the caller is restricted. Keep all
  the scope `id`s and run Step 2's reads **once per scope**, adding
  `--scope-id <id>`, then aggregate (below). Never ask the developer to pick or
  pass a scope — resolving it for them is the whole point.
- **Empty list** → the caller has no scopes and can't read this tenant's backlog.
  Say so and offer the agent-native fallback (see Fallback tiers).
- **`scopes list` isn't a known command, or 404s** → the installed `kodem-cli`
  predates scope resolution. Update it per the **unknown command / unknown flag**
  reaction in Step 2. If it still isn't available, run Step 2 once without
  `--scope-id`: that works for all-resources callers, and a 403 then means this
  developer needs the newer CLI to read a restricted backlog — say so plainly
  rather than treating the missing command as fatal.

### Fan-out and aggregate (restricted callers only)

Run the Step 2 `issues list` (and `quick-wins`) with `--scope-id <id>` for each
resolved scope, then combine into one set:

- **Dedup by issue `id`.** A repo/resource can belong to more than one scope, so
  the same issue comes back from multiple calls — merge, don't concatenate.
- **Re-rank and re-limit *after* merging.** Pass `--limit 0` on each per-scope call
  and apply the user's limit only at the end: merge, dedup, sort by `kodemScore`
  descending, **then** take the top N. This is the one place you deliberately don't
  push `--limit` onto the command — a per-scope limit truncates each list before
  the merge, so a high-scoring issue in one scope can lose to lower-scoring ones in
  another. Every other filter (severity, package, …) still goes on every call.
- **Judge each scope by whether the call succeeded, not by how many issues it
  returned.** The two outcomes are different:
  - **403 / non-zero exit** → that scope can't read this repo. Skip it, continue
    with the others. Expected, not a failure.
  - **`success: true` with `count: 0`** → the read *worked*; that scope simply has
    no open issues for this repo. Also skip it, but it still counts as a
    **successful** read.
- **Fall back only if _every_ scope 403'd.** If at least one scope returned
  `success: true`, you have a valid answer — even when the merged set is empty.
  An empty merged set after successful reads means "no open issues", which is good
  news to report plainly; it does **not** mean unauthorized, so don't drop to the
  agent-native fallback (see the "Not authorized" tier).
- **Quick Wins** are project-scoped: for each scope that returned issues for the
  repo, run `kodem-cli issues quick-wins --project "<projectId>" --skill-trigger
  --json --scope-id <that scope id>`; if several scopes cover it, dedup wins by
  their id. Never sum counts across scopes — dedup.

Steps 3–6 operate on the merged, deduped, re-ranked set; they don't care that it
came from several calls.

## Step 2 — Pull the prioritized backlog

Read the open issues, already ordered by Kodem Score (highest first). Always pass
`--skill-trigger` (marks the read as skill-driven for usage attribution) and
`--json` (machine-readable):

```bash
kodem-cli issues list --repository-name "<org/repo>" --skill-trigger --json --limit 30
```

Scope handling follows Step 1.5: an all-resources caller runs this command exactly
as written; a restricted caller runs it once per scope with `--scope-id <id>` and
merges per Step 1.5's rules.

**Push the user's narrowing onto the command — don't fetch broad and filter
locally.** The CLI filters and sorts by Kodem Score *before* it truncates to
`--limit`, so a matching issue ranked past the window is silently dropped if you
filter after the fact. Add the matching flag instead (`--limit 0` pulls everything).
(The one exception is `--limit` when fanning out over several scopes — see the
note under the command below.)

| The user scoped by | Flag | Match |
| --- | --- | --- |
| severity | `--severity CRITICAL,HIGH` | comma-separated enum (CRITICAL/HIGH/MEDIUM/LOW) |
| runtime-reachable only | `--runtime` | boolean |
| one package | `--package <name>` | package name (supports version expressions) |
| a CVE / risk id | `--cve <id>` | exact |
| issue type | `--type sca,sast,malicious-package,…` | comma-separated enum(s) |
| a Jira ticket | `--jira <ticket_id>` | exact |
| everything actionable | `--fixable` | boolean |

The command **exits non-zero on every failure**, and prints an error envelope with
it. Still read the envelope rather than the exit code alone: `error.message` carries
the detail you need to tell the developer what went wrong, and a `success:false`
body must never be read as an empty backlog. It always prints a JSON envelope:
- **success:** `{ "success": true, "data": { "project": {...}, "count": N, "total": M, "issues": [...] } }`
- **failure:** `{ "success": false, "error": { "message": "...", "code": N } }` — `message` carries the full detail, so read it.

On failure, react by the message:
- **"code repository not found"** → the repo isn't mapped; handle per Step 1 / the
  Fallback tiers — don't treat it as "zero issues".
- **not authorized / forbidden / HTTP 403** → the scope you queried doesn't cover
  this repo. If you're **fanning out** over the caller's scopes (Step 1.5), just
  **skip that scope and continue** — not every scope covers every repo. Only when
  an **all-resources** read (no `--scope-id`) 403s, or **every** resolved scope
  403s for this repo, does the caller genuinely lack access — switch to the
  **agent-native fallback** (see Fallback tiers). Don't retry the same call.
- **unknown command / unknown flag** → the installed CLI is too old for these
  read commands. Update it with the prevention skill's installer
  (`${CLAUDE_SKILL_DIR}/scripts/install.sh`), then retry once;
  if the reads are still unavailable, say a newer `kodem-cli` is required and stop.
- **token expired** (can arrive with exit 0 — see above) → tell the user to run
  `kodem-cli auth login`, and stop.
- anything else (5xx / network) → **retry once; if it still fails, report the error
  message to the user.**

`count` is what this call returned (bounded by `--limit`); **`total`** is the full
number matching your query. Say **"N of M"** (e.g. "top 30 of 212") — and if
`count < total`, there's more beyond the window, so raise `--limit` (or `--limit 0`)
if you need it.

Each issue carries the signals you rank and present by:

- `kodemScore` — the ranking (issues arrive sorted by it, descending)
- `category` — `sca` or `sast` (derived for you)
- `severity`, `riskId` (CVE), `packageName`, `cwe`
- `riskInsights.runtime` (reachable in production), `riskInsights.exploitMaturity`,
  `riskInsights.internetFacing`
- `fixInsights.hasFixVersion` + `fixVersions[]` — Kodem's computed fix (the
  validated bump), and `fixInsights.remediationEffort` (patch/minor/major)
- `issueKaiAnalysis.isFalsePositive` — **Kai** is Kodem's AI code-analysis engine;
  its verdict says whether a code (SAST) finding is a real issue or a false
  positive. This field is that verdict (SAST only; present only when the org has
  Kai enabled)
- `introducedThroughInsights.isDirect` / `isIndirect`

**Apply the per-type default filter** (unless the user's request overrides it):
- **SCA**: keep only issues with a fix — `fixInsights.hasFixVersion == true` for
  the default set. (`--fixable` is broader: public fix *or* Kodem remediation; use
  it when the user wants everything actionable.)
  **Exception — keep base-image issues regardless.** An issue with
  `introducedThroughInsights.fromBaseImage: true` is fixed by a Dockerfile `FROM`
  bump, not a package version, so `hasFixVersion` says nothing useful about it and
  is often `false`. Filtering on it would drop what is frequently the largest and
  highest-leverage part of a containerised repo's backlog before you ever see it.
- **SAST**: fixability isn't the filter (SAST always ships fix guidance) — the
  Kai verdict is. Drop `issueKaiAnalysis.isFalsePositive == true`. If
  `issueKaiAnalysis` is absent/null, Kai isn't enabled for this org — keep the
  issue but flag that verdicts are unavailable and recommend review before fixing
  (see Fallback tiers).
- An issue with `status: "open"` is open even if it carries a `dismissReason`
  (e.g. an automatic `new_finding_detected`) — treat `status` as the source of
  truth; don't silently drop it.
- **Drop issues under `.claude/skills/` and `.claude/plugins/` only.** Those are
  the two directories Claude Code installs skills and plugins into (locally or
  repo-scoped), so a finding there is in this tool's own installed files, not the
  developer's code. Filter those out before ranking — never propose "fixing" the
  skill's own scripts, and don't count them toward the backlog totals you report.
  **Everything else under `.claude/` is the developer's own code** — `hooks/`,
  `commands/`, `agents/`, `settings*.json` are hand-written by them, and a
  hardcoded credential or command injection in `.claude/hooks/deploy.sh` is a real
  finding. Rank and report those normally.
  **Say what you dropped.** If you excluded any issue under those two directories,
  state how many and that they are the tool's own files — a total that silently
  disagrees with the platform's is worse than a slightly longer sentence.

Then take the top N by Kodem Score (default 10).

**Quick Wins** — a single dependency/base-image update that clears several issues
at once. Pull them for the repo (the `projectId` comes from any issue in step 2):

```bash
kodem-cli issues quick-wins --project "<projectId>" --skill-trigger --json
```

Each quick win has `dependencyName`, `currentVersion` → `fixVersion`,
`totalIssues` (how many issues it clears), and `aggregateKodemScore`.

**Policies — surface, never gate.** Kodem policies (the **CI** rules that gate a
build and the **SCM** rules that block a PR/MR merge) ride on the scan, not on
`issues list`. Read them the way the prevention skill does — a policy-aware scan
of the repo, which doubles as your **before** snapshot for this run:

**Run both variants.** The subcommand selects the policy family, and
`--policy-type all` does not widen it: `open-source` returns only the two Open
Source verdicts and `code` only the two Code verdicts. Running one and reporting
its result reads as a clean bill of health on the other, so a repo with four
policies would be described as having two.

```bash
kodem-cli scan code-repository open-source <repo-root> \
  --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
  --description "backlog-fix: baseline"

kodem-cli scan code-repository code <repo-root> \
  --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
  --description "backlog-fix: baseline"
```

Merge the verdicts from both before reporting anything. If one variant errors,
say which side did not answer — that is not the same as it passing.

If either scan prints a `KODEM_UPDATE_AVAILABLE: <version>` trailer, a newer
`kodem-cli` exists. Finish what you're doing first — the current results are still
valid — then offer the update once, using the same installer as the prerequisite.
Never loop on it: if the trailer reappears after updating, an older copy is
shadowing the new one on PATH and the installer names the file to remove.

Read the verdict lines — each prefixed with its origin/category (`[CI · Open
Source]`, `[SCM · Code]`) and a status: `[PASSED]` / `[FAILED]` / `[WARN AND PASS]`
/ `[PARTIAL]`, or `NOT FOUND` when no policy is configured. The worst verdict wins
— a passing CI policy won't rescue a failing SCM one. Use it to:

- **Surface** which policies apply (name CI vs SCM distinctly) and what's currently
  breaching them, in the orientation (Step 3). **Tag SCA and SAST findings alike.**
  Code findings breach `[CI · Code]` / `[SCM · Code]` exactly as dependency findings
  breach the Open Source pair; a plan where every SCA item carries a policy tag and
  no SAST item does means the code scan was never run, not that code findings breach
  nothing.
- **Inform ordering** — a policy-breaching issue rises within the Kodem-Score
  order — but **never to gate the set**: a high-score issue that breaches no policy
  is still in scope, and policy never removes issues from consideration.
- `NOT FOUND` (no policy configured for the repo) → say plainly there are none to
  surface, and rank on Kodem Score + the per-type filter as usual.

## Step 3 — Orient, then show the plan

Open with a **short, plain read** on where the repo stands — not a wall of
findings. Two or three sentences: how many real risks are open, how many are
runtime-reachable, **which policies (if any) are breaching**, and any Quick Win
worth calling out. Then the plan: **one line per item**, grouped so the safe,
high-impact work is obvious:

```
Kodem backlog for acme/store-api — 35 open SCA (fixable), 14 SAST (Kai-confirmed)
Policy: CI Open-Source FAILED (2 findings breach) · SCM Code PASSED
Top runtime-reachable, highest Kodem Score first:

Safe fixes (auto-applicable):
  [HIGH · runtime · policy · score 727]  bump lodash 4.17.11 → 4.17.21  (CVE-2021-23337)
  [MED  · runtime · score 636]           bump axios 0.21.0 → 0.21.4     (CVE-2021-3749)
Quick Wins (one update clears several):
  bump node 20.10.0 → 20.20.2 — clears 1830 issues (aggregate score 542391)
Needs your review (major bump / code change):
  [CRIT · score 664]  express 3.x → 4.x (breaking) — SSRF, review before applying
```

Mark the issues that breach a policy (e.g. a `policy` tag as above) so the
developer sees what CI/SCM would block — but remember policy informs order, it
doesn't shrink the set.

Show, per item: severity, a runtime indicator when present, Kodem Score, what it
is, and Kodem's computed fix (the exact bump). Group into **safe fixes**, **Quick
Wins**, and **needs review**. Keep it scannable.

## Step 4 — Confirm

State the inference you made ("Defaulting to the top 10 by Kodem Score — SCA
fixable, SAST Kai-confirmed") and ask: **"Fix these? (or: broader / narrow /
pick specific ones)."** Safe SCA bumps you'll auto-apply; SAST and major bumps
you'll show and let them decide.

## Step 5 — Apply the fixes

Use **Kodem's computed fix** (`fixVersions`), never a guessed version — it's the
validated bump that lowers breaking-change risk and includes base-image updates a
local scan never sees.

**Check the base image before working through packages one by one.** On a
containerised repo it is usually the largest share of the backlog and one `FROM`
line clears many issues at once, so it is the first thing to *look at* — but it does
not change the ranking (see Ordering rule) and it is **never auto-applied** (see
Out of scope): always surface it and let the developer decide.

- **Recognise them:** `introducedThroughInsights.fromBaseImage`. The flag is
  tri-state like `isDirect`/`isIndirect` — `true`, `false`, or absent/`null`
  meaning unknown. Treat only `true` as confirmed, and don't assume `null` means
  "not from the base image". The package is not in any manifest you can edit — it
  ships inside the image, so a manifest bump cannot clear it. The fix is the
  Dockerfile: bump the `FROM` line, or pin the OS package inside the image.
- **Report Kodem's computed bump:** `baseImageFix` carries `image`, `tags` and
  `digest`. **The tags are aliases of that one digest, not alternative fixes** —
  name whichever tag matches the style already in the Dockerfile (`12.15` vs
  `bookworm`), or `image@digest` if the Dockerfile already pins by digest. Keep the
  existing convention; never propose converting a tag pin to a digest pin uninvited.
- **`baseImageFixCount` > 1** means the fix differs across images and `baseImageFix`
  is only the first. **The field is never 1** — absent or `0` means "zero *or
  exactly one*" distinct fix, so don't read `0` as "no fix".
- **`baseImageFix` absent does NOT mean no fix exists.** The CLI only populates it
  from an expanded per-issue lookup, and that lookup is skipped or lost in several
  ordinary situations: a resource-scoped project id (one prefixed `cimg_`, `vm_` or
  `app_` — a container image is exactly that) never queries it at all; a failed
  lookup is swallowed and the issues come back without it; and `--limit` truncates.
  So on a container-image project expect it to be missing and say so. Report the
  count of base-image findings and that the target image was not returned; check
  the Dockerfile's current `FROM` and the image's own registry tags to give the
  developer something concrete. **Never invent an image, tag or digest.**
- **Say what it will not do locally:** the finding clears once the image is rebuilt
  and the new one is deployed, not when the Dockerfile is saved.

**Deciding what's safe to auto-apply vs. what to show first.** The signal that
matters is the size of the version jump. Determine the bump type by comparing the
current version to the fix (`fixVersions[0]`) as semver. Take the current version
from the **manifest as it is right now**, not the CLI's `packageVersions[0]` —
that field reflects the state at Kodem's last scan and can lag the working tree,
so trusting it blindly can make you write a redundant edit or even a *downgrade*.
Read the manifest, reconcile it against the CLI's version, and never write a
version lower than what's already there:

- **patch** (only the z in x.y.z changes, e.g. 4.1.0 → 4.1.1) or **minor** (the y
  changes, e.g. 1.4.0 → 1.7.0) → **safe: auto-apply** by editing the manifest, and
  tell the developer what changed.

**Editing a lockfile by hand is narrower than editing a manifest.** A lockfile is a
resolved dependency graph with integrity hashes, so hand-editing is only sound when
**both** hold: the package is a **leaf** (nothing else in the tree depends on it, so
no other entry's constraints are invalidated), and you can write a **real integrity
hash** fetched from the registry (`npm view <pkg>@<ver> dist.integrity`) rather than
inventing or dropping one. If either fails, edit the manifest only and tell the
developer to run the ecosystem's install command to regenerate the lock — a lockfile
with a wrong or missing hash is worse than one you left alone, because `npm ci` will
refuse it or silently install something else.
- **major** (the x changes, e.g. 1.x → 2.x), or versions you can't confidently
  parse as semver → **show first** and let the developer decide, since majors
  carry breaking changes.

`fixInsights.remediationEffort` is a helpful supplement, but it's often
`"unknown"` — don't gate on it; fall back to the semver comparison above.

**One package, both a safe and a major fix in the same set** (e.g. three CVEs on
one package needing 0.12.3, 1.0, and 2.2.5): the manifest holds one version, so
the per-issue rules can't both apply. **Defer the whole package to review**,
presenting one decision with the fallback built in: "bumping to 2.2.5 (major)
clears all three; if you don't want the major now, I'll apply 0.12.3 which
clears CVE-X." Never auto-apply the safe bump first and then ask about the major
— that writes the same line twice and contradicts the no-redundant-edit rule.

- **All SAST fixes**: present the guidance and let the developer decide — never
  silently rewrite code logic. Even for hardcoded secrets, don't auto-rewrite:
  moving a secret to an env var can break production code that reads it. Flag it
  prominently and **offer** the fix (move to an env var, add to `.gitignore`,
  rotate the secret); **apply it yourself once the developer approves**.
- **If the end-of-turn security gate blocks, it does not widen your approved
  scope.** The gate scans what changed this turn and can surface findings the
  developer never approved you to touch — including pre-existing ones in files
  outside the plan. Apply its dependency and manifest fixes; for **code-logic**
  findings outside the approved set, report them and ask, exactly as this step
  requires. The gate is a reminder, not an approval, and "the gate told me to" is
  not consent. If it keeps blocking on findings you have not been cleared to fix,
  stop after the second cycle and hand them to the developer — never keep editing
  to make a gate go quiet.
- **Direct vs. transitive** (`introducedThroughInsights`): a **direct** dependency
  is fixed by bumping its version in the manifest; a **transitive** one needs a
  pin using the ecosystem's own mechanism. Two flags, so four cases — decide by
  what the manifest says, never by guessing:
  - `isDirect` true, `isIndirect` false → bump it in the manifest.
  - `isDirect` false, `isIndirect` true → pin it (table below).
  - **both true** → it is genuinely both: listed in the manifest *and* pulled in
    again through another dependency. Bump the manifest line, and say that other
    dependencies also require it, so the installed version may not move until
    those are updated too — check the resolved tree afterwards and add a pin if it
    didn't move.
  - **both false or absent** → the path is undetermined. Read the manifest: edit
    the version there if the package is listed, otherwise pin. Say which you chose
    and that the platform did not report the path.

  **When you take the pin path, tell the developer explicitly** — it's less obvious
  than a direct bump and they may need to reconcile it with their dependency
  tooling. The pin mechanism and the regenerate step, per ecosystem:

  | Ecosystem (manifest) | Transitive pin | Takes effect after |
  | --- | --- | --- |
  | npm (`package-lock.json`) | `overrides` in package.json | `npm install` |
  | pnpm (`pnpm-lock.yaml`) | `pnpm.overrides` in package.json | `pnpm install` |
  | yarn (`yarn.lock`) | `resolutions` in package.json | `yarn install` |
  | Go (`go.mod`) | explicit `require`, added by `go get <module>@<version>` | `go get` (it writes `go.mod` **and** `go.sum`) |
  | Python (`requirements*.txt`) | add a direct pin line, or a constraints file | `pip install -r requirements.txt -c constraints.txt` |
  | Python (poetry `pyproject.toml`) | pin in `[tool.poetry.dependencies]` | `poetry lock && poetry install` |
  | Python (uv `pyproject.toml`) | `constraint-dependencies` under `[tool.uv]` | `uv lock` |
  | Maven (`pom.xml`) | `dependencyManagement` entry | `mvn dependency:tree` to verify, then a build |
  | Gradle (`build.gradle*`) | `resolutionStrategy.force` (or a platform/BOM) | `gradle build` |
  | Ruby (`Gemfile`) | add an explicit `gem` pin | `bundle lock --update <gem>` |
  | Rust (`Cargo.toml`) | `cargo update -p <crate> --precise <version>`; see the note — a dependent's ceiling cannot be overridden from your own manifest | `cargo generate-lockfile` if there is no lock yet, else the update command itself |
  | PHP (`composer.json`) | add an explicit `require` pin | `composer update <pkg>` |

  Four rows are easy to get wrong, so they are spelled out:
  - **Rust** — `cargo update -p <crate> --precise <version>` is the mechanism, and it
    works whenever the fixed version satisfies *every* dependent's requirement, which
    is the normal case for a semver-compatible security patch. Run `cargo tree -i
    <crate>` first to see who requires it and at what range.
    When some dependent caps the version *below* the fix, `--precise` fails with
    `all possible versions conflict with previously selected packages`. **Adding the
    crate to your own `[dependencies]` does not rescue that** — Cargo resolves to the
    highest version satisfying the *intersection* of all requirements and will not
    hold two semver-compatible copies, so your entry only raises the floor, it cannot
    exceed someone else's ceiling. The two things that do work: bump or replace the
    capping dependent, or `[patch.crates-io]` pointing at a **git or path fork**
    carrying the fix — a patch to the same source is rejected, and the fork's declared
    version must stay inside the existing requirement range or Cargo reports
    `patch ... was not used in the crate graph` and silently changes nothing.
    The pin lives in `Cargo.lock`, so **commit it** — and if this crate is published,
    consumers ignore your lock, so only a `[dependencies]` floor bump reaches them.
  - **Go** — a `replace` directive works for an application but does **not**
    propagate to anyone who imports your module. Since Go 1.17 the idiomatic pin is
    an explicit `require`. Hand-editing `go.mod` alone **breaks the build**: it fails
    with `missing go.sum entry` until `go get <module>@<version>` (or `go mod
    download <module>`) writes the hash. If you cannot run those, say so plainly
    rather than leaving a repo that no longer compiles. One limit worth stating: a fix
    published at v2 or later changes the module path (`/v2`), so an explicit `require`
    cannot pin across a major — the dependent keeps importing the old path and both
    modules coexist silently. That needs the dependent updated.
  - **uv** — uv has no `[tool.uv.dependencies]`. Constraints live in
    `constraint-dependencies` under `[tool.uv]`; those must stay satisfiable, so when
    a dependent caps the version below the fix use `override-dependencies` instead.
  - **Python constraints files do nothing without `-c`** — a constraints file that is
    never passed to `pip install` is silently ignored.

  For JS, pick the syntax from the **lockfile actually present**, not from a
  `packageManager` field — the two can disagree. A pin only takes effect once
  the lockfile/build is regenerated (right column); this skill doesn't run
  package managers, so say plainly that the manifest is fixed but the developer
  must run the regenerate step for it to take effect (and to show on the next scan).
- **No lockfile present at all** (not "needs regenerating" — the ecosystem's lock
  file is simply absent, e.g. a `package.json` with no `package-lock.json`
  anywhere in the repo): don't edit the manifest and treat it as done. A version
  bump with nothing to lock it never resolves to a concrete tree, so it can drift
  from what actually installs and won't verify on the next scan. Say so plainly
  and tell the developer to run the ecosystem's install command first (`npm
  install` / `pnpm install` / `yarn install`, etc.) to generate one — same
  install commands as the "takes effect after" column above, just run once
  before the edit instead of after. Two ecosystem notes: for Rust the command is
  `cargo generate-lockfile` (or `cargo build`), and **this rule does not apply to
  Go** — `go.sum` is a checksum file, not a resolved-graph lock, so a Go repo with no
  `go.sum` is not blocked by it; `go get` writes both files together.
- **Before a version change, check interdependencies** across the tree so the
  bump won't break the build — a fix that fails CI helps no one.

## Step 6 — Verify, then hand back

Verification has two halves and **both are required**: the repo's own tests prove
the code still works, and the re-scan proves the findings cleared. A re-scan alone
says nothing about whether the code still runs.

### 6a — Run the repo's tests

**Identify the suite during Step 3, before you edit anything, and run it once then**
— a baseline you take after editing cannot tell a pre-existing failure from one you
caused. If you only think of it now, run it anyway and say the baseline is unknown.

Look for the test command in: a `Makefile` target (`make test`), `package.json`
`scripts.test` (`npm test`), `pytest` / `python -m unittest discover`, `go test
./...`, `cargo test`, `mvn test`, `./gradlew test`, or a CI config
(`.github/workflows/*.yml`, `Jenkinsfile`) naming one.

**Running it needs the developer's permission** — a test command executes code from
the repo, so it is not on this skill's auto-approved list. Ask once, plainly: "I'd
like to run `<command>` to check these changes." If they decline, that is a fine
answer; record that tests were not run. **Read an unfamiliar target before running
it** — `make test` sometimes drops and recreates a database. If it needs a database,
a network service, or looks destructive, say so and let the developer run it.

Run it **once after all your edits**, not after each one. Two runs total is the
budget: one baseline, one after. Long suites are common; don't spend the developer's
time re-running a 30-minute suite per edit.

Then report what actually happened, in the suite's own words:

- Green before and after → say the suite passed and quote its own summary line.
  **Don't invent a count** — most runners don't print `N/N`; use what it printed.
- It broke after your change → **fix it or revert that edit** before handing back.
  Never hand back a red suite as done.
- Already red at baseline → say so, name the failures, and state plainly that the
  suite could not verify your change.
- **No suite exists** → say "no test suite found; these changes are unverified by
  tests". Then do what you can without one: for a dependency bump, check the package
  imports and the entrypoint still starts. Say which check you ran.
- Multiple suites (a monorepo) → run the one covering the files you changed, and name
  which one you ran and which you didn't.

**Never claim "verified", "tested", "confirmed" or "no regressions" when you ran
nothing capable of detecting one.** A policy re-scan finds vulnerabilities, not
breakage — it is not a regression test. If no suite ran, say exactly that.

**Coverage is a real limit, so state it.** If you changed a file the suite does not
import, a green run does not cover that file — name those files rather than letting a
green suite imply they were checked.

### 6b — Re-scan

Re-scan to confirm the fixes landed and caught no regressions. Write the intent
into the scan reason so the platform records before/after and attributes the run
to the skill:

```bash
kodem-cli scan code-repository open-source <repo-root> \
  --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
  --description "backlog-fix: <what you changed, e.g. bumped lodash, axios>"

kodem-cli scan code-repository code <repo-root> \
  --code-repository-name "<org/repo>" --policy-type all --skill-trigger \
  --description "backlog-fix: <what you changed>"
```

**Both, for the same reason as the baseline** — and note the direct consequence: an
open-source re-scan cannot see a SAST fix. If you changed code and only re-scanned
open-source, you have not confirmed anything you did; say so rather than reporting
the fix as verified.

Read the result the same way as the Step 2 baseline: the `[CI · …]` / `[SCM · …]`
policy verdict lines plus the `KODEM_RESULT: <clean|warn|blocked>` trailer; the
scan exits non-zero when it errors or a policy blocks. Do at most **two**
fix→re-scan cycles; if issues remain, show them and ask how to proceed.
**That budget is shared with the end-of-turn gate**, which re-scans at the turn
boundary and also caps itself at two. Count its rounds as your own: two cycles in
total across both, not two each. If the gate blocks after you have already used the
budget here, hand the remaining findings to the developer instead of editing again.

Then hand back:
- Summarize what changed and what's left.
- **State the test result explicitly** — the command you ran and its outcome, or
  that no suite exists. A summary that says "verified" without naming what verified
  it is not acceptable.
- **Report policy before → after** if any policy was breaching at baseline
  (e.g. "CI Open-Source policy: FAILED ❌ → PASSED ✅" or "still failing — 1
  finding left"). If policy was `NOT FOUND`, there's nothing to report here.
- Leave the changes in the **working tree** — never commit or push automatically.
- Offer to open a PR if they want one.
- **State the runtime-resolution expectation plainly:** issues resolve in Kodem
  once the fix is *deployed* and the sensor stops seeing the vulnerable component
  in runtime — not the moment you commit. So the backlog won't drop to zero in
  the platform immediately; that's expected.

## Supported requests (free text → what you do)

| The user says | What you do |
| --- | --- |
| "fix my issues" / "fix the backlog" *(default)* | Top 10 by Kodem Score, SCA fixable + SAST Kai-confirmed. State the inference. |
| "fix all my issues" / "everything fixable" | Every safely-fixable issue, runtime-ordered. |
| "fix all critical and high" | `--severity CRITICAL,HIGH`, fixable, runtime-first. |
| "fix runtime high and critical" / "only the reachable ones" | `--runtime` + severity; runtime-reachable only. |
| "just the dependencies" / "only SAST" | `--type sca` or `--type sast`. |
| "fix everything from lodash" | `--package lodash` — all of that package's issues, together. |
| "just the safe patch bumps" | Fixable issues whose `remediationEffort` is `patch`, applied together. |
| "grab the quick wins" | Pull the repo's Quick Wins. Apply dependency ones like any safe bump; for a base-image Quick Win, update the Dockerfile `FROM` line (this counts as the explicit ask — see Out of scope). |
| "fix my policy violations" / "fix what's blocking CI" | Read the policy verdict from **both** Step 2 scans, scope to the issues under each `[FAILED]` CI/SCM policy, fix those first. **Code policies count** — a repo can breach `[CI · Code]` / `[SCM · Code]` as well as the Open Source pair, and those breaches are usually SAST findings, which still follow Step 5's approval rule rather than being auto-applied. If `NOT FOUND` on both, say there are no policies configured and offer the default fix instead. |
| "fix CVE-2024-3094" | `--cve CVE-2024-3094`. Say so if absent or not fixable. |
| "fix the lodash prototype pollution one" | Fuzzy-match by package/CWE/title — pull the full backlog first (see note), confirm the match, then fix. |
| a pasted Kodem issue link | Decode the issue id from the `g` query param (base64 → JSON `{"id": "..."}`), then locate that exact issue (see note) and fix it. |
| "fix the issue on <ticket_id>" (Jira) | `--jira <ticket_id>` — the issue(s) linked to that ticket. |
| "fix 30 issues" | `--limit 30` instead of 10. |
| "what's my posture?" / "what should I prioritize?" / "full report" | Read-only — not this skill: hand to the **kodem-report** skill (same data pull, zero changes, ends by offering to hand back here). |

**Ordering rule:** always rank by **Kodem Score** (the CLI's default order). A
user's specific ask (runtime-only, critical/high, one package) is a *filter*
applied on top of that order — never a different sort.

**Note — locating one specific issue (pasted link, fuzzy match).** There's no
"fetch one issue by id" command, and the default list is capped by `--limit`. So
when the user points at a *specific* issue (a decoded link id, or a fuzzy
description like "the lodash prototype-pollution one"), pull the **full backlog
with `--limit 0`** and match within it — otherwise the target may sit past the
default window and you'd miss it. Match a decoded link id against `issues[].id`
(the issue's `uiLink` carries the same `g` param, a useful cross-check); match a
fuzzy description against `packageName` / `cwe` / `riskId`. Narrow with a filter
first when you can (e.g. `--package lodash` for "the lodash one") to keep the set
small, then match.

## Fallback tiers — always state which tier you're in

The skill never silently does less; it says what context it has.

- **Full** (connected, mapped, Kai enabled): full value — rank and fix as above.
- **No runtime / no correlation** (no sensor, or code repo and image not
  correlated): rank by the remaining Kodem Score inputs (exploitability,
  severity) plus Kai verdict and fixability, fix, and **say there's no runtime
  context** so priorities are best-effort.
- **Repo not mapped** (never scanned in Kodem): ask once for the repo name; if
  it truly isn't in Kodem, fall back to a local scan (prevention skill) and offer
  to connect it.
- **Not authorized for this repo** (403 / insufficient scope — authenticated, but
  **no scope the caller holds covers this repo**): reached only after Step 1.5's
  scope resolution — i.e. an all-resources caller 403'd, or a restricted caller's
  scopes were all tried and none covered the repo. The CLI can't read this repo's
  triage data, and re-calling it won't help. **Don't use the CLI** — do a
  best-effort **agent-native** pass instead: read the repo's manifests and
  lockfiles yourself (package.json/lock, go.mod, requirements/poetry, pom.xml,
  Gemfile.lock, etc.), flag the dependencies you recognize as vulnerable, and
  propose fixes — auto-applying only safe **patch/minor** bumps and showing majors
  for review, exactly as in Step 5. Say plainly this is **best-effort with no Kodem
  context** (no Kodem Score, runtime reachability, Kai verdict, validated fix
  version, Quick Wins, policy, or before/after re-scan), so ordering is by your own
  judgment of severity — and recommend getting scope access to unlock the full,
  runtime-ranked flow. Don't fabricate certainty you don't have.
- **Kai not enabled**: no code verdict, so you can't filter SAST
  confirmed-vs-false-positive — rank SAST by Kodem Score / severity, flag that
  verdicts are unavailable, and recommend review before fixing.
- **No policies configured** (`NOT FOUND`): nothing changes about the fix flow —
  still rank by Kodem Score + the per-type filter — just say there are no policies
  to surface.
- **No platform access**: this skill can't run (say so). Prevention still works
  locally on the diff.

## Out of scope

Don't auto-commit or auto-merge, and don't mark issues resolved from the skill
(runtime earns that).

**Base-image Quick Wins:** never mutate a built/pushed image, and never fold a
base-image bump into the auto-applied safe-bumps pass — it's a Dockerfile `FROM`
change, not a dependency bump. Always **surface** it (it's often the highest-
leverage item). Editing the `FROM` line is a source change you may make **only
when the developer explicitly asks for it** (e.g. "grab the quick wins" or a
direct yes) — otherwise present it and let them apply it.
