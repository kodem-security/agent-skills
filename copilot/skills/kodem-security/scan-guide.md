# Scan Execution Guide

`<skill-dir>` below is this skill's base directory: the folder that contains this file. Use its absolute path in commands.

## Running the scan

Run the scan through kodem-cli. It handles the baseline, both scans and cleanup, in
any shell:

```bash
kodem-cli agent scan <repo-root>
```

**CRITICAL**: Always use the full path directly — do NOT assign to a variable,
as that breaks the tool-approval allowlist.

The scan prints open-source and code results in turn. It never installs or
updates kodem-cli itself:

- **`kodem-cli` not found** — it may be installed but not on this session's PATH
  yet. Right after an install in this session, call it by the path the installer
  printed (`kodem-cli installed at <path>`): `"<path>" agent scan <repo-root>`, or
  `& "<path>" agent scan <repo-root>` in PowerShell. Otherwise try the installer's
  default folder: `"$HOME/.local/bin/kodem-cli" agent scan <repo-root>`, or
  `& "$env:USERPROFILE\.local\bin\kodem-cli.exe" agent scan <repo-root>` in
  PowerShell. Only if that isn't there either is kodem-cli not installed: ask the user whether to
  install it. If yes, run the installer (below), then re-run the scan once, and
  tell the developer to restart the agent: until then its end-of-turn check can't
  find kodem-cli and doesn't run. If no, stop.
- **The first code scan takes longer**: kodem-cli downloads its code scanner
  (opengrep) by itself, or replaces an older one. Nothing to ask the developer.
- **Code scan errors with `0xc0000135` or exit code `3221225781`** (Windows) — the
  code scanner can't start because the Microsoft Visual C++ Redistributable (x64) is
  missing. Tell the developer to install it
  (https://aka.ms/vs/17/release/vc_redist.x64.exe), and report the open-source
  results meanwhile.

- **`KODEM_RESULT: auth-required`** — see **Signing in** below.

## Signing in

Signing in is the developer's step, never yours. Don't run `kodem-cli auth login`
yourself: it opens a browser and waits up to five minutes for the sign-in, in a
terminal the developer can't see. Ask them to run it in their own terminal; if the
browser doesn't open, they open the URL it prints. Where a browser isn't an option,
an API key in the `KODEM_API_KEY` environment variable works instead.

Right after the installer has run, `kodem-cli` is not on PATH yet: the installer
adds its folder to PATH (the user PATH on Windows, the shell profile elsewhere),
which only new terminals see. Tell the developer to open a new terminal before
`kodem-cli auth login`, and to restart the agent so its hooks find kodem-cli. In
this session, call the CLI by the path the installer printed
(`kodem-cli installed at <path>`), as `& "<path>"` in PowerShell.

## Diff baseline

The scan baselines against the **local HEAD**, so it judges only the
working-tree change about to be committed — minimal scope, no dependency on a
fetched/current default branch, and immune to a stale local `main`. Untracked
(non-ignored) files are staged into a throwaway index for the code scan, so a
brand-new file is covered before you `git add` it — the real index and worktree
are left untouched.

## CLI updates

If the scan output contains a trailer line `KODEM_UPDATE_AVAILABLE: <version>`,
a newer kodem-cli build is available. After presenting the scan results (do not
hold them back — the current results are still valid), ask the user whether they
want to update to `<version>`.

- If **yes**: update, then re-run the scan **once** with the same arguments and
  use the fresh results:

  ```bash
  kodem-cli agent update
  ```

  If kodem-cli isn't installed, use the installer.
  macOS and Linux:

  ```bash
  <skill-dir>/scripts/install.sh
  ```

  Windows (PowerShell):

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File "<skill-dir>/scripts/install.ps1"
  ```

- If **no**: proceed with the results already in hand.

Do this at most **once** — never loop on the update notice. If the marker
reappears after updating, do not update again. This usually means the new
binary is shadowed on PATH by an older copy. On macOS and Linux the installer
prints a `WARNING: an older kodem-cli at <path> shadows the update` line naming
the file to remove; the Windows installer doesn't check for this. Surface that
path to the user, then continue with the current results.

If kodem-cli exits with code **137** (`SIGKILL`, often "Code Signature
Invalid") right after an update on macOS, tell the user to close any running
kodem-cli and run the installer again. The installer's
`kodem-cli ... was killed on launch (exit 137)` warning points to the same fix.

## Reading results

The CLI outputs human-readable text. Open-source results show a table with the
package, version, vulnerability (CVE), severity and the "Fixed In" version; newer
CLI versions also show a CVSS column. Code results show File, Severity, CWE, description, and fix
guidance. Which policy status markers actually appear depends on the tenant's
configured policies — a tenant may only ever emit `[PASSED]`/`[FAILED]`.

**Policy enforcement:**
`kodem-cli agent scan` names the repository after the origin remote's full path
(e.g. `acme/store-api`), or the folder name when there is no origin remote. Pass `--repo-name <org/repo>` only when Kodem knows it by
another name. It checks every policy type (`--policy-type all`). Kodem has one
list of policies. Each policy runs on pull requests (SCM), on CI scans, or both,
so kodem-cli evaluates the policies the **CI** rules enforce and the policies
that would block a PR/MR merge in GitHub/GitLab/Azure DevOps/Bitbucket.

**Every matching policy runs.** Each finding gets one result from all the
policies that matched it: Suppress beats Fail, and Fail beats Warn. The scan
fails when at least one finding is failed and not suppressed. Policy order does
not matter, and a passing policy never rescues a finding that another policy
fails.

Newer kodem-cli versions start with a `Policy result: Fail`, `Warn` or `Pass`
block that lists the triggered policies by name and counts the evaluated ones.
That block's `Policy result` is the scan's verdict. Older versions have no
block: read the per-policy lines alone. Each
policy has its own line, prefixed with its origin and category, e.g.
`[CI · Open Source]` or `[SCM · Code]`. A policy's line shows that policy's own
result, so a `[WARN AND PASS]` line next to a `Policy result: Fail` means another
policy fails the scan. Status markers:
- `[PASSED]` — no policy violations, safe to commit
- `[FAILED]` — findings blocked by policy, must fix; each blocked finding is
  listed under the policy on its own line
- `[WARN AND PASS]` — violations found but policy action is warn-only
- `[PARTIAL]` — a condition couldn't be checked here, for example a Kai
  condition, or runtime facts that couldn't be fetched; the checked conditions still
  pass, but mention the gap so the developer knows the server may decide otherwise
- `NOT FOUND` — no open-source policy configured for this repo (the line
  `Policy Status: NOT FOUND`). The code scan prints no such line: no
  `[… · Code]` line and exit 0 means there is no code policy.

Under a policy, `Active Suppression Policies` names the Suppress policies in
play, and `Suppressed Violations` lists the findings they hid with the policy
that did it. Report suppressed findings as suppressed, never as fixed. Never
treat a finding under `Suppressed Violations` as one to fix.

**Policy notes and warnings** are lines that start with `[!] Policy note`,
`[!] Policy warning` or `[!] Suppress policy`. They never change the exit code,
apart from an unknown-action `Policy note`: that policy's action counts as Fail,
so a finding it matches blocks (exit 9). Read them and tell the developer:
- `[!] Policy note: … has a type or action this version does not know …: it
  fails`: an unknown action counts as Fail, so a finding the policy matches
  **blocks**. Suggest `kodem-cli agent update`.
- `[!] Policy warning: … this CLI version cannot read … Update the CLI`: the
  unreadable part, or the whole policy, was skipped and the rest was checked.
  Suggest `kodem-cli agent update`.
- `[!] Suppress policy … unknown key`: that Suppress policy **does
  not suppress**. Its findings still count, so a Fail policy can still block.
  Suggest `kodem-cli agent update`.
- `[!] Policy warning` or `[!] Policy note` ending `not evaluated in CLI`: the
  policy uses a condition only the platform checks, such as an issue or
  advisory age (SLA). Updating does not help. The server decides, so its
  verdict may differ.
- `[!] Policy warning: … Kai results are not available in the CLI`: the CLI
  never has Kai results. In a Protect policy the Kai condition was left out (or
  the group skipped, if it had only Kai conditions). In a Suppress policy the
  warning ends `so that Suppress group hides nothing`: that group hides
  nothing. Updating does not help.
- `[!] Policy warning: the platform's runtime and exploit maturity facts could
  not be fetched`: policies that need those facts weren't checked on them. The
  server may decide otherwise.

How unknown facts are treated (the policy engine owns these rules):
- Unknown dev dependency or unknown direct never matches that condition.
- Unknown runtime counts as a match for `packageInRuntime` in a Protect policy.
- In a Protect policy, a Kai condition with no Kai result is left out, and the
  group's other conditions decide. A Protect group with only Kai conditions
  matches nothing.
- In a Suppress policy, a group with a Kai condition never matches on the CLI
  (the CLI never has Kai results), so it hides nothing.
- "Number of vulnerable packages is at least" no longer exists.

**A policy that could not be fetched is an error, not "no policy".** The scan
exits 1 (`kodem-cli agent scan` reports it as `10`, `scan-error`). Every
kodem-cli version prints `[-] Failed to fetch open-source policies: <reason>`,
or `[-] Failed to fetch code policies: <reason>` for the code scan. Older open-source scans also print `Policy Status: NOT FOUND`
first, and still exit 1. So read the exit code with the text: `NOT FOUND` with
exit 0 means no policy; `NOT FOUND` with exit 1 and a `Failed to fetch` line is
an error. Report which side failed, never say "passed" or "no policy
configured", and do not block the developer on it.

`kodem-cli scan` exit codes are:
- `0` — nothing blocks. With `Policy Status: NOT FOUND` printed, there is no
  policy: say so and report findings by severity.
- `9` — blocked by policy. This is a verdict, not an error. Fix the findings
  under each `[FAILED]` policy.
- `1` (or any other code) — the scan errored, including a policy that could not
  be fetched even if `NOT FOUND` was printed. Say which side failed. Never
  report it as passed or as "no policy".

`kodem-cli agent scan` exit codes are:
- `0` — clean OR non-blocking findings (status in trailer line)
- `5` — policy-blocked findings; caller should block the action
- `10` — scan errored (CLI ran but did not produce usable results)
- `12` — not authenticated; caller should not block

A trailer line `KODEM_RESULT: <status>` is always emitted — values: `clean`,
`warn`, `blocked`, `scan-error`, `auth-required`.

**When policy status is `NOT FOUND`**, report all findings by severity but
do not block the developer — there is no policy to enforce.

## Remediation

### Open-source (dependency vulnerabilities)

Present each policy-blocked finding to the user: package name, current version,
CVE, and the fix version from the "Fixed In" column.

If the fix is a patch or minor version bump (e.g. 2.0.0 → 2.0.1, 1.3.0 → 1.4.0),
apply it automatically — just tell the developer what you changed. For major
version bumps (e.g. 1.x → 2.x), present the finding and let the developer
decide, since major upgrades can have breaking changes.

If no fix version exists, let the user know and suggest an alternative package
if one is obvious.

### Code (code weaknesses)

Present each policy-blocked finding with the fix guidance from the scan output.
Let the developer decide whether to apply. Don't rewrite code logic silently.

Hardcoded secrets are the one case to push hardest on, but still not to rewrite
uninvited: moving a secret to an environment variable can break code that reads it
elsewhere. Flag it prominently, say the secret must be **rotated** (it is already in
git history, so removing it from the file does not undo the exposure), and offer the
fix — move it to an env var, add `.env` to `.gitignore`. Apply it once the developer
agrees.

## Re-scan

If any policy-blocked findings were fixed, run both scans again to confirm the
fixes worked. Do this at most twice. If issues remain after two re-scans,
show the remaining findings and ask the developer what to do.

## Developer summary

After every scan, show this to the developer:

> **Kodem Security Scan**
> - **Status:** Clean / Issues Found
> - **Critical:** N | **High:** N | **Medium:** N | **Low:** N
> - **Findings:** [brief description of what needs attention]
> - **Result:** Ready to commit / Fix required before commit
> - **Setup:** (only if you installed kodem-cli in this session) Restart the agent:
>   until then its end-of-turn check can't find kodem-cli and doesn't run.
