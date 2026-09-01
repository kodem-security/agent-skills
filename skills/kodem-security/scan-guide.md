# Scan Execution Guide

## Running the scan

Run the scan script. It handles PATH setup, baseline creation, SCA, SAST,
and cleanup automatically:

```bash
${CLAUDE_SKILL_DIR}/scripts/scan.sh <repo-root>
```

Windows / PowerShell-only:

```powershell
${CLAUDE_SKILL_DIR}/scripts/use-bash-windows.ps1 scan.sh <repo-root>
```

**CRITICAL**: Always use the full path directly — do NOT assign to a variable,
as that breaks the tool-approval allowlist.

The script outputs open-source and code results sequentially. If kodem-cli
is not found, it prints an error with install instructions — relay that to
the user and stop.

If both scans fail with auth errors, tell the user to run `kodem-cli auth
login` to complete the browser OAuth flow.

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

- If **yes**: run the installer, then re-run the scan **once** with the same
  arguments and use the fresh results.

  ```bash
  ${CLAUDE_SKILL_DIR}/scripts/install.sh
  ```

  Windows / PowerShell-only:

  ```powershell
  ${CLAUDE_SKILL_DIR}/scripts/use-bash-windows.ps1 install.sh
  ```

- If **no**: proceed with the results already in hand.

Do this at most **once** — never loop on the update notice. If the marker
reappears after updating, do not update again. This usually means the new
binary is shadowed on PATH by an older copy; the installer prints a
`WARNING: an older kodem-cli at <path> shadows the update` line naming the
file to remove. Surface that path to the user, then continue with the
current results.

## Reading results

The CLI outputs human-readable text. Open-source results show a table with
Package, Version, CVE, Severity, and Fixed In (some CLI versions also include a
CVSS column). Code results show File, Severity, CWE, description, and fix
guidance. Which policy status markers actually appear depends on the tenant's
configured policies — a tenant may only ever emit `[PASSED]`/`[FAILED]`.

**Policy enforcement:**
The scan script passes `--code-repository-name` and `--policy-type all` so
kodem-cli evaluates both **CI policies** (the same rules CI enforces) and
**SCM policies** (the rules that would block a PR/MR merge in GitHub/GitLab/
Azure DevOps). Either category can fail the scan — the worst verdict wins,
so a passing CI policy will not rescue a failing SCM one.

Each policy line in the output is prefixed with its origin and category, e.g.
`[CI · Open Source]` or `[SCM · Code]`. Status markers:
- `[PASSED]` — no policy violations, safe to commit
- `[FAILED]` — findings blocked by policy, must fix; each blocked finding is
  listed under the policy on its own line
- `[WARN AND PASS]` — violations found but policy action is warn-only
- `[PARTIAL]` — some conditions couldn't be evaluated locally (e.g. runtime
  reachability, KAI confirmation); the evaluated conditions still pass, but
  mention the gap so the developer knows the server may decide otherwise
- `NOT FOUND` — no policy configured for this repo in either CI or SCM

The script's wrapper exit codes are:
- `0` — clean OR non-blocking findings (status in trailer line)
- `5` — policy-blocked findings; caller should block the action
- `10` — scan errored (CLI ran but did not produce usable results)
- `11` — CLI missing and install failed; caller should not block

A trailer line `KODEM_RESULT: <status>` is always emitted — values: `clean`,
`warn`, `blocked`, `scan-error`, `cli-missing`.

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
