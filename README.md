# Kodem Security Plugin

A Claude Code plugin that lets your coding agent use Kodem: prevention scans on
every diff, developer-invoked fixing of your existing backlog, and read-only
security reports.

It bundles three skills — `kodem-security`, `kodem-backlog-fix`, `kodem-report`
— plus the hooks that make prevention run automatically. What each skill does
and how to ask for it is described in each skill's `SKILL.md`.

## Requirements

`git`, `jq` and `python3` on the PATH. `kodem-cli`, which the plugin installs
for you if it is missing.

All three skills authenticate to the Kodem platform, so each developer needs a
Kodem user. Report needs one with access to all resources. Backlog-fix works
for restricted-access users.

## 1. Install

**User level**, applying to all of that developer's repositories:

```bash
claude plugin marketplace add kodem-security/agent-skills
claude plugin install kodem-security@kodem
```

**Repo level**, applying to everyone who opens that one repository — add this
to the repo's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "kodem": {
      "source": {
        "source": "github",
        "repo": "kodem-security/agent-skills"
      }
    }
  },
  "enabledPlugins": {
    "kodem-security@kodem": true
  }
}
```

Unlike a hand-unzipped skill, installing the plugin also wires up the
prevention hooks automatically — there is no separate "turn on hooks" step.

## 2. Sign in

The first time you use a skill it installs `kodem-cli` if it is missing, then
asks you to sign in:

```bash
kodem-cli auth login
```

That opens a browser, so it is the one step the plugin cannot do for you.

In CI or any other non-interactive environment, do not run `auth login`. Set
an API key as an environment variable instead — see each skill's `SKILL.md`
for the "running headless" details.

## 3. Restart

Claude Code reads plugins, skills and hooks when a session starts, so start a
new session before trying anything.

## 4. Check it worked

- "what's my posture?" gives a read-only summary.
- "fix my issues" gives the backlog, as a plan that waits for your yes.
- Prevention runs on its own, via the bundled hooks, and speaks up only when a
  change breaks a policy.

## Where you run scans matters

On macOS, if the path you point a scan at reaches the directory through a
symlink, the scan reads the resolved parent directory rather than the
directory you named. `/tmp` is a symlink to `/private/tmp` and `/var` is a
symlink to `/private/var`, so a scan run from anywhere under `/tmp` or `/var`
will read everything under `/private/tmp` or `/private/var`, and will report
what it finds there as yours. For Backlog-fix and Report that also reaches the
inventory they send to the platform. Prevention sends no scan data either way.

**Run scans from a real path rather than through `/tmp` or `/var`.** A
repository checked out under your home directory or a CI workspace path is not
affected.

## Uninstall

```bash
claude plugin uninstall kodem-security@kodem
claude plugin marketplace remove kodem
```

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel. When
reporting a problem, quote the plugin version from
`.claude-plugin/plugin.json`.
