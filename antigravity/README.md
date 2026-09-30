# Kodem Security Plugin for Antigravity CLI

An Antigravity CLI plugin that lets your coding agent use Kodem: prevention
scans on every diff, developer-invoked fixing of your existing backlog, and
read-only security reports.

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

Antigravity CLI installs a plugin from a local folder, so install from a
checkout:

```bash
git clone https://github.com/kodem-security/agent-skills
agy plugin install ./agent-skills/antigravity
```

To pick up updates, `git pull` and run the install command again. Installing
the plugin also wires up the prevention hooks — there is no separate "turn on
hooks" step.

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

Antigravity CLI reads plugins, skills and hooks when a session starts, so start
a new session before trying anything.

## 4. Check it worked

- "what's my posture?" gives a read-only summary.
- "fix my issues" gives the backlog, as a plan that waits for your yes.
- Prevention runs on its own, via the bundled hooks, and speaks up only when a
  change breaks a policy.

## How prevention works here

At the end of every agent turn, the bundled hooks scan only what that turn
changed, locally (`--no-trace`, nothing uploaded). A clean result says nothing.
A policy-blocked result goes back to the agent with the findings and the rules
for acting on them: safe dependency bumps it applies, anything bigger it asks
you about first, and it never silences a finding. It re-scans after a fix, at
most twice, and stops if the same findings come back.

In Antigravity a policy block keeps the agent loop going with the findings as
its next input, labelled as coming from the Kodem hook rather than from you.
In a multi-root workspace the gate reviews the first folder.
Antigravity shows nothing else from a stop hook, so if your Kodem sign-in
expires the gate skips silently; the skills still tell you when they run a scan.

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
agy plugin uninstall kodem-security
```

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel. When
reporting a problem, quote the plugin version from
[`plugin.json`](plugin.json).
