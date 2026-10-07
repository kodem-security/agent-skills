# Kodem Security Plugin for GitHub Copilot

A GitHub Copilot plugin that lets your coding agent use Kodem: prevention scans
on every diff, developer-invoked fixing of your existing backlog, and read-only
security reports. Works in Copilot CLI and anywhere else that loads Copilot
agent plugins.

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

```bash
copilot plugin marketplace add kodem-security/agent-skills
copilot plugin install kodem-security@kodem
```

Installing the plugin also wires up the prevention hooks — there is no separate
"turn on hooks" step. Invoke a skill directly with `/kodem-backlog-fix` or
`/kodem-report`, or just ask in plain language.

## 2. Sign in

The first time you use a skill it offers to install `kodem-cli` if it is missing, then
asks you to sign in:

```bash
kodem-cli auth login
```

That opens a browser, so it is the one step the plugin cannot do for you.

In CI or any other non-interactive environment, do not run `auth login`. Set
an API key as an environment variable instead.

## 3. Restart

Copilot reads plugins, skills and hooks when a session starts, so start a new
session before trying anything.

## 4. Check it worked

- "what's my posture?" gives a read-only summary.
- "fix my issues" gives the backlog, as a plan that waits for your yes.
- Prevention runs on its own, via the bundled hooks, and speaks up only when a
  change breaks a policy.
- `/kodem-security` scans your current changes; `/kodem-backlog-fix` and
  `/kodem-report` run those skills directly.

## How prevention works here

At the end of every agent turn, the bundled hooks scan only what that turn
changed, locally (`--no-trace`, nothing uploaded). A clean result says nothing.
A policy-blocked result goes back to the agent with the findings and the rules
for acting on them: safe dependency bumps it applies, anything bigger it asks
you about first, and it never silences a finding. It re-scans after a fix, at
most twice, and stops if the same findings come back.

Copilot overrides a stop hook after 8 consecutive blocks; the gate's own limit
of two re-scans is well inside that.

Copilot shows nothing from a stop hook except a block, so if your Kodem sign-in
expires the gate skips silently. The skills still tell you when they run a scan;
run `kodem-cli auth login` again when they do.

The skills live in the plugin's install directory, outside your repository, so
Copilot asks permission the first time the agent reads or runs one of their
files. Allow it for the session.

## Windows

The hooks are bash scripts, and Copilot runs a hook's `bash` command only where
bash is available. On a PowerShell-only Windows machine prevention does not run;
install Git for Windows. The skills themselves fall back to PowerShell through
`use-bash-windows.ps1`.

## Uninstall

```bash
copilot plugin uninstall kodem-security@kodem
copilot plugin marketplace remove kodem
```

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel. When
reporting a problem, quote the plugin version from
[`plugin.json`](plugin.json).
