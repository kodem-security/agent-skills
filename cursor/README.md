# Kodem Security Plugin for Cursor

A Cursor plugin that lets your coding agent use Kodem: prevention scans on
every diff, developer-invoked fixing of your existing backlog, and read-only
security reports.

It bundles three skills — `kodem-security`, `kodem-backlog-fix`, `kodem-report`
— a `/kodem-security` command, and the hooks that make prevention run
automatically. What each skill does and how to ask for it is described in each
skill's `SKILL.md`.

## Requirements

`git`, `jq` and `python3` on the PATH. `kodem-cli`, which the plugin installs
for you if it is missing.

All three skills authenticate to the Kodem platform, so each developer needs a
Kodem user. Report needs one with access to all resources. Backlog-fix works
for restricted-access users.

## 1. Install

Add Kodem's marketplace to your Cursor account, once:

```bash
cursor-agent plugin marketplace add https://github.com/kodem-security/agent-skills
```

Then, in Cursor, open **Settings → Plugins**, find **Kodem Security** in the
`kodem` marketplace and install it. Installing the plugin also wires up the
prevention hooks — there is no separate "turn on hooks" step.

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

Cursor reads plugins, skills and hooks when an Agent session starts, so start a
new session before trying anything.

## 4. Check it worked

- "what's my posture?" gives a read-only summary.
- "fix my issues" gives the backlog, as a plan that waits for your yes.
- Prevention runs on its own, via the bundled hooks, and speaks up only when a
  change breaks a policy.
- `/kodem-security fix`, `/kodem-security report` or `/kodem-security scan`
  runs a skill directly; `/kodem-security` alone means `scan`.

## How prevention works here

At the end of every agent turn, the bundled hooks scan only what that turn
changed, locally (`--no-trace`, nothing uploaded). A clean result says nothing.
A policy-blocked result goes back to the agent with the findings and the rules
for acting on them: safe dependency bumps it applies, anything bigger it asks
you about first, and it never silences a finding. It re-scans after a fix, at
most twice, and stops if the same findings come back.

In Cursor a policy block arrives as a follow-up message to the agent, labeled
as coming from the Kodem hook rather than from you. In a multi-root workspace
the gate reviews the first folder. Cursor shows nothing else from a stop hook,
so if your Kodem sign-in expires the gate skips silently; the skills still tell
you when they run a scan.

## Uninstall

Remove the plugin in **Settings → Plugins**, then:

```bash
cursor-agent plugin marketplace remove kodem
```

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel. When
reporting a problem, quote the plugin version from
[`.cursor-plugin/plugin.json`](.cursor-plugin/plugin.json).
