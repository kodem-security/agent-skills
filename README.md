# Kodem Agent Skills

Give your AI coding agent Kodem: every agent turn is checked against your Kodem
policies before the code is committed, your existing backlog is fixed in order
of real runtime risk, and your security posture is a question away.

| Skill | What it does |
| --- | --- |
| `kodem-security` | Prevention. At the end of each agent turn, scans only what that turn changed against your CI and SCM policies, and hands policy violations back to the agent to fix. |
| `kodem-backlog-fix` | Fixes the open issues already in Kodem, ranked by Kodem Score, after you approve the plan. |
| `kodem-report` | Read-only posture summary or full report. Changes nothing. |

Ask in plain language ("fix my issues", "what's my posture?"), or run a skill
directly:

- Claude Code, Cursor and Gemini CLI: `/kodem-security scan`, `/kodem-security fix`
  or `/kodem-security report`; `/kodem-security` alone means `scan`.
- GitHub Copilot and Antigravity CLI: `/kodem-security` (scan), `/kodem-backlog-fix`
  or `/kodem-report`.
- Codex: type `@` and pick Kodem Security or one of its skills.

**Requirements:** a Kodem account, and `git`, `jq` and `python3` on the PATH.
`kodem-cli` is installed on first use, after you approve it.
[SECURITY.md](SECURITY.md) covers what runs, what it sends to Kodem, and what
changes on your machine.

## Platforms

| Platform | Directory | Guide |
| --- | --- | --- |
| Claude Code | [`claude/`](claude/) | [`claude/README.md`](claude/README.md) |
| Codex | [`codex/`](codex/) | [`codex/README.md`](codex/README.md) |
| Cursor | [`cursor/`](cursor/) | [`cursor/README.md`](cursor/README.md) |
| Gemini CLI | [`gemini/`](gemini/) | [`gemini/README.md`](gemini/README.md) |
| GitHub Copilot | [`copilot/`](copilot/) | [`copilot/README.md`](copilot/README.md) |
| Antigravity CLI | [`antigravity/`](antigravity/) | [`antigravity/README.md`](antigravity/README.md) |

Quick start:

```bash
# Claude Code
claude plugin marketplace add kodem-security/agent-skills
claude plugin install kodem-security@kodem

# Codex
codex plugin marketplace add kodem-security/agent-skills
codex plugin add kodem-security@kodem

# Cursor: add the marketplace, then install Kodem Security from Settings → Plugins
cursor-agent plugin marketplace add https://github.com/kodem-security/agent-skills

# Gemini CLI
git clone https://github.com/kodem-security/agent-skills
gemini extensions install ./agent-skills/gemini

# GitHub Copilot CLI
copilot plugin marketplace add kodem-security/agent-skills
copilot plugin install kodem-security@kodem

# Antigravity CLI
git clone https://github.com/kodem-security/agent-skills
agy plugin install ./agent-skills/antigravity
```

Each directory is a complete, self-contained install for its platform, with
the same skills and hooks.

## Windows

The hooks and scripts are bash. On Windows, install Git for Windows so Git Bash
is available; the skills fall back to it from PowerShell through
`use-bash-windows.ps1`.

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel. Not a Kodem
customer yet? Visit [kodemsecurity.com](https://www.kodemsecurity.com).
