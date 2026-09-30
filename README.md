# Kodem Agent Skills

Give your AI coding agent Kodem: policy scans before commit, runtime-ranked
fixing of your existing backlog, and read-only security posture reports.

One repository, one directory per agent platform.

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

## Help

`support@kodemsecurity.com`, or our shared Slack or Teams channel.
