# Security

## What runs, and what it sends

| Part | When it runs | What reaches Kodem |
| --- | --- | --- |
| Prevention hook | At the end of every agent turn | Nothing. It scans with `--no-trace`, which sends no scan data; it signs in and reads your policies to evaluate the scan. |
| `kodem-security` skill | When the agent runs a scan | The scan results for the repository, as any Kodem scan reports them. |
| `kodem-backlog-fix` skill | When you ask it to fix issues | It reads your open issues, and reports the baseline scans it runs. |
| `kodem-report` skill | When you ask for a report | It reads your open issues and policies, and reports the scans it runs. Makes no changes. |

Every request goes through `kodem-cli`, signed in as you (`kodem-cli auth login`)
or with an API key.

## What changes on your machine

- **`kodem-cli`** is installed on first use, after you approve it, from
  `public.kodemsecurity.com/artifacts/kodem-cli`, into the directory it already
  occupies on your `PATH`, else `~/.local/bin`. Each download is checked against
  the MD5 the storage bucket reports for the file, and refused if it doesn't
  match. This detects corrupted or altered downloads, not a compromised bucket.
- **`kodem-cli`'s code scanner** (opengrep) is downloaded by `kodem-cli` into
  `~/.kodem` before the first code scan, after you approve it. The prevention
  hook never approves it; until it is there, the hook skips code scanning.
- **The prevention hook** never edits your files, index or branches. To diff a
  turn it writes a snapshot commit object into `.git/objects` (never referenced
  by a branch), creates a temporary `git worktree` that it removes afterwards,
  and keeps small per-session state files in `/tmp/.kodem-*`.
- **The skills** change code only when you approve a fix, and never commit or
  push.

## Reporting a vulnerability

Email `support@kodemsecurity.com` with "Security" in the subject. Please don't
open a public issue for security reports.
