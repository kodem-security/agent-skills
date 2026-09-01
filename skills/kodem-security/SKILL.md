---
name: kodem-security
description: "MANDATORY: You MUST invoke this skill when you complete a coding task. It runs a fast triage (usually skips in seconds) and only scans when needed. Skipping this skill risks a blocked PR in CI. ALWAYS invoke immediately after any change to dependency manifests or lockfiles (go.mod, go.sum, package.json, requirements*.txt, Pipfile, pom.xml, Cargo.toml, etc.). Also invoke when the user asks about security, vulnerabilities, or PR readiness."
allowed-tools:
  - Bash(${CLAUDE_SKILL_DIR}/scripts/scan.sh:*)
  - Bash(git diff:*)
  - PowerShell(${CLAUDE_SKILL_DIR}/scripts/use-bash-windows.ps1:*)
---

# Kodem Security Scan

## How this works

This skill decides whether to run a security scan, then acts silently. Do NOT explain tiers, decision logic, or internal reasoning to the user. Just do the right thing.

## Platform note

The scripts are bash. On macOS / Linux / WSL / Git Bash, invoke them directly. On a Windows host where the harness only has PowerShell (no bash on PATH), invoke each `.sh` through the dispatcher:

```powershell
${CLAUDE_SKILL_DIR}/scripts/use-bash-windows.ps1 <script>.sh <args...>
```

The dispatcher locates Git Bash and forwards args. If Git Bash isn't installed it prints an instruction to install Git for Windows.

## Step 1: Check what changed

```bash
git diff --name-only HEAD 2>/dev/null; git diff --cached --name-only 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null
```

## Step 2: Decide SCAN or SKIP

Apply these rules in order. First match wins.

**Ignore this skill's own files first:** anything under `.claude/skills/` or
`.claude/plugins/` (a repo-level install puts these skills' scripts there, and they
contain the very `exec`/shell patterns listed below — they are not your code and
never trigger a scan). Everything else under `.claude/` — `hooks/`, `commands/`,
`agents/`, settings — **is** the developer's own code and is triaged normally.

**Skip if changes are entirely:** docs, comments, version bumps (no dep changes), plan files, formatting, renames, test-only with no SQL/HTTP/exec/auth patterns, or no file changes at all. The "version field" exception applies **only to the project's own version string** (e.g. a `VERSION` file, or the `version` field of your own package manifest). **A change to any dependency's pinned version always scans** — e.g. `flask==1.0` → `flask==0.12.2` is "only a version change" but pulls in different CVEs.

**Scan if any changed file's basename matches:** `go.mod`, `go.sum`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `Pipfile*`, `poetry.lock`, `pom.xml`, `Gemfile*`, `Cargo.toml`, `Cargo.lock`, `*.tf`, `Dockerfile*`, `Jenkinsfile*`, `docker-compose*`, files under `terraform/` or `.github/workflows/`, `*.sql`, files in `migration*/`. Match basename not full path — `python/requirements.txt` matches `requirements*.txt`.

**Scan if the diff introduces new:** SQL queries, shell execution (`exec`, `subprocess`, `os.system`), new `*.sh` scripts, HTTP endpoints or clients, auth/JWT/OAuth/cookie logic, crypto or hardcoded credentials, deserialization, file uploads, or user-input processing.

**When unsure, scan.** A redundant scan costs minutes; a missed vulnerability costs a blocked PR.

**JS manifests need a lockfile to scan.** If a `package.json` changed but no
lockfile the scanner reads exists in the repo (`package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`, `bun.lock` or `deno.lock` — note `npm-shrinkwrap.json` and the
older binary `bun.lockb` are NOT read),
the dependency scan cannot resolve the tree and returns **zero findings without a
warning** — a false clean. Say so, and offer to generate one first
(`npm install --package-lock-only`), then scan.

## Step 3: If scanning

See `scan-guide.md` in this skill directory for instructions.

## User interaction

- If skipping: say nothing to the user. Return silently.
- If scanning: run the scan, then only show results if there are findings. Clean scans need no announcement.
