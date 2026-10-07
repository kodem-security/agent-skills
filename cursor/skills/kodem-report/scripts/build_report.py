#!/usr/bin/env python3
"""Build a Kodem Security report from platform data.

Pulls a repo's triage data via kodem-cli (issues, Quick Wins, policy verdicts),
digests it into a canonical report.json, and renders a human-readable report.
The rendered markdown is complete on its own: correct counts, the full findings
list, policies, computed next steps, and the missing-signal notes. An agent (or
a human) can add judgment on top, but nothing here depends on one.

Usage:
  build_report.py <repo-root> [--repo-name org/repo] [--view full|posture]
                  [--format md|json|csv] [--out DIR] [--skip-policy-scan]
                  [--severity CRITICAL,HIGH] [--type sca|sast] [--runtime]
                  [--package NAME] [--cve ID]

Output: the rendered report on stdout, plus report.json and report.<fmt> written
to --out (default: a temp directory — never the repo). Machine trailers:
  BUILD_REPORT_FILES: <dir>
  BUILD_REPORT_RESULT: ok
  KODEM_UPDATE_AVAILABLE: <version>   (only when the CLI reported one)

Exit codes: 0 ok · 2 kodem-cli missing · 3 not authenticated · 4 repo not mapped
5 not authorized (scope) · 6 CLI too old for the read commands · 1 other error.
"""
import argparse
import csv
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile

CLI = os.environ.get("KODEM_CLI_BIN", "kodem-cli")
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Other": 4}

UNRESOLVABLE_MANIFESTS = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                     "bun.lock", "deno.lock"),
    "pyproject.toml": ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock",
                       "requirements.txt"),
    "Pipfile": ("Pipfile.lock",),
    "Cargo.toml": ("Cargo.lock",),
    "composer.json": ("composer.lock", "installed.json"),
    "Gemfile": ("Gemfile.lock", "Gemfile.next.lock"),
}

RUNTIME_EVALUATED = ("HAS_EVIDENCE", "NO_INDICATION")

SYNTHESIZED_SERVER_SIDE = ("package.json",)


class Parser(argparse.ArgumentParser):
    """Exit 1 on bad arguments — exit 2 is reserved for 'kodem-cli missing'."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"ERROR: {message}", file=sys.stderr)
        sys.exit(1)

EXIT_CLI_MISSING = 2
EXIT_UNAUTHENTICATED = 3
EXIT_NOT_MAPPED = 4
EXIT_FORBIDDEN = 5
EXIT_CLI_TOO_OLD = 6


def fail(code, msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def run_cli(args, timeout=180, timeout_fatal=True):
    """Run kodem-cli; returns (rc, stdout, stderr). Exits if the binary is absent."""
    if shutil.which(CLI) is None:
        fail(EXIT_CLI_MISSING, f"{CLI} not found on PATH — install it first (see the skill's Step 0).")
    try:
        proc = subprocess.run([CLI] + args, capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        if timeout_fatal:
            fail(1, f"kodem-cli {' '.join(args[:2])} timed out after {timeout}s")
        return 124, "", f"timed out after {timeout}s"
    return proc.returncode, proc.stdout, proc.stderr


def classify_error(message):
    m = message.lower()
    if "code repository not found" in m or "could not map" in m:
        return EXIT_NOT_MAPPED
    if "403" in m or "not authorized" in m or "forbidden" in m or "insufficient scope" in m:
        return EXIT_FORBIDDEN
    if "authenticate" in m or "credentials" in m or "auth login" in m:
        return EXIT_UNAUTHENTICATED
    if ("unknown command" in m or "unrecognized" in m or "unhandled command" in m
            or "unknown flag" in m or "unknown option" in m
            or "flag provided but not defined" in m):
        return EXIT_CLI_TOO_OLD
    return 1


def cli_json(args):
    rc, out, err = run_cli(args)
    text = out.strip() or err.strip()
    try:
        envelope = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        fail(classify_error(text), f"kodem-cli did not return JSON: {text[:300]}")
    if not envelope.get("success"):
        message = ((envelope.get("error") or {}).get("message")) or text[:300]
        fail(classify_error(message), message)
    return envelope.get("data") or {}


def check_auth():
    rc, out, err = run_cli(["auth", "status"])
    if rc != 0:
        fail(EXIT_UNAUTHENTICATED,
             f"not authenticated with the Kodem platform ({(err or out).strip() or 'no credentials'}) "
             "— run: kodem-cli auth login")


def derive_repo_name(repo_root):
    proc = subprocess.run(["git", "-C", repo_root, "remote", "get-url", "origin"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        fail(1, "cannot derive the repo name (no 'origin' remote) — pass --repo-name org/repo")
    url = proc.stdout.strip().rstrip("/")
    name = re.sub(r"\.git$", "", url)
    m = re.search(r"[:/]([^/:]+/[^/]+)$", name)
    if not m:
        fail(1, f"cannot parse org/repo from remote '{url}' — pass --repo-name org/repo")
    return m.group(1)


def pull_issues(repo_name, scope_args):
    args = ["issues", "list", "--repository-name", repo_name,
            "--skill-trigger", "--json", "--limit", "0"] + scope_args
    return cli_json(args)


def pull_quick_wins(project_ids):
    wins, failed = [], 0
    for pid in project_ids:
        rc, out, err = run_cli(["issues", "quick-wins", "--project", pid,
                                "--skill-trigger", "--json"])
        try:
            envelope = json.loads(out.strip() or err.strip())
            if envelope.get("success"):
                wins.extend((envelope.get("data") or {}).get("quickWins") or [])
            else:
                failed += 1
        except (json.JSONDecodeError, ValueError):
            failed += 1
    return wins, {"failed": failed, "total": len(project_ids)}


SCANNER_MISSING = []


def pull_policy(repo_root, repo_name):
    """Run both variants (distinct rule sets); a non-zero rc can mean 'blocked', not an error."""
    results = []
    for variant in ("open-source", "code"):
        rc, out, err = run_cli(["scan", "code-repository", variant, repo_root,
                                "--code-repository-name", repo_name,
                                "--policy-type", "all", "--skill-trigger",
                                "--description", "report: read-only posture check"],
                               timeout=900, timeout_fatal=False)
        text = (out or "") + ("\n" + err if err else "")
        if "binary download declined" in text:
            SCANNER_MISSING.append(variant)
        results.append((variant, rc, text))
    return results


def parse_policy(text, rc):
    """A failed or unparseable scan is 'unavailable', never 'no policies configured'."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    verdicts, breaches = [], []
    current = None
    update_available = None
    saw_not_found = False
    for line in text.splitlines():
        stripped = line.strip()
        m = re.search(r"\[(CI|SCM)\s*·\s*([^\]]+)\]\s*(?:Policy:\s*\"([^\"]+)\")?.*?"
                      r"\[(PASSED|FAILED|WARN AND PASS|PARTIAL)\](?:\s*-\s*(.+))?", stripped)
        if m:
            current = {"origin": m.group(1), "category": m.group(2).strip(),
                       "name": (m.group(3) or "").strip() or None,
                       "status": m.group(4),
                       "rule": (m.group(5) or "").strip() or None,
                       "breaches": []}
            verdicts.append(current)
            continue
        if stripped.lower().startswith("blocked:"):
            item = stripped[len("blocked:"):].strip()
            breaches.append(item)
            if current is not None:
                current["breaches"].append(item)
            continue
        if "NOT FOUND" in stripped:
            saw_not_found = True
        m = re.match(r"KODEM_UPDATE_AVAILABLE:\s*(\S+)", stripped)
        if m:
            update_available = m.group(1)
    if verdicts:
        state = "ok"
    elif saw_not_found and rc == 0:
        state = "not_found"
    else:
        state = "unavailable"
    interesting = [l for l in text.splitlines()
                   if re.search(r"\[(CI|SCM)|NOT FOUND|blocked:|KODEM_RESULT|Error|error", l)]
    return {"state": state, "scan_rc": rc, "verdicts": verdicts, "breaches": breaches,
            "raw": interesting[:10], "update_available": update_available}


def merge_policies(parsed):
    """'not_found' only when both sides cleanly reported none; otherwise 'unavailable' unless verdicts exist."""
    merged = {"state": "unavailable", "verdicts": [], "breaches": [], "raw": [],
              "update_available": None, "sides": {}}
    for variant, p in parsed:
        merged["sides"][variant] = p["state"]
        merged["verdicts"] += p["verdicts"]
        merged["breaches"] += p["breaches"]
        merged["raw"] += [f"[{variant}] {l}" for l in p["raw"]]
        merged["update_available"] = merged["update_available"] or p["update_available"]
    states = set(merged["sides"].values())
    if merged["verdicts"]:
        merged["state"] = "ok"
    elif states == {"not_found"}:
        merged["state"] = "not_found"
    return merged


def norm_link(url):
    url = (url or "").strip()
    if not url:
        return ""
    url = url.replace("?&", "?", 1)
    if re.match(r"(?i)https?://", url):
        return url
    if "://" in url:
        return ""
    return "https://" + url


def norm_severity(value):
    sev = (value or "").capitalize()
    return sev if sev in ("Critical", "High", "Medium", "Low") else "Other"


def normalize(issue):
    risk = issue.get("riskInsights") or {}
    fix = issue.get("fixInsights") or {}
    intro = issue.get("introducedThroughInsights") or {}
    kai = issue.get("issueKaiAnalysis")
    category = issue.get("category") or ""
    if category == "sca":
        versions = "/".join(issue.get("packageVersions") or []) or "?"
        title = f"{issue.get('packageName') or '?'}@{versions}"
        fix_versions = issue.get("fixVersions") or []
        if not fix_versions:
            fix_text = "no fix version"
        elif any(not re.match(r"^v?\d", v) for v in fix_versions):
            fix_text = f"no clean fix version (platform lists: {' / '.join(fix_versions)})"
        else:
            fix_text = "bump to " + " / ".join(fix_versions)
        fixable = bool(fix.get("hasFixVersion"))
    else:
        title = issue.get("filePath") or issue.get("packageName") or "?"
        fix_text = "remediation guidance in Kodem"
        fixable = True
    return {
        "id": issue.get("id"),
        "project": issue.get("projectName") or issue.get("projectId"),
        "category": category,
        "severity": norm_severity(issue.get("severity")),
        "score": issue.get("kodemScore") or 0,
        "title": title,
        "risk_id": issue.get("riskId") or (issue.get("cwe") or {}).get("id") or "",
        "cwe": (issue.get("cwe") or {}).get("id") or "",
        "runtime": risk.get("runtime"),
        "runtime_status": issue.get("runtimeMarkingStatus") or "",
        "exploit_maturity": (risk.get("exploitMaturity") or "UNDETERMINED").lower(),
        "fix": fix_text,
        "fixable": fixable,
        "kai": None if kai is None else ("false positive" if kai.get("isFalsePositive") else "confirmed"),
        "direct": intro.get("isDirect"),
        "from_base_image": intro.get("fromBaseImage"),
        "base_image_fix": issue.get("baseImageFix") or None,
        "base_image_fix_count": issue.get("baseImageFixCount") or 0,
        "path": issue.get("filePath") or "",
        "ui_link": norm_link(issue.get("uiLink") or ""),
        "dismiss_reason": issue.get("dismissReason") or "",
    }


def _dedupe_quick_wins(quick_wins):
    seen, out = set(), []
    for w in quick_wins:
        entry = {
            "dependency": re.sub(r"[:@]" + re.escape(w.get("currentVersion") or "\x00") + r"$", "",
                                 w.get("dependencyName") or w.get("displayName") or "?"),
            "current": w.get("currentVersion") or "?",
            "fix": w.get("fixVersion") or "?",
            "clears": w.get("totalIssues") or 0,
            "aggregate_score": w.get("aggregateKodemScore") or 0,
        }
        key = (entry["dependency"], entry["current"], entry["fix"])
        if key not in seen:
            seen.add(key)
            out.append(entry)
    return out


def manifests_without_lockfile(repo_root):
    """Manifests with no lockfile in their own dir or any ancestor, committed or on disk."""
    if not shutil.which("git"):
        return []
    top = subprocess.run(["git", "-C", repo_root, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0:
        return []
    root = top.stdout.strip() or repo_root

    listing = subprocess.run(
        ["git", "-C", root, "ls-tree", "-r", "--name-only", "-z", "HEAD"],
        capture_output=True, text=True)
    if listing.returncode != 0:
        listing = subprocess.run(["git", "-C", root, "ls-files", "-z"],
                                 capture_output=True, text=True)
        if listing.returncode != 0:
            return []
    paths = [p for p in listing.stdout.split("\0") if p]

    def in_vendor_dir(path):
        return bool({"node_modules", "vendor", ".venv", "venv"} & set(path.split("/")[:-1]))

    all_locks = {lock for locks in UNRESOLVABLE_MANIFESTS.values() for lock in locks}
    lock_dirs = {posixpath.dirname(p) for p in paths
                 if posixpath.basename(p) in all_locks and not in_vendor_dir(p)}

    def resolved_by(directory, lockfiles):
        probe = directory
        for _ in range(probe.count("/") + 2):
            if probe in lock_dirs and any(
                    os.path.exists(os.path.join(root, probe, lock)) or
                    posixpath.join(probe, lock).lstrip("/") in paths
                    for lock in lockfiles):
                return True
            if any(os.path.exists(os.path.join(root, probe, lock)) for lock in lockfiles):
                return True
            if probe in ("", "/"):
                return False
            probe = posixpath.dirname(probe)
        return False

    unresolved = []
    for path in paths:
        lockfiles = UNRESOLVABLE_MANIFESTS.get(posixpath.basename(path))
        if not lockfiles or in_vendor_dir(path):
            continue
        if not resolved_by(posixpath.dirname(path), lockfiles):
            unresolved.append(path)
    return sorted(unresolved)


TOOL_INSTALL_DIRS = {
    ".claude": ("skills", "plugins"),
    ".cursor": ("plugins",),
    ".gemini": ("extensions",),
    ".codex": ("plugins",),
}
OWN_SKILL_HOSTS = (".cursor", ".gemini", ".github", ".agents", ".codex")
OWN_SKILLS = ("kodem-security", "kodem-backlog-fix", "kodem-report")
TOOL_INSTALL_PATHS_TEXT = (
    ", ".join(f"`{host}/{sub}/`" for host, subs in TOOL_INSTALL_DIRS.items() for sub in subs)
    + ", and this tool's own skills (" + ", ".join(f"`{s}`" for s in OWN_SKILLS)
    + ") in any other host's `skills/`"
)


def is_tool_own_file(path):
    """Match whole path segments: `lstrip("./")` once turned ".claude/skills/x" into "claude/skills/x"."""
    parts = [p for p in (path or "").replace("\\", "/").split("/") if p not in ("", ".")]
    for index, part in enumerate(parts[:-1]):
        if parts[index + 1] in TOOL_INSTALL_DIRS.get(part, ()):
            return True
        if (part in OWN_SKILL_HOSTS and parts[index + 1] == "skills"
                and index + 2 < len(parts) - 1 and parts[index + 2] in OWN_SKILLS):
            return True
    return False


def digest(data, policy, quick_wins, qw_unavailable, repo_name, scope_desc,
           unresolved_manifests=()):
    findings = [normalize(i) for i in data.get("issues") or []]
    excluded = [f for f in findings if is_tool_own_file(f["path"])]
    findings = [f for f in findings if not is_tool_own_file(f["path"])]
    projects = sorted({f["project"] for f in findings if f["project"]})
    sast = [f for f in findings if f["category"] == "sast"]
    sca = [f for f in findings if f["category"] == "sca"]

    breach_text = " ".join(policy.get("breaches") or [])

    breach_has_ids = bool(re.search(r"\b(CVE-\d{4}-\d+|GHSA-[\w-]+)\b", breach_text))

    def breaches_policy(f):
        if not breach_text:
            return False
        def word_hit(needle):
            return bool(needle) and re.search(
                rf"(?<![\w.@/-]){re.escape(needle)}(?![\w.@/-])", breach_text) is not None
        if breach_has_ids:
            return word_hit(f["risk_id"])
        pkg = f["title"].rsplit("@", 1)[0]
        return word_hit(f["risk_id"]) or (f["category"] == "sca" and word_hit(pkg))

    for f in findings:
        f["policy_breach"] = breaches_policy(f)

    counts = {sev: {"sca": 0, "sast": 0} for sev in SEV_ORDER}
    for f in findings:
        if f["severity"] in counts and f["category"] in ("sca", "sast"):
            counts[f["severity"]][f["category"]] += 1

    signals = {
        "runtime_present": any(f["runtime_status"] in RUNTIME_EVALUATED for f in findings),
        "kai_enabled": any(f["kai"] is not None for f in sast) if sast else None,
        "policy_state": policy.get("state"),
        "quick_wins_failed_projects": qw_unavailable,
        "exploit_undetermined": sum(1 for f in findings
                                    if f["exploit_maturity"] == "undetermined"),
        "manifests_without_lockfile": list(unresolved_manifests),
        "base_image_findings": sum(1 for f in findings if f["from_base_image"] is True),
        "base_image_fix_known": sum(1 for f in findings if f["base_image_fix"]),
        "uncategorized": sum(1 for f in findings
                             if f["category"] not in ("sca", "sast")),
        "excluded_tool_own_files": len(excluded),
    }

    ranked = sorted(findings, key=lambda f: (not f["policy_breach"],
                                             f["kai"] == "false positive", -f["score"]))
    return {
        "repo": repo_name,
        "scope": scope_desc,
        "projects": projects,
        "total": len(findings),
        "platform_total": data.get("total", len(findings)),
        "counts": counts,
        "runtime_reachable": sum(1 for f in findings if f["runtime"]),
        "sca_total": len(sca),
        "sca_fixable": sum(1 for f in sca if f["fixable"]),
        "sast_total": len(sast),
        "signals": signals,
        "policy": policy,
        "quick_wins": _dedupe_quick_wins(quick_wins),
        "findings": findings,
        "top_priorities": ranked[:5],
    }


def finding_line(f, show_project=False):
    tags = []
    if f["runtime"]:
        tags.append("runtime")
    if f["policy_breach"]:
        tags.append("policy")
    tag_text = (" · ".join(tags) + " · ") if tags else ""
    if f["category"] == "sast" and f["cwe"] and f["risk_id"] != f["cwe"]:
        ident = f"{f['cwe']}: {f['risk_id']}" if f["risk_id"] else f["cwe"]
    else:
        ident = f["risk_id"] or f["cwe"]
    parts = [f"- [{tag_text}score {f['score']}] {f['title']} — {ident}"]
    if f["exploit_maturity"] != "undetermined":
        parts.append(f"exploit: {f['exploit_maturity']}")
    parts.append(f"fix: {f['fix']}")
    if f["category"] == "sast" and f["kai"]:
        parts.append(f"Kai: {f['kai']}")
    if show_project and f["project"]:
        parts.append(f"project: {f['project']}")
    return " · ".join(parts)


def quick_win_line(w):
    return (f"Quick Win: bump {w['dependency']} {w['current']} → {w['fix']} — clears "
            f"{w['clears']} container-image findings (tracked separately from the issues above)")


def policy_section(rep):
    policy = rep["policy"]
    state = policy.get("state")
    if state == "skipped":
        return ["Policy check skipped on this run (--skip-policy-scan)."]
    if state == "unavailable":
        return ["Policy state unknown — the policy check did not return a verdict "
                "on this run. Not the same as having no policies."]
    if state == "not_found":
        return ["No policies are configured for this repo — nothing to enforce, "
                "so nothing is breaching."]
    lines = []
    for v in policy["verdicts"]:
        name = f" \"{v['name']}\"" if v.get("name") else ""
        rule = f" — {v['rule']}" if v.get("rule") else ""
        lines.append(f"[{v['origin']} · {v['category']}]{name} {v['status']}{rule}")
        for b in v.get("breaches") or []:
            lines.append(f"  - breaching: {b}")
    for variant, side_state in (policy.get("sides") or {}).items():
        if side_state == "unavailable":
            lines.append(f"The {variant} policy check returned no verdict on this run — "
                         "not the same as passing.")
        elif side_state == "not_found" and policy["verdicts"]:
            lines.append(f"No {variant} policies are configured.")
    return lines


def signal_notes(rep):
    s = rep["signals"]
    notes = []
    if SCANNER_MISSING:
        notes.append("The code policy check needs kodem-cli's code scanner (opengrep), which isn't "
                     "downloaded yet. Run a Kodem scan and approve the download to set it up.")
    returned = rep["total"] + (s.get("excluded_tool_own_files") or 0)
    if rep["platform_total"] > returned and not rep["scope"]:
        notes.append(f"The platform reported {rep['platform_total']} matching issues but "
                     f"returned {returned} — the list below may be incomplete.")
    dropped = s.get("excluded_tool_own_files") or 0
    if dropped:
        notes.append(
            f"{dropped} finding(s) in this tool's own installed files (under "
            f"{TOOL_INSTALL_PATHS_TEXT}) were excluded from every count "
            "here — they are our shipped scripts, not your code. The platform's total "
            f"is therefore {dropped} higher than this report's. Findings elsewhere "
            "under those dot-directories (your own skills, hooks, commands, agents, "
            "settings) are your own code and ARE included.")
    uncategorized = s.get("uncategorized") or 0
    if uncategorized:
        notes.append(
            f"{uncategorized} of {rep['total']} issues carry no recognized type "
            "(neither SCA nor code), so they are counted in the total but appear in "
            "neither column of the severity table. The table under-counts by that "
            "many — read the findings list, not the table.")
    unresolved = s.get("manifests_without_lockfile") or []
    if rep["scope"] and "code" in rep["scope"] and "dependenc" not in rep["scope"]:
        unresolved = []
    if unresolved:
        shown = ", ".join(f"`{p}`" for p in unresolved[:3])
        more = f" (and {len(unresolved) - 3} more)" if len(unresolved) > 3 else ""
        plural = "these manifests" if len(unresolved) > 1 else "this manifest"
        note = (f"No lockfile resolves {shown}{more}. Dependencies are read from the "
                f"resolved tree in a lockfile, so the dependencies declared in "
                f"{plural} were probably not scanned — a zero count for that "
                "ecosystem may mean \"not scanned\" rather than \"clean\". Generate "
                "and commit the lockfile (e.g. `npm install --package-lock-only`, "
                "`poetry lock`, `uv lock`, `cargo generate-lockfile`, "
                "`composer update --lock`, `bundle lock`), then re-run.")
        if any(posixpath.basename(p) in SYNTHESIZED_SERVER_SIDE for p in unresolved):
            note += (" For npm the platform tries to synthesise a lockfile before "
                     "scanning, so findings may still be present — but that needs "
                     "registry access and is skipped for npm workspaces, so it is "
                     "not something to rely on.")
        notes.append(note)
    if not rep["findings"]:
        return notes
    if not s["runtime_present"]:
        notes.append(
            f"**Runtime reachability is unknown on this repo, not zero.** No issue was "
            f"evaluated against runtime (no sensor, or the code repo and image aren't "
            f"correlated), so the runtime-reachable count above reads {rep['runtime_reachable']} "
            "because nothing could be checked — not because nothing is reachable. Runtime is "
            "the signal Kodem Score weights most heavily, so treat the ranking as "
            "best-effort on the remaining signals.")
    if rep["sast_total"] and not s["kai_enabled"]:
        notes.append("Kai verdicts are unavailable (Kai is not enabled) — code findings are "
                     "ranked by Kodem Score/severity; review them before fixing.")
    und = s["exploit_undetermined"]
    if und == rep["total"]:
        notes.append("Exploit maturity is undetermined on every issue.")
    elif und:
        notes.append(f"Exploit maturity is undetermined on {und} of {rep['total']} issues "
                     "(those lines omit it).")
    qw = s["quick_wins_failed_projects"]
    if qw and qw.get("failed"):
        if qw["failed"] == qw["total"]:
            notes.append("Quick Wins could not be fetched on this run.")
        else:
            notes.append(f"Quick Wins unavailable for {qw['failed']} of {qw['total']} projects.")
    return notes


def footer(rep):
    examples = ["\"fix the top 10\""]
    if rep["runtime_reachable"]:
        examples.append("\"fix the runtime-reachable ones\"")
    if rep["quick_wins"]:
        examples.append("\"take the quick win\"")
    return ["",
            f"To fix any of this, run the backlog fix (kodem-backlog-fix) — e.g. "
            f"{' or '.join(examples[:2])}.",
            "Note: issues resolve in Kodem once a fix is deployed and the sensor stops "
            "seeing the vulnerable component — not the moment code is committed."]


def render_full(rep, elide_findings=False):
    out = [f"# Kodem Security report — {rep['repo']}"]
    if rep["scope"]:
        out.append(f"_Scoped: {rep['scope']} — issues outside this scope are not shown._")
    out += ["", "## 1. Overview",
            f"Kodem project(s): {', '.join(rep['projects']) or 'none'}"]
    out.append(f"Open issues: {rep['total']} · runtime-reachable: {rep['runtime_reachable']} · "
               f"SCA with a validated fix: {rep['sca_fixable']}/{rep['sca_total']}")
    out += ["", "## 2. Findings summary", "| Severity | SCA | SAST | Total |", "|---|---|---|---|"]
    for sev in SEV_ORDER:
        c = rep["counts"][sev]
        if sev == "Other" and not (c["sca"] or c["sast"]):
            continue
        out.append(f"| {sev} | {c['sca']} | {c['sast']} | {c['sca'] + c['sast']} |")
    out.append(f"| **Total** | **{rep['sca_total']}** | **{rep['sast_total']}** | **{rep['total']}** |")
    out += ["", "## 3. Policies & breaches"]
    for l in policy_section(rep):
        s = l.strip()
        out.append(f"  {s}" if s.startswith("- breaching") else f"- {s}")
    multi = len(rep["projects"]) > 1
    out += ["", f"## 4. All findings ({rep['total']} — grouped by severity, runtime first)"]
    if not rep["findings"]:
        out.append("None — the backlog is clean.")
    for sev in SEV_ORDER:
        group = [f for f in rep["findings"] if f["severity"] == sev]
        if not group:
            continue
        group.sort(key=lambda f: (not f["runtime"], -f["score"]))
        out.append(f"### {sev} ({len(group)})")
        shown = group[:3] if elide_findings else group
        out += [finding_line(f, show_project=multi) for f in shown]
        if len(group) > len(shown):
            out.append(f"- … {len(group) - len(shown)} more {sev} findings (complete list in the report file)")
        out.append("")
    if elide_findings and rep["findings"]:
        out.append("_This backlog is large, so only the top of each severity group is shown "
                   "inline — the complete findings list is in the report file named on the "
                   "BUILD_REPORT_FILES line below._")
    if rep["findings"] or rep["quick_wins"]:
        out += ["## 5. Recommended next steps"]
        n = 0
        for f in rep["top_priorities"]:
            n += 1
            link = f" — [view in Kodem]({f['ui_link']})" if f["ui_link"] else ""
            out.append(f"{n}. {finding_line(f, show_project=multi)[2:]}{link}")
        for w in rep["quick_wins"]:
            n += 1
            out.append(f"{n}. {quick_win_line(w)}")
    notes = signal_notes(rep)
    if notes:
        out += ["", "**Missing signals:**"] + [f"- {n}" for n in notes]
    return "\n".join(out + (footer(rep) if rep["findings"] else []))


def render_posture(rep):
    sev_bits = " / ".join(
        f"{rep['counts'][sev]['sca'] + rep['counts'][sev]['sast']} {sev}"
        for sev in SEV_ORDER
        if not (sev == "Other" and not (rep['counts'][sev]['sca'] or rep['counts'][sev]['sast'])))
    out = [f"Kodem posture — {rep['repo']}"]
    if rep["scope"]:
        out.append(f"Scoped: {rep['scope']}")
    if len(rep["projects"]) > 1:
        out.append(f"Projects: {', '.join(rep['projects'])}")
    out.append(f"Open: {rep['total']} ({sev_bits}) · {rep['sca_total']} SCA · {rep['sast_total']} SAST")
    out.append(f"Real risk: {rep['runtime_reachable']} runtime-reachable · "
               f"Fixable: {rep['sca_fixable']}/{rep['sca_total']} SCA with a validated fix")
    policy_lines = policy_section(rep)
    out.append("Policy: " + " · ".join(l for l in policy_lines if not l.strip().startswith("- breaching")))
    out += [f"  {l.strip()}" for l in policy_lines if l.strip().startswith("- breaching")]
    multi = len(rep["projects"]) > 1
    if rep["findings"]:
        out.append("Top priorities (Kodem Score):")
        for i, f in enumerate(rep["top_priorities"], 1):
            out.append(f"  {i}. {finding_line(f, show_project=multi)[2:]}")
    else:
        out.append("The backlog is clean — nothing to prioritize.")
    for w in rep["quick_wins"]:
        out.append(quick_win_line(w))
    notes = signal_notes(rep)
    if notes:
        out += ["Missing signals: " + " ".join(notes)]
    return "  \n".join(out + (footer(rep) if rep["findings"] else []))


def render_csv(rep):
    buf = io.StringIO()
    writer = csv.writer(buf)

    def safe(value):
        # Guard against spreadsheet formula injection.
        text = str(value)
        return "'" + text if text[:1] in ("=", "+", "-", "@") else text

    writer.writerow(["severity", "category", "score", "title", "risk_id", "cwe", "runtime",
                     "exploit_maturity", "fix", "kai", "policy_breach", "project", "ui_link"])
    for f in rep["findings"]:
        writer.writerow([safe(f["severity"]), f["category"], f["score"], safe(f["title"]),
                         safe(f["risk_id"]), safe(f["cwe"]), f["runtime"],
                         f["exploit_maturity"], safe(f["fix"]), f["kai"] or "",
                         f["policy_breach"], safe(f["project"]), safe(f["ui_link"])])
    return buf.getvalue()


def main():
    ap = Parser(description=__doc__,
                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo_root")
    ap.add_argument("--repo-name")
    ap.add_argument("--view", choices=["full", "posture"], default="full")
    ap.add_argument("--format", dest="fmt", choices=["md", "json", "csv"], default="md")
    ap.add_argument("--out")
    ap.add_argument("--inline-limit", type=int, default=50,
                    help="above this many findings, stdout shows a preview and points "
                         "to the report file (0 = always print everything)")
    ap.add_argument("--skip-policy-scan", action="store_true")
    ap.add_argument("--severity")
    ap.add_argument("--type", dest="issue_type")
    ap.add_argument("--runtime", action="store_true")
    ap.add_argument("--package")
    ap.add_argument("--cve")
    args = ap.parse_args()

    args.repo_root = os.path.abspath(args.repo_root)
    if not os.path.isdir(args.repo_root):
        fail(1, f"repo root not found: {args.repo_root}")
    if args.out:
        args.out = os.path.abspath(args.out)
    os.chdir(args.repo_root)

    check_auth()
    repo_name = args.repo_name or derive_repo_name(args.repo_root)

    scope_args, scope_bits = [], []
    if args.severity:
        scope_args += ["--severity", args.severity]
        names = [s.strip().capitalize() for s in args.severity.split(",")]
        scope_bits.append(" and ".join(names) + " severities")
    if args.issue_type:
        scope_args += ["--type", args.issue_type]
        kind = {"sca": "dependency (SCA) issues", "sast": "code (SAST) issues"}
        scope_bits.append(kind.get(args.issue_type.lower(), f"{args.issue_type} issues"))
    if args.package:
        scope_args += ["--package", args.package]
        scope_bits.append(f"package {args.package}")
    if args.cve:
        scope_args += ["--cve", args.cve]
        scope_bits.append(args.cve)
    if args.runtime:
        scope_args.append("--runtime")
        scope_bits.append("runtime-reachable only")
    scope_desc = ", ".join(scope_bits)

    data = pull_issues(repo_name, scope_args)
    project_ids = sorted({i.get("projectId") for i in data.get("issues") or [] if i.get("projectId")})
    quick_wins, qw_unavailable = pull_quick_wins(project_ids)

    if args.skip_policy_scan:
        policy = {"state": "skipped", "verdicts": [], "breaches": [],
                  "raw": [], "update_available": None, "sides": {}}
    else:
        policy = merge_policies([(variant, parse_policy(text, rc))
                                 for variant, rc, text in pull_policy(args.repo_root, repo_name)])

    rep = digest(data, policy, quick_wins, qw_unavailable, repo_name, scope_desc,
                 manifests_without_lockfile(args.repo_root))

    out_dir = args.out or tempfile.mkdtemp(prefix="kodem-report-")
    # Never write into the repo (realpath, so a symlink can't smuggle the write inside).
    try:
        inside = os.path.commonpath(
            [os.path.realpath(out_dir), os.path.realpath(args.repo_root)]
        ) == os.path.realpath(args.repo_root)
    except ValueError:
        inside = False
    if inside:
        fail(1, "--out must point outside the repo (the report never writes into it); "
                "pass a temp or home directory instead")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(rep, f, indent=2)

    rendered = {"md": render_full(rep) if args.view == "full" else render_posture(rep),
                "json": json.dumps(rep, indent=2),
                "csv": render_csv(rep)}[args.fmt]
    ext = {"md": "md", "json": "json", "csv": "csv"}[args.fmt]
    with open(os.path.join(out_dir, f"report.{ext}"), "w") as f:
        f.write(rendered + "\n")

    elide = bool(args.inline_limit) and len(rep["findings"]) > args.inline_limit
    if elide:
        if args.fmt == "md" and args.view == "full":
            stdout_text = render_full(rep, elide_findings=True)
        elif args.fmt in ("json", "csv"):
            stdout_text = (f"{len(rep['findings'])} findings — too many to print inline; "
                           f"the complete report.{ext} is in the directory below.")
        else:
            stdout_text, elide = rendered, False
    else:
        stdout_text = rendered

    print(stdout_text)
    print()
    print(f"BUILD_REPORT_FILES: {out_dir}")
    if elide:
        print(f"BUILD_REPORT_INLINE: elided ({len(rep['findings'])} findings > "
              f"--inline-limit {args.inline_limit}; the file has the complete list)")
    if policy.get("update_available"):
        print(f"KODEM_UPDATE_AVAILABLE: {policy['update_available']}")
    print("BUILD_REPORT_RESULT: ok")


if __name__ == "__main__":
    main()
