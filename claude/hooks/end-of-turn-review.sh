#!/usr/bin/env bash
# Stop hook — end-of-turn security gate.
#
# When the turn ends, diff the working tree against the pre-turn baseline
# (capture-baseline.sh) to find what changed this turn, then scan:
#   • SAST — diff-aware over a detached worktree at the baseline with this turn's
#     changes overlaid, so only findings introduced this turn are reported.
#   • SCA  — over a temp dir of the changed manifests (+companion lockfiles),
#     compared against a baseline temp dir for only-new dependency findings.
# Runs --no-trace (local-only). Findings come back repo-relative (worktree and
# temp-dir prefixes stripped), so no temp path leaks to context.
#
# Outcome:
#   • policy block → block the stop, return findings to fix
#   • auth-required → one systemMessage line to the developer, turn ends
#   • anything else (clean/warn/scan-error/cli-missing) → silent, turn ends
#
# Loop safety: a round counter (MAX_ROUNDS, matching the backlog-fix skill's two-cycle
# cap) plus a no-progress guard that gives up when findings repeat, keeping the hash.
# Not .stop_hook_active — these guards also let remediation edits re-scan.
# Baseline: written only when none exists, deleted once a review reaches a verdict.
#
# Stdin (hook JSON): .session_id, .cwd

set -u

command -v jq  >/dev/null 2>&1 || exit 0
command -v git >/dev/null 2>&1 || exit 0

HOOK_INPUT="$(cat)"
get() { printf '%s' "$HOOK_INPUT" | jq -r "$1" 2>/dev/null; }

SESSION_ID="$(get '.session_id // "nosession"')"
CWD="$(get '.cwd // ""')"
[ -n "$CWD" ] || CWD="$PWD"

REPO="$(git -C "$CWD" rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$REPO" ] || exit 0

KEY="$(printf '%s' "$SESSION_ID" | shasum 2>/dev/null | cut -c1-16)"
[ -n "$KEY" ] || KEY=default
SHA_FILE="/tmp/.kodem-base-sha-${KEY}"
UNT_FILE="/tmp/.kodem-base-unt-${KEY}"
ROUNDS="/tmp/.kodem-review-rounds-${KEY}"
LASTHASH="/tmp/.kodem-review-lasthash-${KEY}"
MAX_ROUNDS=2

# Well-known empty-tree object — baseline for a repo with no commits yet.
EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

reset_state() { rm -f "$ROUNDS" "$LASTHASH" "/tmp/.kodem-review-treesig-${KEY}" 2>/dev/null || true; }

# ONLY after a verdict on this turn's changes. Bailing without scanning must keep
# the baseline, or the un-reviewed changes fold into the next one and escape.
clear_baseline() { rm -f "$SHA_FILE" "$UNT_FILE" 2>/dev/null || true; }

# ---- Determine the diff baseline (captured by capture-baseline.sh at UPS) ----
BASE=""
[ -f "$SHA_FILE" ] && BASE="$(cat "$SHA_FILE" 2>/dev/null)"
# An unresolvable baseline is worse than none: `git diff <garbage>` returns nothing,
# which reads as "nothing changed" and skips the gate.
if [ -n "$BASE" ] && ! git -C "$REPO" rev-parse --verify --quiet "${BASE}^{tree}" >/dev/null 2>&1; then
  BASE=""
fi
if [ -z "$BASE" ]; then
  # No usable baseline (e.g., session started mid-stream) → fall back to HEAD, or
  # the empty tree for a repo with no commits.
  BASE="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "$EMPTY_TREE")"
fi
[ -n "$BASE" ] || BASE="$EMPTY_TREE"

# ---- Build the changed-file set (repo-relative), NUL-safe ----
# NUL reads + core.quotePath=false so odd filenames aren't split or dropped — a
# dropped file escapes the gate. The two sets are disjoint, so no dedup.
mtime_of() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0; }
baseline_mtime() { # echo baseline mtime for $1, empty if it wasn't untracked at baseline
  [ -f "$UNT_FILE" ] || return 1
  local lp lm
  while IFS= read -r -d '' lp && IFS= read -r -d '' lm; do
    if [ "$lp" = "$1" ]; then printf '%s' "$lm"; return 0; fi
  done < "$UNT_FILE"
  return 1
}

REL_FILES=()

# Our own installed scripts live under .claude/skills|plugins and carry the very
# patterns the scanner looks for. Everything else under .claude/ is the developer's.
is_tool_own_file() {
  case "$1" in
    .claude/skills/*|.claude/plugins/*|*/.claude/skills/*|*/.claude/plugins/*) return 0 ;;
  esac
  return 1
}

# Tracked files changed this turn (skip deletions — non-existent paths).
while IFS= read -r -d '' rel; do
  [ -n "$rel" ] || continue
  [ -f "$REPO/$rel" ] || continue
  is_tool_own_file "$rel" && continue
  REL_FILES+=("$rel")
done < <(git -C "$REPO" -c core.quotePath=false diff -z --name-only "$BASE" -- 2>/dev/null || true)

# Untracked files: new this turn, or pre-existing untracked whose mtime moved.
while IFS= read -r -d '' p; do
  [ -n "$p" ] || continue
  [ -f "$REPO/$p" ] || continue
  is_tool_own_file "$p" && continue
  bm="$(baseline_mtime "$p" || true)"
  if [ -z "$bm" ] || [ "$bm" != "$(mtime_of "$REPO/$p")" ]; then
    REL_FILES+=("$p")
  fi
done < <(git -C "$REPO" -c core.quotePath=false ls-files -z --others --exclude-standard 2>/dev/null || true)

# A pre-existing untracked file is in the baseline commit but not the real index, so
# `git diff` re-lists it every turn unchanged. Drop anything matching the baseline.
TREESIG_SRC=""
if [ "${#REL_FILES[@]}" -gt 0 ]; then
  _kept=()
  for rel in "${REL_FILES[@]}"; do
    cur="$(git -C "$REPO" hash-object "$REPO/$rel" 2>/dev/null)"
    base_blob="$(git -C "$REPO" rev-parse "$BASE:$rel" 2>/dev/null)"
    if [ -n "$cur" ] && [ "$cur" = "$base_blob" ]; then continue; fi
    _kept+=("$rel")
    TREESIG_SRC="${TREESIG_SRC}${rel}:${cur}
"
  done
  REL_FILES=(${_kept[@]+"${_kept[@]}"})
fi
# Content signature of what changed. A give-up only holds while the tree still says
# the same thing; otherwise a different violation sharing the same file/rule/CWE
# identifiers would stay masked, since those lines carry no line numbers.
TREESIG="$(printf '%s' "$TREESIG_SRC" | LC_ALL=C sort | shasum 2>/dev/null | awk '{print $1}')"
TREESIG_FILE="/tmp/.kodem-review-treesig-${KEY}"
if [ -f "$TREESIG_FILE" ] && [ "$TREESIG" != "$(cat "$TREESIG_FILE" 2>/dev/null)" ]; then
  reset_state
fi

# Nothing scannable changed → silent. Reviewed, so the baseline goes too.
if [ "${#REL_FILES[@]}" -eq 0 ]; then
  reset_state
  clear_baseline
  exit 0
fi

# ---- Loop backstop ----
ROUND=0
[ -f "$ROUNDS" ] && ROUND="$(cat "$ROUNDS" 2>/dev/null || echo 0)"
case "$ROUND" in ''|*[!0-9]*) ROUND=0 ;; esac
if [ "$ROUND" -ge "$MAX_ROUNDS" ]; then
  # Out of rounds. Keep LASTHASH (stays quiet) and the baseline (findings uncleared).
  rm -f "$ROUNDS" 2>/dev/null || true
  printf '%s' "$TREESIG" > "$TREESIG_FILE" 2>/dev/null || true
  exit 0
fi

# ---- Locate the scan engine ----
# Helpers are SEARCHED, not at a fixed path, so this one file works whether it is
# installed as a plugin or as a standalone skill. A fixed path is what let the two
# shipped copies drift and ship a stale gate. Neither layout is privileged, and
# CLAUDE_PLUGIN_ROOT is optional — standalone installs never set it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
# Only used to reach the plugin layout's sibling skills/ directory; harmless if unset.
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(dirname "$SCRIPT_DIR")}"
find_helper() { # echo the first existing path for helper $1; non-zero if none
  local name="$1" candidate
  for candidate in \
    "$SCRIPT_DIR/$name" \
    "$SCRIPT_DIR/scripts/$name" \
    "$PLUGIN_ROOT/skills/kodem-security/scripts/$name"
  do
    if [ -f "$candidate" ]; then printf '%s' "$candidate"; return 0; fi
  done
  return 1
}
SCAN="$(find_helper scan.sh || true)"
if [ -z "$SCAN" ]; then
  # Nothing reviewed — keep the baseline so the changes stay pending.
  reset_state
  exit 0
fi

# ---- Stage the changed files into a temp dir (mirroring repo-relative paths) ----
is_depfile() {
  case "$(basename "$1")" in
    go.mod|go.sum|package.json|package-lock.json|yarn.lock|pnpm-lock.yaml|\
    requirements*.txt|Pipfile|Pipfile.lock|pyproject.toml|poetry.lock|uv.lock|pdm.lock|pom.xml|\
    build.gradle|build.gradle.kts|Gemfile|Gemfile.lock|Cargo.toml|Cargo.lock) return 0 ;;
  esac
  return 1
}

# Guard mktemp so an empty var can't later turn `mkdir -p "$CUR_DIR/$d"` into a
# write at the filesystem root. A failed mktemp → bail silently (never block).
CUR_DIR="$(mktemp -d)" || exit 0
BASE_DIR="$(mktemp -d)" || { rm -rf "$CUR_DIR" 2>/dev/null || true; exit 0; }
WT_DIR=""   # diff-aware SAST worktree (set below if any source changed)
cleanup_stage() {
  [ -n "$WT_DIR" ] && git -C "$REPO" worktree remove --force "$WT_DIR" >/dev/null 2>&1
  rm -rf "$CUR_DIR" "$BASE_DIR" ${WT_DIR:+"$WT_DIR"} 2>/dev/null || true
}
trap cleanup_stage EXIT

# Stage one repo-relative path: current content → CUR_DIR, pre-turn content →
# BASE_DIR (absent if the file is new this turn, so its deps count as new).
stage_one() {
  local rel="$1" d
  [ -e "$CUR_DIR/$rel" ] && return 0          # already staged
  [ -f "$REPO/$rel" ] || return 0
  d="$(dirname "$rel")"
  mkdir -p "$CUR_DIR/$d" && cp "$REPO/$rel" "$CUR_DIR/$rel" 2>/dev/null || true
  if git -C "$REPO" cat-file -e "$BASE:$rel" 2>/dev/null; then
    mkdir -p "$BASE_DIR/$d"
    git -C "$REPO" show "$BASE:$rel" > "$BASE_DIR/$rel" 2>/dev/null || true
  fi
}

HAS_SOURCE=false
HAS_MANIFEST=false
for rel in "${REL_FILES[@]}"; do
  stage_one "$rel"
  if is_depfile "$rel"; then HAS_MANIFEST=true; else HAS_SOURCE=true; fi
done

# For each changed manifest, also stage its sibling dependency files — e.g. a
# changed package.json needs its package-lock.json; a changed go.mod needs go.sum.
if [ "$HAS_MANIFEST" = true ]; then
  for rel in "${REL_FILES[@]}"; do
    is_depfile "$rel" || continue
    d="$(dirname "$rel")"
    base="$REPO"; [ "$d" != "." ] && base="$REPO/$d"
    for entry in "$base"/*; do
      [ -f "$entry" ] || continue
      is_depfile "$entry" || continue
      sib="${entry#"$REPO"/}"
      stage_one "$sib"
    done
  done
fi

# Diff-aware SAST: a detached worktree at the baseline with this turn's files
# overlaid and staged, so only new findings are reported. Staging is required — the
# scanner keys off git state. The real repo is never touched.
if [ "$HAS_SOURCE" = true ] && [ -n "$BASE" ]; then
  WT_DIR="$(mktemp -d)" || WT_DIR=""
  if [ -n "$WT_DIR" ] && git -C "$REPO" worktree add --detach --quiet "$WT_DIR" "$BASE" 2>/dev/null; then
    for rel in "${REL_FILES[@]}"; do
      [ -f "$REPO/$rel" ] || continue
      mkdir -p "$WT_DIR/$(dirname "$rel")" 2>/dev/null || true
      cp "$REPO/$rel" "$WT_DIR/$rel" 2>/dev/null || true
    done
    git -C "$WT_DIR" add -A >/dev/null 2>&1 || true
  else
    # Worktree prep failed → fall back to a self-scoped directory scan (reports
    # all findings in the changed files rather than only-new ones).
    [ -n "$WT_DIR" ] && { rm -rf "$WT_DIR" 2>/dev/null || true; }
    WT_DIR=""
  fi
fi

# SAST scans the worktree diff-aware (or the changed-file dir if no worktree);
# SCA scans the staged manifests against the baseline dir for only-new deps.
REPO_NAME="$(git -C "$REPO" remote get-url origin 2>/dev/null | sed 's|\.git$||' | sed -E 's|.*/||')"
[ -n "$REPO_NAME" ] || REPO_NAME="$(basename "$REPO")"
BRANCH_NAME="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

# Nothing left to scan — our own files only, or the code scan was skipped above.
if [ "$HAS_SOURCE" = false ] && [ "$HAS_MANIFEST" = false ]; then
  reset_state
  clear_baseline
  exit 0
fi

SCAN_ARGS=(--no-trace --repo-name "$REPO_NAME" --branch-name "$BRANCH_NAME")
if [ "$HAS_SOURCE" = true ]; then
  if [ -n "$WT_DIR" ]; then SCAN_ARGS+=(--sast-worktree "$WT_DIR")
  else                      SCAN_ARGS+=(--sast-dir "$CUR_DIR"); fi
fi
[ "$HAS_MANIFEST" = true ] && SCAN_ARGS+=(--sca-dir "$CUR_DIR" --sca-baseline-dir "$BASE_DIR")

OUT="$(bash "$SCAN" "$REPO" "${SCAN_ARGS[@]}" 2>&1)"
STATUS="$(printf '%s\n' "$OUT" | grep -oE '^KODEM_RESULT: [a-z-]+' | tail -n1 | awk '{print $2}')"

# Only a policy block returns to the agent. Everything else stays silent.
if [ "$STATUS" != "blocked" ]; then
  reset_state
  # clean/warn reached a verdict; the rest did not, so keep the baseline.
  case "$STATUS" in clean|warn) clear_baseline ;; esac
  # The one exception to staying silent. An expired token fails every scan, recurs
  # daily, and the developer clears it in one command — so silence here costs a
  # whole session of unreviewed edits. systemMessage reaches the developer without
  # blocking the turn or putting anything in front of the agent, so the gate stays
  # fail-open. Every other failure remains silent: nothing the developer can act on.
  if [ "$STATUS" = "auth-required" ]; then
    jq -nc '{systemMessage:"Kodem gate skipped: not authenticated — run `kodem-cli auth login`"}' 2>/dev/null \
      || echo '{"systemMessage":"Kodem gate skipped: not authenticated — run `kodem-cli auth login`"}'
  fi
  exit 0
fi

# Strip our bookkeeping lines and any temp-dir prefix from the findings text
# (findings are already repo-relative; this is a safeguard).
STRIP_SED="s|${CUR_DIR}/||g; s|${BASE_DIR}/||g"
[ -n "$WT_DIR" ] && STRIP_SED="$STRIP_SED; s|${WT_DIR}/||g"
FINDINGS="$(printf '%s\n' "$OUT" \
  | grep -vE '^KODEM_(RESULT|FINDINGS|UPDATE_AVAILABLE):' \
  | grep -vE '^\[\+\] ' \
  | sed "$STRIP_SED")"

# Hash the stable identifiers (file / rule / CWE), normalised first: the CLI orders
# findings nondeterministically and decorates them with tree glyphs and ANSI, none of
# which changes what was found. Strip both, sort, so the hash is the set alone.
ESC="$(printf '\033')"
STRUCT="$(printf '%s' "$FINDINGS" \
  | sed -E "s/${ESC}\[[0-9;]*m//g" \
  | LC_ALL=C sed -E 's/^[^A-Za-z0-9]+//' \
  | grep -E 'violates .* rule|CWE:|^File:' \
  | LC_ALL=C sort)"
# Fallback if the output format changes: strip volatile timings, or the hash moves
# every run and the guard never fires.
[ -n "$STRUCT" ] || STRUCT="$(printf '%s' "$FINDINGS" \
  | grep -vE 'Duration|[0-9]+\.[0-9]+ ?s|elapsed|Total Issues' | LC_ALL=C sort)"
HASH="$(printf '%s' "$STRUCT" | shasum 2>/dev/null | awk '{print $1}')"
if [ -f "$LASTHASH" ] && [ "$HASH" = "$(cat "$LASTHASH" 2>/dev/null)" ]; then
  # Give up on this set; KEEP the hash so unchanged findings stay quiet (it clears on a clean scan or new findings).
  rm -f "$ROUNDS" 2>/dev/null || true
  printf '%s' "$TREESIG" > "$TREESIG_FILE" 2>/dev/null || true
  exit 0
fi

echo "$((ROUND + 1))" > "$ROUNDS" 2>/dev/null || true
printf '%s' "$HASH" > "$LASTHASH" 2>/dev/null || true

REASON="Kodem security policy gate FAILED for this turn's changes. They will be re-scanned automatically when you finish.

${FINDINGS}

How to act on these — this gate is a REMINDER, NOT AN APPROVAL. It does not widen the scope the developer approved.
- \"Already approved\" means the developer approved this specific file and this specific change. If no such approval exists — which is the normal case on an ordinary coding turn — then the approved set is EMPTY, and everything below that needs approval needs asking.
- Safe dependency fixes (a patch or minor version bump, a transitive pin): apply them now. A MAJOR bump, a package that needs both a safe and a major fix, a lockfile edit, or running a package manager still needs the developer's agreement — present it, don't apply it.
- Code-logic changes (rewriting a query, replacing eval, adding validation, moving a secret): apply only what was already approved, and only at the size that was approved. If the fix turns out materially bigger than what you described — a rewrite rather than an edit — stop and re-confirm before writing it. Otherwise report the finding and ask. This gate does not override the skill's rule against silently rewriting logic.
- Never make a finding disappear instead of fixing it: no suppression or ignore comments, no deleting the file, no dropping or downgrading the dependency, no editing a Kodem policy or ignore list. Fix it or report it.
- Policy rules (e.g. banned package names) evaluate the full manifest, so a finding may pre-date this turn's edits. If a finding pre-dates your change, is a genuine false positive, or can't be fixed now, leave it and raise it to the user.
- At most two fix-and-re-scan cycles in total, counting any you already ran this turn. If findings remain after the second, stop and hand the rest to the user rather than continuing to edit."

jq -nc --arg r "$REASON" '{decision:"block", reason:$r}'
exit 0
