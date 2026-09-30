#!/usr/bin/env bash
# Kodem end-of-turn security gate: scans this turn's changes and blocks the stop on a
# policy violation. Fails open (exit 0, silent) on any error.
# Usage: end-of-turn-review.sh [--platform claude|codex|gemini|copilot|cursor|antigravity]
#   host         event       policy block                    auth notice
#   Claude Code  Stop        {decision:"block", reason}      systemMessage
#   Codex        Stop        {decision:"block", reason}      systemMessage
#   Gemini CLI   AfterAgent  {decision:"deny", reason}       systemMessage
#   Copilot      agentStop   {decision:"block", reason}      none
#   Cursor       stop        {followup_message}              none
#   Antigravity  Stop        {decision:"continue", reason}   none

set -u

PLATFORM=claude
while [ $# -gt 0 ]; do
  case "$1" in
    --platform)   PLATFORM="${2:-claude}"; shift 2 || shift ;;
    --platform=*) PLATFORM="${1#--platform=}"; shift ;;
    *)            shift ;;
  esac
done
case "$PLATFORM" in
  claude|cursor|gemini|copilot|antigravity|codex) ;;
  *) echo "kodem: unknown --platform '$PLATFORM'; skipping" >&2; exit 0 ;;
esac

command -v jq  >/dev/null 2>&1 || exit 0
command -v git >/dev/null 2>&1 || exit 0

HOOK_INPUT="$(cat)"
get() { printf '%s' "$HOOK_INPUT" | jq -r "$1" 2>/dev/null; }

SESSION_ID="$(get '.session_id // .sessionId // .conversation_id // .conversationId // "nosession"')"
CWD="$(get '.cwd // .workspace_roots[0] // .workspacePaths[0] // ""')"
[ -n "$CWD" ] || CWD="$PWD"

if [ "$PLATFORM" = cursor ]; then
  case "$(get '.status // "completed"')" in completed) ;; *) exit 0 ;; esac
fi

REPO="$(git -C "$CWD" rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$REPO" ] || exit 0

KEY="$(printf '%s' "$SESSION_ID" | shasum 2>/dev/null | cut -c1-16)"
[ -n "$KEY" ] || KEY=default
SHA_FILE="/tmp/.kodem-base-sha-${KEY}"
UNT_FILE="/tmp/.kodem-base-unt-${KEY}"
ROUNDS="/tmp/.kodem-review-rounds-${KEY}"
LASTHASH="/tmp/.kodem-review-lasthash-${KEY}"
MAX_ROUNDS=2

EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

reset_state() { rm -f "$ROUNDS" "$LASTHASH" "/tmp/.kodem-review-treesig-${KEY}" 2>/dev/null || true; }

# Clear ONLY after a verdict, or un-reviewed changes fold into the next baseline and escape.
clear_baseline() { rm -f "$SHA_FILE" "$UNT_FILE" 2>/dev/null || true; }

BASE=""
[ -f "$SHA_FILE" ] && BASE="$(cat "$SHA_FILE" 2>/dev/null)"
if [ -n "$BASE" ] && ! git -C "$REPO" rev-parse --verify --quiet "${BASE}^{tree}" >/dev/null 2>&1; then
  BASE=""
fi
if [ -z "$BASE" ]; then
  BASE="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "$EMPTY_TREE")"
fi
[ -n "$BASE" ] || BASE="$EMPTY_TREE"

mtime_of() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0; }
baseline_mtime() {
  [ -f "$UNT_FILE" ] || return 1
  local lp lm
  while IFS= read -r -d '' lp && IFS= read -r -d '' lm; do
    if [ "$lp" = "$1" ]; then printf '%s' "$lm"; return 0; fi
  done < "$UNT_FILE"
  return 1
}

REL_FILES=()

is_tool_own_file() {
  case "/$1" in
    */.claude/skills/*|*/.claude/plugins/*) return 0 ;;
    */.cursor/plugins/*|*/.gemini/extensions/*|*/.codex/plugins/*) return 0 ;;
    */.cursor/skills/kodem-*|*/.gemini/skills/kodem-*|*/.github/skills/kodem-*|\
    */.agents/skills/kodem-*|*/.codex/skills/kodem-*)
      case "/$1" in */skills/kodem-security/*|*/skills/kodem-backlog-fix/*|*/skills/kodem-report/*) return 0 ;; esac ;;
  esac
  return 1
}

while IFS= read -r -d '' rel; do
  [ -n "$rel" ] || continue
  [ -f "$REPO/$rel" ] || continue
  is_tool_own_file "$rel" && continue
  REL_FILES+=("$rel")
done < <(git -C "$REPO" -c core.quotePath=false diff -z --name-only "$BASE" -- 2>/dev/null || true)

while IFS= read -r -d '' p; do
  [ -n "$p" ] || continue
  [ -f "$REPO/$p" ] || continue
  is_tool_own_file "$p" && continue
  bm="$(baseline_mtime "$p" || true)"
  if [ -z "$bm" ] || [ "$bm" != "$(mtime_of "$REPO/$p")" ]; then
    REL_FILES+=("$p")
  fi
done < <(git -C "$REPO" -c core.quotePath=false ls-files -z --others --exclude-standard 2>/dev/null || true)

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
TREESIG="$(printf '%s' "$TREESIG_SRC" | LC_ALL=C sort | shasum 2>/dev/null | awk '{print $1}')"
TREESIG_FILE="/tmp/.kodem-review-treesig-${KEY}"
if [ -f "$TREESIG_FILE" ] && [ "$TREESIG" != "$(cat "$TREESIG_FILE" 2>/dev/null)" ]; then
  reset_state
fi

if [ "${#REL_FILES[@]}" -eq 0 ]; then
  reset_state
  clear_baseline
  exit 0
fi

# Round cap plus the no-progress guard below prevent endless block loops.
ROUND=0
[ -f "$ROUNDS" ] && ROUND="$(cat "$ROUNDS" 2>/dev/null || echo 0)"
case "$ROUND" in ''|*[!0-9]*) ROUND=0 ;; esac
if [ "$ROUND" -ge "$MAX_ROUNDS" ]; then
  rm -f "$ROUNDS" 2>/dev/null || true
  printf '%s' "$TREESIG" > "$TREESIG_FILE" 2>/dev/null || true
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "")"
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(dirname "$SCRIPT_DIR")}"
find_helper() {
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
  reset_state
  exit 0
fi

is_depfile() {
  case "$(basename "$1")" in
    go.mod|go.sum|package.json|package-lock.json|yarn.lock|pnpm-lock.yaml|\
    requirements*.txt|Pipfile|Pipfile.lock|pyproject.toml|poetry.lock|uv.lock|pdm.lock|pom.xml|\
    build.gradle|build.gradle.kts|Gemfile|Gemfile.lock|Cargo.toml|Cargo.lock) return 0 ;;
  esac
  return 1
}

CUR_DIR="$(mktemp -d)" || exit 0
BASE_DIR="$(mktemp -d)" || { rm -rf "$CUR_DIR" 2>/dev/null || true; exit 0; }
WT_DIR=""
cleanup_stage() {
  [ -n "$WT_DIR" ] && git -C "$REPO" worktree remove --force "$WT_DIR" >/dev/null 2>&1
  rm -rf "$CUR_DIR" "$BASE_DIR" ${WT_DIR:+"$WT_DIR"} 2>/dev/null || true
}
trap cleanup_stage EXIT

stage_one() {
  local rel="$1" d
  [ -e "$CUR_DIR/$rel" ] && return 0
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
    [ -n "$WT_DIR" ] && { rm -rf "$WT_DIR" 2>/dev/null || true; }
    WT_DIR=""
  fi
fi

REPO_NAME="$(git -C "$REPO" remote get-url origin 2>/dev/null | sed 's|\.git$||' | sed -E 's|.*/||')"
[ -n "$REPO_NAME" ] || REPO_NAME="$(basename "$REPO")"
BRANCH_NAME="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

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

if [ "$STATUS" != "blocked" ]; then
  reset_state
  case "$STATUS" in clean|warn) clear_baseline ;; esac
  if [ "$STATUS" = "auth-required" ] && case "$PLATFORM" in claude|gemini|codex) true ;; *) false ;; esac; then
    jq -nc '{systemMessage:"Kodem gate skipped: not authenticated — run `kodem-cli auth login`"}' 2>/dev/null \
      || echo '{"systemMessage":"Kodem gate skipped: not authenticated — run `kodem-cli auth login`"}'
  fi
  exit 0
fi

STRIP_SED="s|${CUR_DIR}/||g; s|${BASE_DIR}/||g"
[ -n "$WT_DIR" ] && STRIP_SED="$STRIP_SED; s|${WT_DIR}/||g"
FINDINGS="$(printf '%s\n' "$OUT" \
  | grep -vE '^KODEM_(RESULT|FINDINGS|UPDATE_AVAILABLE):' \
  | grep -vE '^\[\+\] ' \
  | sed "$STRIP_SED")"

ESC="$(printf '\033')"
STRUCT="$(printf '%s' "$FINDINGS" \
  | sed -E "s/${ESC}\[[0-9;]*m//g" \
  | LC_ALL=C sed -E 's/^[^A-Za-z0-9]+//' \
  | grep -E 'violates .* rule|CWE:|^File:' \
  | LC_ALL=C sort)"
[ -n "$STRUCT" ] || STRUCT="$(printf '%s' "$FINDINGS" \
  | grep -vE 'Duration|[0-9]+\.[0-9]+ ?s|elapsed|Total Issues' | LC_ALL=C sort)"
HASH="$(printf '%s' "$STRUCT" | shasum 2>/dev/null | awk '{print $1}')"
if [ -f "$LASTHASH" ] && [ "$HASH" = "$(cat "$LASTHASH" 2>/dev/null)" ]; then
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

# These hosts re-prompt with the reason; label it so it can't pass as the developer's approval.
case "$PLATFORM" in
  cursor|gemini|antigravity) REASON="[Automated message from the Kodem security hook, not from the developer.]

${REASON}" ;;
esac

case "$PLATFORM" in
  cursor) jq -nc --arg r "$REASON" '{followup_message:$r}' ;;
  gemini) jq -nc --arg r "$REASON" '{decision:"deny", reason:$r}' ;;
  antigravity) jq -nc --arg r "$REASON" '{decision:"continue", reason:$r}' ;;
  *)      jq -nc --arg r "$REASON" '{decision:"block", reason:$r}' ;;
esac
exit 0
