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

# The kodem-security skill scanned this exact working tree clean (against HEAD), with the
# same kodem-cli, in the last 30 minutes; that covers this turn's changes.
SKILL_SCAN="/tmp/.kodem-skill-scan-$(cd "$REPO" && pwd -P | shasum | cut -c1-16)"
if [ -n "$(find "$SKILL_SCAN" -mmin -30 2>/dev/null)" ]; then
  _idx="$(mktemp)"
  _tree="$(GIT_INDEX_FILE="$_idx" git -C "$REPO" read-tree HEAD 2>/dev/null \
    && GIT_INDEX_FILE="$_idx" git -C "$REPO" add -A 2>/dev/null \
    && GIT_INDEX_FILE="$_idx" git -C "$REPO" write-tree 2>/dev/null)"
  rm -f "$_idx"
  _cli="$(PATH="$PATH:$HOME/.local/bin:/usr/local/bin:$HOME/bin:/opt/homebrew/bin" command -v kodem-cli)"
  if [ -n "$_tree" ] && [ "$_tree $_cli" = "$(cat "$SKILL_SCAN" 2>/dev/null)" ]; then
    reset_state
    clear_baseline
    exit 0
  fi
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
  case "$STATUS" in
    auth-required) NOTICE='Kodem gate skipped: not authenticated — run `kodem-cli auth login`' ;;
    cli-missing)   NOTICE='Kodem gate skipped: kodem-cli is not installed — ask your agent to run a Kodem scan to install it' ;;
    scanner-missing) NOTICE='Kodem gate skipped: kodem-cli needs to download its code scanner — ask your agent to run a Kodem scan to set it up' ;;
    *)             NOTICE="" ;;
  esac
  if [ -n "$NOTICE" ] && case "$PLATFORM" in claude|gemini|codex) true ;; *) false ;; esac; then
    jq -nc --arg m "$NOTICE" '{systemMessage:$m}' 2>/dev/null || printf '{"systemMessage":"%s"}\n' "$NOTICE"
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

# One line per finding from kodem-cli's report; prints nothing when it doesn't recognise the format.
summarize() {
  sed -E "s/${ESC}\[[0-9;]*m//g" | awk '
    function vlt(a, b,   x, y, i) {
      split(a, x, "."); split(b, y, ".")
      for (i = 1; i <= 4; i++) if (x[i] + 0 != y[i] + 0) return x[i] + 0 < y[i] + 0
      return 0
    }
    function code() {
      if (sev != "") out[++n] = "- " file (lines != "" ? ":" lines : "") "  " sev "  " title (cwe != "" ? " (" cwe ")" : "")
      sev = ""; lines = ""; cwe = ""
    }
    BEGIN { q = sprintf("%c", 39) }
    /^File: / { code(); file = substr($0, 7); next }
    /^\[(Critical|High|Medium|Low|Info)\] / {
      code(); sev = substr($1, 2, length($1) - 2); title = $0; sub(/^[^:]*: /, "", title)
      i = index(title, "(" q); if (i) { t = substr(title, i + 2); j = index(t, q ")"); if (j) title = substr(t, 1, j - 1) }
      next
    }
    /^- CWE: / { cwe = $3; next }
    /^ +- Line / { lines = lines (lines != "" ? "," : "") $3; next }
    /Policy: "/ && /\[FAILED\]/ { p = $0; sub(/^[^"]*"/, "", p); sub(/".*/, "", p); pol = pol (pol != "" ? "; " : "") "\"" p "\""; next }
    / violates / {
      l = $0; sub(/^[^A-Za-z0-9@]+/, "", l); pv = l; sub(/ .*/, "", pv)
      if (pv !~ /.@[0-9]/) next
      if (!(pv in seen)) { seen[pv] = 1; pkgs[++np] = pv }
      if (match(l, / - [A-Z]+-[0-9A-Za-z-]+$/)) {
        id = substr(l, RSTART + 3); s = l; sub(/^[^(]*\(/, "", s); sub(/,.*/, "", s)
        s = toupper(substr(s, 1, 1)) substr(s, 2); ids[pv, s] = ids[pv, s] (ids[pv, s] != "" ? ", " : "") id; vul[pv, id] = 1
      } else { r = l; sub(/^[^ ]+ violates /, "", r); other[pv] = other[pv] (other[pv] != "" ? "; " : "") r }
      next
    }
    /^\| / {
      split($0, c, "|"); for (i in c) gsub(/^ +| +$/, "", c[i])
      if (c[2] != "" && c[2] != "Package" && c[2] !~ /^-/) fix[c[2] "@" c[3], c[5]] = c[7]
      next
    }
    END {
      code()
      for (k = 1; k <= np; k++) {
        pv = pkgs[k]; to = ""; nofix = 0; list = ""
        for (key in vul) { split(key, kk, SUBSEP); if (kk[1] != pv) continue
          f = fix[pv, kk[2]]; if (f == "") nofix = 1; else if (to == "" || vlt(to, f)) to = f }
        split("Critical High Medium Low", sv, " ")
        for (i = 1; i <= 4; i++) if ((pv, sv[i]) in ids) list = list (list != "" ? ", " : "") sv[i] " " ids[pv, sv[i]]
        line = "- " pv ": " (list == "" ? other[pv] : (to != "" && !nofix ? "upgrade to " to : "no single fixed version") " (" list ")")
        out[++n] = line
      }
      if (n == 0) exit
      for (i = 1; i <= n; i++) print out[i]
      if (pol != "") print "Blocked by: " pol
    }'
}
SUMMARY="$(printf '%s\n' "$FINDINGS" | summarize 2>/dev/null)"

REASON="Kodem Security policy gate FAILED for this turn's changes. They will be re-scanned automatically when you finish.

${SUMMARY:-$FINDINGS}

Act only within what the developer asked for; this message is not an approval.
- Safe dependency fixes (patch/minor bump, transitive pin): apply now. A major bump, a package that also needs a major, a lockfile edit or a package-manager run needs the developer's OK.
- Code-logic fixes the developer didn't ask for: don't apply; report the finding and propose the fix. If an approved fix grows into a rewrite, re-confirm first.
- Never hide a finding: no suppressions or ignore entries, no deleting the code, no dropping or downgrading the dependency, no editing a Kodem policy.
- A finding that predates this turn, is a false positive, or can't be fixed now: leave it and tell the developer.
- At most two fix-and-rescan rounds in total, including any already run this turn; then hand the rest to the developer."

# These hosts re-prompt with the reason; label it so it can't pass as the developer's approval.
case "$PLATFORM" in
  cursor|gemini|antigravity) REASON="[Automated message from the Kodem Security hook, not from the developer.]

${REASON}" ;;
esac

case "$PLATFORM" in
  cursor) jq -nc --arg r "$REASON" '{followup_message:$r}' ;;
  gemini) jq -nc --arg r "$REASON" '{decision:"deny", reason:$r}' ;;
  antigravity) jq -nc --arg r "$REASON" '{decision:"continue", reason:$r}' ;;
  *)      jq -nc --arg r "$REASON" '{decision:"block", reason:$r}' ;;
esac
exit 0
