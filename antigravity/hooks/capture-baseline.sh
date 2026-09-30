#!/usr/bin/env bash
# Kodem prompt-submit hook: snapshots the pre-turn tree for end-of-turn-review.sh.
# Usage: capture-baseline.sh [--platform claude|codex|gemini|copilot|cursor|antigravity]
#   host         event                  session id         working directory
#   Claude Code  UserPromptSubmit       .session_id        .cwd
#   Codex        UserPromptSubmit       .session_id        .cwd
#   Gemini CLI   BeforeAgent            .session_id        .cwd
#   Copilot      userPromptSubmitted    .sessionId         .cwd
#   Cursor       beforeSubmitPrompt     .conversation_id   .workspace_roots[0]
#   Antigravity  PreInvocation          .conversationId    .workspacePaths[0]
# Written only when none exists, cleared only after a verdict: else un-reviewed changes escape.

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

# Cursor blocks the prompt on non-JSON output: emit {"continue":true} on every exit path.
if [ "$PLATFORM" = cursor ]; then
  trap 'printf "%s\n" "{\"continue\":true}"' EXIT
fi

command -v jq  >/dev/null 2>&1 || exit 0
command -v git >/dev/null 2>&1 || exit 0

HOOK_INPUT="$(cat)"
get() { printf '%s' "$HOOK_INPUT" | jq -r "$1" 2>/dev/null; }

SESSION_ID="$(get '.session_id // .sessionId // .conversation_id // .conversationId // "nosession"')"
CWD="$(get '.cwd // .workspace_roots[0] // .workspacePaths[0] // ""')"
[ -n "$CWD" ] || CWD="$PWD"

REPO="$(git -C "$CWD" rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$REPO" ] || exit 0

KEY="$(printf '%s' "$SESSION_ID" | shasum 2>/dev/null | cut -c1-16)"
[ -n "$KEY" ] || KEY=default
SHA_FILE="/tmp/.kodem-base-sha-${KEY}"
UNT_FILE="/tmp/.kodem-base-unt-${KEY}"

KTMP="$(cd /tmp 2>/dev/null && pwd -P || echo /tmp)"
find "$KTMP" -maxdepth 1 -name '.kodem-base-*'   ! -name "*-${KEY}" -mtime +1 -delete 2>/dev/null || true
find "$KTMP" -maxdepth 1 -name '.kodem-review-*' ! -name "*-${KEY}" -mtime +1 -delete 2>/dev/null || true

if [ -s "$SHA_FILE" ]; then
  for state in "$SHA_FILE" "$UNT_FILE" \
               "/tmp/.kodem-review-rounds-${KEY}" "/tmp/.kodem-review-lasthash-${KEY}"; do
    [ -e "$state" ] && touch "$state" 2>/dev/null
  done
  exit 0
fi

BASE=""
TMP_INDEX="$(mktemp 2>/dev/null || echo "")"
if [ -n "$TMP_INDEX" ]; then
  HEAD_SHA="$(git -C "$REPO" rev-parse --verify --quiet HEAD 2>/dev/null || echo "")"
  [ -n "$HEAD_SHA" ] && GIT_INDEX_FILE="$TMP_INDEX" git -C "$REPO" read-tree HEAD 2>/dev/null
  if GIT_INDEX_FILE="$TMP_INDEX" git -C "$REPO" add -A 2>/dev/null; then
    TREE="$(GIT_INDEX_FILE="$TMP_INDEX" git -C "$REPO" write-tree 2>/dev/null || echo "")"
    if [ -n "$TREE" ]; then
      if [ -n "$HEAD_SHA" ]; then
        BASE="$(git -C "$REPO" commit-tree "$TREE" -p "$HEAD_SHA" -m kodem-baseline 2>/dev/null || echo "")"
      else
        BASE="$(git -C "$REPO" commit-tree "$TREE" -m kodem-baseline 2>/dev/null || echo "")"
      fi
    fi
  fi
  rm -f "$TMP_INDEX" 2>/dev/null || true
fi
if [ -z "$BASE" ]; then
  BASE="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "")"
fi

printf '%s\n' "$BASE" > "$SHA_FILE" 2>/dev/null || true

mtime_of() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0; }
: > "$UNT_FILE" 2>/dev/null || true
while IFS= read -r -d '' p; do
  [ -n "$p" ] || continue
  printf '%s\0%s\0' "$p" "$(mtime_of "$REPO/$p")" >> "$UNT_FILE" 2>/dev/null || true
done < <(git -C "$REPO" -c core.quotePath=false ls-files --others --exclude-standard -z 2>/dev/null)

exit 0
