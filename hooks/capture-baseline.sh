#!/usr/bin/env bash
# UserPromptSubmit hook — snapshot the pre-turn working tree.
#
# Records git state at turn start so the Stop hook can diff against it — catching
# changes from any source, since the set comes from git, not edit-tool tracking.
#
# The baseline is the last REVIEWED state, not the last prompt: written only when none
# exists, deleted once a review completes. Re-capturing every prompt let a mid-turn
# message hide an un-reviewed change from the gate.
#
# Per-session state under /tmp:
#   .kodem-base-sha-<key>  baseline commit (full pre-turn tree), or HEAD if unavailable
#   .kodem-base-unt-<key>  untracked <path>\0<mtime> pairs (to detect new-this-turn files)
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

# Outside a git repo there's nothing to diff — stay silent.
REPO="$(git -C "$CWD" rev-parse --show-toplevel 2>/dev/null)" || exit 0
[ -n "$REPO" ] || exit 0

KEY="$(printf '%s' "$SESSION_ID" | shasum 2>/dev/null | cut -c1-16)"
[ -n "$KEY" ] || KEY=default
SHA_FILE="/tmp/.kodem-base-sha-${KEY}"
UNT_FILE="/tmp/.kodem-base-unt-${KEY}"

# GC old sessions' state. Resolve the real tmp dir first — `find` won't descend a
# symlinked start point, and on macOS /tmp is one. Skips this session: a pending
# baseline's mtime no longer moves every prompt, so a GC could reap a live one.
KTMP="$(cd /tmp 2>/dev/null && pwd -P || echo /tmp)"
find "$KTMP" -maxdepth 1 -name '.kodem-base-*'   ! -name "*-${KEY}" -mtime +1 -delete 2>/dev/null || true
find "$KTMP" -maxdepth 1 -name '.kodem-review-*' ! -name "*-${KEY}" -mtime +1 -delete 2>/dev/null || true

# A review is still open from an earlier prompt — leave its baseline alone, and keep
# the state young so another session's GC can't age it out.
if [ -s "$SHA_FILE" ]; then
  for state in "$SHA_FILE" "$UNT_FILE" \
               "/tmp/.kodem-review-rounds-${KEY}" "/tmp/.kodem-review-lasthash-${KEY}"; do
    [ -e "$state" ] && touch "$state" 2>/dev/null
  done
  exit 0
fi

# A dangling commit of the full pre-turn tree — tracked plus untracked non-ignored
# files — built via a throwaway index so the real index, worktree and stash are
# untouched. Untracked files are included so the Stop hook can suppress findings
# that already existed in files not yet committed.
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
# Fallback if the snapshot failed for any reason → HEAD (tracked-only), then empty.
if [ -z "$BASE" ]; then
  BASE="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo "")"
fi

printf '%s\n' "$BASE" > "$SHA_FILE" 2>/dev/null || true

# Untracked paths + mtimes, so the Stop hook can tell new-this-turn from existing
# WIP. NUL-delimited pairs survive odd filenames.
mtime_of() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo 0; }
: > "$UNT_FILE" 2>/dev/null || true
while IFS= read -r -d '' p; do
  [ -n "$p" ] || continue
  printf '%s\0%s\0' "$p" "$(mtime_of "$REPO/$p")" >> "$UNT_FILE" 2>/dev/null || true
done < <(git -C "$REPO" -c core.quotePath=false ls-files --others --exclude-standard -z 2>/dev/null)

exit 0
