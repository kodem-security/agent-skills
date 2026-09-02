#!/usr/bin/env bash
set -euo pipefail

# Kodem Security Scan — open-source + code analysis with diff baseline
# Usage: scan.sh <repo-root> [--open-source-only | --code-only] [--description <TAG>]
#                [--no-trace]
#
# Whole-repo mode baselines against HEAD (see "Create baseline" below).
#
# Staged mode (end-of-turn hook) — scan caller-prepared directories in plain
# directory mode, so SCA resolves dependencies correctly:
#   --sast-dir <dir>          directory of changed source files to SAST-scan
#   --sast-worktree <dir>     git worktree (HEAD = pre-turn baseline, working tree
#                             = current/staged) to SAST-scan diff-aware (only-new)
#   --sca-dir <dir>           directory of changed manifests (+companions) for SCA
#   --sca-baseline-dir <dir>  pre-turn version of --sca-dir (--compare-with; only-new)
#   --repo-name <name>        identity for policy (staged temp dir has no remote)
#   --branch-name <name>      identity for policy
#
# Exit codes (consumed by the caller, e.g. the end-of-turn Stop hook):
#   0  clean OR non-blocking findings (status in trailer line)
#   5  policy-blocked findings — caller should block the action
#   10 scan errored (CLI ran but did not produce usable results)
#   11 CLI missing and install failed — caller should not block
#
# Trailer lines always emitted: "KODEM_RESULT: <status>" and "KODEM_FINDINGS: <n>".
# Status values: clean | warn | blocked | auth-required | scan-error | cli-missing

export PATH="$PATH:$HOME/.local/bin:/usr/local/bin:$HOME/bin:/opt/homebrew/bin"

REPO_ROOT="${1:-.}"
shift || true
SCRIPT_DIR="$(dirname "$0")"

MODE="both"          # both, --open-source-only, --code-only
DESCRIPTION=""       # forwarded to kodem-cli --description
NO_TRACE=false       # forward --no-trace to kodem-cli (local-only gate)

# Staged mode (used by the end-of-turn hook): scan caller-prepared directories
# (a temp dir holding only the changed files, mirroring repo paths) in plain
# directory mode, so SCA resolves dependencies correctly and SAST/SCA each run
# in a single invocation. Identity (repo name/branch) is supplied explicitly
# since a staged temp dir has no git remote.
STAGED=false
SAST_DIR=""          # directory to SAST-scan (changed source files), no baseline
SAST_WORKTREE=""     # git worktree (HEAD = pre-turn baseline, working tree = current,
                     # changes staged) to SAST-scan diff-aware — only-new findings
SCA_DIR=""           # directory to SCA-scan (changed manifests + companions)
SCA_BASELINE_DIR=""  # pre-turn version of SCA_DIR, for --compare-with (only-new)
REPO_NAME_OVERRIDE=""
BRANCH_NAME_OVERRIDE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --open-source-only|--code-only)
      MODE="$1"
      shift
      ;;
    --no-trace)
      NO_TRACE=true
      shift
      ;;
    --sast-dir)        STAGED=true; SAST_DIR="${2:-}"; shift 2 ;;
    --sast-dir=*)      STAGED=true; SAST_DIR="${1#--sast-dir=}"; shift ;;
    --sast-worktree)   STAGED=true; SAST_WORKTREE="${2:-}"; shift 2 ;;
    --sast-worktree=*) STAGED=true; SAST_WORKTREE="${1#--sast-worktree=}"; shift ;;
    --sca-dir)         STAGED=true; SCA_DIR="${2:-}"; shift 2 ;;
    --sca-dir=*)       STAGED=true; SCA_DIR="${1#--sca-dir=}"; shift ;;
    --sca-baseline-dir)   SCA_BASELINE_DIR="${2:-}"; shift 2 ;;
    --sca-baseline-dir=*) SCA_BASELINE_DIR="${1#--sca-baseline-dir=}"; shift ;;
    --repo-name)       REPO_NAME_OVERRIDE="${2:-}"; shift 2 ;;
    --repo-name=*)     REPO_NAME_OVERRIDE="${1#--repo-name=}"; shift ;;
    --branch-name)     BRANCH_NAME_OVERRIDE="${2:-}"; shift 2 ;;
    --branch-name=*)   BRANCH_NAME_OVERRIDE="${1#--branch-name=}"; shift ;;
    --description)
      DESCRIPTION="${2:-}"
      shift 2
      ;;
    --description=*)
      DESCRIPTION="${1#--description=}"
      shift
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

DESCRIPTION_ARGS=()
if [ -n "$DESCRIPTION" ]; then
  DESCRIPTION_ARGS=(--description "$DESCRIPTION")
fi

NO_TRACE_ARGS=()
if [ "$NO_TRACE" = true ]; then
  NO_TRACE_ARGS=(--no-trace)
fi

emit_result() { echo "KODEM_RESULT: $1"; }
emit_update_available() { echo "KODEM_UPDATE_AVAILABLE: $1"; }

ensure_cli() {
  if command -v kodem-cli &>/dev/null; then return 0; fi
  echo "kodem-cli not found on PATH; installing..."
  if ! "$SCRIPT_DIR/install.sh"; then
    echo "ERROR: kodem-cli installation failed"
    return 1
  fi
  command -v kodem-cli &>/dev/null
}

if ! ensure_cli; then
  emit_result "cli-missing"
  exit 11
fi

# "unknown flag" output means the installed CLI predates a flag we're passing.
# Refresh once and let the caller retry.
is_flag_error() {
  echo "$1" | grep -qE "Flag error:|unknown flag"
}

refresh_cli() {
  echo "Detected obsolete kodem-cli (unknown flag); downloading a new version..."
  "$SCRIPT_DIR/install.sh" || return 1
}

# Auth-failure detector — triggers a browser OAuth fallback + retry.
# No scan mode works unauthenticated: every one exits 1, --no-trace included (it
# only skips the upload), so this is a hard stop rather than a degraded scan.
AUTH_FAILED=false
is_auth_error() {
  echo "$1" | grep -qE "Failed to authenticate|No credentials provided|expired or been revoked"
}

# Resolve absolute path and repo name (for platform policy enforcement)
REPO_ROOT=$(cd "$REPO_ROOT" && git rev-parse --show-toplevel 2>/dev/null || echo "$REPO_ROOT")
REPO_NAME=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null \
  | sed 's|\.git$||' | sed -E 's|.*/||') \
  || REPO_NAME=$(basename "$REPO_ROOT")
BRANCH_NAME=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Staged mode supplies identity explicitly (the staged temp dir has no remote).
[ -n "$REPO_NAME_OVERRIDE" ] && REPO_NAME="$REPO_NAME_OVERRIDE"
[ -n "$BRANCH_NAME_OVERRIDE" ] && BRANCH_NAME="$BRANCH_NAME_OVERRIDE"

# Decide which scans to run. Unknown mode values fall through to the
# default arm and run both — preferring over-scan to silent skip.
RUN_OPEN_SOURCE=true
RUN_CODE=true
case "$MODE" in
  --open-source-only) RUN_CODE=false ;;
  --code-only)        RUN_OPEN_SOURCE=false ;;
esac

# In staged mode, each scan runs only if the caller supplied its target. SAST
# accepts either a plain directory (--sast-dir, no baseline) or a prepared
# worktree (--sast-worktree, diff-aware against its HEAD).
if [ "$STAGED" = true ]; then
  if { [ -n "$SAST_DIR" ] && [ -d "$SAST_DIR" ]; } || \
     { [ -n "$SAST_WORKTREE" ] && [ -d "$SAST_WORKTREE" ]; }; then :; else RUN_CODE=false; fi
  [ -n "$SCA_DIR" ] && [ -d "$SCA_DIR" ] || RUN_OPEN_SOURCE=false
fi

# Create baseline for diff scanning (whole-repo mode only).
#
# A pre-commit / pre-PR gate should judge only the change in front of it, not
# the rest of the repo. We baseline against the local HEAD, so the scan covers
# exactly the working-tree changes about to be committed. This needs no fetched
# or current default branch, can't be thrown off by a stale local `main`, and
# keeps the scanned delta minimal.
BASELINE_DIR=$(mktemp -d)
BASELINE_OK=false

# The baseline is only consumed via --compare-with (whole-repo mode). Staged mode
# brings its own baseline directory (SCA_BASELINE_DIR), so the git-worktree
# baseline is never built there.
NEED_BASELINE=true
if [ "$STAGED" = true ]; then
  NEED_BASELINE=false
fi

if [ "$NEED_BASELINE" = true ] && git -C "$REPO_ROOT" rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
  if git -C "$REPO_ROOT" worktree add --detach "$BASELINE_DIR" HEAD --quiet 2>/dev/null; then
    BASELINE_OK=true
  elif git -C "$REPO_ROOT" archive HEAD 2>/dev/null | tar -x -C "$BASELINE_DIR" 2>/dev/null; then
    BASELINE_OK=true
  fi
fi

COMPARE_ARGS=()
if [ "$BASELINE_OK" = true ] && [ "$(ls -A "$BASELINE_DIR" 2>/dev/null)" ]; then
  COMPARE_ARGS=(--compare-with "$BASELINE_DIR")
fi

if [ "$BASELINE_OK" = true ]; then
  echo "Baseline: HEAD ($(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null))"
elif [ "$NEED_BASELINE" = true ]; then
  # Only a concern in whole-repo mode, where the baseline scopes the diff.
  echo "WARNING: Could not create baseline — results may include pre-existing findings"
fi

# Per-scan targets and compare args. Whole-repo mode scans REPO_ROOT and shares
# the git-worktree baseline for both scans. Staged mode points each scan at its
# prepared target: SAST runs either self-scoped over a directory (--sast-dir,
# reports every weakness) or diff-aware over a worktree (--sast-worktree, only-
# new findings vs the worktree's HEAD); SCA compares against the staged baseline
# dir so it flags only newly-introduced dependency vulnerabilities.
SAST_TARGET="$REPO_ROOT"
SCA_TARGET="$REPO_ROOT"
SAST_COMPARE_ARGS=(${COMPARE_ARGS[@]+"${COMPARE_ARGS[@]}"})
SCA_COMPARE_ARGS=(${COMPARE_ARGS[@]+"${COMPARE_ARGS[@]}"})
if [ "$STAGED" = true ]; then
  SCA_TARGET="$SCA_DIR"
  SAST_COMPARE_ARGS=()
  SCA_COMPARE_ARGS=()
  if [ -n "$SAST_WORKTREE" ]; then
    # Diff-aware: the worktree's HEAD is the baseline and its staged tree is the
    # current state. kodem-cli derives the baseline commit from HEAD, so only
    # findings introduced since the baseline are reported.
    SAST_TARGET="$SAST_WORKTREE"
    SAST_COMPARE_ARGS=(--compare-with "$SAST_WORKTREE")
  else
    # No baseline: report every weakness in the changed files.
    SAST_TARGET="$SAST_DIR"
  fi
  if [ -n "$SCA_BASELINE_DIR" ] && [ -d "$SCA_BASELINE_DIR" ]; then
    SCA_COMPARE_ARGS=(--compare-with "$SCA_BASELINE_DIR")
  fi
fi

# Run scans
SCA_EXIT=0
SAST_EXIT=0
SCA_CLEAN=""
SAST_CLEAN=""

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# Portable extraction (BSD grep on macOS lacks -P/\K). Returns 0 if no match.
extract_total_issues() {
  echo "$1" | sed -nE 's/.*Total Issues:[[:space:]]*([0-9]+).*/\1/p' | head -n 1 \
    | awk 'NF{print; found=1} END{if(!found) print 0}'
}

# Run a kodem-cli scan with auth retry and one CLI-refresh retry on flag
# errors. Sets the named OUTPUT and EXIT variables in the caller.
# Args: <output_var> <exit_var> <command...>
run_scan() {
  local out_var="$1" exit_var="$2"; shift 2
  local out exit_code=0
  out=$("$@" 2>&1) || exit_code=$?

  if [ $exit_code -ne 0 ] && is_auth_error "$out"; then
    # Staged mode is the end-of-turn hook. Nobody asked it to run, so a browser
    # OAuth window would open unbidden and stall the turn until it resolved.
    # Record the failure instead and let the caller say one line about it.
    if [ "$STAGED" = true ]; then
      AUTH_FAILED=true
    else
      echo "Authentication required, launching browser OAuth..."
      if kodem-cli auth login; then
        exit_code=0
        out=$("$@" 2>&1) || exit_code=$?
        if [ $exit_code -ne 0 ] && is_auth_error "$out"; then AUTH_FAILED=true; fi
      else
        echo "ERROR: kodem-cli authentication failed"
        AUTH_FAILED=true
      fi
    fi
  fi

  # kodem-cli exits 0 even on "Flag error: unknown flag". After refresh, if
  # the same pattern persists we force a non-zero exit so the classifier
  # treats it as scan-error instead of clean.
  if is_flag_error "$out"; then
    if refresh_cli; then
      exit_code=0
      out=$("$@" 2>&1) || exit_code=$?
    fi
    if is_flag_error "$out"; then
      exit_code=10
    fi
  fi

  printf -v "$out_var" '%s' "$out"
  printf -v "$exit_var" '%s' "$exit_code"
}

# Always request all policy types (CI + SCM). Don't gate on a --help probe — v5+
# accept --policy-type without listing it there. Old CLIs that reject it are
# refreshed-and-retried via run_scan's is_flag_error path.
POLICY_TYPE_ARGS=(--policy-type all)

if $RUN_OPEN_SOURCE; then
  echo "=== open-source ==="
  run_scan SCA_OUTPUT SCA_EXIT \
    kodem-cli scan code-repository open-source "$SCA_TARGET" \
      --code-repository-name "$REPO_NAME" --branch-name "$BRANCH_NAME" \
      --skill-trigger \
      ${POLICY_TYPE_ARGS[@]+"${POLICY_TYPE_ARGS[@]}"} \
      ${DESCRIPTION_ARGS[@]+"${DESCRIPTION_ARGS[@]}"} \
      ${NO_TRACE_ARGS[@]+"${NO_TRACE_ARGS[@]}"} \
      ${SCA_COMPARE_ARGS[@]+"${SCA_COMPARE_ARGS[@]}"}
  SCA_CLEAN=$(echo "$SCA_OUTPUT" | strip_ansi)
  echo "$SCA_CLEAN"
  if [ "$SCA_EXIT" -ne 0 ] && [ "$SCA_EXIT" -ne 5 ] && [ "$SCA_EXIT" -ne 6 ] && [ "$SCA_EXIT" -ne 9 ]; then
    echo "open-source verdict: scan errored (exit=$SCA_EXIT)"
  else
    SCA_ISSUES=$(extract_total_issues "$SCA_CLEAN")
    echo "open-source verdict: $SCA_ISSUES issues found"
  fi
fi

if $RUN_CODE; then
  echo "=== code ==="
  # Apply a throwaway index (pending-commit staging) to the code scan only (SCA
  # ignores it; it must not affect the `git worktree add` baseline above). With no
  # caller-supplied index, stage the working tree (incl. untracked files) so the
  # scan sees files not yet `git add`-ed. The real index and worktree are untouched.
  MANUAL_INDEX=""
  if [ "$STAGED" = false ] && [ -z "${KODEM_SCAN_INDEX:-}" ] \
     && git -C "$REPO_ROOT" rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    MANUAL_INDEX="$(mktemp 2>/dev/null || echo "")"
    if [ -n "$MANUAL_INDEX" ]; then
      GIT_INDEX_FILE="$MANUAL_INDEX" git -C "$REPO_ROOT" read-tree HEAD 2>/dev/null || true
      GIT_INDEX_FILE="$MANUAL_INDEX" git -C "$REPO_ROOT" add -A 2>/dev/null || true
      KODEM_SCAN_INDEX="$MANUAL_INDEX"
    fi
  fi
  if [ -n "${KODEM_SCAN_INDEX:-}" ] && [ -f "${KODEM_SCAN_INDEX}" ]; then
    export GIT_INDEX_FILE="${KODEM_SCAN_INDEX}"
  fi
  run_scan SAST_OUTPUT SAST_EXIT \
    bash -c 'echo y | "$@"' _ \
    kodem-cli scan code-repository code "$SAST_TARGET" \
      --code-repository-name "$REPO_NAME" --branch-name "$BRANCH_NAME" \
      --skill-trigger \
      ${POLICY_TYPE_ARGS[@]+"${POLICY_TYPE_ARGS[@]}"} \
      ${DESCRIPTION_ARGS[@]+"${DESCRIPTION_ARGS[@]}"} \
      ${NO_TRACE_ARGS[@]+"${NO_TRACE_ARGS[@]}"} \
      ${SAST_COMPARE_ARGS[@]+"${SAST_COMPARE_ARGS[@]}"}
  SAST_CLEAN=$(echo "$SAST_OUTPUT" | strip_ansi)
  echo "$SAST_CLEAN"
  unset GIT_INDEX_FILE 2>/dev/null || true
  [ -n "$MANUAL_INDEX" ] && rm -f "$MANUAL_INDEX" 2>/dev/null || true
  if [ "$SAST_EXIT" -ne 0 ] && [ "$SAST_EXIT" -ne 5 ] && [ "$SAST_EXIT" -ne 6 ] && [ "$SAST_EXIT" -ne 9 ]; then
    echo "code verdict: scan errored (exit=$SAST_EXIT)"
  else
    SAST_ISSUES="${SAST_ISSUES:-$(extract_total_issues "$SAST_CLEAN")}"
    echo "code verdict: $SAST_ISSUES issues found"
  fi
fi

# Cleanup
if [ "$BASELINE_OK" = true ]; then
  git -C "$REPO_ROOT" worktree remove "$BASELINE_DIR" --force 2>/dev/null || true
fi
rm -rf "$BASELINE_DIR"

# Surface kodem-cli's "New ... version available" notice as a marker so the
# skill can offer an update. Emit before classification to cover every exit.
UPDATE_TEXT="${SCA_CLEAN:-} ${SAST_CLEAN:-}"
if echo "$UPDATE_TEXT" | grep -qi "version available"; then
  LATEST_VER=$(echo "$UPDATE_TEXT" \
    | sed -nE 's/.*version available:[[:space:]]*([^,[:space:]]+).*/\1/p' | head -n1)
  emit_update_available "${LATEST_VER:-unknown}"
fi

# kodem-cli exit codes consumed below:
#   0 = clean
#   1 = unclassified error
#   5 = --enforce-policy set but no policy found
#   6 = legacy "no policy found"
#   9 = policy-blocked findings
# kodem-cli may also exit 0 with "Policy Status: NOT FOUND" in scan output,
# so we check the text as a fallback.
SCA_EXIT="${SCA_EXIT:-0}"
SAST_EXIT="${SAST_EXIT:-0}"
SCA_ISSUES="${SCA_ISSUES:-0}"
SAST_ISSUES="${SAST_ISSUES:-0}"

# Structured findings trailer so callers don't have to parse human-readable
# verdict prose. Always emitted (counts are 0 when a scan errored/was skipped).
echo "KODEM_FINDINGS: $(( SCA_ISSUES + SAST_ISSUES ))"

POLICY_NOT_FOUND=false
if echo "$SCA_CLEAN $SAST_CLEAN" 2>/dev/null | grep -q "Policy Status: NOT FOUND"; then
  POLICY_NOT_FOUND=true
fi

# Classify in priority order: blocked > auth-required > scan-error > warn > clean.
# scan-error wins over warn because we cannot trust counts when the CLI errored.
# auth-required is split out of scan-error so callers can say something about the
# one failure the developer can clear themselves.
is_scan_error() {
  local code="$1"
  [ "$code" -ne 0 ] && [ "$code" -ne 5 ] && [ "$code" -ne 6 ] && [ "$code" -ne 9 ]
}

if [ "$SCA_EXIT" -eq 9 ] || [ "$SAST_EXIT" -eq 9 ] || [ "$SCA_EXIT" -eq 5 ] || [ "$SAST_EXIT" -eq 5 ]; then
  echo "POLICY: FAILED — findings blocked by policy (same rules as CI)"
  emit_result "blocked"
  exit 5
fi

if [ "$AUTH_FAILED" = true ]; then
  echo "ERROR: not authenticated — run 'kodem-cli auth login'"
  emit_result "auth-required"
  exit 12
fi

if is_scan_error "$SCA_EXIT" || is_scan_error "$SAST_EXIT"; then
  echo "ERROR: Scan errored (open-source=$SCA_EXIT, code=$SAST_EXIT) — results unreliable"
  emit_result "scan-error"
  exit 10
fi

if [ "$SCA_EXIT" -eq 6 ] || [ "$SAST_EXIT" -eq 6 ] || [ "$POLICY_NOT_FOUND" = true ]; then
  echo "POLICY: NOT FOUND — no applicable policy, falling back to severity-based evaluation"
  emit_result "warn"
  exit 0
fi

# Both scans exited 0. Distinguish clean from non-blocking findings by count.
if [ "${SCA_ISSUES:-0}" = "0" ] && [ "${SAST_ISSUES:-0}" = "0" ]; then
  echo "POLICY: PASSED"
  emit_result "clean"
else
  echo "POLICY: PASSED — non-blocking findings present (open-source=$SCA_ISSUES, code=$SAST_ISSUES)"
  emit_result "warn"
fi
exit 0
