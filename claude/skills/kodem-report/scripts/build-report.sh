#!/usr/bin/env bash
# Build a Kodem security report from platform data — deterministic digest+render.
# Thin wrapper: dependency checks, then delegates to build_report.py.
#
#   build-report.sh <repo-root> [options]     (see build_report.py --help)
#
# Exit codes (shared with build_report.py):
#   0 report built · 2 kodem-cli missing · 3 not authenticated · 4 repo not mapped
#   5 not authorized (insufficient scope) · 6 CLI too old for the read commands
#   7 python3 missing · 1 anything else
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer python3; fall back to `python` when it is a Python 3 (common on
# Windows Git Bash). Exit 7 only when no usable Python exists.
PY=""
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1 && python -c 'import sys; sys.exit(sys.version_info[0] != 3)' 2>/dev/null; then
  PY=python
else
  echo "ERROR: Python 3 is required to build the report (it ships with macOS and most Linux distros)." >&2
  exit 7
fi

exec "$PY" "$HERE/build_report.py" "$@"
