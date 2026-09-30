#!/usr/bin/env bash
# Builds a Kodem security report: checks dependencies, then runs build_report.py (see --help).
# Exit: 0 ok · 1 other · 2 kodem-cli missing · 3 not authenticated · 4 repo not mapped
#       5 not authorized · 6 CLI too old · 7 python3 missing
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
