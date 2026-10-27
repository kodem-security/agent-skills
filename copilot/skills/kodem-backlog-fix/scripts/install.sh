#!/usr/bin/env bash
set -euo pipefail

# Install or update kodem-cli on macOS or Linux: replaces every writable copy on PATH, else installs to
# ~/.local/bin. Windows: install.ps1.
# Usage: install.sh [version]   (or KODEM_CLI_VERSION; KODEM_CLI_INSTALL_DIR overrides the target)

PUBLIC_BASE="https://public.kodemsecurity.com/artifacts/kodem-cli"
VERSION_SEG="${KODEM_CLI_VERSION:-${1:-latest}}"

detect_platform() {
  local os="" arch=""
  case "$(uname -s)" in
    Darwin) os="darwin" ;;
    Linux)  os="linux"  ;;
    MINGW*|MSYS*|CYGWIN*)
      echo "kodem-cli: on Windows, install it with install.ps1 from PowerShell." >&2
      return 1 ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
  esac
  if [ -z "$os" ] || [ -z "$arch" ]; then
    echo "kodem-cli: this OS/architecture is not supported." >&2
    return 1
  fi
  echo "${os}-${arch}"
}

canonical_path() {
  local p="$1" dir
  dir=$(cd "$(dirname "$p")" 2>/dev/null && pwd) || dir=$(dirname "$p")
  echo "$dir/$(basename "$p")"
}

# The file must match the MD5 the storage bucket reports for it (x-goog-hash).
verify_download() {
  local file="$1" headers="$2" expected actual
  expected=$(tr -d '\r' < "$headers" | sed -n 's/^[Xx]-[Gg]oog-[Hh]ash: *md5=//p' | tail -n1)
  if [ -z "$expected" ]; then
    echo "WARNING: the download server sent no checksum; kodem-cli was not verified" >&2
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    actual=$(openssl dgst -md5 -binary "$file" | openssl base64)
  elif command -v python3 >/dev/null 2>&1; then
    actual=$(python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.md5(open(sys.argv[1],"rb").read()).digest()).decode())' "$file")
  else
    echo "WARNING: no openssl or python3 to verify the download; kodem-cli was not verified" >&2
    return 0
  fi
  if [ "$actual" != "$expected" ]; then
    echo "ERROR: kodem-cli download failed its checksum (expected md5 $expected, got $actual); not installed" >&2
    return 1
  fi
}

HINT_DIR=""
resolve_targets() {
  local binary_name="$1"
  if [ -n "${KODEM_CLI_INSTALL_DIR:-}" ]; then
    echo "hint:$KODEM_CLI_INSTALL_DIR"
    echo "$KODEM_CLI_INSTALL_DIR/$binary_name"
    return
  fi

  local p rp seen="" found=false
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    rp=$(canonical_path "$p")
    case ":$seen:" in *":$rp:"*) continue ;; esac
    seen="$seen:$rp"
    if [ -w "$(dirname "$rp")" ] || { [ -e "$rp" ] && [ -w "$rp" ]; }; then
      echo "$rp"; found=true
    fi
  done < <(type -aP "$binary_name" 2>/dev/null || true)

  if [ "$found" = false ]; then
    echo "hint:$HOME/.local/bin"
    echo "$HOME/.local/bin/$binary_name"
  fi
}

resolve_symlink() {
  local p="$1" link hops=0
  while [ -L "$p" ]; do
    hops=$((hops + 1))
    [ "$hops" -le 40 ] || return 1
    link=$(readlink "$p") || return 1
    case "$link" in
      /*) p="$link" ;;
      *)  p="$(dirname "$p")/$link" ;;
    esac
  done
  echo "$p"
}

# Stage, then mv: a new inode, so macOS doesn't SIGKILL the upgraded binary (exit 137).
STAGED=""
replace_binary() {
  local src="$1" t="$2" dir
  dir=$(dirname "$t")
  [ -d "$t" ] && return 1
  if [ ! -w "$dir" ]; then
    [ -f "$t" ] && [ -w "$t" ] || return 1
    cp "$src" "$t" 2>/dev/null && chmod +x "$t" 2>/dev/null
    return
  fi
  STAGED=$(mktemp "$dir/.kodem-cli.new.XXXXXX" 2>/dev/null) || { STAGED=""; return 1; }
  if ! { cp "$src" "$STAGED" && chmod 755 "$STAGED"; } 2>/dev/null; then
    rm -f "$STAGED"; STAGED=""; return 1
  fi
  if mv -f "$STAGED" "$t" 2>/dev/null; then
    STAGED=""; return 0
  fi
  rm -f "$STAGED"; STAGED=""
  return 1
}

smoke_test() {
  local t="$1" rc=0
  ( "$t" --help >/dev/null 2>&1; exit $? ) 2>/dev/null || rc=$?
  [ "$rc" -eq 0 ] && return 0
  if [ "$rc" -eq 137 ] && [ "$(uname -s)" = "Darwin" ]; then
    echo "WARNING: $t was killed on launch (exit 137, likely code signature). Close any running kodem-cli and re-run this installer." >&2
  else
    echo "WARNING: $t --help failed (exit $rc)." >&2
  fi
  return 1
}

# Adds ~/.local/bin to PATH in the profile of the user's shell (zsh or bash), unless a line there already mentions it
add_to_profile() {
  local name profile
  case "${SHELL:-}" in
    */zsh|zsh)   name=.zshrc ;;
    */bash|bash) name=.bashrc ;;
    *) return 1 ;;
  esac
  profile="$HOME/$name"
  if [ -e "$profile" ] && [ ! -r "$profile" ]; then return 1; fi
  if grep -qF '.local/bin' "$profile" 2>/dev/null; then
    echo "~/.local/bin is set in ~/$name. Open a new terminal for it to take effect."
    return 0
  fi
  {
    if [ -s "$profile" ] && [ -n "$(tail -c1 "$profile")" ]; then echo; fi
    echo 'export PATH="$HOME/.local/bin:$PATH"'
  } 2>/dev/null >> "$profile" || return 1
  echo "Added ~/.local/bin to PATH in ~/$name. Open a new terminal for it to take effect."
}

main() {
  if ! [[ "$VERSION_SEG" =~ ^(latest|v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]]; then
    echo "ERROR: invalid kodem-cli version: $VERSION_SEG" >&2
    return 1
  fi
  local platform
  platform=$(detect_platform) || return 1

  local binary_name="kodem-cli" remote_name="kodem-cli-${platform}"

  # Only ever delete our own temp files.
  trap '[ -z "${TMP_DL:-}" ] || rm -f "$TMP_DL" "$TMP_DL.headers"; [ -z "${STAGED:-}" ] || rm -f "$STAGED"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  local tmp
  tmp=$(mktemp)
  TMP_DL="$tmp"
  echo "Downloading $remote_name ($VERSION_SEG)..."
  # HTTPS only, redirects included; at most 10 minutes. A dropped connection may not recur, so up to 3 tries; an
  # HTTP error (22, e.g. no such release) would.
  local attempt=1 rc
  while :; do
    rc=0
    curl -fsSL --proto =https --proto-redir =https --max-time 600 --retry 3 -D "$tmp.headers" \
      "$PUBLIC_BASE/$VERSION_SEG/$remote_name" -o "$tmp" || rc=$?
    { [ "$rc" = 0 ] || [ "$rc" = 22 ] || [ "$attempt" -ge 3 ]; } && break
    attempt=$((attempt + 1)); sleep 2
  done
  if [ "$rc" != 0 ]; then
    rm -f "$tmp" "$tmp.headers"
    echo "ERROR: failed to download kodem-cli ($VERSION_SEG) for $platform" >&2
    return 1
  fi
  if ! verify_download "$tmp" "$tmp.headers"; then
    rm -f "$tmp" "$tmp.headers"
    return 1
  fi
  chmod +x "$tmp"
  # A download that doesn't run replaces nothing
  local rc=0
  ( "$tmp" --help >/dev/null 2>&1; exit $? ) 2>/dev/null || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "ERROR: the downloaded kodem-cli doesn't run (--help exited $rc); nothing was replaced" >&2
    return 1
  fi

  local -a targets=()
  # resolve_targets runs in a subshell: it reports the PATH-hint folder as a "hint:" line, not in HINT_DIR
  while IFS= read -r line; do
    case "$line" in hint:*) HINT_DIR="${line#hint:}" ;; ?*) targets+=("$line") ;; esac
  done < <(resolve_targets "$binary_name")

  local t real installed_any=false
  for t in "${targets[@]}"; do
    mkdir -p "$(dirname "$t")"
    if ! real=$(resolve_symlink "$t"); then
      echo "WARNING: skipping $t — its symlink chain doesn't resolve" >&2
      continue
    fi
    if replace_binary "$tmp" "$real"; then
      echo "kodem-cli installed at $t"
      smoke_test "$real" || true
      installed_any=true
    else
      echo "WARNING: could not write $t" >&2
    fi
  done
  rm -f "$tmp"; TMP_DL=""

  if [ "$installed_any" != true ]; then
    echo "ERROR: kodem-cli could not be installed to any writable location" >&2
    return 1
  fi
  # An agent session started before the install doesn't see it: its end-of-turn check doesn't run until a restart
  echo "Restart your agent so its Kodem hooks find kodem-cli."

  hash -r 2>/dev/null || true
  local active active_rp matched=false
  active=$(command -v "$binary_name" 2>/dev/null || true)
  if [ -n "$active" ]; then
    active_rp=$(canonical_path "$active")
    for t in "${targets[@]}"; do
      { [ "$t" = "$active_rp" ] || [ "$t" -ef "$active" ]; } && matched=true
    done
    if [ "$matched" != true ]; then
      echo "WARNING: an older kodem-cli at $active_rp shadows the update on PATH — remove it so the new version takes effect." >&2
    fi
  fi

  [ -n "$HINT_DIR" ] || return 0
  case ":$PATH:" in
    *":$HINT_DIR:"*) ;;
    *)
      # Only the fallback ~/.local/bin goes into the shell's profile, never a KODEM_CLI_INSTALL_DIR
      if [ -z "${KODEM_CLI_INSTALL_DIR:-}" ] && add_to_profile; then return 0; fi
      echo "WARNING: $HINT_DIR is not in your PATH." >&2
      echo "Add this line to your shell profile:" >&2
      echo "  export PATH=\"\$PATH:$HINT_DIR\"" >&2
      ;;
  esac
}

main "$@"
