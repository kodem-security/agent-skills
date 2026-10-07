#!/usr/bin/env bash
set -euo pipefail

# Install or update kodem-cli: replaces every writable copy on PATH, else installs to ~/.local/bin.
# Usage: install.sh [version]   (or KODEM_CLI_VERSION; KODEM_CLI_INSTALL_DIR overrides the target)

PUBLIC_BASE="https://public.kodemsecurity.com/artifacts/kodem-cli"
VERSION_SEG="${KODEM_CLI_VERSION:-${1:-latest}}"

detect_platform() {
  local os="" arch=""
  case "$(uname -s)" in
    Darwin)               os="darwin"  ;;
    Linux)                os="linux"   ;;
    MINGW*|MSYS*|CYGWIN*) os="windows" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
  esac
  if [ -z "$os" ] || [ -z "$arch" ] || \
     { [ "$os" = "windows" ] && [ "$arch" = "arm64" ]; }; then
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
    HINT_DIR="$KODEM_CLI_INSTALL_DIR"
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
    HINT_DIR="$HOME/.local/bin"
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
  local src="$1" t="$2" dir old
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
  # Windows can't overwrite a running .exe but can rename it; one fixed <name>.old, never deleted.
  case "$t" in
    *.exe)
      old="$t.old"
      if [ -f "$t" ] && [ ! -d "$old" ] && mv -f "$t" "$old" 2>/dev/null; then
        if mv -f "$STAGED" "$t" 2>/dev/null; then
          STAGED=""; return 0
        fi
        if ! mv -f "$old" "$t" 2>/dev/null; then
          echo "WARNING: could not restore $t — the previous copy is at $old; rename it back." >&2
        fi
      fi
      ;;
  esac
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

main() {
  local platform
  platform=$(detect_platform) || return 1

  local binary_name remote_name
  if [[ "$platform" == windows-* ]]; then
    binary_name="kodem-cli.exe"
    remote_name="kodem-cli-${platform}.exe"
  else
    binary_name="kodem-cli"
    remote_name="kodem-cli-${platform}"
  fi

  # Only ever delete our own temp files.
  trap '[ -z "${TMP_DL:-}" ] || rm -f "$TMP_DL" "$TMP_DL.headers"; [ -z "${STAGED:-}" ] || rm -f "$STAGED"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  local tmp
  tmp=$(mktemp)
  TMP_DL="$tmp"
  echo "Downloading $remote_name ($VERSION_SEG)..."
  if ! curl -fsSL --retry 3 -D "$tmp.headers" "$PUBLIC_BASE/$VERSION_SEG/$remote_name" -o "$tmp"; then
    rm -f "$tmp" "$tmp.headers"
    echo "ERROR: failed to download kodem-cli ($VERSION_SEG) for $platform" >&2
    return 1
  fi
  if ! verify_download "$tmp" "$tmp.headers"; then
    rm -f "$tmp" "$tmp.headers"
    return 1
  fi
  chmod +x "$tmp"

  local -a targets=()
  while IFS= read -r line; do [ -n "$line" ] && targets+=("$line"); done < <(resolve_targets "$binary_name")

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

  hash -r 2>/dev/null || true
  local active active_rp matched=false
  active=$(command -v "$binary_name" 2>/dev/null || true)
  if [ -n "$active" ]; then
    active_rp=$(canonical_path "$active")
    for t in "${targets[@]}"; do
      [ "$t" = "$active_rp" ] && matched=true
    done
    if [ "$matched" != true ]; then
      echo "WARNING: an older kodem-cli at $active_rp shadows the update on PATH — remove it so the new version takes effect." >&2
    fi
  fi

  [ -n "$HINT_DIR" ] || return 0
  case ":$PATH:" in
    *":$HINT_DIR:"*) ;;
    *)
      INSTALL_DIR="$HINT_DIR"
      case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
          # Not setx: it silently truncates PATH at 1024 chars.
          win_dir=$(cygpath -w "$INSTALL_DIR")
          if powershell.exe -NoProfile -Command "
            \$cur = [Environment]::GetEnvironmentVariable('Path','User');
            if (-not ((\$cur -split ';') -contains '$win_dir')) {
              [Environment]::SetEnvironmentVariable('Path', \$cur + ';$win_dir', 'User')
            }" >/dev/null 2>&1; then
            echo "Added $win_dir to user PATH. Open a new terminal for it to take effect."
          else
            echo "WARNING: $INSTALL_DIR is not in your PATH and auto-update failed." >&2
            echo "Add it manually:  setx Path \"%Path%;$win_dir\"" >&2
          fi
          ;;
        *)
          echo "WARNING: $INSTALL_DIR is not in your PATH." >&2
          echo "Add this line to your shell profile:" >&2
          echo "  export PATH=\"\$PATH:$INSTALL_DIR\"" >&2
          ;;
      esac
      ;;
  esac
}

main "$@"
