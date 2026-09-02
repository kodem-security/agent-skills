#!/usr/bin/env bash
set -euo pipefail

# Install or update kodem-cli. Overwrites every writable copy on PATH so the one
# that runs gets replaced; installs to ~/.local/bin if none exist. Override with
# KODEM_CLI_INSTALL_DIR; pin a version via KODEM_CLI_VERSION or $1 (e.g. "v3.8.1").

PUBLIC_BASE="https://public.kodemsecurity.com/artifacts/kodem-cli"
VERSION_SEG="${KODEM_CLI_VERSION:-${1:-latest}}"

# Map the host to a published binary suffix (darwin-arm64, linux-amd64, ...).
# Windows-on-ARM is rejected — no native build; use WSL or x64 emulation.
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

# Resolve to <real-dir>/<basename> so duplicate or symlinked PATH entries collapse.
canonical_path() {
  local p="$1" dir
  dir=$(cd "$(dirname "$p")" 2>/dev/null && pwd) || dir=$(dirname "$p")
  echo "$dir/$(basename "$p")"
}

# Echo the file(s) to overwrite: every writable kodem-cli on PATH (so a shadowed
# copy can't keep the old binary running), or a fresh ~/.local/bin if none exist.
# KODEM_CLI_INSTALL_DIR overrides. Sets HINT_DIR for the PATH hint.
HINT_DIR=""
resolve_targets() {
  local binary_name="$1"
  if [ -n "${KODEM_CLI_INSTALL_DIR:-}" ]; then
    HINT_DIR="$KODEM_CLI_INSTALL_DIR"
    echo "$KODEM_CLI_INSTALL_DIR/$binary_name"
    return
  fi

  # Skip non-writable copies silently; the post-install check warns only if one
  # actually shadows the update.
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

  local tmp
  tmp=$(mktemp)
  echo "Downloading $remote_name ($VERSION_SEG)..."
  if ! curl -fsSL --retry 3 "$PUBLIC_BASE/$VERSION_SEG/$remote_name" -o "$tmp"; then
    rm -f "$tmp"
    echo "ERROR: failed to download kodem-cli ($VERSION_SEG) for $platform" >&2
    return 1
  fi
  chmod +x "$tmp"

  local -a targets=()
  while IFS= read -r line; do [ -n "$line" ] && targets+=("$line"); done < <(resolve_targets "$binary_name")

  local t installed_any=false
  for t in "${targets[@]}"; do
    mkdir -p "$(dirname "$t")"
    if cp "$tmp" "$t" 2>/dev/null && chmod +x "$t" 2>/dev/null; then
      echo "kodem-cli installed at $t"
      installed_any=true
    else
      echo "WARNING: could not write $t" >&2
    fi
  done
  rm -f "$tmp"

  if [ "$installed_any" != true ]; then
    echo "ERROR: kodem-cli could not be installed to any writable location" >&2
    return 1
  fi

  # Warn if the binary that will run isn't one we wrote (shadowed). Clear bash's
  # command hash first so the lookup is fresh.
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

  # PATH hint only applies to a fresh/explicit install dir; overwrites are
  # already reachable.
  [ -n "$HINT_DIR" ] || return 0
  case ":$PATH:" in
    *":$HINT_DIR:"*) ;;
    *)
      INSTALL_DIR="$HINT_DIR"
      case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
          # Persist to Windows user PATH via SetEnvironmentVariable, not setx —
          # setx silently truncates PATH at 1024 chars.
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
