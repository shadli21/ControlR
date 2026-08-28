#!/usr/bin/env bash
#
# ControlR macOS uninstaller.
# 
# Disclaimer: AI-generated.  Validated on Macbook Air M1 Tahoe with
# multiple agent installs.
#
# Discovers potential ControlR launch services. ControlR and its rebranded
# variants register services under these files:
#
#   LaunchDaemons - agent:
#     /Library/LaunchDaemons/app.<brand>.agent.plist
#     /Library/LaunchDaemons/app.<brand>.agent.<instance>.plist
#
#   LaunchDaemons - installer helper:
#     /Library/LaunchDaemons/app.<brand>.agent.installer.plist
#     /Library/LaunchDaemons/app.<brand>.agent.installer.<instance>.plist
#
#   LaunchAgents - desktop client:
#     /Library/LaunchAgents/app.<brand>.desktop.plist
#     /Library/LaunchAgents/app.<brand>.desktop.<instance>.plist
#
# Because rebranded variants share the "app.<brand>" prefix, candidates are
# matched with wildcards so every branded install is offered as a potential
# target. The user picks which ones to remove.
#
# Each selected service is stopped (booted out) and its plist removed. The
# related application files are removed too. Their locations are read from the
# installed plist's ProgramArguments[0] (the running program's path), which is
# more reliable than reconstructing brand/instance casing from filenames:
#
#   agent     -> /Library/Application Support/<Brand>/<Instance>/   (install dir)
#   installer -> /tmp/<brand>_Update/<Instance>/                    (staging dir)
#   desktop   -> /Applications/<Bundle>.app/                        (app bundle)
#
# IMPORTANT: this script must NOT be run with sudo. The desktop client
# LaunchAgent is booted out of the user's GUI session domain, which requires
# a non-root context. sudo is used only for the operations that actually need
# root (bootout of system LaunchDaemons and removal of files under /Library).

set -euo pipefail

DAEMONS_DIR="/Library/LaunchDaemons"
AGENTS_DIR="/Library/LaunchAgents"

# The current discovered candidates. This script targets bash 3.2 (the macOS
# default), so plain global arrays are used instead of namerefs/mapfile.
_candidates_paths=()
_candidates_kinds=()

# Abort if run as root (e.g. via sudo). The desktop client bootout must run as
# the normal user, and the whole flow relies on that.
if [ "$(id -u)" -eq 0 ]; then
  echo "Error: this script must not be run with sudo." >&2
  echo "Run it as a normal user. sudo is requested only where it is actually needed." >&2
  exit 1
fi

# Read the launchd service Label from a plist, falling back to the file name
# (launchd labels mirror the plist base name for these services).
read_label() {
  local path="$1"
  local label
  label="$(/usr/libexec/PlistBuddy -c "Print :Label" "$path" 2>/dev/null)" || label=""
  if [ -z "$label" ]; then
    label="$(basename "$path" .plist)"
  fi
  printf '%s' "$label"
}

# Read the first ProgramArguments entry (the running program's path) from a
# plist. Returns empty if it cannot be read, and never fails (so callers under
# `set -e` are safe even when the plist is missing or unreadable).
read_program_path() {
  local path="$1"
  local program
  program="$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$path" 2>/dev/null)" || program=""
  printf '%s' "$program"
}

# Remove the application files for a service. The program path is supplied by
# the caller (read from the plist before it is deleted); each service kind maps
# to a known parent to remove so we clean up the whole install.
remove_app_files() {
  local kind="$1"
  local program="$2"

  if [ -z "$program" ]; then
    echo "   Could not read program path from plist; leaving application files in place."
    return
  fi

  local target=""
  case "$kind" in
    desktop)
      # /Applications/<Bundle>.app/Contents/MacOS/<exec> -> walk up to .app
      local cursor="$program"
      while [ "$cursor" != "/" ] && [ "${cursor%.app}" = "$cursor" ]; do
        cursor="$(dirname "$cursor")"
      done
      if [ "${cursor%.app}" != "$cursor" ] && [ -d "$cursor" ]; then
        target="$cursor"
      fi
      ;;
    installer)
      # /tmp/<brand>_Update/<Instance>/<exec> -> staging dir
      target="$(dirname "$program")"
      ;;
    agent)
      # /Library/Application Support/<Brand>/<Instance>/<exec> -> install dir
      target="$(dirname "$program")"
      ;;
  esac

  if [ -n "$target" ] && [ -e "$target" ]; then
    echo "   Removing application files: $target"
    sudo rm -rf "$target"
  else
    echo "   Application files not found (${target:-unknown})."
  fi
}

# Rediscover candidates: agents first, then installers, then desktop clients.
discover_candidates() {
  _candidates_paths=()
  _candidates_kinds=()
  local f

  while IFS= read -r f; do
    _candidates_paths+=("$f")
    _candidates_kinds+=("agent")
  done < <(find "$DAEMONS_DIR" -maxdepth 1 -type f \
    -name 'app.*.agent*.plist' ! -name 'app.*.agent.installer*' 2>/dev/null | sort)

  while IFS= read -r f; do
    _candidates_paths+=("$f")
    _candidates_kinds+=("installer")
  done < <(find "$DAEMONS_DIR" -maxdepth 1 -type f \
    -name 'app.*.agent.installer*.plist' 2>/dev/null | sort)

  while IFS= read -r f; do
    _candidates_paths+=("$f")
    _candidates_kinds+=("desktop")
  done < <(find "$AGENTS_DIR" -maxdepth 1 -type f \
    -name 'app.*.desktop*.plist' 2>/dev/null | sort)
}

# Stop (bootout) a service and remove its plist.
remove_one() {
  local kind="$1"
  local path="$2"
  local label
  label="$(read_label "$path")"

  # Capture the program path before the plist is removed below.
  local program
  program="$(read_program_path "$path")"

  echo ""
  echo "== Removing [$kind] $(basename "$path") =="
  echo "   Label: $label"

  case "$kind" in
    desktop)
      # User-scope LaunchAgent in the GUI session domain: no sudo needed.
      echo "   Stopping in gui/$(id -u) ..."
      launchctl bootout "gui/$(id -u)" "$label" 2>/dev/null || true
      launchctl remove "$label" 2>/dev/null || true
      ;;
    *)
      # System LaunchDaemon: requires root.
      echo "   Stopping in system ..."
      sudo launchctl bootout "system/$label" 2>/dev/null || true
      sudo launchctl remove "$label" 2>/dev/null || true
      ;;
  esac

  # Plist files under /Library are root-owned.
  if [ -e "$path" ]; then
    echo "   Removing plist ..."
    sudo rm -f "$path"
  fi

  # Remove the application files (program + data) for this service.
  remove_app_files "$kind" "$program"

  echo "   Done."
}

main() {
  while true; do
    discover_candidates

    local total="${#_candidates_paths[@]}"
    if [ "$total" -eq 0 ]; then
      echo ""
      echo "No ControlR services found to uninstall."
      exit 0
    fi

    echo ""
    echo "=== Potential ControlR uninstall targets ==="
    local i
    for ((i = 0; i < total; i++)); do
      printf '  %2d) [% -9s] %s\n' "$((i + 1))" "${_candidates_kinds[$i]}" \
        "$(basename "${_candidates_paths[$i]}")"
    done
    echo ""
    echo "  s) Skip - remove nothing and exit"
    echo "  q) Quit / abort"
    echo ""

    local choice
    read -r -p "Select a number, s, or q: " choice

    case "$choice" in
      q | Q)
        echo "Aborted. No further changes made."
        exit 1
        ;;
      s | S)
        echo "Skipped. No further changes made."
        exit 0
        ;;
      '' | *[!0-9]*)
        echo "Invalid choice. It must be a number, 's', or 'q'."
        ;;
      *)
        local num="$((10#$choice))"
        if [ "$num" -lt 1 ] || [ "$num" -gt "$total" ]; then
          echo "Invalid selection. Choose a number between 1 and $total."
        else
          local idx="$((num - 1))"
          remove_one "${_candidates_kinds[$idx]}" "${_candidates_paths[$idx]}"
        fi
        ;;
    esac
  done
}

main "$@"
