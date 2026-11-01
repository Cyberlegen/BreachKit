#!/usr/bin/env bash
# =============================================================================
# BreachKit :: init.sh
# -----------------------------------------------------------------------------
# Single entry point that prepares a machine to run BreachKit.
#
# Steps:
#   1. warp_init.sh      - launch the Warp terminal used for the HITL workflow.
#   2. hexstrike_init.sh - make sure the HexStrike AI MCP backend exists and is
#      configured (checks source, virtualenv, requirements, config; installs or
#      repairs whatever is missing).
#
# Usage:
#   ./init.sh                 # check + install/repair HexStrike
#   ./init.sh --check         # verify only (no changes)
#   ./init.sh --status        # show what is installed
#   ./init.sh --start         # ensure + start the HexStrike MCP server
#   ./init.sh --core-only     # skip heavy optional wheels (angr, pwntools, ...)
#   ./init.sh --force         # wipe and reinstall HexStrike
#
# Any argument is forwarded to hexstrike_init.sh (see its --help).
# Set BREACHKIT_SKIP_WARP=1 to skip the Warp step.
# Set BREACHKIT_SKIP_HEXSTRIKE=1 to skip the HexStrike step.
#
# Note: run this inside the environment where BreachKit will execute - the
# HexStrike server is expected to be reachable at http://127.0.0.1:8888.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
HEXSTRIKE_SCRIPT="$SCRIPT_DIR/hexstrike_init.sh"

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Step 1: Warp terminal
# ---------------------------------------------------------------------------
init_warp() {
  # If read-only/informational flags or stop flag are passed, skip Warp
  for arg in "$@"; do
    case "$arg" in
      -c|--check|-S|--status|-h|--help|--stop)
        return 0
        ;;
    esac
  done

  if [ "${BREACHKIT_SKIP_WARP:-0}" = "1" ]; then
    warn "BREACHKIT_SKIP_WARP=1 - skipping Warp launch"
    return 0
  fi
  if [ ! -f "$SCRIPT_DIR/warp_init.sh" ]; then
    warn "warp_init.sh not found - skipping Warp launch"
    return 0
  fi
  chmod +x "$SCRIPT_DIR/warp_init.sh"
  ( cd "$SCRIPT_DIR" && ./warp_init.sh ) || warn "warp_init.sh failed (no display?) - continuing"
}

# ---------------------------------------------------------------------------
# Step 2: HexStrike AI MCP backend
# ---------------------------------------------------------------------------
init_hexstrike() {
  if [ "${BREACHKIT_SKIP_HEXSTRIKE:-0}" = "1" ]; then
    warn "BREACHKIT_SKIP_HEXSTRIKE=1 - skipping HexStrike setup"
    return 0
  fi

  [ -f "$HEXSTRIKE_SCRIPT" ] || die "hexstrike_init.sh not found next to init.sh ($HEXSTRIKE_SCRIPT)"

  # Register the helper as executable, then hand over to it.
  chmod +x "$HEXSTRIKE_SCRIPT"
  log "hexstrike_init.sh is executable - running it"
  "$HEXSTRIKE_SCRIPT" "$@"
}

main() {
  log "BreachKit init starting in $SCRIPT_DIR"
  init_warp "$@"
  init_hexstrike "$@"
  ok "BreachKit init finished"
}

main "$@"
