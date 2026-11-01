#!/usr/bin/env bash
# =============================================================================
# tests/test_init_flags.sh - BK-007 exit criteria
# -----------------------------------------------------------------------------
# Verifies that informational / non-interactive flags never spawn the Warp GUI:
#   * --check, --status, --help exit without touching warp-terminal
#   * a piped (non-interactive) run never touches warp-terminal
#   * CI=1 never touches warp-terminal, even on a real pty
#   * on an interactive desktop it still launches (gating is not dead code)
#
# A fake `warp-terminal` on PATH records every launch, so a single unexpected
# GUI spawn fails the suite.
#
# Run: ./tests/test_init_flags.sh   (exit 0 = all pass)
# =============================================================================
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
INIT="$ROOT/init.sh"

pass=0
fail=0
ok()  { printf '[+] %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '[x] %s\n' "$*"; fail=$((fail + 1)); }

SANDBOX="$(mktemp -d)"
trap 'rm -rf -- "$SANDBOX"' EXIT
export WARP_MARKER="$SANDBOX/warp-launched"
FAKEBIN="$SANDBOX/bin"
OUT="$SANDBOX/out.log"
mkdir -p "$FAKEBIN"
cat >"$FAKEBIN/warp-terminal" <<'SH'
#!/usr/bin/env bash
printf 'launched\n' >>"$WARP_MARKER"
SH
chmod +x "$FAKEBIN/warp-terminal"

warp_launched() { [ -s "$WARP_MARKER" ]; }
reset_marker()   { rm -f -- "$WARP_MARKER"; }

# Piped (non-interactive) invocation.
run_init() {
  env -u CI -u DISPLAY -u WAYLAND_DISPLAY \
    PATH="$FAKEBIN:$PATH" BREACHKIT_SKIP_HEXSTRIKE=1 \
    "$INIT" "$@" </dev/null >"$OUT" 2>&1
  echo $?
}

assert_no_warp() {   # <label> <rc>
  if warp_launched; then bad "$1 spawned Warp"; else ok "$1 did not spawn Warp"; fi
  [ "$2" -eq 0 ] && ok "$1 exited 0" || bad "$1 exited $2"
}

reset_marker
rc="$(run_init --help)"
assert_no_warp "--help" "$rc"
grep -Eq 'Steps:|Usage:' "$OUT" && ok "--help printed init.sh usage" || bad "--help printed no usage"

reset_marker
rc="$(run_init --status)"
assert_no_warp "--status" "$rc"

reset_marker
rc="$(run_init --stop)"
assert_no_warp "--stop" "$rc"

# --check is allowed to exit non-zero when the backend is not installed, but it
# must never spawn a GUI.
reset_marker
rc="$(run_init --check)"
if warp_launched; then bad "--check spawned Warp"; else ok "--check did not spawn Warp"; fi
[ "$rc" -eq 0 ] && ok "--check exited 0" || printf '[i] --check exited %s (non-zero passes when backend missing)\n' "$rc"

# Interactive desktop simulation, but CI=1 -> still no GUI.
reset_marker
DISPLAY=:99 WARP_MARKER="$WARP_MARKER" PATH="$FAKEBIN:$PATH" BREACHKIT_SKIP_HEXSTRIKE=1 CI=1 \
  script -qec "$INIT" /dev/null >"$OUT" 2>&1 || true
if warp_launched; then bad "CI=1 spawned Warp"; else ok "CI=1 did not spawn Warp"; fi

# Interactive desktop, no CI -> Warp is expected to launch (proves gating live).
if command -v script >/dev/null 2>&1; then
  reset_marker
  env -u CI DISPLAY=:99 WARP_MARKER="$WARP_MARKER" PATH="$FAKEBIN:$PATH" BREACHKIT_SKIP_HEXSTRIKE=1 \
    script -qec "$INIT" /dev/null >"$OUT" 2>&1 || true
  if warp_launched; then ok "interactive desktop launched Warp"; else bad "interactive desktop did not launch Warp"; fi
else
  printf '[i] `script` not available - skipping positive Warp launch test\n'
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
