#!/usr/bin/env bash
# =============================================================================
# tests/test_safe_reset.sh - BK-006 exit criteria
# -----------------------------------------------------------------------------
# Verifies that a destructive reset can never happen silently:
#   * wildcard paths are refused
#   * relative / shallow / protected / out-of-tree paths are refused
#   * symlinks are refused
#   * non-interactive runs without --yes are refused and change nothing
#   * --yes moves the tree into the backup dir instead of deleting it
#   * retention keeps only the N newest backups
#
# Run: ./tests/test_safe_reset.sh   (exit 0 = all pass)
# =============================================================================
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "$HERE/.." && pwd -P)"
SCRIPT="$ROOT/hexstrike_init.sh"

pass=0
fail=0
ok()   { printf '[+] %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '[x] %s\n' "$*"; fail=$((fail + 1)); }

# Sandbox: a fake repo root with a fake install tree.
SANDBOX="$(mktemp -d)"
trap 'rm -rf -- "$SANDBOX"' EXIT
FAKE_ROOT="$SANDBOX/repo"
FAKE_HS="$FAKE_ROOT/tools/hexstrike-ai"
FAKE_BK="$FAKE_ROOT/.backups"
mkdir -p "$FAKE_HS/hexstrike-env" "$FAKE_HS/sub"
: >"$FAKE_HS/hexstrike_server.py"
: >"$FAKE_HS/requirements.txt"

# Runs the script against the sandbox and returns its combined output. The repo
# URL points at a non-existent local path so any post-reset clone fails fast -
# these tests only care about the reset logic, not about installing upstream.
run_hs() {
  BREACHKIT_ROOT="$FAKE_ROOT" HEXSTRIKE_DIR="$FAKE_HS" HEXSTRIKE_BACKUP_DIR="$FAKE_BK" \
    HEXSTRIKE_REPO_URL="file://$SANDBOX/no-such-repo.git" \
    "$SCRIPT" "$@" 2>&1 </dev/null
}

expect_refusal() {   # <label> <pattern> <args...>
  local label="$1" pattern="$2"; shift 2
  local out rc
  out="$(run_hs "$@")"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -Fq -- "$pattern"; then
    ok "refused: $label"
  else
    bad "expected refusal for $label (rc=$rc, pattern='$pattern')"
    printf '    output: %s\n' "$(printf '%s' "$out" | tail -2)"
  fi
}

# 1. Wildcard path is refused before anything runs.
expect_refusal "wildcard source dir" "wildcards" --force --yes --dir "$FAKE_ROOT/tools/*"

# 2. A virtualenv pointing outside the install dir is refused outright.
out="$(BREACHKIT_ROOT="$FAKE_ROOT" HEXSTRIKE_DIR="$FAKE_HS" \
       HEXSTRIKE_VENV="$SANDBOX/elsewhere/deep/venv" HEXSTRIKE_BACKUP_DIR="$FAKE_BK" \
       HEXSTRIKE_REPO_URL="file://$SANDBOX/no-such-repo.git" \
       "$SCRIPT" --force --yes 2>&1 </dev/null)"
if printf '%s' "$out" | grep -Fq -- "must live inside HEXSTRIKE_DIR"; then
  ok "refused: venv outside the install dir"
else
  bad "venv outside the install dir was not refused"
fi

# 3. Shallow and protected paths are refused.
expect_refusal "shallow dir" "too close to the filesystem root" --force --yes --dir "/tmp"
expect_refusal "repo root as install dir" "protected path" --force --yes --dir "$FAKE_ROOT"

# 4. Non-interactive reset without --yes is refused and deletes nothing.
out="$(run_hs --force --dir "$FAKE_HS")"
if printf '%s' "$out" | grep -Fq -- "needs confirmation" && [ -f "$FAKE_HS/hexstrike_server.py" ]; then
  ok "non-interactive reset refused, tree untouched"
else
  bad "non-interactive reset was not refused"
fi

# 5. Symlinked install dir is refused.
ln -sfn "$FAKE_HS" "$SANDBOX/link-hs"
out="$(BREACHKIT_ROOT="$FAKE_ROOT" HEXSTRIKE_DIR="$SANDBOX/link-hs" \
       HEXSTRIKE_BACKUP_DIR="$FAKE_BK" "$SCRIPT" --force --yes 2>&1 </dev/null)"
if printf '%s' "$out" | grep -Fq -- "symlink"; then
  ok "refused: symlinked install dir"
else
  bad "symlinked install dir was not refused"
fi

# 6. --yes moves the tree to the backup dir instead of deleting it.
before="$(find "$FAKE_HS" -type f | wc -l)"
out="$(run_hs --force --yes --dir "$FAKE_HS" --core-only)"
moved="$(find "$FAKE_BK" -maxdepth 1 -name 'hexstrike-ai.*' | wc -l)"
if [ "$moved" -ge 1 ] && [ ! -e "$FAKE_HS/hexstrike_server.py" ]; then
  ok "reset backed up the tree instead of deleting it ($before files preserved)"
else
  bad "tree was not moved into the backup dir"
fi

# 7. Retention: only the N newest backups survive.
for i in 1 2 3 4 5; do
  mkdir -p "$FAKE_HS"
  : >"$FAKE_HS/hexstrike_server.py"
  run_hs --force --yes --dir "$FAKE_HS" --keep-backups 2 >/dev/null
done
kept="$(find "$FAKE_BK" -maxdepth 1 -name 'hexstrike-ai.*' | wc -l)"
if [ "$kept" -eq 2 ]; then
  ok "retention kept only 2 backups"
else
  bad "retention kept $kept backups, expected 2"
fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
