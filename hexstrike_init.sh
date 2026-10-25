#!/usr/bin/env bash
# =============================================================================
# BreachKit :: hexstrike_init.sh
# -----------------------------------------------------------------------------
# Idempotent bootstrap/health-check for the HexStrike AI MCP server backend
# (https://github.com/0x4m4/hexstrike-ai).
#
# What it does, in order:
#   1. Verifies host prerequisites (git, python3 >= 3.8, venv, pip, curl).
#   2. Checks whether the HexStrike source tree is present and complete
#      (hexstrike_server.py + requirements.txt); clones it if it is missing.
#   3. Checks whether the dedicated virtualenv exists and is healthy;
#      creates it if it is missing or broken.
#   4. Checks whether the Python requirements are installed (import test +
#      checksum of requirements.txt); installs/repairs them if they are not.
#   5. Writes the MCP client config file (absolute paths, server URL/port).
#   6. Optionally starts the server and waits for /health to answer.
#
# Every step is skipped when it is already satisfied, so the script is safe to
# run repeatedly (e.g. from init.sh or CI) without side effects.
#
# Usage:
#   ./hexstrike_init.sh                # ensure: check + install/repair what is missing
#   ./hexstrike_init.sh --check        # verify only, change nothing; exit 1 if not ready
#   ./hexstrike_init.sh --status       # human readable report (exit 0)
#   ./hexstrike_init.sh --start        # ensure everything, then launch the MCP server
#   ./hexstrike_init.sh --force        # wipe the checkout/venv and reinstall
#   ./hexstrike_init.sh --core-only    # skip optional extras (angr, pwntools, ...)
#   ./hexstrike_init.sh --insecure-tls # last resort: relax pip TLS checks
#   ./hexstrike_init.sh --help
#
# Environment overrides:
#   HEXSTRIKE_DIR          install location        (default: <repo>/tools/hexstrike-ai)
#   HEXSTRIKE_REPO_URL     git remote              (default: official upstream repo)
#   HEXSTRIKE_BRANCH       git branch              (default: master)
#   HEXSTRIKE_VENV         virtualenv path         (default: <HEXSTRIKE_DIR>/hexstrike-env)
#   HEXSTRIKE_CONFIG       generated MCP config    (default: <repo>/config/hexstrike_mcp.json)
#   HEXSTRIKE_LOG_DIR      log directory           (default: <repo>/logs)
#   HEXSTRIKE_HOST         health-check host       (default: 127.0.0.1)
#   HEXSTRIKE_PORT         server port             (default: 8888)
#   HEXSTRIKE_SERVER_URL   full base URL           (default: http://$HOST:$PORT)
#   HEXSTRIKE_PYTHON       interpreter for venv    (default: python3)
#
# Notes:
#   * HexStrike's 150+ external security tools (nmap, nuclei, gobuster, ...)
#     are installed separately; missing ones are reported as warnings only.
#   * HexStrike's HTTP/MCP server itself needs NO API key. The API key belongs
#     to whichever AI client (Claude/Cursor/...) talks to it.
#
# Exit codes: 0 = ready/success, 1 = not ready or setup failed.
# =============================================================================

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_PATH")" >/dev/null 2>&1 && pwd -P)"

# ---------------------------------------------------------------------------
# Paths / settings (defaults; overridable through the environment)
# ---------------------------------------------------------------------------
if [ -n "${BREACHKIT_ROOT:-}" ]; then
  REPO_ROOT="$BREACHKIT_ROOT"
elif REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  REPO_ROOT="$SCRIPT_DIR"
fi

# Remember values supplied through the environment so --dir/--port can still
# re-derive their dependants without clobbering explicit overrides.
ENV_SERVER_URL="${HEXSTRIKE_SERVER_URL:-}"
ENV_VENV="${HEXSTRIKE_VENV:-}"

HEXSTRIKE_REPO_URL="${HEXSTRIKE_REPO_URL:-https://github.com/0x4m4/hexstrike-ai.git}"
HEXSTRIKE_BRANCH="${HEXSTRIKE_BRANCH:-master}"
HEXSTRIKE_DIR="${HEXSTRIKE_DIR:-$REPO_ROOT/tools/hexstrike-ai}"
HEXSTRIKE_VENV="${HEXSTRIKE_VENV:-$HEXSTRIKE_DIR/hexstrike-env}"
HEXSTRIKE_CONFIG="${HEXSTRIKE_CONFIG:-$REPO_ROOT/config/hexstrike_mcp.json}"
HEXSTRIKE_LOG_DIR="${HEXSTRIKE_LOG_DIR:-$REPO_ROOT/logs}"
HEXSTRIKE_HOST="${HEXSTRIKE_HOST:-127.0.0.1}"
HEXSTRIKE_PORT="${HEXSTRIKE_PORT:-8888}"
HEXSTRIKE_SERVER_URL="${HEXSTRIKE_SERVER_URL:-http://$HEXSTRIKE_HOST:$HEXSTRIKE_PORT}"
HEXSTRIKE_PYTHON="${HEXSTRIKE_PYTHON:-python3}"
HEXSTRIKE_MIN_PY_MINOR=8   # HexStrike requires Python 3.8+

MODE="ensure"       # ensure | check | status
FORCE=0
CORE_ONLY=0
START_SERVER=0
INSECURE_TLS=0

# Derived paths
SERVER_SCRIPT="$HEXSTRIKE_DIR/hexstrike_server.py"
MCP_SCRIPT="$HEXSTRIKE_DIR/hexstrike_mcp.py"
REQ_FILE="$HEXSTRIKE_DIR/requirements.txt"
VENV_PY="$HEXSTRIKE_VENV/bin/python"
MARKER="$HEXSTRIKE_VENV/.breachkit-requirements.sha256"
SERVER_LOG="$HEXSTRIKE_LOG_DIR/hexstrike-server.log"
PID_FILE="$HEXSTRIKE_LOG_DIR/hexstrike-server.pid"

# Import names (not pip names) used to verify the install. These are the
# Modules hexstrike_server.py imports at top level, i.e. without them the
# server cannot boot at all.
CORE_MODULES=(flask requests psutil fastmcp bs4 aiohttp selenium mitmproxy)
# Needed only by individual tool wrappers, so their absence is a warning.
OPTIONAL_MODULES=(angr pwn webdriver_manager bcrypt)
# Fallback install set (used by --core-only and when requirements.txt fails).
# Ranges mirror upstream requirements.txt so the resolver stays consistent;
# unpinned names let fastmcp 4.x in, which conflicts with mitmproxy.
CORE_PACKAGES=(
  "flask>=2.3.0,<4.0.0"
  "requests>=2.31.0,<3.0.0"
  "psutil>=5.9.0,<6.0.0"
  "fastmcp>=0.2.0,<1.0.0"
  "beautifulsoup4>=4.12.0,<5.0.0"
  "aiohttp>=3.8.0,<4.0.0"
  "selenium>=4.15.0,<5.0.0"
  "mitmproxy>=9.0.0,<11.0.0"
  "bcrypt==4.0.1"
)
# Optional extras, installed best-effort (and skipped by --core-only). These
# are needed only by some tool wrappers, not to boot the server.
EXTRAS_PACKAGES=(
  "webdriver-manager>=4.0.0,<5.0.0"
  "pwntools>=4.10.0,<5.0.0"
  "angr>=9.2.0,<10.0.0"
)
# Filled in by pip_install() and reused by install_extras().
PIP_ARGS=()

# A small, representative sample of the external tools HexStrike drives.
SEC_TOOLS=(nmap gobuster nuclei sqlmap ffuf subfinder httpx katana nikto
           dirsearch hydra john hashcat gdb radare2 binwalk exiftool)

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'
else
  C_RESET=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''
fi

info() { printf '%s[*]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }
hdr()  { printf '\n%s==> %s%s\n' "$C_DIM" "$*" "$C_RESET"; }

usage() {
  sed -n '3,48p' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  local url_given=0 venv_given=0
  if [ -n "$ENV_SERVER_URL" ]; then url_given=1; fi
  if [ -n "$ENV_VENV" ]; then venv_given=1; fi

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -c|--check)      MODE="check" ;;
      -S|--status)     MODE="status" ;;
      -s|--start)      START_SERVER=1 ;;
      --stop)          MODE="stop" ;;
      -f|--force)      FORCE=1 ;;
      --core-only)     CORE_ONLY=1 ;;
      --insecure-tls)  INSECURE_TLS=1 ;;
      --port)          shift; HEXSTRIKE_PORT="${1:?--port requires a value}" ;;
      --dir)           shift; HEXSTRIKE_DIR="${1:?--dir requires a value}" ;;
      --url)           shift; url_given=1; HEXSTRIKE_SERVER_URL="${1:?--url requires a value}" ;;
      -h|--help)       usage; exit 0 ;;
      *)               die "unknown option: $1 (try --help)" ;;
    esac
    shift
  done

  # Re-derive everything that depends on the parsed values.
  if [ "$url_given" -eq 0 ]; then HEXSTRIKE_SERVER_URL="http://$HEXSTRIKE_HOST:$HEXSTRIKE_PORT"; fi
  if [ "$venv_given" -eq 0 ]; then HEXSTRIKE_VENV="$HEXSTRIKE_DIR/hexstrike-env"; fi
  SERVER_SCRIPT="$HEXSTRIKE_DIR/hexstrike_server.py"
  MCP_SCRIPT="$HEXSTRIKE_DIR/hexstrike_mcp.py"
  REQ_FILE="$HEXSTRIKE_DIR/requirements.txt"
  VENV_PY="$HEXSTRIKE_VENV/bin/python"
  MARKER="$HEXSTRIKE_VENV/.breachkit-requirements.sha256"
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

require_cmd() {
  have "$1" && return 0
  if [ "$MODE" = "check" ] || [ "$MODE" = "status" ]; then
    warn "required command '$1' not found.${2:+ $2}"
    return 1
  fi
  die "required command '$1' not found.${2:+ $2}"
}

file_hash() {
  local f="$1"
  if have sha256sum; then
    sha256sum "$f" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$f" | awk '{print $1}'
  else
    cksum "$f" | awk '{print $1 "-" $2}'
  fi
}

python_usable() {
  local py="$1"
  [ -n "$py" ] && have "$py" || return 1
  "$py" - "$HEXSTRIKE_MIN_PY_MINOR" <<'PY' >/dev/null 2>&1
import sys
sys.exit(0 if sys.version_info >= (3, int(sys.argv[1])) else 1)
PY
}

# Prints the subset of module names that cannot be imported.
modules_missing() {
  "$VENV_PY" - "$@" <<'PY'
import importlib.util, sys
missing = []
for name in sys.argv[1:]:
    try:
        found = importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        found = False
    if not found:
        missing.append(name)
print(" ".join(missing))
PY
}

# Any interpreter that can run stdlib-only probes (fallback when curl is absent).
probe_python() {
  if [ -x "$VENV_PY" ]; then printf '%s' "$VENV_PY"
  elif have "$HEXSTRIKE_PYTHON"; then printf '%s' "$HEXSTRIKE_PYTHON"
  elif have python3; then printf '%s' "python3"
  else return 1
  fi
}

health_ok() {
  if have curl; then
    curl -fsS --max-time 4 "$HEXSTRIKE_SERVER_URL/health" >/dev/null 2>&1 && return 0
    return 1
  fi
  local py; py="$(probe_python)" || return 1
  "$py" - "$HEXSTRIKE_SERVER_URL/health" <<'PY' >/dev/null 2>&1
import sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=4) as r:
        sys.exit(0 if getattr(r, "status", 200) < 400 else 1)
except Exception:
    sys.exit(1)
PY
}

# 0 = something is listening on host:port, 1 = port looks free.
port_in_use() {
  local py; py="$(probe_python)" || return 1
  "$py" - "$HEXSTRIKE_HOST" "$HEXSTRIKE_PORT" <<'PY' >/dev/null 2>&1
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(2)
try:
    s.connect((host, port))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

# ---------------------------------------------------------------------------
# Individual checks (return 0 = satisfied, 1 = missing/broken)
# ---------------------------------------------------------------------------
check_source() {
  if [ -f "$SERVER_SCRIPT" ] && [ -f "$REQ_FILE" ]; then
    return 0
  fi
  return 1
}

check_venv() {
  [ -x "$VENV_PY" ] || return 1
  "$VENV_PY" -c 'import sys, pip' >/dev/null 2>&1 || return 1
  return 0
}

check_python_deps() {
  check_venv || return 1
  local missing
  missing="$(modules_missing "${CORE_MODULES[@]}")" || return 1
  if [ -n "$missing" ]; then
    DEPS_MISSING="$missing"
    return 1
  fi
  # Optional (heavy) packages are reported but never block readiness.
  local opt
  opt="$(modules_missing "${OPTIONAL_MODULES[@]}")" || opt=""
  DEPS_OPTIONAL_MISSING="$opt"
  return 0
}

check_config() {
  [ -f "$HEXSTRIKE_CONFIG" ] || return 1
  grep -Fq -- "$HEXSTRIKE_SERVER_URL" "$HEXSTRIKE_CONFIG" 2>/dev/null || return 1
  grep -Fq -- "$MCP_SCRIPT" "$HEXSTRIKE_CONFIG" 2>/dev/null || return 1
  return 0
}

# ---------------------------------------------------------------------------
# Setup steps (each is a no-op when the matching check already passes)
# ---------------------------------------------------------------------------
ensure_source() {
  if [ "$FORCE" -eq 1 ] && [ -e "$HEXSTRIKE_DIR" ]; then
    warn "--force: removing existing source tree at $HEXSTRIKE_DIR"
    rm -rf -- "$HEXSTRIKE_DIR"
  fi

  if check_source; then
    ok "HexStrike source present: $HEXSTRIKE_DIR"
    return 0
  fi

  require_cmd git "Install it first (apt-get install -y git)."
  mkdir -p -- "$(dirname -- "$HEXSTRIKE_DIR")"

  if [ -d "$HEXSTRIKE_DIR/.git" ]; then
    info "HexStrike checkout incomplete - refreshing from origin/$HEXSTRIKE_BRANCH"
    git -C "$HEXSTRIKE_DIR" fetch --depth 1 origin "$HEXSTRIKE_BRANCH" \
      || die "git fetch failed for $HEXSTRIKE_REPO_URL"
    git -C "$HEXSTRIKE_DIR" reset --hard "origin/$HEXSTRIKE_BRANCH" \
      || die "git reset failed in $HEXSTRIKE_DIR"
  elif [ -d "$HEXSTRIKE_DIR" ] && [ -n "$(ls -A "$HEXSTRIKE_DIR" 2>/dev/null)" ]; then
    die "$HEXSTRIKE_DIR exists but is not a HexStrike checkout. Move it away or re-run with --force."
  else
    info "cloning $HEXSTRIKE_REPO_URL (branch: $HEXSTRIKE_BRANCH)"
    git clone --depth 1 --branch "$HEXSTRIKE_BRANCH" "$HEXSTRIKE_REPO_URL" "$HEXSTRIKE_DIR" \
      || die "git clone failed (check network access to $HEXSTRIKE_REPO_URL)"
  fi

  check_source || die "checkout finished but hexstrike_server.py / requirements.txt are still missing in $HEXSTRIKE_DIR"
  ok "HexStrike source ready: $HEXSTRIKE_DIR"
}

ensure_venv() {
  if [ "$FORCE" -eq 1 ] && [ -e "$HEXSTRIKE_VENV" ]; then
    warn "--force: removing existing virtualenv at $HEXSTRIKE_VENV"
    rm -rf -- "$HEXSTRIKE_VENV"
  fi

  if check_venv; then
    ok "virtualenv healthy: $HEXSTRIKE_VENV"
    return 0
  fi

  if [ -e "$HEXSTRIKE_VENV" ]; then
    warn "virtualenv at $HEXSTRIKE_VENV looks broken - recreating"
    rm -rf -- "$HEXSTRIKE_VENV"
  fi

  python_usable "$HEXSTRIKE_PYTHON" \
    || die "'$HEXSTRIKE_PYTHON' is missing or older than 3.$HEXSTRIKE_MIN_PY_MINOR (HexStrike needs Python 3.8+)."

  info "creating virtualenv at $HEXSTRIKE_VENV"
  "$HEXSTRIKE_PYTHON" -m venv "$HEXSTRIKE_VENV" \
    || die "venv creation failed (Debian/Ubuntu: apt-get install -y python3-venv)"

  # Some distros ship a venv without a usable pip.
  if ! "$VENV_PY" -m pip --version >/dev/null 2>&1; then
    "$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
  fi

  check_venv || die "virtualenv at $HEXSTRIKE_VENV is not usable after creation"
  ok "virtualenv created: $HEXSTRIKE_VENV"
}

pip_install() {
  # Respect a custom CA bundle (corporate proxy / TLS-inspecting egress).
  local cert="${PIP_CERT:-${SSL_CERT_FILE:-${REQUESTS_CA_BUNDLE:-${CURL_CA_BUNDLE:-}}}}"
  PIP_ARGS=()
  if [ -n "$cert" ] && [ -r "$cert" ]; then
    info "using CA bundle: $cert"
    PIP_ARGS+=(--cert "$cert")
  fi
  # Extra pip flags, e.g. HEXSTRIKE_PIP_ARGS="--index-url https://mirror/simple"
  if [ -n "${HEXSTRIKE_PIP_ARGS:-}" ]; then
    # shellcheck disable=SC2206
    PIP_ARGS+=(${HEXSTRIKE_PIP_ARGS})
  fi

  # Opt-in escape hatch for TLS-inspecting proxies whose CA cannot be used.
  if [ "$INSECURE_TLS" -eq 1 ] || [ "${HEXSTRIKE_INSECURE_TLS:-0}" = "1" ]; then
    warn "--insecure-tls: relaxing pip TLS verification for PyPI hosts"
    PIP_ARGS+=(--trusted-host pypi.org --trusted-host pypi.python.org
               --trusted-host files.pythonhosted.org)
  fi

  "$VENV_PY" -m pip install --disable-pip-version-check "${PIP_ARGS[@]}" \
    --upgrade pip setuptools wheel >/dev/null 2>&1 \
    || warn "could not upgrade pip/setuptools/wheel (continuing with what is installed)"

  # Stage 1 - everything the server imports at startup. Must succeed.
  info "installing required packages for the HexStrike server"
  "$VENV_PY" -m pip install --disable-pip-version-check --retries 3 --timeout 60 \
    "${PIP_ARGS[@]}" "${CORE_PACKAGES[@]}" \
    || die "pip install of the required packages failed. Check network/proxy access to PyPI, then re-run: $0 --force"
}

# Heavy, optional wheels (angr, pwntools, webdriver-manager). Installed
# best-effort: HexStrike boots without them, only some tool wrappers need them.
install_extras() {
  [ "$CORE_ONLY" -eq 1 ] && { info "--core-only: skipping optional extras"; return 0; }

  local pkg failed=()
  for pkg in "${EXTRAS_PACKAGES[@]}"; do
    info "installing optional package: $pkg"
    if ! "$VENV_PY" -m pip install --disable-pip-version-check --retries 2 --timeout 60 \
         --only-binary=:all: "${PIP_ARGS[@]}" "$pkg"; then
      failed+=("${pkg%%[><=]*}")
    fi
  done

  if [ "${#failed[@]}" -gt 0 ]; then
    warn "optional packages not installable from wheels here: ${failed[*]}"
    warn "HexStrike still runs; install them manually if a module needs them:"
    warn "  $VENV_PY -m pip install ${failed[*]}  (may need a compiler/build toolchain)"
  else
    ok "optional extras installed"
  fi
  return 0
}

ensure_python_deps() {
  check_venv || die "cannot install requirements without a working virtualenv"

  local want current="" missing
  want="$(file_hash "$REQ_FILE")"
  if [ -f "$MARKER" ]; then current="$(cat "$MARKER" 2>/dev/null || true)"; fi

  if check_python_deps; then
    if [ "$current" = "$want" ] || [ "$CORE_ONLY" -eq 1 ]; then
      ok "Python requirements already satisfied"
      if [ -n "${DEPS_OPTIONAL_MISSING:-}" ]; then
        warn "optional packages not importable: $DEPS_OPTIONAL_MISSING (server still boots)"
      fi
      return 0
    fi
    info "requirements.txt changed since the last install - refreshing dependencies"
  else
    info "missing Python packages: ${DEPS_MISSING:-unknown}"
  fi

  pip_install
  check_python_deps || die "required Python packages still not importable: ${DEPS_MISSING:-unknown}"

  install_extras
  check_python_deps || die "required Python packages disappeared during install: ${DEPS_MISSING:-unknown}"

  printf '%s\n' "$want" >"$MARKER"
  ok "Python requirements installed"
}


# ---------------------------------------------------------------------------
# MCP client config
# ---------------------------------------------------------------------------
ensure_config() {
  local cfg_dir tmp
  cfg_dir="$(dirname -- "$HEXSTRIKE_CONFIG")"
  mkdir -p -- "$cfg_dir"

  tmp="$(mktemp "$cfg_dir/.hexstrike_mcp.XXXXXX")"
  "$VENV_PY" - "$tmp" "$HEXSTRIKE_DIR" "$VENV_PY" "$MCP_SCRIPT" \
                 "$HEXSTRIKE_SERVER_URL" "$HEXSTRIKE_PORT" "$REQ_FILE" <<'PY'
import json, os, sys

out, hs_dir, venv_py, mcp_script, url, port, req = sys.argv[1:8]
cfg = {
    "mcpServers": {
        "hexstrike-ai": {
            "command": venv_py,
            "args": [mcp_script, "--server", url],
            "description": "HexStrike AI - MCP cybersecurity automation backend",
            "timeout": 300,
            "disabled": False,
            "env": {
                "HEXSTRIKE_SERVER_URL": url,
                "HEXSTRIKE_PORT": str(port),
                "HEXSTRIKE_HOME": hs_dir,
                "PYTHONUNBUFFERED": "1",
            },
        }
    },
    "breachkit": {
        "generated_by": "hexstrike_init.sh",
        "hexstrike_dir": hs_dir,
        "venv_python": venv_py,
        "server_script": os.path.join(hs_dir, "hexstrike_server.py"),
        "requirements": req,
        "server_url": url,
        "port": int(port),
        "health_url": url + "/health",
    },
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2)
    fh.write("\n")
PY

  if [ -f "$HEXSTRIKE_CONFIG" ] && cmp -s "$tmp" "$HEXSTRIKE_CONFIG"; then
    rm -f -- "$tmp"
    ok "MCP config up to date: $HEXSTRIKE_CONFIG"
  else
    mv -f -- "$tmp" "$HEXSTRIKE_CONFIG"
    ok "MCP config written: $HEXSTRIKE_CONFIG"
  fi
}

# ---------------------------------------------------------------------------
# External security tools (informational only)
# ---------------------------------------------------------------------------
report_security_tools() {
  local t found=() missing=()
  for t in "${SEC_TOOLS[@]}"; do
    if have "$t"; then found+=("$t"); else missing+=("$t"); fi
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    ok "external security tools: all ${#SEC_TOOLS[@]} sampled tools found"
  else
    info "external security tools: ${#found[@]}/${#SEC_TOOLS[@]} sampled found"
    warn "not installed (optional, HexStrike disables those modules): ${missing[*]}"
  fi
}

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
start_server() {
  if health_ok; then
    ok "HexStrike server already answering at $HEXSTRIKE_SERVER_URL"
    return 0
  fi
  if port_in_use; then
    warn "port $HEXSTRIKE_PORT is in use but $HEXSTRIKE_SERVER_URL/health does not answer"
    warn "stop whatever owns the port, or re-run with --port <other>"
    return 1
  fi

  mkdir -p -- "$HEXSTRIKE_LOG_DIR"
  info "starting HexStrike server on port $HEXSTRIKE_PORT (log: $SERVER_LOG)"
  (
    cd "$HEXSTRIKE_DIR"
    nohup "$VENV_PY" hexstrike_server.py --port "$HEXSTRIKE_PORT" >>"$SERVER_LOG" 2>&1 &
    printf '%s\n' "$!" >"$PID_FILE"
  )

  local i
  for i in $(seq 1 30); do
    if health_ok; then
      ok "HexStrike server is up (pid $(cat "$PID_FILE" 2>/dev/null || echo '?'), $HEXSTRIKE_SERVER_URL)"
      return 0
    fi
    sleep 1
  done

  warn "server did not answer /health within 30s - last log lines:"
  tail -n 20 "$SERVER_LOG" 2>/dev/null >&2 || true
  return 1
}



# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
run_check() {
  local problems=0

  hdr "Checking HexStrike AI prerequisites"
  require_cmd git "Install it first (apt-get install -y git)." || problems=$((problems + 1))
  if python_usable "$HEXSTRIKE_PYTHON"; then
    ok "python: $("$HEXSTRIKE_PYTHON" -V 2>&1) ($(command -v "$HEXSTRIKE_PYTHON"))"
  else
    warn "'$HEXSTRIKE_PYTHON' missing or older than 3.$HEXSTRIKE_MIN_PY_MINOR"
    problems=$((problems + 1))
  fi

  hdr "Checking HexStrike source"
  if check_source; then
    ok "source present: $HEXSTRIKE_DIR"
  else
    warn "source missing: $HEXSTRIKE_DIR"
    problems=$((problems + 1))
  fi

  hdr "Checking virtualenv"
  if check_venv; then
    ok "virtualenv: $HEXSTRIKE_VENV"
  else
    warn "virtualenv missing/broken: $HEXSTRIKE_VENV"
    problems=$((problems + 1))
  fi

  hdr "Checking Python requirements"
  if check_python_deps; then
    ok "required packages importable: ${CORE_MODULES[*]}"
    if [ -n "${DEPS_OPTIONAL_MISSING:-}" ]; then
      warn "optional packages missing: $DEPS_OPTIONAL_MISSING"
    fi
  else
    warn "missing packages: ${DEPS_MISSING:-unknown}"
    problems=$((problems + 1))
  fi

  hdr "Checking config"
  if check_config; then
    ok "config: $HEXSTRIKE_CONFIG"
  else
    warn "config missing/stale: $HEXSTRIKE_CONFIG"
    problems=$((problems + 1))
  fi

  hdr "Checking server"
  if health_ok; then
    ok "server healthy: $HEXSTRIKE_SERVER_URL/health"
  elif port_in_use; then
    warn "port $HEXSTRIKE_PORT is busy but /health does not answer"
  else
    info "server not running (port $HEXSTRIKE_PORT free) - launch it with: $0 --start"
  fi

  echo
  if [ "$problems" -eq 0 ]; then
    ok "HexStrike is installed and configured. Run '$0 --start' to launch the MCP server."
    return 0
  fi
  warn "$problems problem(s) found. Run '$0' (or 'init.sh') to fix them."
  return 1
}

run_status() {
  printf 'BreachKit / HexStrike status\n'
  printf '  repo root       : %s\n' "$REPO_ROOT"
  printf '  source dir      : %s\n' "$HEXSTRIKE_DIR"
  printf '  virtualenv      : %s\n' "$HEXSTRIKE_VENV"
  printf '  config file     : %s\n' "$HEXSTRIKE_CONFIG"
  printf '  server url      : %s\n' "$HEXSTRIKE_SERVER_URL"
  printf '  server script   : %s\n' "$SERVER_SCRIPT"
  printf '  log file        : %s\n' "$SERVER_LOG"
  printf '  source present  : %s\n' "$(check_source && echo yes || echo no)"
  printf '  venv healthy    : %s\n' "$(check_venv && echo yes || echo no)"
  if check_python_deps; then
    printf '  requirements    : installed\n'
  elif check_venv; then
    printf '  requirements    : missing (%s)\n' "${DEPS_MISSING:-unknown}"
  else
    printf '  requirements    : n/a (no virtualenv yet)\n'
  fi
  if check_venv; then
    printf '  optional wheels : %s\n' "$(modules_missing "${OPTIONAL_MODULES[@]}" 2>/dev/null | sed 's/^$/all present/')"
  else
    printf '  optional wheels : n/a\n'
  fi
  printf '  config present  : %s\n' "$(check_config && echo yes || echo no)"
  printf '  server /health  : %s\n' "$(health_ok && echo up || echo down)"
  echo
  report_security_tools
  return 0
}

run_stop() {
  hdr "HexStrike AI :: stop"
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      info "stopping HexStrike server (PID $pid)"
      kill "$pid" 2>/dev/null || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
      ok "HexStrike server stopped"
    else
      info "PID file exists but process $pid not running"
    fi
    rm -f -- "$PID_FILE"
  else
    info "no PID file found at $PID_FILE"
  fi
  # Also ensure no orphan process listening on port
  if port_in_use; then
    warn "port $HEXSTRIKE_PORT still in use - attempting cleanup"
  else
    ok "port $HEXSTRIKE_PORT is free"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  case "$MODE" in
    check)  run_check ;;
    status) run_status ;;
    ensure) run_ensure ;;
    stop)   run_stop ;;
    *)      die "internal error: unknown mode '$MODE'" ;;
  esac
}

main "$@"
