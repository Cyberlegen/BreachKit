#!/usr/bin/env bash
# =============================================================================
# BreachKit :: install.sh (Single-Command Downloader & Bootstrap)
# -----------------------------------------------------------------------------
# Downloads/sets up BreachKit, creates virtualenv, installs dependencies,
# and runs the interactive demo.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Cyberlegen/BreachKit/2a/install.sh | bash
# =============================================================================

set -euo pipefail

REPO_URL="https://github.com/Cyberlegen/BreachKit.git"
INSTALL_DIR="${BREACHKIT_INSTALL_DIR:-$HOME/breachkit}"
BRANCH="${BREACHKIT_BRANCH:-2a}"

print_banner() {
    printf '\033[36m'
    printf '============================================================\n'
    printf '          BREACHKIT ONE-COMMAND DOWNLOAD & SETUP            \n'
    printf '============================================================\n'
    printf '\033[0m'
}

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

main() {
    print_banner()

    command -v git >/dev/null 2>&1 || err "git is required but not installed."
    command -v python3 >/dev/null 2>&1 || err "python3 is required but not installed."

    log "Target installation directory: $INSTALL_DIR"

    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Existing BreachKit repository found - pulling latest updates"
        git -C "$INSTALL_DIR" fetch origin "$BRANCH"
        git -C "$INSTALL_DIR" checkout "$BRANCH"
        git -C "$INSTALL_DIR" pull origin "$BRANCH"
    else
        log "Cloning BreachKit ($BRANCH branch) into $INSTALL_DIR"
        git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    fi

    cd "$INSTALL_DIR"

    log "Setting up Python virtual environment"
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi

    # shellcheck disable=SC1091
    source .venv/bin/activate

    log "Upgrading pip & installing BreachKit in editable mode"
    pip install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
    pip install -e ".[dev]"

    ok "BreachKit successfully installed!"
    printf '\n'
    log "Setup complete! Run 'breachkit --help' or execute 'python demo.py' anytime."
}

main "$@"
