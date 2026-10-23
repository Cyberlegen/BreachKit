# BreachKit
AI Powered Offensive Security Audit/Bug Bounty Pipeline(Dynamic and HITL) in the form of a package. Customizable. Requires Human supervision.

## Quick start

BreachKit drives the [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) MCP server as its
offensive tooling backend. Bootstrap everything with:

```bash
./init.sh            # checks HexStrike, clones/configures/installs what is missing
./init.sh --start    # same, then launch the MCP server on http://127.0.0.1:8888
```

`init.sh` runs `hexstrike_init.sh`, which is idempotent and can also be used on its own:

| command | effect |
| --- | --- |
| `./hexstrike_init.sh` | verify + install/repair HexStrike (source, venv, requirements, config) |
| `./hexstrike_init.sh --check` | verify only, change nothing (non-zero exit if not ready) |
| `./hexstrike_init.sh --status` | human readable report of paths and state |
| `./hexstrike_init.sh --start` | ensure everything, then start the server and wait for `/health` |
| `./hexstrike_init.sh --core-only` | skip optional extras (angr, pwntools, webdriver-manager) |
| `./hexstrike_init.sh --force` | wipe the checkout/venv and reinstall |
# Set BREACHKIT_SKIP_HEXSTRIKE=1 to skip the HexStrike step.
#
# Note: run this inside the environment where BreachKit will execute - the
# HexStrike server is expected to be reachable at http://127.0.0.1:8888.

Installed layout (all git-ignored): `tools/hexstrike-ai/` (upstream checkout + `hexstrike-env`
virtualenv), `config/hexstrike_mcp.json` (generated MCP client config), `logs/` (server log + pid).

Overridable environment variables: `HEXSTRIKE_DIR`, `HEXSTRIKE_VENV`, `HEXSTRIKE_REPO_URL`,
`HEXSTRIKE_BRANCH`, `HEXSTRIKE_HOST`, `HEXSTRIKE_PORT`, `HEXSTRIKE_SERVER_URL`,
`HEXSTRIKE_CONFIG`, `HEXSTRIKE_LOG_DIR`, `HEXSTRIKE_PYTHON`, `HEXSTRIKE_PIP_ARGS`,
`BREACHKIT_SKIP_HEXSTRIKE=1`.

Note: HexStrike's 150+ external security tools (nmap, nuclei, gobuster, ...) are **not** installed
by this script — install them from your distro or Kali. Missing ones are reported as warnings, and
HexStrike disables their modules. HexStrike's server itself needs no API key; that belongs to the
MCP client you connect to it.

Only use BreachKit/HexStrike against systems you are authorized to test.

