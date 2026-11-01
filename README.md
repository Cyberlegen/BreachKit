# BreachKit

AI Powered Offensive Security Audit/Bug Bounty Pipeline (Dynamic and HITL) in the form of a package. Customizable. Requires Human supervision.

---

## 🚀 One-Command Download & Setup

Download, install, and run the pipeline instantly on Linux, macOS, or Windows WSL:

```bash
curl -sSL https://raw.githubusercontent.com/Cyberlegen/BreachKit/2a/install.sh | bash
```

---

## 🎬 Interactive Demo

Want to see BreachKit's policy engine, HITL approval gates, crash-safe state machine, and write-time evidence redaction in action? Run the interactive demo:

```bash
python demo.py
```

---

## 🛠️ Quick Start & Usage

BreachKit drives the [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) MCP server as its offensive tooling backend.

### Bootstrap & Server Management

```bash
./init.sh            # checks prerequisites, sets up venv, verifies HexStrike
./init.sh --start    # ensures everything and launches the MCP server on 127.0.0.1:8888
./init.sh --stop     # securely terminates background servers and frees ports
```

### CLI Verbs

```bash
breachkit --help
breachkit init --check
breachkit run --scope scope.yaml
breachkit approve --job-id <job-id>
breachkit resume --job-id <job-id>
breachkit report --job-id <job-id>
breachkit stop --hard
```

---

## 🔒 Security & Architecture Guarantees

1. **Strict Scope Enforcement**: Unmatched targets or exclusions are blocked at the dispatcher level before any tool executes.
2. **Human-in-the-Loop (HITL) Gate**: Active and intrusive tool actions require explicit approval records bound to the engagement scope hash.
3. **Write-Time Redaction**: Sensitive authorization tokens, API keys, and cookies are redacted at write time before evidence artifacts touch disk.
4. **Hash-Chained Audit Log**: Every event is appended to `audit.jsonl` with SHA-256 hash chaining to ensure tamper-evident execution transcripts.
