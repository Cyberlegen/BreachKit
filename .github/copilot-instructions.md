# Copilot instructions for BreachKit

## Repository snapshot

- This repository is intentionally minimal at the moment: the tracked project files are README.md, init.sh, and standard repo metadata.
- The project is described in README.md as "AI Powered Offensive Security Audit/Bug Bounty Pipeline (Dynamic and HITL)" and explicitly notes that it requires human supervision.
- Do not assume a mature application framework or a large established codebase exists yet. The repo is currently more of a bootstrap/starting point than a fully implemented product.

## Build, test, and lint commands

There is no package manager, test runner, linter, or CI configuration in the current repository snapshot.

Current supported repo command:

- `bash ./init.sh` — starts the Warp terminal environment used by the repo’s initialization script.

If the project grows beyond this bootstrap stage, add the real commands here and keep them aligned with the repository’s actual tooling.

## High-level architecture

The big-picture intent is a human-in-the-loop offensive security / bug bounty pipeline rather than a single standalone script. The project is positioned as AI-assisted auditing with human oversight, so future code should remain organized around distinct operational stages instead of a single monolithic workflow.

At this stage, the architecture is not fully implemented; the important point is to preserve the product’s intent:

- AI-assisted offensive security workflow
- Human review / supervision as a core part of the system
- Pipeline-oriented design rather than ad hoc script collection

When adding new code, keep responsibilities explicit and avoid intermixing unrelated automation into a single file.

## Key conventions and repo-specific patterns

- Keep README.md and any new project docs aligned with the actual repository purpose. This repo’s value is in the concept of an AI-powered audit pipeline, not in generic boilerplate.
- Maintain the human-in-the-loop nature of the project. Security automation should support review and oversight, not replace it.
- Prefer small, clear, purpose-specific files over broad infrastructure or framework scaffolding unless the project genuinely needs them.
- Because this repo is a minimal bootstrap, avoid introducing large tooling ecosystems or build systems without a clear need.
- Treat this project as security-sensitive by default: new features should be explicit about workflow boundaries, safety checks, and whether human review is required.

## Working expectations

- Keep changes narrow and intentional. This repository does not yet have established conventions beyond its security-audit mission and minimal bootstrap layout.
- If the project grows, prefer adding the smallest necessary structure that supports the workflow rather than creating generic automation or unrelated devops scaffolding.
- Update README.md when new capabilities or entry points are introduced so future Copilot sessions understand the current state of the project.
