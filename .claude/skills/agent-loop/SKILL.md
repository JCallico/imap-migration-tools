---
name: agent-loop
description: Operate this repository's issue-to-pull-request agent loop dispatcher. Use when asked to check the loop's setup, show its status or quota, preview or run a dispatcher tick, bootstrap its labels, or pause and resume it.
---

# Agent Loop Operator

Operate the dispatcher in `tools/agent_loop/`. Read `docs/agent-loop.md` for setup and the administrator workflow, and
`docs/agent-loop-plan.md` for the design. Follow the repository's contributor instructions.

## Rules

- Run every command from the repository root as `PYTHONPATH=tools .venv/bin/python -m agent_loop <command>`.
- Use the GitHub CLI for any GitHub inspection; never call the GitHub API another way.
- Never make authorization decisions yourself. Only the dispatcher decides whether a comment or label came from a
  repository administrator.
- Read-only commands (`doctor`, `status`, `tick --dry-run`, `labels` without `--apply`) need no confirmation.
- A live `tick`, `labels --apply`, `pause`, and `resume` change shared state. Run them only when the user explicitly
  asks for that specific operation.
- Never print, copy, or move the GitHub App private key or tokens, and never add API-key variables to the environment.

## Workflow

1. Run `doctor`. Report failures with their fix from `docs/agent-loop.md`; warnings are informational.
2. Run `status` to show stage models, quota state and resume times, and managed items.
3. Run `tick --dry-run` and summarize the planned actions in priority order, including waits and their reasons.
4. Only on explicit request, run the requested mutating command and report its output.

If the dispatcher reports a configuration error, explain which rule failed (for example, the review model must differ
from every code-authoring model) and propose the smallest `.github/agent-loop.toml` change; do not edit it unless asked.
