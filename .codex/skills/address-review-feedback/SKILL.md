---
name: address-review-feedback
description: Address review feedback on a pull request in this repository inside a sandboxed git worktree, deciding for each review item whether to fix it, decline it with evidence, or escalate it. Used by the agent loop's feedback stage; also usable manually to work through review comments.
---

# Address Review Feedback

The cross-agent canonical skill is
[`../../../.claude/skills/address-review-feedback/SKILL.md`](../../../.claude/skills/address-review-feedback/SKILL.md).
Read it completely and follow that workflow. Keep this adapter minimal so Codex, Claude, and GitHub Copilot use one
maintained source of instructions.
