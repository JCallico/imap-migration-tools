After finishing a batch of changes, always run:
ruff check src/ tools/ test/
ruff format --check src/ tools/ test/
python3 -m pytest test

When writing tests, favor input/output results (integration) over specific implementation and number of calls. Avoid patching and mocking as much as possible.

For development-machine, native GUI, Android, or Omarchy Windows-VM setup, use the cross-agent
`.claude/skills/setup-development-environment/SKILL.md` skill and only its relevant platform reference.

