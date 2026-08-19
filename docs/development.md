# Development

## Set up a source checkout

```bash
git clone https://github.com/JCallico/imap-migration-tools.git
cd imap-migration-tools
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install python-dotenv
```

Python 3.9 and newer are supported. Read [AGENTS.md](../AGENTS.md) before contributing; it documents repository
conventions, public compatibility requirements, and subsystem ownership.

## Repository layout

| Location | Responsibility |
|---|---|
| `src/imap_*.py` | Primary CLI entry points |
| `src/*_imap_*.py` | Compatibility wrappers for legacy script names |
| `src/cli/` | Argument parsing and command-specific configuration |
| `src/auth/` | OAuth2 authentication and encrypted credential caching |
| `src/core/` | Shared migration and IMAP behavior |
| `src/providers/` | Provider-specific behavior |
| `src/utils/` | Shared utilities, including `.env` loading |
| `test/` | Unit and local IMAP integration tests mirroring the source tree |

## Run tests

The source tree is not installed during direct test execution, so set `PYTHONPATH`:

```bash
PYTHONPATH=src .venv/bin/python -m pytest test/ -v
```

Run one module while iterating:

```bash
PYTHONPATH=src .venv/bin/python -m pytest test/test_imap_count.py -v
```

Tests isolate themselves from the repository's real `.env`. CLI `.env` integration cases use temporary files and real
command entry points. Never make tests depend on developer credentials or the platform's real OAuth credential store.

Some integration tests start mock IMAP servers on loopback ports. In a restricted environment, grant local socket
binding permission rather than removing that coverage.

## Quality checks

The common Make targets are:

```bash
make test
make lint
make format-check
make ci
```

Run the underlying pre-commit checks directly with:

```bash
.venv/bin/python -m ruff check src/ tools/ test/
.venv/bin/python -m ruff format --check src/ tools/ test/
git diff --check
```

CI also runs Bandit, syntax and import checks, a non-blocking mypy check, and the test suite on Python 3.9 through 3.13.
The CI test jobs install the project before pytest so missing runtime dependencies cannot be hidden by a developer's
environment.

## Adding or changing CLI configuration

- Preserve existing command options, environment variables, and compatibility wrappers.
- Load `.env` at the beginning of `main()` before reading environment-backed defaults.
- Preserve precedence: CLI, OS environment, `.env`, then built-in defaults.
- Treat a host and its credentials as one account boundary.
- Give environment-backed booleans positive and negative CLI forms.
- Add an end-to-end `.env` case to each affected `test/test_imap_*.py` module, using its local fixture and an observable
  outcome rather than parser interception.
- Update [Configuration](configuration.md), workflow examples, and `.env.example` when the public interface changes.

Before implementing a new feature, check whether a maintained library already supplies it. For authentication,
encryption, caching, and other security- or data-sensitive behavior, prefer established libraries and document the
dependency and portability tradeoffs before implementation.
