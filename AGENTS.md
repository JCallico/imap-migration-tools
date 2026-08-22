# IMAP Migration Tools Contributor Guide

## Project layout

- `src/imap_backup.py`, `src/imap_restore.py`, `src/imap_migrate.py`, `src/imap_count.py`, and `src/imap_compare.py` are the primary CLI entry points.
- `src/*_imap_*.py` files are compatibility wrappers for older script names. Keep them working when changing an entry point.
- Shared IMAP, authentication, provider, and cache logic belongs in `src/core/`, `src/auth/`, `src/providers/`, and `src/utils/`.
- Tests mirror the source layout. CLI integration tests live in the corresponding `test/test_imap_*.py` file.

## Development workflow

Before implementing a new feature, investigate whether a maintained library
already provides the complete feature or important building blocks. Present
the user with the viable options before implementation: add a dependency and
use the existing library, or implement the behavior from scratch, including
the relevant maintenance, security, and portability tradeoffs. Prefer an
established library for security- and data-sensitive concerns such as
authentication, encryption, caching, and database access.

Use Python 3.9+ and run commands from the repository root. The source tree is not installed during tests, so include `PYTHONPATH=src` when invoking pytest directly.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .  # install declared runtime dependencies
.venv/bin/python -m pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m pytest test/ -v
.venv/bin/python -m ruff check src/ tools/ test/
.venv/bin/python -m ruff format --check src/ tools/ test/
```

`make test`, `make lint`, and `make format-check` provide the same common checks. CI also runs Bandit, a non-blocking mypy check, syntax/import checks, and tests on Python 3.9 through 3.13.

Tests use local mock IMAP servers and bind loopback ports. In restricted environments, rerun them with the permission needed for local socket binding rather than changing the tests to avoid integration coverage.

CI test jobs must install the project (for example, `pip install .`) before
running pytest. Installing test tools alone can hide missing runtime
dependencies locally and cause collection failures in the clean CI matrix.

## Code conventions

- Target Python 3.9 compatibility. Follow the Ruff configuration in `pyproject.toml` (120-column lines, double quotes, and sorted imports).
- Use concise module and function docstrings. Place reusable behavior in the existing subsystem directories rather than duplicating it in CLI files.
- Preserve CLI compatibility: command-line options, environment variables, and legacy wrapper scripts are public interfaces.
- When renaming shared or module-level symbols, search the entire source and test trees for compatibility aliases and re-exports before running tests.
- Keep sensitive values out of version control. `.env` is ignored; `.env.example` is the committed, non-secret template.

## OAuth2 caching

- Keep process-local and persistent OAuth2 caching behind
  `src/auth/oauth2_cache.py`. Provider-specific authentication modules should
  consume that interface and must not implement cache paths, encryption,
  locking, or persistence directly.
- The current cache implementation uses MSAL Extensions. Use only its
  platform-encrypted persistence; never add a plaintext token-cache fallback.
  If encryption or the cache library is unavailable, authentication must
  continue with process-local caching only and provide concise installation or
  diagnostic guidance.
- Use `OAUTH2_CACHE_ENABLED` and `OAUTH2_CACHE_DIR` for shared cache
  configuration. Keep cache settings provider-neutral so additional OAuth2
  providers can reuse them.
- Treat cached access tokens, refresh tokens, serialized credentials, and
  client secrets as sensitive. Partition entries by provider, client, and
  normalized account identity; use non-identifying hashed filenames and
  cross-process locking.
- Keep terminology precise: an MSAL `PublicClientApplication` is an
  application object, while the persistent token cache stores credentials.
  Avoid using a generic name such as `cache` for both concepts.
- Import optional provider dependencies at the point of use and convert a
  missing dependency into a short, actionable installation message rather
  than an import traceback.
- Put backend behavior tests in `test/auth/test_oauth2_cache.py`. Exercise the
  real persistence and locking library with temporary data where practical;
  provider authentication tests may isolate external browser and identity
  service boundaries. Ensure tests never access the developer's real
  credential store.

## `.env` configuration

- Load `.env` through `utils.dotenv.load_dotenv()` at the start of a CLI `main()` function, before reading environment variables or constructing `argparse` defaults.
- The loader discovers `.env` from the process working directory (and its parents), not from the installed package directory.
- Precedence is: command-line arguments, existing OS environment variables, `.env` values, then script defaults. Keep `override=False` so CI, shell, and secret-manager values remain authoritative.
- `python-dotenv` is a standard runtime dependency. The legacy `imap-migration-tools[dotenv]` extra remains an empty compatibility alias. If changes affect `.env` support, update `README.md`, `.env.example`, and the CI/dev dependency setup as needed.
- For CLI `.env` coverage, add an end-to-end case to each affected `test/test_imap_*.py` module. Use its local `dotenv_file` fixture, run the real `main()`, and assert an observable outcome against a mock IMAP server or local backup. Do not replace this with parser interception or a centralized CLI test module.

## Verification before handoff

Do not stage or commit changes automatically. Only create a commit when the user explicitly asks for one.

Run the focused tests for changed code first, then the full suite when practical. Before every commit, always run:

```bash
.venv/bin/python -m ruff check src/ tools/ test/
.venv/bin/python -m ruff format --check src/ tools/ test/
git diff --check
```

If the formatter check reports files, run `ruff format` on those files, then rerun the complete check sequence. Do not rely on `ruff check` alone: it does not enforce the CI formatter check.

For user-facing changes, verify the relevant README examples and the `.env.example` template match the implementation.
