# IMAP Email Migration Tools

![CI](https://github.com/JCallico/imap-migration-tools/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/github/JCallico/imap-migration-tools/graph/badge.svg?token=SDF29GC5VV)](https://codecov.io/github/JCallico/imap-migration-tools)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A collection of command-line tools for migrating, backing up, restoring, counting, and comparing email on IMAP
servers. The tools were created for large migrations where simpler clients timed out or could not resume reliably.

They support password and OAuth2 authentication, incremental operation, Gmail labels, standard IMAP flags, local
`.eml` backups, and destination synchronization.

> These tools can copy and delete email. Test with non-critical data, verify counts and backups, and review destructive
> options before using them on an important account. The software is provided without warranty.

## Commands

| Installed command | Source entry point | Purpose |
|---|---|---|
| `imap-migrate` | `src/imap_migrate.py` | Copy or move email between IMAP accounts |
| `imap-backup` | `src/imap_backup.py` | Download an IMAP account as `.eml` files |
| `imap-restore` | `src/imap_restore.py` | Upload a local backup to an IMAP account |
| `imap-compare` | `src/imap_compare.py` | Compare folder counts across IMAP or local sources |
| `imap-count` | `src/imap_count.py` | Count messages on an account or in a local backup |

Legacy script names remain available as compatibility wrappers.

## Installation

Python 3.9 or newer is required. Install with `.env` support using `pipx`:

```bash
pipx install "imap-migration-tools[dotenv]"
```

Or use pip in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install "imap-migration-tools[dotenv]"
```

Basic password authentication needs no additional authentication package. OAuth2 provider and encrypted cache
dependencies are installed by the project. See [Installation](docs/installation.md) for platform and source setup.

## Quick start

Copy the safe configuration template:

```bash
cp .env.example .env
```

Edit `.env` with source and destination credentials. The template enables password authentication by default; OAuth2
values are empty. Configure only one authentication method per account.

Migrate all folders:

```bash
imap-migrate
```

Or provide a complete account directly:

```bash
imap-migrate \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.example.com" \
  --dest-user "destination@example.com" \
  --dest-pass "destination-password"
```

Back up and verify an account:

```bash
imap-backup \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "app-password" \
  --dest-path "./mail-backup"

imap-compare \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "app-password" \
  --dest-path "./mail-backup"
```

## Configuration essentials

Configuration precedence is:

1. Command-line arguments
2. Existing OS environment variables
3. `.env` values
4. Script defaults

Authentication is resolved as one choice, so a higher-precedence password cannot be displaced by a lower-precedence
OAuth client ID, or vice versa. A host is an account boundary: when overriding a host, provide its username and password
or OAuth client ID from the same or a higher-precedence source.

Environment-backed booleans have positive and negative CLI forms. For example:

```bash
imap-migrate --src-delete
imap-migrate --no-src-delete
imap-backup --dest-delete
imap-backup --no-dest-delete
```

When local, source, and destination count targets coexist, choose explicitly:

```bash
imap-count --target local
imap-count --target source
imap-count --target destination
```

See [Configuration](docs/configuration.md) for all precedence, authentication, mode-selection, namespace, and boolean
rules.

## Common workflows

- [Migration, backup, restore, count, and comparison examples](docs/workflows.md)
- [OAuth2 setup for Microsoft and Google](docs/oauth2.md)
- [Troubleshooting and operational safety](docs/troubleshooting.md)
- [Development, testing, and CI](docs/development.md)

For large migrations, start with a count, run a non-destructive copy, compare the result, and only then consider
deletion or synchronization options.

## Contributing

Create a virtual environment, install the project and development requirements, then run:

```bash
make ci
```

See [Development](docs/development.md) and [AGENTS.md](AGENTS.md) for the complete contributor workflow and repository
conventions.

## License

Licensed under the [MIT License](LICENSE).
