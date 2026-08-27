# Configuration

The tools accept command-line arguments, OS environment variables, and an optional `.env` file.

## Create a `.env` file

```bash
cp .env.example .env
```

On PowerShell:

```powershell
Copy-Item .env.example .env
```

`.env` is ignored by Git. Keep credentials out of commits, shell history, logs, and shared screenshots.

## Account variables

Source settings are used by backup, migration, comparison, and as count fallbacks:

```env
SRC_IMAP_HOST="imap.gmail.com"
SRC_IMAP_USERNAME="source@gmail.com"
SRC_IMAP_PASSWORD="source-app-password"
```

Destination settings are used by restore, migration, comparison, and destination counting:

```env
DEST_IMAP_HOST="imap.example.com"
DEST_IMAP_USERNAME="destination@example.com"
DEST_IMAP_PASSWORD="destination-password"
```

Count also supports its historical single-account aliases:

```env
IMAP_HOST="imap.example.com"
IMAP_USERNAME="user@example.com"
IMAP_PASSWORD="app-password"
```

## Precedence

Values are resolved in this order:

1. Command-line arguments
2. Existing OS environment variables
3. `.env`
4. Script defaults

The ordering applies to logical groups, not just individual fields. An OS password selects password authentication over
an OAuth client ID found only in `.env`. An OS OAuth client ID similarly selects OAuth over a `.env` password.

## Authentication choice

Configure exactly one method per account.

Password:

```env
SRC_IMAP_PASSWORD="app-password"
SRC_OAUTH2_CLIENT_ID=""
SRC_OAUTH2_CLIENT_SECRET=""
```

OAuth2:

```env
SRC_IMAP_PASSWORD=""
SRC_OAUTH2_CLIENT_ID="application-client-id"
SRC_OAUTH2_CLIENT_SECRET="google-client-secret-if-required"
```

Explicit CLI authentication clears an inherited competing method:

```bash
imap-backup --src-pass "temporary-app-password"
imap-backup --src-oauth2-client-id "application-client-id"
```

When both methods are configured at the same environment level, OAuth remains the compatibility default. Avoid relying
on that fallback; choose one method explicitly.

## Hosts are account boundaries

Changing a host without changing its credentials could send credentials to the wrong endpoint. Therefore, an explicit
host requires a username and authentication choice in the same command:

```bash
imap-backup \
  --src-host "imap.example.com" \
  --src-user "user@example.com" \
  --src-pass "app-password" \
  --dest-path "./backup"
```

An OS-level host also requires its username and authentication method from OS or CLI configuration. It cannot silently
inherit those values from `.env`. OAuth client secrets and Microsoft account-type settings are not carried from a
lower-precedence account.

Partial username or authentication overrides remain valid when the host itself is inherited.

## Local paths and operating modes

`BACKUP_LOCAL_PATH` is the backup destination and restore source. Comparison uses `SRC_LOCAL_PATH` and
`DEST_LOCAL_PATH` independently.

Explicit path arguments select local mode. Explicit IMAP connection arguments select IMAP mode. Do not combine a path
with explicit IMAP arguments for the same side.

Count detects available local, source, and destination targets. If multiple targets are configured, select one:

```bash
imap-count --target local
imap-count --target source
imap-count --target destination
```

An explicit path or complete ad hoc account also resolves the mode:

```bash
imap-count --path "./backup"

imap-count \
  --host "imap.example.com" \
  --user "user@example.com" \
  --pass "app-password"
```

A path-only legacy configuration and a single configured account continue to be selected automatically.

## Boolean options

Environment-backed booleans accept `true` or `false`. Every positive CLI option has a negative form, including:

```text
--src-delete / --no-src-delete
--dest-delete / --no-dest-delete
--preserve-labels / --no-preserve-labels
--preserve-flags / --no-preserve-flags
--gmail-mode / --no-gmail-mode
--manifest-only / --no-manifest-only
--apply-labels / --no-apply-labels
--apply-flags / --no-apply-flags
--full-restore / --no-full-restore
```

This allows one invocation to disable a setting enabled by OS environment or `.env` configuration.

## Destination namespaces

Destination namespace prefixes are normally detected with the IMAP `NAMESPACE` command. For a server that does not
advertise its namespace correctly, configure it explicitly:

```env
DEST_FOLDER_PREFIX="INBOX."
DEST_FOLDER_SEP="."
```

## Operational settings

```env
MAX_WORKERS=4
BATCH_SIZE=10
OAUTH2_CACHE_ENABLED="true"
OAUTH2_CACHE_DIR=""
MIGRATE_CACHE_DIR=""
FULL_MIGRATE="false"
```

Reduce `MAX_WORKERS` when a provider reports too many simultaneous connections.

See [Workflows](workflows.md) for complete examples and [OAuth2](oauth2.md) for provider setup.
