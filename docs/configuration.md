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

## Projects

The terminal interface (`imap-tools`) and desktop GUI (`imap-tools-gui`) organize configurations as projects. A
project is exactly one `.env` file, and both interfaces share the same projects:

| Project | File |
| --- | --- |
| `default` | `~/.imap-migration-tools/.env` (`%USERPROFILE%\.imap-migration-tools\.env` on Windows) |
| Named project | `~/.imap-migration-tools/<name>.env` |
| `local` | A `.env` discovered from the launch directory or its parents, or chosen with `--env` |

Because the projects directory is in your home directory, `default` and named projects are available regardless of the
directory from which an interface is launched. Create, rename, and delete named projects from the interface; renaming
moves the one file and never leaves a second copy behind. The `default` and `local` projects cannot be renamed or
deleted from the interfaces. Project names must be valid file names on every platform, 60 characters or fewer, and
unique regardless of letter case; `default` and `local` are reserved.

Switching projects saves any pending edit to the current project first and then reloads the complete form from the
selected file, so no value from the previous project is carried over. The last selected project reopens on the next
launch. Launch options select a project explicitly:

```bash
imap-tools --project "Acme Corp"
imap-tools-gui --project default
imap-tools --env /path/to/other/.env      # opened as the local project
```

At launch, `--env` (or `IMAP_TOOLS_ENV_FILE`) takes precedence, followed by `--project`, the last selected project, a
discovered local `.env`, and finally `default`. Set `IMAP_TOOLS_PROJECTS_DIR` to store projects in another directory.

Operations started from either interface receive `IMAP_TOOLS_ENV_FILE` naming the active project file. The command-line
tools honor the same variable, loading exactly that file instead of discovering `.env`, which also lets scripts run
against a project:

```bash
IMAP_TOOLS_ENV_FILE=~/.imap-migration-tools/"Acme Corp.env" imap-count
```

A missing file named by `IMAP_TOOLS_ENV_FILE` stops the command instead of running with no configuration.

### Moving an existing `.env` into projects

An existing project directory `.env` keeps working as the `local` project whenever an interface is launched from that
directory. To make it available from anywhere, copy it into the projects directory under the name you want, keeping it
private to your account:

```bash
mkdir -p ~/.imap-migration-tools
chmod 700 ~/.imap-migration-tools
cp /path/to/project/.env ~/.imap-migration-tools/"Acme Corp.env"
chmod 600 ~/.imap-migration-tools/"Acme Corp.env"
```

On PowerShell:

```powershell
New-Item -ItemType Directory -Force "$HOME\.imap-migration-tools" | Out-Null
Copy-Item C:\path\to\project\.env "$HOME\.imap-migration-tools\Acme Corp.env"
```

Copy it to `~/.imap-migration-tools/.env` instead to make it the `default` project. Once the copy is verified, remove
or rename the original to avoid maintaining two versions of the same credentials.

### Recovering a moved or deleted project file

Project files are read directly from the projects directory, so moving a file back into it (named `<name>.env`)
restores that project; the project list refreshes automatically. If the active project's file is moved or deleted by
another program or another instance, the interface keeps the form, marks the project as missing, and does not recreate
the file on the next edit. Restore the file, or switch to another project. When `default` has no file yet, for example
on first use, the first valid edit creates it.

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
