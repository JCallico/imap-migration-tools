# Workflows

These examples use the installed command names. When running from a source checkout, replace a command such as
`imap-migrate` with `PYTHONPATH=src .venv/bin/python src/imap_migrate.py`.

## A safe migration sequence

For an important account:

1. Count the source.
2. Make a local backup or perform a non-destructive migration.
3. Compare the source and destination.
4. Inspect unexpected differences.
5. Only then enable source or destination deletion.

```bash
imap-count --target source
imap-migrate --no-src-delete --no-dest-delete
imap-compare
```

Commands use `.env` configuration when available. Every example can instead receive a complete account through CLI
arguments; see [Configuration](configuration.md).

## Count messages

Count the only configured target:

```bash
imap-count
```

Choose among configured local, source, and destination targets:

```bash
imap-count --target source
imap-count --target destination
imap-count --target local
```

Count an ad hoc server or local backup:

```bash
imap-count --host "imap.example.com" --user "user@example.com" --pass "app-password"
imap-count --path "./mail-backup"
```

An explicit complete account selects IMAP mode, so `--path ""` is not required.

## Migrate between IMAP accounts

Copy all folders using configured source and destination accounts:

```bash
imap-migrate
```

Migrate one folder:

```bash
imap-migrate "Archive/2025"
```

Enable the migration cache to skip previously copied messages on later runs:

```bash
imap-migrate --migrate-cache "./migration-cache"
```

Reprocess all messages while continuing to update an enabled cache when verification or changed metadata requires it:

```bash
imap-migrate --migrate-cache "./migration-cache" --full-migrate
```

Preserve message flags and Gmail labels:

```bash
imap-migrate --preserve-flags --preserve-labels
```

Move instead of copy only after validating the destination:

```bash
imap-migrate --src-delete
```

If `DELETE_FROM_SOURCE=true` is inherited from the environment, disable it for a dry run:

```bash
imap-migrate --no-src-delete
```

Destination synchronization deletes destination-only messages and is destructive:

```bash
imap-migrate --dest-delete
```

Use `--no-dest-delete` to override `DEST_DELETE=true` for one invocation.

## Gmail migrations

Gmail mode works from All Mail so a message stored under several labels is transferred once. Label metadata can then
be applied at the destination.

```bash
imap-migrate --gmail-mode --preserve-labels --preserve-flags
```

Review deletion options especially carefully in Gmail mode: removing a message from All Mail removes it from the Gmail
account, not merely from one label.

## Back up to local storage

Back up every folder as `.eml` files:

```bash
imap-backup --dest-path "./mail-backup"
```

Back up a single folder:

```bash
imap-backup --dest-path "./mail-backup" "Archive/2025"
```

Preserve flags and Gmail labels in the backup metadata:

```bash
imap-backup --dest-path "./mail-backup" --preserve-flags --preserve-labels
```

For a Gmail backup, download All Mail and build its label manifest:

```bash
imap-backup --dest-path "./mail-backup" --gmail-mode --preserve-labels --preserve-flags
```

Rebuild only the manifest when messages are already present:

```bash
imap-backup --dest-path "./mail-backup" --gmail-mode --manifest-only
```

Local synchronization can remove files no longer present on the server. Enable it only against a verified backup:

```bash
imap-backup --dest-path "./mail-backup" --dest-delete
```

## Restore a local backup

Restore all folders:

```bash
imap-restore --src-path "./mail-backup"
```

Restore one folder:

```bash
imap-restore --src-path "./mail-backup" "Archive/2025"
```

Apply saved labels and flags:

```bash
imap-restore --src-path "./mail-backup" --apply-labels --apply-flags
```

Restore is incremental by default. A full restore processes all local messages and can synchronize metadata on messages
already present:

```bash
imap-restore --src-path "./mail-backup" --full-restore --apply-labels --apply-flags
```

Use `--no-full-restore`, `--no-apply-labels`, or `--no-apply-flags` to disable inherited settings.

## Compare results

Compare configured source and destination IMAP accounts:

```bash
imap-compare
```

Compare an IMAP account with a local backup:

```bash
imap-compare \
  --src-host "imap.example.com" \
  --src-user "user@example.com" \
  --src-pass "app-password" \
  --dest-path "./mail-backup"
```

Compare two local backups:

```bash
imap-compare --src-path "./backup-before" --dest-path "./backup-after"
```

Count and comparison results are valuable checks, but equal folder counts do not by themselves prove that every
message and metadata value is identical. Retain the source or a backup until the migrated account has been inspected.
