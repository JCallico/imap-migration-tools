# Troubleshooting

## Authentication fails

- Confirm that the username belongs to the configured host.
- Use an app password when the provider requires one for IMAP.
- For OAuth2, verify the client ID, client secret where required, consent, delegated IMAP permission, and account type.
- Configure only one authentication method per account.
- If a host is supplied on the CLI or in the OS environment, supply its username and authentication at the same or a
  higher configuration level. Lower-precedence `.env` credentials are intentionally not inherited across a host
  boundary.

## A `.env` value is ignored

Existing OS environment variables override `.env`, and CLI values override both. Inspect exported variables in the
current shell and remember that an empty OS variable still has higher precedence than a `.env` value.

Automatic `.env` loading is included in the standard package. If it is unavailable in an older or incomplete
environment, reinstall the current package:

```bash
python -m pip install --upgrade imap-migration-tools
```

The loader searches the working directory and its parents. It does not search relative to the installed package.

## Count reports an ambiguous target

`BACKUP_LOCAL_PATH`, a source account, and a destination account can all be valid count targets. Choose the intended
one explicitly:

```bash
imap-count --target local
imap-count --target source
imap-count --target destination
```

For an ad hoc count, a complete `--host`, `--user`, and password or OAuth client ID selects the supplied server. A
non-empty `--path` selects a local backup.

## Too many IMAP connections

Some providers enforce a low concurrent-connection limit. Reduce workers:

```bash
imap-migrate --workers 2
imap-backup --workers 2
```

Or set `MAX_WORKERS=2` in the environment. Avoid running several migration commands against the same account at once.

## Timeouts or interrupted runs

Migration, backup, and restore operations are designed to resume. Rerun the same command; incremental state and message
identity checks avoid repeating completed work. Preserve the cache and backup directories until verification is
complete.

If failures repeat:

- lower `MAX_WORKERS` and `BATCH_SIZE`;
- verify network stability and provider status;
- run a single folder to isolate the failure;
- use `--full-migrate` or `--full-restore` only when a deliberate reprocessing pass is needed.

## Destination folders have the wrong prefix

The destination namespace is normally obtained from the server. If it is missing or incorrect, configure the prefix
and separator:

```env
DEST_FOLDER_PREFIX="INBOX."
DEST_FOLDER_SEP="."
```

Verify the result on a test folder before migrating an account.

## Gmail labels or flags are missing

Enable metadata preservation during the source operation and application during restore:

```bash
imap-backup --gmail-mode --preserve-labels --preserve-flags
imap-restore --apply-labels --apply-flags
```

The backup must contain the corresponding manifest metadata. `--manifest-only` can rebuild Gmail label metadata when
the messages have already been downloaded.

## Deletion behavior is unexpected

`--src-delete` removes successfully copied source messages. `--dest-delete` removes destination-only messages or local
files during synchronization. Their negative forms override settings inherited from `.env` or the OS:

```bash
imap-migrate --no-src-delete --no-dest-delete
imap-backup --no-dest-delete
```

In Gmail mode, deleting from All Mail deletes the message from the account rather than merely removing one label.
Always retain a verified backup before enabling deletion.

## Reporting a problem

Open an issue in the [GitHub issue tracker](https://github.com/JCallico/imap-migration-tools/issues) with the command
name, Python version, provider, and sanitized error output. Remove usernames, tokens, passwords, client secrets, and
message contents.
