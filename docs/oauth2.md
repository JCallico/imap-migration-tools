# OAuth2 authentication

OAuth2 is available for Microsoft and Google accounts. It avoids storing an account password, but requires an
application registration and an interactive sign-in the first time credentials are acquired.

## Provider detection

The provider is inferred from the IMAP host:

| Host | Provider |
|---|---|
| `outlook.office365.com` | Microsoft 365 work or school account |
| `imap-mail.outlook.com` | Microsoft personal account |
| `imap.gmail.com` | Google |

Microsoft account type can be set to `auto`, `personal`, or `work` with `SRC_ACCOUNT_TYPE`, `DEST_ACCOUNT_TYPE`, or
`ACCOUNT_TYPE` for the count command.

## Configure an account

Choose OAuth2 instead of a password for each account:

```env
SRC_IMAP_HOST="imap.gmail.com"
SRC_IMAP_USERNAME="source@gmail.com"
SRC_IMAP_PASSWORD=""
SRC_OAUTH2_CLIENT_ID="google-client-id"
SRC_OAUTH2_CLIENT_SECRET="google-client-secret"
```

The destination equivalents use the `DEST_` prefix. The count command also supports `OAUTH2_CLIENT_ID`,
`OAUTH2_CLIENT_SECRET`, and `ACCOUNT_TYPE` with its `IMAP_` account aliases.

CLI options use the same account boundary:

```bash
imap-backup \
  --src-host "imap.gmail.com" \
  --src-user "user@gmail.com" \
  --src-oauth2-client-id "client-id" \
  --src-oauth2-client-secret "client-secret" \
  --dest-path "./mail-backup"
```

Do not configure a password and OAuth client ID at the same precedence level. See [Configuration](configuration.md) for
the resolution rules.

## Microsoft setup

Create an application registration in Microsoft Entra ID:

1. Register an application that supports the intended account type.
2. Enable public client flows for device or interactive authentication.
3. Add the delegated Exchange Online IMAP permission `IMAP.AccessAsUser.All`.
4. Grant consent where the tenant requires administrator approval.
5. Put the application (client) ID in `SRC_OAUTH2_CLIENT_ID` or `DEST_OAUTH2_CLIENT_ID`.

A client secret is not normally used for the public-client Microsoft flow:

```env
SRC_IMAP_HOST="outlook.office365.com"
SRC_IMAP_USERNAME="user@organization.example"
SRC_IMAP_PASSWORD=""
SRC_OAUTH2_CLIENT_ID="microsoft-application-id"
SRC_ACCOUNT_TYPE="work"
```

Use `imap-mail.outlook.com` and `personal` for a personal Outlook account when auto-detection is not suitable.

## Google setup

In Google Cloud Console:

1. Create or select a project.
2. Configure the OAuth consent screen.
3. Create an OAuth client ID for a desktop application.
4. Record both its client ID and client secret.
5. Ensure IMAP access is permitted for the account or Google Workspace organization.

```env
SRC_IMAP_HOST="imap.gmail.com"
SRC_IMAP_USERNAME="user@gmail.com"
SRC_IMAP_PASSWORD=""
SRC_OAUTH2_CLIENT_ID="google-client-id"
SRC_OAUTH2_CLIENT_SECRET="google-client-secret"
```

## Token caching

OAuth tokens are cached in memory during a process. Persistent caching is enabled by default when the platform-backed
MSAL Extensions store is available:

```env
OAUTH2_CACHE_ENABLED="true"
OAUTH2_CACHE_DIR=""
```

Set `OAUTH2_CACHE_ENABLED=false` to disable persistent caching. `OAUTH2_CACHE_DIR` changes the cache location when a
specific writable directory is required.

Persistent entries are partitioned by provider, client, and normalized account identity. The cache uses the operating
system's encrypted credential support and cross-process locking. If encrypted persistence is unavailable, the command
continues with process-local caching and does not create a plaintext token cache.

Treat client secrets, cached credentials, refresh tokens, and access tokens as sensitive. Never commit them or place
them in shared backup directories.
