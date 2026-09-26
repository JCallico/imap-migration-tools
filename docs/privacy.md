# IMAP Migration Tools Privacy Policy

Last updated: September 19, 2026

IMAP Migration Tools is a local-first application for counting, comparing, backing up, restoring, and migrating IMAP
mailboxes. This policy describes the Android application’s current pre-release behavior. It does not replace the
privacy terms of Google, Microsoft, an email provider, or an organization which manages your account or device.

## Data the application handles

The application handles the account details you provide or authorize, such as an IMAP server, email address,
authentication method, and provider account identifier. While performing an operation, it may process mailbox names,
message metadata, message content, attachment data, and message flags or labels.

Passwords are used for the requested connection and are not written to Android project configuration files. Google
and Microsoft sign-in credentials are managed through their authentication SDKs and Android-protected application
storage. The application stores project configuration, operation history, and diagnostic output locally. History and
diagnostics may contain mailbox or folder names, counts, and provider error messages.

## Local backups and exports

Mailbox backups are saved in the application’s private storage on the Android device. IMAP Migration Tools does not
operate a server which receives those backups. A private workspace remains on the device until Android clears the
app’s storage or the app is uninstalled, although backup synchronization can add or remove files within that workspace.

An archive exported through Android’s document picker is a separate ZIP copy stored in the location selected by the
user. Exporting does not move or delete the app-private backup. If the selected location is managed by a file-sync or
cloud-storage provider, that provider receives and retains the ZIP under its own policies. The user must delete an
exported ZIP with the Files app or the application or service which manages that location, including its trash,
recycle bin, retained versions, or synchronized copies when applicable.

Importing reads a selected ZIP and creates a separate backup workspace in the active project’s private storage. It
does not change or delete the selected ZIP. A failed import removes its temporary app-private extraction directory,
but not the selected source file.

## Network services

The application connects directly to the email servers and identity providers selected by the user. Those providers
receive the information required to authenticate the account and perform the requested mailbox operation under their
own privacy policies. The application does not currently include advertising, analytics, or a third-party crash-reporting
service.

## Deletion and retention

### Disconnect

Disconnect removes the selected account association from that project endpoint. When another project or endpoint still
uses the same provider account, the shared provider authorization remains available to that other reference. When the
last reference is disconnected, the app asks Google to revoke its granted Gmail scope or asks MSAL to remove the
Microsoft account from this app’s token cache, as applicable. The local disconnect completes only if that provider SDK
operation succeeds.

Disconnect does not delete the Google or Microsoft account, sign it out of Android or other applications, delete mail,
or undo a completed backup, restore, or migration. It may not end sessions retained by a browser, authentication
broker, device account, or identity provider. To remove any remaining provider-side grant, the user must remove IMAP
Migration Tools from the provider’s connected-app or account-security settings. Mail and accounts must be deleted at
the mail or identity provider.

Google and Microsoft sign-in connects an existing provider account so the app can perform a user-requested IMAP
operation. It does not create an IMAP Migration Tools account, developer-hosted identity, or server-side profile. A
project is a local configuration file, not an account. Accordingly, when Google Play asks whether this app lets users
create an account, the current application should be described as **not offering app-account creation**. The Play
Console data-deletion questions still require accurate answers about the locally stored data described below.

For Google, the last-reference Disconnect action uses Google's authorization API to revoke the scopes granted to this
application; a future connection requires consent again. For Microsoft, Disconnect removes the account and this app's
tokens from MSAL's application cache. It does not remove the Microsoft account from a broker or device and does not
claim to revoke tenant/provider consent. Users can remove any remaining Microsoft grant in their Microsoft account or
organization's connected-app controls.

### Delete a project

Deleting a project always removes that project’s private `.env` configuration and account references. If the project
owns private backup workspaces, the app lists them and asks the user to choose one of these actions:

- **Delete project only** retains its private backup workspaces. They remain available under **Manage retained
  backups**, where each workspace can be exported or permanently deleted.
- **Delete project + backups** also permanently deletes every private backup workspace owned by the project.

Neither choice deletes operation history, provider accounts, provider-side authorization, mail, or ZIP files exported
outside the app. A retained workspace’s **Delete backup** action deletes only that app-private workspace; exported ZIP
copies remain and must be deleted separately. If the project has no private backup workspaces, the app states that fact
and presents a single **Delete project** action.

The **Delete local backup orphans** operation option is not whole-backup deletion. When enabled for a backup, it may
remove individual local message files which no longer exist on the source mailbox so the workspace mirrors the source.

### Delete operation history

Each History card provides **Delete saved output** with a confirmation. This permanently removes only that run's local
timestamp, status, progress events, result, and error from the app's private history file. It does not cancel or undo
the completed operation, alter either mailbox, delete a project or backup, remove an exported archive, or disconnect a
provider. History is capped at the 100 most recent completed runs; adding a later run automatically removes the oldest
entry beyond that limit.

### Clear storage or uninstall

Clearing application storage or uninstalling removes app-private projects, operation history and output, authentication
state stored by this app, imported backup copies, active backup workspaces, and retained backup workspaces. It does not
remove:

- ZIP archives or other copies exported outside app-private storage;
- the original ZIP selected for an import;
- provider accounts, mail, or changes already made by restore or migration operations;
- provider-side grants or sessions retained by an identity provider, browser, broker, or device account; or
- copies retained by a file-sync, backup, or cloud-storage provider.

Those items must be deleted separately in the Files app, the relevant storage service, Android’s account settings, or
the mail or identity provider. Empty provider trash or deleted-items folders and cloud-storage recycle bins when
permanent deletion is required, subject to the provider’s retention policy.

### Mailbox deletion

Mailbox operations which explicitly enable source deletion or destination/local orphan deletion can delete mail or
local backup files. The application asks for confirmation before starting operations which can delete server messages.
Disconnecting, deleting a project, clearing app storage, or uninstalling does not reverse mailbox changes. The user
must remove unwanted restored or migrated messages at the mail provider and complete any provider-specific permanent
deletion steps.

## Security

The application uses Android application isolation and provider authentication libraries to protect local data and
credentials. No software can guarantee absolute security. Keep the device protected, install trusted builds, review
operation settings before starting a transfer, and do not publish credentials or private mailbox content in support
requests.

Passwords and OAuth access/refresh tokens are not written to project files or operation history. Android output is
redacted before display, notification, and history retention to remove known credentials, account identifiers, private
paths, email addresses, and per-message subject/filename details. Folder names and aggregate counts remain because
they are operation results. Mail bodies and attachments are stored only when the user intentionally creates or imports
a local mailbox backup. The app has no analytics or remote crash-reporting SDK; Android system diagnostics remain
subject to the device and Android vendor's own controls.

## Changes

This policy may change as the pre-release application gains features or distribution services. The revision date at
the top identifies the current version.

## Contact

For support or privacy questions, use the project’s
[public issue tracker](https://github.com/JCallico/imap-migration-tools/issues). Do not include passwords, access or
refresh tokens, private email, or mailbox content in a public issue.
