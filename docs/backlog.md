# Product backlog

This backlog records planned cross-interface work which is intentionally outside the current Android implementation.
It is not a release commitment or an indication that an item is already supported.

## Project support for the terminal and desktop applications

Add named projects to the Textual TUI and native desktop GUI. Each project must map to exactly one `.env` file and make
switching among independent migration configurations explicit.

Acceptance criteria:

- Users can create, select, rename, and delete projects without manually entering `.env` paths.
- Every project has a stable `.env` path; renaming the project does not silently create a second configuration.
- Existing `.env` discovery and explicit `--env` launches remain backward compatible.
- Switching projects reloads the complete form and does not merge credentials or settings from the previous project.
- Passwords, client secrets, and tokens retain the existing masking, file-permission, and cache protections.
- External edits, validation errors, concurrent instances, and project deletion receive the same safety treatment as
  the current single-`.env` workflow.
- The TUI and GUI share project registry and lifecycle behavior instead of implementing incompatible formats.
- Documentation includes migration from existing `.env` files and recovery when a registered file is moved or deleted.

The CLI project-selection experience should be designed alongside this work, while preserving direct `--env` usage.

## Project deletion and retained-backup management for the terminal and desktop applications

Bring the Android project-deletion decision and retained-backup manager to the Textual TUI and native desktop GUI when
named projects are implemented. Adapt the storage operations to explicit desktop backup paths rather than assuming
Android app-private storage.

Acceptance criteria:

- Deleting a project asks whether to delete only its configuration or also delete the backup workspaces owned by it.
- The destructive choice names the exact project and backup paths, requires confirmation, and never includes exported
  archives or mail-provider data.
- Backups preserved during project deletion remain discoverable in a retained-backup manager instead of becoming
  inaccessible filesystem orphans.
- Users can inspect the location and size of each retained backup, attach it to another project, export or move it, and
  permanently delete it with a separate confirmation.
- External, removable, network, read-only, missing, and symbolic-link paths are handled safely. A partial filesystem
  failure is reported without claiming that all requested data was deleted.
- Project deletion does not silently revoke provider authorization, delete provider accounts, or reverse mailbox
  changes. Those boundaries use the same wording as the Android privacy and lifecycle documentation.
- The TUI and GUI share project ownership metadata and retained-backup services so a workspace managed in one interface
  remains understandable in the other.

## User-friendly authentication for the terminal and desktop applications

Bring the Android application's account authentication experience to the Textual TUI and native desktop GUI. Account
setup must offer the same three choices: Password, Google, and Microsoft. Users authenticate through the provider's
authorization flow and must never be asked to find, copy, or paste OAuth access tokens, refresh tokens, client secrets,
or authorization codes.

Acceptance criteria:

- Password authentication retains the existing host, username, and masked-password workflow.
- Google authentication launches the system browser, requests the IMAP scope, captures the callback safely, and obtains
  the account identity and tokens without asking the user to enter OAuth credentials manually.
- Microsoft authentication launches the system browser, uses the configured Entra public-client application and IMAP
  delegated permission, and obtains the account identity and tokens without manual credential entry.
- Successful authorization populates the account email automatically; the user does not need to enter it separately.
- Provider SDKs or maintained OAuth libraries securely cache credentials and silently renew access tokens across
  application restarts. Interactive authentication is shown only when provider policy or account state requires it.
- Users can explicitly disconnect an account, which removes its locally cached credentials and project association.
- Authentication failures, cancellation, revoked consent, expired sessions, MFA, and conditional-access challenges are
  reported with concise, actionable messages rather than raw exceptions.
- Source and destination accounts can use different authentication methods and identities, with associations isolated
  per project.
- OAuth tokens and client secrets are never written to project `.env` files or logs.
- The TUI and GUI share the same authentication services and cache behavior instead of implementing separate provider
  logic.

## Backup storage preflight for the terminal and desktop applications

Bring the Android backup storage-estimation and low-space safeguards to the Textual TUI and native desktop GUI. Reuse
the shared read-only IMAP estimator, but query capacity for the filesystem volume containing the selected backup path.

Acceptance criteria:

- Starting a backup automatically estimates the RFC822 size of messages not already present in the incremental backup.
- Users can wait for the estimate or deliberately start the backup while estimation continues in the background.
- The review and live-output views show the estimated download size, available space, and expected remaining space.
- Estimates include documented safety headroom and are presented as estimates rather than exact values.
- If estimation is unavailable, users receive a clear warning and can explicitly choose whether to continue.
- Available space is monitored throughout the backup, and the operation stops safely before consuming the reserved
  minimum free space.
- Capacity checks use the actual destination volume and handle network, removable, and disconnected filesystems with
  actionable errors.
- The TUI and GUI share estimation behavior and result models rather than implementing separate IMAP scans.

## TUI-inspired desktop appearance

Bring the native desktop GUI on every supported platform into the same visual family as the TUI and Android
application without replacing native desktop interaction patterns.

Acceptance criteria:

- Terminal-inspired panels, typography, operation accents, status indicators, and output formatting remain
  recognizable across Linux, macOS, and Windows.
- The GUI provides coordinated light and dark palettes and can follow the operating-system theme.
- Existing window transparency and interface zoom controls remain supported in both themes.
- Transparency preserves text contrast and focus visibility instead of applying uniform opacity to all content.
- Zoom continues to scale the complete interface coherently, including dialogs, touch/click targets, and output text.
- Theme, transparency, and zoom preferences remain independent, persist across restarts, and retain their existing
  compatibility and validation behavior.
- Platform-specific window-manager limitations degrade gracefully without changing the core application workflow.
