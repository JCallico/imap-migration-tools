# Native Android application

The Android application uses Kotlin and Jetpack Compose for its native interface and embeds the existing Python
`imap_services` engine with Chaquopy. It supports Count, Compare, Backup, Restore, and Migrate with the same service
options as the command-line, terminal, and desktop interfaces.

## Architecture

The project is intentionally Android-native; it does not use a multiplatform UI or application framework.

| Layer | Responsibility |
| --- | --- |
| `android/app/.../model` | Kotlin operation, account, target, option, progress, and result models |
| `android/app/.../engine` | Secret-conscious JSON request encoding and the Chaquopy adapter |
| `android/app/.../auth` | Native Google AuthorizationClient and Microsoft MSAL account authorization |
| `android/app/.../ui/theme` | System-aware light/dark palettes, typography, shapes, and semantic status colors |
| `android/app/.../ui/components` | Reusable terminal-inspired panels, branding, status, and key/value components |
| `src/mobile/bridge.py` | Validation and translation into the public `imap_services` API |
| `src/imap_services` | Existing IMAP operations, provider behavior, retries, and structured results |
| `android/app/.../operation` | Foreground execution, cancellation, notifications, and local history |
| Jetpack Compose screens | Android configuration, output, confirmation, and history experiences |

Python is called in-process. The Android application never starts a shell or CLI subprocess. Progress crosses the
boundary as structured JSON events, and results return in a structured JSON envelope. The bridge has no Android imports,
so its behavior is covered by the normal Python test suite.

## Build from source

Install Android Studio with Android SDK 36, JDK 17, Gradle 8.13, and Python 3.13. From the repository root:

```bash
gradle -p android testDebugUnitTest assembleDebug
```

Developers using `mise` can install the repository-pinned JDK, Gradle, and Python versions with `mise install`. Configure
the Android SDK through Android Studio or set `sdk.dir` in the ignored `android/local.properties` file. Before building
OAuth-enabled variants, complete the provider registration described in [Configure OAuth](#configure-oauth).

The debug APK is written to `android/app/build/outputs/apk/debug/app-debug.apk`. CI performs the same test and build.
Chaquopy packages `src/` directly, so edits to the shared Python services are included in the next Android build without
copying source files.

## Appearance

The native interface follows the visual language of the terminal application without imitating terminal interaction.
It uses bordered panels, compact status markers, green operation accents, yellow warnings, and monospaced operational
data while retaining native Android controls and touch targets. The application follows Android's system light or dark
theme automatically. Light mode uses an off-white workspace and accessible dark green; dark mode uses the TUI's
near-black workspace and bright green accent. Dynamic system colors are intentionally not applied so the command-line,
terminal, desktop, and mobile applications retain a recognizable shared identity.

## Run the app

The repository launchers build, test, install, and launch the application on an Android emulator or a connected
physical device using the same commands. A physical device needs one-time preparation before the launcher can select
it; the emulator needs none.

### One-command launcher (recommended)

The repository launchers install missing SDK packages, create or reuse an emulator, wait for Android, run the local
build checks, install the APK, and open the application. They can also select a connected physical device. The only
one-time host prerequisite is Android Studio/SDK command-line tools plus either `mise` or an existing JDK 17 and Gradle
8.13 installation. When `mise` is available, the launchers install the repository-pinned JDK, Gradle, and Python
versions automatically.

On Linux or macOS, run this from the repository root and choose a target:

```bash
tools/run_android.sh
```

On Windows PowerShell:

```powershell
.\tools\run_android.ps1
```

The interactive choices are a normal emulator, an Android 15 emulator with 16 KB memory pages, or an authorized
physical device. Useful non-interactive examples are:

```bash
tools/run_android.sh --target emulator
tools/run_android.sh --target emulator --16kb --connected-tests
tools/run_android.sh --target device --serial DEVICE_SERIAL
```

```powershell
.\tools\run_android.ps1 -Target emulator
.\tools\run_android.ps1 -Target emulator -PageSize16Kb -ConnectedTests
.\tools\run_android.ps1 -Target device -Serial DEVICE_SERIAL
```

Instrumentation tests are opt-in because they install a test package and take control of the selected device. Add
`--connected-tests` or `-ConnectedTests` to run them before the launcher reinstalls and opens the application. Use
`--headless` or `-Headless` when a graphical emulator window cannot be displayed. If Windows blocks local PowerShell
scripts, use `powershell -ExecutionPolicy Bypass -File .\tools\run_android.ps1` for that invocation. The 16 KB Windows
path also uses `bash.exe` from Git for Windows to run the common ELF validator. A physical device target must be
prepared and authorized first; see [Prepare a physical device](#prepare-a-physical-device).

Confirm that the Configure screen offers Count, Compare, Backup, Restore, and Migrate, then use Output to follow a run
and History to inspect completed runs. Selecting a history item replaces the Output view with that saved run's events
and formatted result. Merely navigating between screens preserves the displayed output; it changes only when a history
item is selected or a new operation starts. Tap an Output section header to collapse or expand the operation monitor,
live or saved output, and result summary independently. On Android 13 and newer, choose **Allow** when the application
requests notification permission; operations use a persistent progress notification with a Cancel action.

The emulator has normal outbound network access. When connecting to a test IMAP server bound to the development
machine's loopback interface, enter `10.0.2.2` instead of `127.0.0.1` as its hostname; inside the emulator, `127.0.0.1`
refers to Android itself. A physical device cannot use `10.0.2.2`; use a hostname or LAN address routable from the
device instead, ensure the workstation firewall permits the test connection, and retain valid TLS certificate
verification. Public IMAP provider hostnames require no special routing.

### Prepare a physical device

1. Open **Settings → About phone** and tap **Build number** seven times. Device manufacturers may use slightly
   different names or locations.
2. Open **Developer options** and enable **USB debugging**.
3. Connect a data-capable USB cable, unlock the device, and select a USB mode which permits a data connection if the
   manufacturer requires it.
4. Accept the device's **Allow USB debugging?** prompt after verifying the workstation's RSA fingerprint. Select
   **Always allow** only on a trusted development workstation.

Windows may require the device manufacturer's ADB USB driver. macOS normally requires no additional setup. Linux must
have suitable `udev` rules and permission for the logged-in user; distribution packages commonly provide Android
platform-tools rules.

Confirm that ADB reports the authorization state as `device`, not `unauthorized` or `offline`, before running the
launcher with `--target device`:

```bash
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb start-server
adb devices -l
```

Copy the desired serial from `adb devices -l` and pass it to the launcher's `--serial`/`-Serial` option; the launcher
also prompts for one interactively when more than one device or emulator is connected.

#### Optional wireless debugging

Android 11 and newer can use ADB over Wi-Fi. Keep the device and workstation on the same trusted network, enable
**Wireless debugging** in Developer options, then choose **Pair device with pairing code**. The pairing port and the
debugging port shown by Android may be different:

```bash
adb pair DEVICE_IP:PAIRING_PORT
adb connect DEVICE_IP:DEBUGGING_PORT
adb devices -l
```

Enter the six-digit code from the device when `adb pair` requests it, then pass the resulting
`DEVICE_IP:DEBUGGING_PORT` value to the launcher's `--serial`/`-Serial` option.

OAuth registration follows the APK signing certificate, not the physical device. A debug build made with a different
debug keystore has a different Google SHA-1 and Microsoft signature hash. Before testing provider login on a physical
device, ensure the certificate used for this build is registered and that `android/local.properties` contains the
corresponding Microsoft redirect configuration described in [Configure OAuth](#configure-oauth).

### Troubleshooting a graphical emulator window on Linux

Some Android Emulator distributions do not include a Qt Wayland platform plugin. If a graphical emulator window
reports that `wayland` is unavailable and its `xcb` fallback cannot connect to the X display, run the launcher with
`--headless` (or `-Headless` on Windows) instead: it starts the emulator without a Qt window and prints a `scrcpy`
command to view it. This also covers the case where `am start` reports success but no simulator window is visible —
`am start` opens the application inside Android; it does not create a host-side viewer for an emulator started with
`-no-window`. Install `scrcpy` through the operating system's package manager, then run the printed command, for
example:

```bash
scrcpy --serial emulator-5554 --no-audio --window-title "IMAP Migration Tools — Android Emulator"
```

Closing the `scrcpy` window only closes the viewer; it does not stop the emulator or application. Rerunning
`tools/run_android.sh --headless` reuses the already-running emulator instead of starting a second copy. Inspect the
emulator's own log at `~/.android/<avd-name>.log` if it does not register with ADB.

### Validate 16 KB page-size compatibility

The automated launcher is the shortest complete validation path. Choose option 2, or run:

```bash
tools/run_android.sh --target emulator --16kb --connected-tests
```

```powershell
.\tools\run_android.ps1 -Target emulator -PageSize16Kb -ConnectedTests
```

This installs the stable Android 15 Google APIs 16 KB image for the workstation architecture, creates a separate
`imap_tools_16k` AVD, verifies that `getconf PAGE_SIZE` returns `16384`, validates every packaged `.so`, runs the Android
checks and optional instrumentation suite, and launches the app. It does not replace a normal development AVD.

To audit an already-built APK without starting an emulator, install NDK 28 and run:

```bash
sdkmanager "build-tools;35.0.0" "ndk;28.2.13676358"
ANDROID_HOME="${ANDROID_HOME:-$ANDROID_SDK_ROOT}" \
    tools/check_android_16kb.sh android/app/build/outputs/apk/debug/app-debug.apk
```

Validate the bundle configuration and its complete native-library set as well:

```bash
gradle -p android bundleDebug
tools/check_android_16kb.sh android/app/build/outputs/bundle/debug/app-debug.aab
```

The validator inspects every ELF `LOAD` segment with NDK `llvm-readelf` and requires at least `0x4000` alignment. It
then runs the official `zipalign -c -P 16 -v 4` APK check. For an AAB, it also uses Bundletool to require
`PAGE_ALIGNMENT_16K` for Play-generated APKs. CI runs both audits after every Android build. When testing manually,
confirm the emulator rather than inferring its page size from the AVD name:

```bash
adb -s EMULATOR_SERIAL shell getconf PAGE_SIZE
```

The expected result is `16384`. A successful launch and instrumentation run on that device verifies runtime loading;
do not rely on Android's 16 KB compatibility mode as release evidence. Re-run both the packaged-library audit and the
emulator test whenever Chaquopy, Python, AndroidX, AGP, NDK, or another native dependency changes. See Android's
[official 16 KB page-size guide](https://developer.android.com/guide/practices/page-sizes).

## Physical-device support notes

The prototype supports Android 7.0 (API 24) or newer on 64-bit ARM and x86_64 devices. Google authentication also
requires Google Play services. Use a test device or test Android user profile when possible: uninstalling the prototype
removes its private projects and backup workspaces. See [Prepare a physical device](#prepare-a-physical-device) for
one-time setup before running the launcher against a device.

### Physical-device test checklist

For the complete release resilience and API/ABI matrix—including cancellation, process death, restart, storage,
authorization, network, background, and minified-release cases—use
[Android release resilience and compatibility testing](android-release-testing.md).

1. Verify the Configure, Output, and History screens in both system light and dark themes and at the device's normal and
   largest practical font/display sizes.
2. Create and switch projects, restart the app, and confirm each project's non-secret settings return independently.
3. Connect a Google or Microsoft test account, run Count, restart the app, and confirm silent reauthentication works.
4. Back up a deliberately small test folder. Verify the storage estimate, **Start while estimating**, live Output,
   completion history, workspace export, and the foreground notification's Cancel action.
5. Turn off Wi-Fi only long enough to verify that Backup, Restore, and Migrate show the network warning; cancel instead
   of transferring data unless mobile-data use is intentional.
6. Send the app to the background during a small operation, return to it, rotate the device, and confirm progress and
   output remain coherent.
7. Disconnect an OAuth account and confirm that another project referencing the same provider account remains usable.

The optional instrumentation suite can also run on the selected device. Set `ANDROID_SERIAL` to the device's serial
from `adb devices -l` first if more than one device or emulator is connected:

```bash
export ANDROID_SERIAL="DEVICE_SERIAL_FROM_ADB"
gradle -p android connectedDebugAndroidTest
```

Use a test device/profile for instrumentation. Although the suite confines its project lifecycle checks to a temporary
project, automated UI tests install a test package and control the application.

### Logs, updates, and cleanup

Capture only the application's logs while reproducing a problem, adding `-s SERIAL` when more than one device or
emulator is connected:

```bash
adb logcat --clear
adb logcat --pid="$(adb shell pidof com.callicode.imaptools)"
```

Rerun the launcher for later revisions; it rebuilds, reinstalls with `-r` (which preserves the app's existing private
data), and reopens the app. Export any backup workspace which must be retained before uninstalling, because this
command permanently removes the app's private projects, workspaces, history, and locally associated credentials:

```bash
adb uninstall com.callicode.imaptools
```

When testing is complete, disable USB or wireless debugging, forget the paired workstation under **Wireless
debugging**, or use **Revoke USB debugging authorizations** in Developer options.

For platform-level details, see Android's official guides for
[running on a hardware device](https://developer.android.com/studio/run/device) and
[configuring Developer options](https://developer.android.com/studio/debug/dev-options).

## Projects

The Configure screen supports named projects for separate migration configurations. Creating a project immediately
selects it, and selecting another project replaces the complete configuration form. Changes autosave to a real `.env`
file under the application's private `files/projects/<stable-id>/` directory. Stable IDs keep a project's storage path
independent of its display name. Backup workspaces live under `files/backups/<stable-id>/`, preventing projects with the
same workspace name from reading or modifying one another. Migration resume caches are additionally partitioned by a
non-identifying hash of both account endpoints.

The first launch after upgrading creates a **Default** project from the previous Android configuration. A project can be
deleted only when at least one other project exists. When backups exist, the deletion prompt lists their workspace names
and offers **Delete project only**, which preserves them under **Manage retained backups**, and **Delete project +
backups**, which permanently removes all of the project’s private workspaces. A project without backups receives a
single **Delete project** action. Every choice removes the project `.env` but leaves operation history, exported
archives, provider authorization, mail, and provider accounts unchanged. Retained workspaces can be exported or
permanently deleted individually from the project screen.

Project `.env` files use the shared variable names where the concepts match, including `SRC_IMAP_HOST`,
`DEST_IMAP_HOST`, `MAX_WORKERS`, and `PRESERVE_FLAGS`. Android-only UI state uses `ANDROID_`-prefixed keys. These files
are an internal persistence format; project-configuration import and export are not currently exposed. Backup-workspace
ZIP import and export are separate operations described below.

## Storage and credentials

Android scoped storage does not expose arbitrary document-provider directories as POSIX paths, while the shared Python
engine operates on directory paths. The application therefore uses managed backup workspaces inside its private app
storage. Workspace names are normalized before they become path components. The native Android document picker imports
and exports compatible workspaces as ZIP archives; imports reject path traversal, oversized archives, and accidental
replacement of an existing workspace. Removing the app removes private workspaces, so export a verified backup before
uninstalling the application.

### Data lifecycle and deletion

| Action | What the app does | What remains and must be removed elsewhere |
| --- | --- | --- |
| **Disconnect** | Removes the account association from that project endpoint. If the same provider account has no other project or endpoint references, the app asks Google to revoke authorization or asks MSAL to remove the Microsoft account from this app’s cache. The disconnect completes only if that SDK operation succeeds. | It does not delete mail or the provider account, sign the account out of Android or other apps, or undo completed operations. Remove any remaining authorization in the provider’s connected-app/security settings and delete mail at the provider. |
| **Delete project only** | Deletes that project’s private `.env` configuration and account references, while placing its private workspaces under **Manage retained backups**. Each retained workspace can be exported or permanently deleted later. | Operation history, exported ZIPs, provider authorization, accounts, and mail remain. |
| **Delete project + backups** | Deletes the project configuration and permanently deletes all private backup workspaces owned by that project. | Operation history, exported ZIPs, provider authorization, accounts, and mail remain. Delete those separately where they are stored. |
| **Export ZIP** | Writes a separate copy of the selected private workspace to the document-provider location chosen by the user. The private workspace remains. | Delete the ZIP with Files or the selected storage/cloud application. Also empty its trash or remove synchronized/versioned copies when required. |
| **Import ZIP** | Reads the selected ZIP into a new private workspace under the active project. The source ZIP is not changed. A failed import removes its temporary private extraction directory. | Delete the original ZIP separately. The imported private copy can be removed with its project using **Delete project + backups**, retained and managed after **Delete project only**, or removed by clearing storage/uninstalling. |
| **Delete local backup orphans** | During Backup, removes individual local message files which are no longer on the source mailbox. This synchronizes a workspace; it does not delete the entire backup. | Other workspace content, exported copies, and provider mail remain. |
| **Delete saved output** | Permanently removes one operation's timestamp, status, progress events, result, and error from private history. History otherwise retains the 100 newest completed runs. | It does not undo the operation, change mail, delete projects/backups/archives, or disconnect an account. |
| **Clear storage / uninstall** | Permanently removes all app-private projects, history/output, app-held authentication state, imported copies, and backup workspaces. | Exported ZIPs, source ZIPs used for import, provider accounts, mail, completed mailbox changes, provider-side grants/sessions, and cloud/file-provider copies remain and must be removed in those systems. |

Clearing storage and uninstalling are all-or-nothing cleanup operations in the current prototype. Before using either,
export and verify every backup which must be retained. Neither action reverses a restore or migration. To permanently
remove restored or migrated messages, delete them at the mail provider and complete that provider’s Trash, Deleted
Items, retention, or purge workflow. Android vendors label the cleanup command differently; it is normally under
**Settings → Apps → IMAP Migration Tools → Storage & cache → Clear storage**. Confirm the application name before
proceeding because the action cannot be undone.

Passwords and OAuth access tokens remain in memory and are not written to project `.env` files, preferences, or history.
They remain associated with their project while the application process is running. Hostnames, usernames, provider
account identifiers, modes, and operation options persist in the active project's private `.env`. The application asks
the native provider SDK for a current access token immediately before each run and supplies it through the existing
service boundary using `OAuth2Config.access_token`. The desktop-only browser and encrypted cache implementations are not
used on Android.

Output events, foreground-notification text, operation results, and errors pass through an Android privacy redactor
before display or history retention. It removes credentials and account identifiers known to the request, email
addresses, app-private paths, `.eml` filenames, and the subject/filename field from per-message transfer progress.
Folder names and aggregate counts remain visible as intended operation results. The application does not bundle an
analytics or remote crash-reporting SDK. Mail bodies and attachments exist locally only inside backup workspaces the
user explicitly creates or imports.

All project files, history, authentication-library caches, imported workspaces, and local backups are below Android's
app-private data directory. Project and history writers additionally set owner-only file access, `allowBackup` is
disabled in the manifest, and no component exposes these files through a content provider. Export is the deliberate
exception: the user chooses a document-provider destination, and that provider controls the exported ZIP's permissions,
sync, versioning, and deletion behavior.

### Google Play account-deletion answers

The current app does not create an IMAP Migration Tools account or maintain a developer backend. Google/Microsoft
sign-in and password IMAP authenticate an existing mail-provider account for a direct mailbox operation; a local
project is configuration, not an app account. In Play Console, answer the app-account-creation question **No** for this
architecture, while still completing the mandatory data-deletion questions accurately. Do not describe Disconnect or
Delete project as deleting the user's Google, Microsoft, or mail-provider account.

Google Disconnect on the last local reference calls `AuthorizationClient.revokeAccess`, which revokes this app's
requested Gmail authorization. Microsoft Disconnect on the last reference calls MSAL `removeAccount`, which removes
tokens associated with this client from its application cache but, especially with a broker, does not remove the
account from the device or claim to revoke provider-side consent. The user must use the provider's account/security or
organization controls for any remaining grant or session.

### Persisted-data audit

| Data | Location and protection | Deletion behavior |
| --- | --- | --- |
| Project configuration | Private `files/projects/<id>/.env`, owner-only; contains hosts, usernames/provider IDs, modes, names, and options but no password or access/refresh token | Delete project, Clear storage, or uninstall |
| Provider authentication | Provider SDK-managed cache in app-private storage; access tokens are otherwise held only in process memory | Last-reference Disconnect removes/revokes as described above; Clear storage/uninstall removes this app's local cache; provider-side state may remain |
| Operation history | Private, owner-only `files/operation-history.json`; capped at 100; redacted before persistence | Delete saved output, Clear storage, or uninstall |
| Active/retained/imported backups | Private `files/backups/<project-id>/`; may intentionally contain complete RFC 5322 messages and attachments | Delete project + backups, Delete backup for retained workspaces, Clear storage, or uninstall |
| Migration progress cache | Private hashed path inside the owning project workspace; contains message identifiers used to resume | Deleted with its workspace/project backup data, Clear storage, or uninstall |
| Exported ZIP | User-selected document-provider location outside app-private storage | Delete in Files/provider and empty provider trash/version history if required |
| Source ZIP selected for import | Original provider location; the app reads but does not modify it | Delete separately in Files/provider |
| Logs/crash reports | No app log file, analytics SDK, or remote crash reporter is included | Android/vendor system diagnostics are controlled outside the app |

## Configure OAuth

Normal users choose **Google** or **Microsoft**, tap **Connect**, and complete the provider's account and consent screen.
They never enter a client ID or paste an access token. Provider application registration is a one-time responsibility
for whoever builds and distributes the APK.

The application requests only the provider scope needed for IMAP:

- Google: `https://mail.google.com/`
- Microsoft: `https://outlook.office.com/IMAP.AccessAsUser.All`

### Google

The emulator or physical device must contain Google Play services. Google authorization is associated with the APK's
package and signing certificate; it is not configured on each test device.

#### Obtain the application identity

Build the APK first, then read the package and SHA-1 fingerprint from the build inputs and the APK which will actually
be installed:

```bash
gradle -p android assembleDebug

grep 'applicationId =' android/app/build.gradle.kts
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
APKSIGNER="$(find "$ANDROID_HOME/build-tools" -type f -name apksigner | sort -V | tail -1)"
"$APKSIGNER" verify --print-certs android/app/build/outputs/apk/debug/app-debug.apk
```

For this repository, the package printed by the first command is `com.callicode.imaptools`. Copy the colon-delimited
SHA-1 represented by `Signer #1 certificate SHA-1 digest`; Google accepts either uppercase or lowercase hex. Do not copy
the SHA-256 digest.

Repeat this registration for every certificate used to distribute the app. A locally installed debug APK uses the
developer's debug certificate. A sideloaded release APK uses its release certificate. A build installed through Google
Play uses the **App signing key certificate** SHA-1 shown on Play Console's **App integrity** page, which can differ from
the upload certificate.

#### Configure Google Cloud

In [Google Cloud Console](https://console.cloud.google.com/), perform these steps in the project which will own the app's
OAuth configuration:

1. Select an existing project or create one. Keep the same project selected throughout these steps.
2. Open **APIs & Services → Library**, find **Gmail API**, and select **Enable**.
3. Open **Google Auth Platform → Branding**. If prompted, select **Get started**, enter the application name, support
   email, and developer contact email, then save the configuration.
4. Open **Google Auth Platform → Audience**. Choose **Internal** only when every user belongs to the same eligible Google
   Workspace organization; otherwise choose **External**. Leave an External prototype in **Testing** and add every
   Google account which will test the app under **Test users**.
5. Open **Google Auth Platform → Data Access**, select **Add or remove scopes**, and add
   `https://mail.google.com/`. If it is not listed, use the manual scope entry. Confirm that it appears in the project's
   restricted scopes, then save.
6. Open **Google Auth Platform → Clients**, select **Create client**, and choose **Android** as the application type.
7. Enter a descriptive client name, package name `com.callicode.imaptools`, and the SHA-1 obtained from the APK. Create
   the client. Create additional Android clients in this same project for other signing certificates as needed.
8. Allow several minutes for a newly created or changed client to propagate, then retry **Connect** in the app.

No downloaded client JSON, Google client ID, or client secret belongs in this Android project or
`android/local.properties`. Google Play services identifies the client from the installed package and certificate. The
project's consent configuration, Gmail API, OAuth client, and test-user list must therefore agree.

After authorization, the app calls Gmail's `users.getProfile` endpoint with the short-lived access token to obtain the
authorized mailbox address required as the IMAP XOAUTH2 username. This call uses the same Gmail scope and does not
request another permission. Access tokens and profile responses are not logged or persisted.

The `https://mail.google.com/` full-mail scope is restricted. An External app may use listed test users while its
publishing status is Testing, but general distribution requires Google's OAuth verification and any security assessment
applicable to how restricted user data is handled.

#### Verify and troubleshoot Google authorization

On the device, select Google, tap **Connect**, choose a listed test account, and approve access. The app should return to
the account panel and show **Connected as** with the selected address. Selecting an account is only the first part of the
flow: Google validates the package/fingerprint pair immediately afterward.

If account selection returns to the app without completing sign-in, inspect Logcat for
`UNREGISTERED_ON_API_CONSOLE`. That response means the installed APK's package and signing certificate do not match an
Android OAuth client in the selected Google Cloud project:

```bash
adb logcat -c
# Reproduce the sign-in failure on the device, then run:
adb logcat -d | grep -E 'UNREGISTERED_ON_API_CONSOLE|Authorization|GoogleAuth'
```

Compare the APK-derived package and SHA-1 again with **Google Auth Platform → Clients**. Also verify that the selected
account is listed under **Audience → Test users** while an External app is in Testing. Cloud-side registration changes
do not alter the APK, so a matching installed build can be retried without rebuilding or reinstalling it. If a different
APK was installed, rebuild it, repeat the identity check, and install it with the explicit device serial described in
[Prepare a physical device](#prepare-a-physical-device).

### Microsoft

In the Microsoft Entra admin center:

1. Create an app registration that supports the intended organizational and personal Microsoft account types.
2. Add an **Android** platform with package name `com.callicode.imaptools` and the signature hash of the APK signing
   certificate. Copy the client ID and generated MSAL redirect URI.
3. Under API permissions, add the delegated Office 365 Exchange Online permission `IMAP.AccessAsUser.All`. Grant tenant
   consent if required by the organization's policy.

For the standard debug key, calculate the Base64 signature hash with:

```bash
keytool -exportcert \
    -alias androiddebugkey \
    -keystore "$HOME/.android/debug.keystore" \
    -storepass android \
    -keypass android \
    | openssl sha1 -binary \
    | openssl base64
```

Keep the printed, unescaped Base64 value as the signature hash. Use the exact redirect URI generated by Entra, whose
final path component is the URL-encoded form of that hash. Add these values to the ignored `android/local.properties`
beside `sdk.dir`:

```properties
oauth.microsoft.clientId=00000000-0000-0000-0000-000000000000
oauth.microsoft.redirectUri=msauth://com.callicode.imaptools/URL_ENCODED_SIGNATURE_HASH
oauth.microsoft.signatureHash=UNESCAPED_BASE64_SIGNATURE_HASH
```

Do not commit `local.properties`. A build without the Microsoft values remains usable with password and Google
authentication; choosing Microsoft displays a configuration error instead of asking the user for developer settings.

### Test the sign-in flow

Build and install the app using the launcher described in [Run the app](#run-the-app). Then:

1. Choose an operation which uses an IMAP account.
2. Select **Google** or **Microsoft** for that account and tap **Connect**.
3. Select an account and approve the IMAP permission. The account panel should show **Connected as** followed by the
   provider email address.
4. Tap **Run**. The application silently obtains a current token when possible; if provider interaction is required, it
   opens the provider screen and resumes the operation afterward.
5. Tap **Disconnect** to remove the account association from the current project. If no other project or endpoint uses
   that provider account, the app also revokes Google authorization or removes the account from its MSAL cache. This
   does not sign the account out of Android or the provider's other applications, delete mail, or necessarily end a
   browser, broker, or provider session. Remove any remaining grant in the provider’s connected-app or account-security
   settings.

## Background execution

Every run is an immediate network operation explicitly started by the user. On Android 14 (API 34) and newer, the app
schedules it as a `JobScheduler` user-initiated data-transfer (UIDT) job. UIDT jobs are Android's supported path for
user-started network transfers which need to continue while the app is in the background. They appear in Android's task
manager, use a persistent progress notification with a Cancel action, and are not subject to Android 15's shared
six-hour `dataSync` foreground-service background limit.

Android 13 and older do not provide UIDT jobs, so the same runner uses a user-started `dataSync` foreground service as a
compatibility path. The service implements Android's timeout callback defensively, although the Android 15+ path does
not use that service. Both paths share the same privacy redaction, storage checks, history, notification, and
cancellation code.

The scheduler applies an internet-network constraint. Backup, Restore, and Migrate require unmetered Wi-Fi unless the
user accepts the mobile-data confirmation; that choice is carried into the job constraint. Count and Compare may use
the currently available network without the large-transfer prompt. A completed Backup estimate is supplied to Android
as estimated download bytes so the scheduler can account for the expected payload.

Cancellation is cooperative. The mobile event adapter checks cancellation between structured progress updates and asks
the existing worker pools to unwind. Network calls already in progress may take until their configured timeout to return.
Android may also stop a UIDT job because its network constraint is lost, for device health, or because the process is
killed. Credentials remain process-only and are never serialized into `JobInfo`, so the app deliberately does not
silently retry a stopped job after process death. Open the app and start the operation again; migration's existing
progress cache safely skips completed work.

Before Backup, Restore, or Migrate starts outside an unmetered Wi-Fi connection, the app warns that the operation may
transfer substantial data and requires explicit confirmation. Count and Compare do not trigger this large-transfer
warning.

Backup also performs a read-only storage preflight after authentication. It asks the IMAP server for each missing
message's declared RFC822 size without downloading message bodies, compares the total with the allocatable space on the
app's storage volume, and shows the estimated download, message count, available space, and expected remaining space.
The estimate reserves an additional 15 percent plus 256 MB because mailbox contents, metadata, and available storage
can change while the operation runs.

Users may wait for the estimate or choose **Start while estimating**. When started early, the estimate continues on a
separate read-only IMAP connection and its result appears in Output. If the estimate later shows that the backup cannot
fit, the run stops. If the server cannot provide a complete estimate, the app explains that limitation and offers an
explicit **Back up anyway** choice. During every backup, Android rechecks allocatable space every five seconds and stops
before the 256 MB reserve is consumed.

### Test Android 14+ transfer scheduling

Use an Android 14 or newer emulator/device and keep the serial explicit when more than one device is connected:

```bash
export ANDROID_SERIAL=emulator-5554
gradle -p android installDebug
adb -s "$ANDROID_SERIAL" shell am start -W -n com.callicode.imaptools/.MainActivity
```

Start any operation from the visible app, then verify job `41001` is present and the progress notification offers
**Cancel**:

```bash
adb -s "$ANDROID_SERIAL" shell dumpsys jobscheduler com.callicode.imaptools
```

For a Backup, Restore, or Migrate test on unmetered Wi-Fi, disable Wi-Fi and verify the queued job does not begin on a
metered connection without confirmation. Repeat, accept the in-app mobile-data confirmation, and verify it can begin.
Use a non-production mailbox for the following stop test; Android asks the runner to cancel the active operation:

```bash
adb -s "$ANDROID_SERIAL" shell cmd jobscheduler timeout com.callicode.imaptools 41001
```

Confirm that Output reports the stop, the notification disappears, and the app remains usable. Then start the operation
again and confirm it resumes safely where the operation supports a progress cache. Also test the notification's
**Cancel** action. Android's task-manager **Stop** control terminates the entire app process by platform design, so use
it only to verify that reopening the app is safe and that no credential or operation request was persisted.

## Current distribution boundary

The Android project is an unsigned source/CI build. Play signing, release credentials, privacy disclosures, store
listing material, and physical-device verification are release work and are not stored in this repository. Follow the
[Google Play publication checklist](android-publishing.md) to prepare, approve, test, and publish a production build.
