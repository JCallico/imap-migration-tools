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

## Run on an Android emulator

### Android Studio

1. Install Android Studio and open the repository's `android` directory as the project.
2. In **Tools → SDK Manager**, install Android SDK Platform 36, Android SDK Build-Tools 35, Android SDK Platform-Tools,
   Android Emulator, and an API 35 or 36 Google APIs/Google Play system image for the workstation architecture.
3. In **Tools → Device Manager**, select **Create virtual device**, choose a phone profile such as Medium Phone, select
   the installed system image, and finish the wizard.
4. Start the device with its play button. Wait for the Android home screen on the first boot.
5. Select the `app` run configuration and the running virtual device, then click **Run**.

Android Studio performs the Gradle build, installs the debug application, and opens it. The Android project is the
top-level `android` directory; it is intentionally not inside the Python `src` package.

### Command line

The following commands are for a POSIX shell on Linux or macOS. First open the `android` project in Android Studio at
least once. Android Studio writes the selected SDK location to the ignored `android/local.properties` file. From the
repository root, load and validate that exact location:

```bash
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH"
test -n "$ANDROID_HOME" && test -d "$ANDROID_HOME" || {
    echo "Open the android project in Android Studio and configure its SDK first." >&2
    exit 1
}
```

Do not copy an example SDK pathname into `local.properties`. If `ANDROID_HOME` was previously exported with an invalid
value, the commands above replace it with the project configuration.

Install the build, emulator, and system-image components with the standard Android SDK command-line tools. The example
below uses the x86_64 image commonly used on Intel and AMD workstations; use the corresponding `arm64-v8a` image on an
ARM workstation. Then create and verify the phone AVD:

```bash
sdkmanager \
    "platforms;android-36" \
    "build-tools;35.0.0" \
    "platform-tools" \
    "emulator" \
    "system-images;android-36;google_apis;x86_64"
avdmanager create avd \
    --name medium_phone \
    --package "system-images;android-36;google_apis;x86_64" \
    --device pixel_5
emulator -list-avds
```

Start the resulting `medium_phone` AVD in one terminal:

```bash
emulator -avd medium_phone -no-snapshot-load
```

On Linux, enabling KVM is strongly recommended for acceptable emulator performance.

Leave that terminal open while using the emulator. In a second terminal, return to the repository root, reload the SDK
environment, wait for Android to finish booting, build and install the APK, and explicitly open its main Activity:

```bash
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
gradle -p android lintDebug testDebugUnitTest installDebug
adb shell am start -W -n com.callicode.imaptools/.MainActivity
```

The command succeeds when `am start` reports `Status: ok` and `Activity: com.callicode.imaptools/.MainActivity`.

#### Linux Wayland fallback

Some Android Emulator distributions do not include a Qt Wayland platform plugin. If the graphical start command
reports that `wayland` is unavailable and its `xcb` fallback cannot connect to the X display, run the emulator without
its Qt window and display it with `scrcpy` instead. This also applies when `am start` reports success but no simulator
window is visible: `am start` opens the application inside Android; it does not create a host-side viewer for an
emulator which was started with `-no-window`.

Install `scrcpy` through the operating system's package manager, then run these commands from the repository root. The
example explicitly targets `emulator-5554`, so it remains safe when a physical Android device is connected at the same
time. If `adb devices -l` reports a different emulator serial, use that value instead:

```bash
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
export ANDROID_SERIAL="emulator-5554"

if systemctl --user is-active --quiet android-emulator-medium-phone.service; then
    echo "The medium_phone emulator service is already running."
else
    systemctl --user reset-failed android-emulator-medium-phone.service 2>/dev/null || true
    systemd-run --user --unit=android-emulator-medium-phone --collect \
        --setenv=ANDROID_HOME="$ANDROID_HOME" \
        --setenv=ANDROID_SDK_ROOT="$ANDROID_HOME" \
        "$ANDROID_HOME/emulator/emulator" -avd medium_phone \
        -no-window -no-audio -no-snapshot-load -gpu software
fi

adb -s "$ANDROID_SERIAL" wait-for-device
until [ "$(adb -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do
    sleep 2
done
ANDROID_SERIAL="$ANDROID_SERIAL" gradle -p android lintDebug testDebugUnitTest installDebug
adb -s "$ANDROID_SERIAL" shell am start -W -n com.callicode.imaptools/.MainActivity
SDL_VIDEODRIVER=wayland scrcpy --serial "$ANDROID_SERIAL" --no-audio \
    --window-title "IMAP Migration Tools — Android Emulator"
```

`systemd-run` makes the headless emulator independent of the terminal which launched it. Keep the `scrcpy` terminal
open while interacting with Android. The `--no-audio` option avoids initializing an unnecessary audio-forwarding
channel; it does not mute Android operations because this application has no audio interface. Closing the `scrcpy`
window only closes the viewer; it does not stop the emulator or application. If the service is already active, do not
start a second copy of the same AVD—run only the final `scrcpy` command to reopen its viewer.

Inspect the detached emulator log with:

```bash
journalctl --user -u android-emulator-medium-phone -f
```

On Android 13 and newer, choose **Allow** when the application requests notification permission. Long operations use a
foreground-service notification to show progress and provide a Cancel action.

Confirm that the Configure screen offers Count, Compare, Backup, Restore, and Migrate, then use Output to follow a run
and History to inspect completed runs. Selecting a history item replaces the Output view with that saved run's events
and formatted result. Merely navigating between screens preserves the displayed output; it changes only when a history
item is selected or a new operation starts. Tap an Output section header to collapse or expand the operation monitor,
live or saved output, and result summary independently. The emulator has normal outbound network access. When connecting
to a test IMAP server bound to the development machine's loopback interface, enter `10.0.2.2` instead of `127.0.0.1` as
its hostname; inside the emulator, `127.0.0.1` refers to Android itself.

Useful diagnostics and cleanup commands are:

```bash
adb devices -l
adb logcat --pid="$(adb shell pidof com.callicode.imaptools)"
adb uninstall com.callicode.imaptools
adb emu kill
```

If the emulator was started with the Wayland fallback, `adb emu kill` also causes the temporary user service to become
inactive. If necessary, stop it directly with `systemctl --user stop android-emulator-medium-phone`.

## Run on a physical Android device

The prototype supports Android 7.0 (API 24) or newer on 64-bit ARM and x86_64 devices. Google authentication also
requires Google Play services. Use a test device or test Android user profile when possible: uninstalling the prototype
removes its private projects and backup workspaces.

### Prepare the device

1. Open **Settings → About phone** and tap **Build number** seven times. Device manufacturers may use slightly
   different names or locations.
2. Open **Developer options** and enable **USB debugging**.
3. Connect a data-capable USB cable, unlock the device, and select a USB mode which permits a data connection if the
   manufacturer requires it.
4. Accept the device's **Allow USB debugging?** prompt after verifying the workstation's RSA fingerprint. Select
   **Always allow** only on a trusted development workstation.

Windows may require the device manufacturer's ADB USB driver. macOS normally requires no additional setup. Linux must
have suitable `udev` rules and permission for the logged-in user; distribution packages commonly provide Android
platform-tools rules. Android Studio's **Tools → Troubleshoot Device Connections** can diagnose USB discovery issues.

Load the configured SDK and confirm that ADB reports the authorization state as `device`, not `unauthorized` or
`offline`:

```bash
export ANDROID_HOME="$(sed -n 's/^sdk.dir=//p' android/local.properties)"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$ANDROID_HOME/platform-tools:$PATH"
adb start-server
adb devices -l
```

If more than one emulator or device is connected, copy the desired serial from `adb devices -l` and use it explicitly:

```bash
export ANDROID_SERIAL="DEVICE_SERIAL_FROM_ADB"
adb -s "$ANDROID_SERIAL" get-state
```

### Optional wireless debugging

Android 11 and newer can use ADB over Wi-Fi. Keep the device and workstation on the same trusted network, enable
**Wireless debugging** in Developer options, then choose **Pair device with pairing code**. The pairing port and the
debugging port shown by Android may be different:

```bash
adb pair DEVICE_IP:PAIRING_PORT
adb connect DEVICE_IP:DEBUGGING_PORT
adb devices -l
export ANDROID_SERIAL="DEVICE_IP:DEBUGGING_PORT"
```

Enter the six-digit code from the device when `adb pair` requests it. Android Studio also supports pairing through
**Device Manager → Pair Devices Using Wi-Fi**.

### Build, install, and launch

OAuth registration follows the APK signing certificate, not the physical device. A debug build made with a different
debug keystore has a different Google SHA-1 and Microsoft signature hash. Before testing provider login, ensure the
certificate used for this build is registered and that `android/local.properties` contains the corresponding Microsoft
redirect configuration described in [Configure OAuth](#configure-oauth).

From the repository root, run the normal verification build, install the APK onto the selected device, and launch it:

```bash
gradle -p android lintDebug testDebugUnitTest assembleDebug
adb -s "$ANDROID_SERIAL" install -r android/app/build/outputs/apk/debug/app-debug.apk
adb -s "$ANDROID_SERIAL" shell am start -W -n com.callicode.imaptools/.MainActivity
```

`install -r` preserves the prototype's existing private data. On Android 13 and newer, allow notifications so foreground
operations can display progress and cancellation controls. Android Studio users can instead open the `android`
directory, select the connected device in the run target menu, and run the `app` configuration.

Unlike the emulator, a physical device cannot use `10.0.2.2` to reach the workstation. Use a hostname or LAN address
routable from the device, ensure the workstation firewall permits the test connection, and retain valid TLS certificate
verification. Public IMAP provider hostnames require no special routing.

### Physical-device test checklist

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

The optional instrumentation suite can also run on the selected device:

```bash
ANDROID_SERIAL="$ANDROID_SERIAL" gradle -p android connectedDebugAndroidTest
```

Use a test device/profile for instrumentation. Although the suite confines its project lifecycle checks to a temporary
project, automated UI tests install a test package and control the application.

### Logs, updates, and cleanup

Capture only the application's logs while reproducing a problem:

```bash
adb -s "$ANDROID_SERIAL" logcat --clear
adb -s "$ANDROID_SERIAL" logcat --pid="$(adb -s "$ANDROID_SERIAL" shell pidof com.callicode.imaptools)"
```

Rebuild and repeat `adb install -r` for later prototype revisions. Export any backup workspace which must be retained
before uninstalling, because this command permanently removes the app's private projects, workspaces, history, and
locally associated credentials:

```bash
adb -s "$ANDROID_SERIAL" uninstall com.callicode.imaptools
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
deleted only when at least one other project exists. Deleting a project removes its `.env` configuration but does not
remove backup workspaces or provider accounts from the device.

Project `.env` files use the shared variable names where the concepts match, including `SRC_IMAP_HOST`,
`DEST_IMAP_HOST`, `MAX_WORKERS`, and `PRESERVE_FLAGS`. Android-only UI state uses `ANDROID_`-prefixed keys. These files
are an internal persistence format for now; document-provider import and export can be added independently.

## Storage and credentials

Android scoped storage does not expose arbitrary document-provider directories as POSIX paths, while the shared Python
engine operates on directory paths. The application therefore uses managed backup workspaces inside its private app
storage. Workspace names are normalized before they become path components. The native Android document picker imports
and exports compatible workspaces as ZIP archives; imports reject path traversal, oversized archives, and accidental
replacement of an existing workspace. Removing the app removes private workspaces, so export a verified backup before
uninstalling the application.

Passwords and OAuth access tokens remain in memory and are not written to project `.env` files, preferences, or history.
They remain associated with their project while the application process is running. Hostnames, usernames, provider
account identifiers, modes, and operation options persist in the active project's private `.env`. The application asks
the native provider SDK for a current access token immediately before each run and supplies it through the existing
service boundary using `OAuth2Config.access_token`. The desktop-only browser and encrypted cache implementations are not
used on Android.

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
[Run on a physical Android device](#run-on-a-physical-android-device).

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

Build and install the app using the emulator steps above. Then:

1. Choose an operation which uses an IMAP account.
2. Select **Google** or **Microsoft** for that account and tap **Connect**.
3. Select an account and approve the IMAP permission. The account panel should show **Connected as** followed by the
   provider email address.
4. Tap **Run**. The application silently obtains a current token when possible; if provider interaction is required, it
   opens the provider screen and resumes the operation afterward.
5. Tap **Disconnect** to remove the account association from the current project. If no other project or endpoint uses
   that provider account, the app also revokes Google authorization or removes the account from its MSAL cache. This
   does not sign the account out of Android or the provider's other applications.

## Background execution

Runs execute in a user-started `dataSync` foreground service with a persistent progress notification and Cancel action.
Android may still impose platform execution limits. In particular, Android 15 limits `dataSync` foreground-service time
while an application remains in the background. Keep the application visible for unusually long migrations and use the
migration progress cache to resume interrupted work.

Cancellation is cooperative. The mobile event adapter checks cancellation between structured progress updates and asks
the existing worker pools to unwind. Network calls already in progress may take until their configured timeout to return.

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

## Current distribution boundary

The Android project is an unsigned source/CI build. Play signing, release credentials, privacy disclosures, store
listing material, and physical-device verification are release work and are not stored in this repository. Follow the
[Google Play publication checklist](android-publishing.md) to prepare, approve, test, and publish a production build.
