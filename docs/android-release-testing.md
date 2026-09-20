# Android release resilience and compatibility testing

This document records release-readiness evidence for the native Android application and provides a repeatable test
procedure. Use only synthetic mailboxes and dedicated provider test accounts. Never exercise destructive cases against
a production mailbox.

## Evidence recorded September 19, 2026

The test artifact was the R8-minified `release` APK produced by `assembleRelease`, aligned, and signed locally with a
test-only certificate. It is not a Play upload artifact and must not be distributed. Its SHA-256 was:

```text
def6beedaff04a2fc0b7a47b860733d212e8b184c1a8cfdda30818bcd9774272
```

| Target | ABI | Minified release launch | Connected tests | Result |
| --- | --- | --- | --- | --- |
| Android 7.0 / API 24 emulator | x86-64 | Cold launch | 9 applicable tests | Passed |
| Android 11 / API 30 emulator | x86-64 | Cold launch | 9 applicable tests | Passed |
| Android 16 / API 36 emulator | x86-64 | Cold launch, background, offline, and post-reboot launch | 11 tests | Passed |
| Android 15 / API 35, 16 KB page emulator | x86-64 | Debug runtime/native-library validation | 8 tests at time of audit | Passed |
| Samsung SM-G955W, Android 9 / API 28 | ARM64 | Cold launch, background, offline, and post-reboot launch | 10 applicable tests | Passed |

The API 24 and API 30 runs exclude the two Android 14+ UIDT assertions by design. API 36 runs them. The release APK is
installed for the cold-launch/lifecycle checks; `connectedDebugAndroidTest` installs the instrumented debug application
for behavioral assertions because Android instrumentation cannot attach the debug-signed test package to the separately
signed release application.

The following evidence also passed:

- 144 focused Python tests for the embedded mobile bridge, Google and Microsoft token acquisition/refresh and failure
  paths, IMAP reconnect/token refresh, cancellation, network failures, and migration progress-cache resume.
- A synthetic 2,000-message local mailbox on Android cancels cooperatively, leaves the source intact, and succeeds when
  the same operation is started again.
- A deterministic zero-available-storage test stops Backup before Python work starts. Android 14+ Backup jobs also set
  the platform storage-not-low constraint and retain the app's 256 MB runtime reserve.
- UIDT job construction requires internet, requires an unmetered network until the user approves metered transfer, and
  supplies known Backup/Restore byte estimates. The UI confirmation policy covers Backup, Restore, and Migrate.
- A simulated Android system stop is retained as a concise failed result and is not silently retried with in-memory
  credentials. The user can reopen the app and start again; cache-aware migration and restore skip completed work.
- On API 36, the release process survived being backgrounded, opened while both Wi-Fi and mobile data were disabled,
  and cold-launched after a full emulator reboot. No fatal application exception appeared in logcat.

These tests verify deterministic behavior without storing real credentials in the test package. They do not replace
live provider testing. Before publication, complete the remaining provider-backed row below:

- Revoke Google and Microsoft access from each provider's test-account security page while the app is installed. Start
  an operation, confirm the app asks the user to reconnect without exposing provider details, reconnect, and repeat it.

The physical-device matrix was completed with the same minified artifact used on the emulators. The Samsung retained
the release process while backgrounded, launched while Wi-Fi and mobile data were disabled, launched after a full
device reboot, loaded Chaquopy's ARM64 native libraries, and passed all ten applicable instrumented tests. The tenth
test dispatches real work through the API 24–33 foreground service while no activity is visible. Wi-Fi and mobile data
were restored to their original enabled state after the offline test.

## Reproduce the automated checks

Run the host and Android build tests from the repository root:

```bash
PYTHONPATH=src .venv/bin/python -m pytest -q \
  test/mobile/test_bridge.py \
  test/auth/test_oauth2_google.py \
  test/auth/test_oauth2_microsoft.py \
  test/core/test_imap_session.py \
  test/imap_services/test_service_contracts.py \
  test/test_migrate_resume.py \
  test/test_migrate_with_cache.py

gradle -p android \
  lintDebug testDebugUnitTest assembleDebug assembleDebugAndroidTest \
  lintRelease testReleaseUnitTest assembleRelease bundleRelease
```

Run the connected suite against an explicitly selected device so another emulator or phone cannot receive the test
package accidentally:

```bash
export ANDROID_SERIAL="serial-from-adb-devices"
adb -s "$ANDROID_SERIAL" shell getprop ro.build.version.sdk
adb -s "$ANDROID_SERIAL" shell getprop ro.product.cpu.abi
ANDROID_SERIAL="$ANDROID_SERIAL" gradle -p android connectedDebugAndroidTest
```

Use `tools/run_android.sh --target device --connected-tests` on Linux/macOS or
`tools\run_android.ps1 -Target device -ConnectedTests` on Windows for the guided physical-device path. The launcher
builds, tests, installs, and starts the application using one selected serial.

## Physical resilience checklist

Use a large synthetic mailbox whose deletion is harmless and record the device model, Android version, ABI, app
version, signing-certificate fingerprint, and APK checksum.

1. Start each operation, use its Cancel action during active I/O, and confirm the app becomes ready for a new run.
2. Start a cache-enabled migration, stop the app process from Android's task manager, reopen it, and start the migration
   again. Confirm already completed messages are skipped and no duplicates are created.
3. Repeat step 2 across a full device restart. The app intentionally waits for the user to restart interrupted work.
4. Fill only the test device until Android reports low storage. Confirm Backup remains queued or stops before consuming
   the 256 MB reserve, then free the test data and retry.
5. Revoke provider authorization outside the app and expire the test session. Confirm silent renewal works when valid;
   otherwise the app gives a short reconnect action and never logs tokens or account identifiers.
6. During each large-transfer operation, disable Wi-Fi and mobile data, restore connectivity, and confirm a clear stop
   or continuation with consistent history. Repeat on metered data and verify explicit approval is required for Backup,
   Restore, and Migrate.
7. Background the app for at least 15 minutes. On API 34+, inspect UIDT job `41001`; on API 24–33, confirm the foreground
   notification remains visible. Exercise the notification Cancel action and Android's task-manager Stop action.
8. Reopen the app after every interruption and verify Configure, Output, and History remain coherent. Retry the operation
   and compare source/destination counts before deleting the synthetic data.

On API 34+, Android documents these UIDT test commands:

```bash
adb -s "$ANDROID_SERIAL" shell dumpsys jobscheduler com.callicode.imaptools
adb -s "$ANDROID_SERIAL" shell cmd jobscheduler timeout com.callicode.imaptools 41001
```

The timeout command exercises the system-stop callback. Android's task-manager **Stop** action instead kills the whole
process immediately, so both paths must be tested.

## Minified-release device matrix

The release build is unsigned unless a release signing configuration is deliberately supplied. Create a temporary,
locally signed test APK using a non-production test key, or use an internal Play testing track. Never commit a keystore,
password, signed APK, or generated `local.properties`.

For every supported matrix row:

1. Build `assembleRelease` and record the source revision, APK checksum, app version, and certificate fingerprint.
2. Install the same minified artifact with `adb -s SERIAL install -r PATH_TO_SIGNED_TEST_APK`.
3. Cold-launch with `adb -s SERIAL shell am start -S -W -n com.callicode.imaptools/.MainActivity`.
4. Exercise password, Google, and Microsoft authentication and all five operations with synthetic data.
5. Run the resilience checklist above and inspect app-scoped logcat for crashes or sensitive data.
6. Run the connected suite separately, noting that it installs the instrumented debug build.
7. Repeat on API 24, a representative intermediate API, API 36, x86-64, ARM64, and the Samsung-class hardware target.

Keep the Google Play pre-launch report as additional evidence; it does not replace the physical provider-authentication
and long-transfer cases.
