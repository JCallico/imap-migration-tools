# Android dependency, license, vulnerability, and Play SDK Index review

This document records the September 2026 review of every SDK the native Android application depends on: publisher,
license, version currency, known vulnerabilities, Google Play SDK Index status, and the data behavior needed to
answer Play Console's Data safety form. Re-run this review whenever a dependency version changes, before every Play
submission, and at minimum every 6 months per the
[Data safety and SDK warning](android-publishing.md#6-complete-play-console-setup-and-declarations) checklist items.

## Scope and method

Versions below are the exact resolved versions from `gradle -p android app:dependencies --configuration
releaseRuntimeClasspath`, not just the declared versions in `build.gradle.kts` (Gradle upgrades several transitive
versions automatically). 159 unique artifacts resolve on the release classpath; this document gives full individual
treatment to the four families named in the release checklist (Chaquopy/Python, Google Play Services, MSAL, Compose)
and MSAL's non-trivial transitive graph, and a grouped treatment for the remaining first-party AndroidX/Kotlin/Jetpack
libraries, which carry materially lower review risk (same publisher, same license, no history of CVEs at this scale).

## Chaquopy and the embedded Python runtime

| Component | Version | Publisher | License |
| --- | --- | --- | --- |
| Chaquopy Gradle plugin | 17.0.0 | Chaquo Ltd | MIT (since v12.0.1; earlier versions were a paid/closed license) |
| Bundled CPython | 3.13.9 (declared `version = "3.13"`) | Python Software Foundation | PSF License |

The app declares no Chaquopy `pip { install(...) }` block, so **no third-party PyPI package ships in the APK** — only
CPython's standard library and the project's own `src/` tree. Confirmed by import audit: the mobile bridge
(`src/mobile/bridge.py`) and everything it calls (`imap_services`, `core`, `providers`, `auth/imap_oauth2.py`) import
only stdlib modules (`imaplib`, `ssl`, `email`, `json`, `socket`, `threading`, `dataclasses`, `pathlib`). The desktop-only
OAuth libraries (`msal`, `google-auth-oauthlib`, `msal_extensions`) are imported lazily inside function bodies in
`src/auth/oauth2_google.py`, `oauth2_microsoft.py`, and `oauth2_cache.py`, and those code paths are never reached on
Android because Kotlin supplies a live `OAuth2Config.access_token` directly, so the absence of those packages from the
Android build is safe, not just unused.

- **License**: MIT, no commercial fee, no install/revenue threshold, no restriction for a closed-source Play Store app.
- **Version currency**: 17.0.0 is current (Dec 2025); Python 3.13 support has been stable since Chaquopy 16.0.0 (Oct
  2024) and is explicitly recommended over 3.12 for correct behavior on 16 KB page-size devices.
- **Vulnerabilities**: no published GitHub security advisories against Chaquopy. CPython's imaplib/ssl/email hardening
  fixes from the March 2026 security releases (3.10.20/3.11.15/3.12.13, backported to the 3.13.x line) are included by
  3.13.9; the latest available patch is 3.13.15 (Aug 2026) — track this but no active CVE targets our bundled version.
- **Play SDK Index**: not listed. The Index covers commercial ad/analytics/monetization SDKs at Play-defined usage
  thresholds; a build-time language runtime does not meet that categorization.
- **Data safety**: Chaquopy adds no network calls, telemetry, or licensing pings of its own (that mechanism existed
  only under the pre-12.0.1 paid license and was removed). Only the app's own IMAP/OAuth network activity is
  declarable, and that is unrelated to Chaquopy as a component.

## Google Play Services (Auth family)

Direct dependency `com.google.android.gms:play-services-auth:21.5.1`, used only for `AuthorizationClient` (the
`https://mail.google.com/` IMAP scope grant) and a Gmail `users.getProfile` call to learn the authorized address. No
general Google Sign-In, profile, or contacts scope is requested.

| Artifact | Resolved version |
| --- | --- |
| `play-services-auth` | 21.5.1 |
| `play-services-auth-api-phone` | 18.0.2 |
| `play-services-auth-base` | 18.0.10 |
| `play-services-base` | 18.5.0 |
| `play-services-basement` | 18.9.0 |
| `play-services-fido` | 20.1.0 |
| `play-services-tasks` | 18.2.0 |
| `androidx.credentials:credentials` / `credentials-play-services-auth` | 1.2.2 |
| `com.google.android.libraries.identity.googleid:googleid` | 1.1.0 |

- **License**: proprietary — the [Android SDK License Agreement](https://developer.android.com/studio/terms), not
  Apache/OSS. Key obligations: no modification/reverse-engineering/derivative works (§3.4); adequate privacy notice
  and secure storage for any personal data obtained via Google Account APIs (§4.2–4.3); no interference with Google's
  servers (§4.4); Google may modify, discontinue, or terminate the license at its discretion (§3.6, §9.3). No
  redistribution obligation beyond normal Play Store distribution of the compiled app.
- **Version currency**: within a few minor releases of head as of September 2026 — current, not stale.
- **API deprecation note**: Google has deprecated `GoogleSignIn`/`GoogleSignInClient` (legacy sign-in) in favor of
  Credential Manager, but **`AuthorizationClient`, the API this app actually uses, is explicitly not deprecated** and
  remains Google's recommended path for scope-based authorization even after an app's *authentication* moves to
  Credential Manager. This app requests authorization only, so it is already on the forward-supported API and needs
  no migration.
- **Vulnerabilities**: no CVEs found against current versions. Historical CVE-2022-2390 (PendingIntent mutability) and
  CVE-2022-1799 (debug-signature trust) against `play-services-basement` were fixed years before 18.9.0.
- **Play SDK Index**: has a listing (`play.google.com/sdks/details/com-google-android-gms-play-services-auth`); no
  version-specific warning found in secondary sources. Being a first-party Google SDK, cross-check directly inside
  Play Console's own SDK Index integration at submission time rather than relying solely on this external check.
- **Data safety**: declare **email address** (account/personal identifier — the authorized mailbox address, used for
  app functionality, not shared with third parties) and the **OAuth access token** itself (held only in this app's own
  in-memory/cache boundary, already documented in [privacy.md](privacy.md)). `play-services-fido` is pulled in
  transitively via Credential Manager but never invoked (no passkey/FIDO API calls) — do not declare passkey/biometric
  or FIDO device-identifier data. No advertising ID is exposed by this integration.

## Microsoft Authentication Library (MSAL) for Android

Direct dependency `com.microsoft.identity.client:msal:8.4.1`, used only for the
`https://outlook.office365.com/IMAP.AccessAsUser.All` IMAP scope grant. MSAL pulls in a large transitive graph through
Microsoft's shared `common`/`common4j` identity core:

| Artifact | Resolved version | License | CVE status |
| --- | --- | --- | --- |
| `com.microsoft.identity.client:msal` | 8.4.1 | MIT | Only historical CVE-2019-1487 (fixed long ago, pre-0.3.1-Alpha); **not affected**. Outdated by two releases — 8.5.0 is current (Sep 2024); recommend upgrading to pick up `common`/transitive patches. |
| `com.microsoft.identity:common` / `common4j` | 24.5.0 | MIT | No published CVEs. (CVE-2025-32016 is a *different*, .NET-only `Microsoft.Identity.Web` library — not applicable.) |
| `com.nimbusds:nimbus-jose-jwt` | 10.0.2 | Apache 2.0 | CVE-2025-53864 (JWT claim recursion DoS) affects 10.0.x **before** 10.0.2 — **fixed version, not affected**. |
| `com.google.code.gson:gson` | 2.8.9 | Apache 2.0 | CVE-2022-25647 (deserialization DoS) affects versions **before** 2.8.9 — **exact fixed version, not affected**. |
| `com.squareup.moshi:moshi` / `moshi-adapters` | 1.15.2 | Apache 2.0 | No CVEs found. |
| `com.squareup.okio:okio` | 3.7.0 | Apache 2.0 | CVE-2023-3635 (GzipSource DoS) fixed in 1.17.6/3.4.0 — **not affected**. |
| `org.apache.httpcomponents.core5:httpcore5` | 5.3 | Apache 2.0 | **Affected**: CVE-2026-54399 (header-size resource exhaustion) and CVE-2026-54428 (HPACK unlimited header size), both fixed in 5.5.0+. Low practical risk here (this app is an outbound OAuth/token client, not an HTTP server accepting attacker-controlled connections), but this is MSAL's transitive pin, not ours to bump directly — tracked as an upgrade-MSAL action item. |
| `com.yubico.yubikit:android` / `core` / `piv` | 2.5.0 | Apache 2.0 | Dormant hardware-security-key support; only activates if a YubiKey is attached via USB/NFC and explicitly invoked. This app never does. No behavior or data impact. |
| `io.opentelemetry:opentelemetry-*` | 1.62.0 / extension-kotlin 1.18.0 | Apache 2.0 | Local instrumentation API only; transmits nothing externally unless the host app registers an exporter, which this app does not. |
| `androidx.webkit`, `androidx.browser`, `androidx.datastore`, `androidx.credentials` | current stable | Apache 2.0 | No CVEs found. |
| `org.slf4j:slf4j-api` | 2.0.9 | MIT | No CVEs found. |
| `com.microsoft.device.display:display-mask` | 0.3.0 | MIT-style (Microsoft OSS) | Surface Duo dual-screen support; dormant on non-Duo devices. |
| `com.github.stephenc.jcip:jcip-annotations` | 1.0-1 | Apache 2.0 | No CVEs found. |

**License compatibility**: every license found across the MSAL graph is MIT or Apache 2.0 — fully compatible with this
project's MIT license and with closed-source distribution; no GPL/LGPL/EPL/copyleft component exists anywhere in the
graph.

**Play SDK Index**: no fetchable listing found (the Index's UI is JS-rendered); no evidence of any policy/safety flag
against MSAL in any secondary source checked.

**Data safety — corrected finding**: a 2019-era community report ([GitHub issue
#1050](https://github.com/AzureAD/microsoft-authentication-library-for-android/issues/1050)) found that MSAL's
`TelemetryContext` collected the device's persistent hardware `ANDROID_ID`. **This was fixed in the `common` library
in v3.1.0 (February 2021)**: MSAL now generates and locally caches a random, non-hardware-tied GUID for telemetry
correlation instead of reading `ANDROID_ID`. This app's `common`/`common4j` 24.5.0 is many major versions past that
fix, so **no persistent hardware device identifier is collected**. MSAL still attaches standard OAuth-protocol
diagnostic telemetry (SDK version, correlation ID, the locally-generated random GUID) to its own token requests sent
to Microsoft's identity endpoints (`login.microsoftonline.com`) as part of normal authentication-protocol exchange —
this is comparable to any OAuth client's request headers, sent only to Microsoft's own auth service, not a separate
third-party analytics endpoint. Broker-discovery code (checking for Authenticator/Company Portal) runs even without a
broker installed but this app's plain-IMAP-scope flow does not enroll in broker/Conditional Access, so no broker data
leaves the device. **For Play Data safety disclosure**: declare **account identifiers** (UPN/email, tenant/object ID)
and the **authentication token** (held in this app's own boundary) as collected for app functionality; the
MSAL-generated correlation GUID is diagnostic/protocol telemetry sent only to Microsoft's own identity service, not a
persistent device identifier, and should not be declared under "Device or other IDs."

**Action item**: upgrade `com.microsoft.identity.client:msal` from 8.4.1 to 8.5.0 (or later) to pick up `common`
library and transitive `httpcore5` patches. Not performed as part of this review; re-test the OAuth/reconnect flows on
both providers if this upgrade is made.

## AndroidX Compose, Jetpack, and Kotlin

All first-party Google (AndroidX/Jetpack) or JetBrains (Kotlin) libraries, all **Apache License 2.0**, all actively
maintained with no history of published CVEs at this scale. Representative resolved versions:

| Library | Version |
| --- | --- |
| `androidx.compose:compose-bom` | 2025.12.01 (current stable channel is 2026.03–04.x; app's pin is a few months behind head, not deprecated) |
| `androidx.compose.material3:material3` | 1.4.0 (stable since Sep 2025) |
| `androidx.activity:activity-compose` | 1.11.0 |
| `androidx.lifecycle:*` | 2.9.4 |
| `androidx.core:core-ktx` | 1.17.0 |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.2.21 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-*` | 1.9.0 |

No Play SDK Index listing applies (first-party Jetpack/Kotlin, not a commercial SDK). No data-safety declaration
applies — these are UI/language-runtime libraries with no network or data-collection behavior of their own.

**Build-toolchain note (not a shipped-app dependency)**: CVE-2026-53914 affects the Kotlin Gradle Plugin before
2.4.20 (unsafe deserialization in build-cache metadata, relevant to build-machine/CI security if a shared or remote
Gradle build cache is used). This repository's Kotlin plugin is pinned to 2.2.21. This is a build-time supply-chain
consideration, not a runtime vulnerability shipped in the APK, and is unrelated to the app's Data safety declarations;
tracked here for CI hygiene rather than as a release blocker.

## Consolidated data-safety inputs

For the Play Console Data safety form, this review's SDK-level findings reduce to:

| Data type | Collected by | Purpose | Shared off-device? |
| --- | --- | --- | --- |
| Email address / account identifier | `play-services-auth` (Google), MSAL (Microsoft) | Identify the authorized mailbox for app functionality | No — used only to configure the IMAP connection |
| OAuth access/refresh tokens | `play-services-auth`, MSAL | Authenticate IMAP connections | No — held in this app's own process memory/cache only; see [privacy.md](privacy.md) |
| Diagnostic/correlation telemetry (random GUID, SDK version, correlation ID) | MSAL (`common`) | Standard OAuth-protocol diagnostics | Sent only to Microsoft's own identity endpoint as part of the authentication request itself, not to a third-party analytics service |

No advertising ID, no persistent hardware device identifier (confirmed fixed for MSAL; never requested by
`play-services-auth` in this integration), no passkey/FIDO/biometric data, and no telemetry from Chaquopy, Compose,
AndroidX, or Kotlin. Combine this table with the app's own data flows (already covered in
[privacy.md](privacy.md) and [android.md](android.md#storage-and-credentials)) when completing the Data safety
checklist item.
