# Open-source notices

IMAP Migration Tools is distributed under the repository’s [MIT License](../LICENSE).

## Android application

The Android application bundles the following components. `google-auth-oauthlib`, MSAL for Python, MSAL Extensions,
and `python-dotenv` are desktop/CLI-only dependencies of this repository and are **not** bundled into the Android
APK: Chaquopy has no `pip install` configuration, so only CPython's standard library and this repository's own
`src/` code ship on Android. See [Android dependency, license, vulnerability, and Play SDK Index
review](android-dependency-review.md) for the complete transitive inventory, versions, and vulnerability findings.

| Component | License |
| --- | --- |
| AndroidX and Jetpack Compose | Apache License 2.0 |
| Kotlin and kotlinx-coroutines | Apache License 2.0 |
| Chaquopy | MIT License |
| CPython (bundled runtime, no third-party packages) | Python Software Foundation License |
| Google Play services (`play-services-auth` and transitives) | Proprietary — [Android SDK License Agreement](https://developer.android.com/studio/terms), not open source |
| Microsoft Authentication Library (MSAL) for Android, and Microsoft `common`/`common4j` | MIT License |
| Nimbus JOSE+JWT, Gson, Moshi, okio, Apache HttpComponents Core5, OpenTelemetry, `jcip-annotations` (MSAL transitives) | Apache License 2.0 |
| YubiKit for Android (MSAL transitive; dormant unless a YubiKey is attached) | Apache License 2.0 |
| SLF4J API, Microsoft `display-mask` (MSAL transitives) | MIT License |

## Desktop, CLI, and TUI applications

| Component | License |
| --- | --- |
| `google-auth-oauthlib` | Apache License 2.0 |
| MSAL for Python and MSAL Extensions | MIT License |
| `python-dotenv` | BSD 3-Clause License |

Produce and review the release artifact’s complete dependency and license inventory before every public release,
preserve all notices required by those licenses, and update this document when dependencies change.
