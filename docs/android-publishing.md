# Google Play publication checklist

Use this checklist to take the native Android application from the current development build to a production release
on Google Play. It is intentionally broader than the build instructions in [android.md](android.md): publication also
requires identity-provider approval, privacy and policy work, store assets, controlled testing, and operational
ownership after launch.

Google changes Play requirements regularly. This checklist was reviewed on **September 17, 2026**. Recheck every
linked Google requirement in the month the release is submitted and resolve every item under **Play Console → Policy
and programs → App content → Needs attention**.

## Current repository baseline

| Item | Current value or state | Publication action |
| --- | --- | --- |
| Application ID | `com.callicode.imaptools` | Confirm ownership before creating the Play app; this identifier is permanent |
| Minimum Android | API 24 | Confirm that excluding older devices is intentional |
| Compile/target Android | API 36 | Meets the Google Play phone-app target for submissions from August 31, 2026 |
| Version | `versionCode = 1`, `versionName = 1.0.0-alpha01` | Choose the first public version; every upload needs a higher version code |
| Architectures | `arm64-v8a`, `x86_64` | Confirm that excluding 32-bit devices is intentional; test both retained ABIs |
| Release optimization | R8/minification enabled | Test the release build, not only debug builds |
| Release signing | Not configured in the repository | Create and protect an upload key; use Play App Signing |
| Launcher artwork | Production adaptive, round, legacy, monochrome, and 512 px Play icons | Recheck the signed release on representative launchers before submission |
| Privacy policy | About screen links to the repository policy | Publish the final reviewed policy on the verified publisher domain |
| Google OAuth | Test configuration using restricted Gmail scope | Complete production OAuth verification and register the Play signing SHA-1 |
| Microsoft OAuth | Development Entra registration | Register the Play signing identity and remove the unverified-publisher warning |
| Background transfer | UIDT job on API 34+; `dataSync` compatibility service on API 24–33 | Test system/user stops and complete the compatibility foreground-service declaration |
| Distribution artifact | Debug APK/CI build | Produce and validate a signed Android App Bundle (`.aab`) |

Items in the last column are work still required unless Play Console or the repository shows otherwise. Do not infer
approval from a successful sideloaded build.

## 1. Make the product and ownership decisions

- [X] Decide whether the publisher is an individual or an organization. Prefer an organization account when the app is
  published by a business; organization enrollment requires verified organization details and normally a D-U-N-S
  number.
  Organization name:
- [X] Confirm the public developer name, legal owner, support email, support website, phone number, and postal details.
  Developer name:
  Legal owner:
  Support email:
  Support website: https://github.com/JCallico/imap-migration-tools
- [ ] Confirm ownership of `com.callicode.imaptools`. Do not create a disposable Play application with this ID: package
  names cannot be reused as a different app after publication.
- [ ] Decide the default listing language, initial countries/regions, free or paid status, and whether the app will have
  ads or purchases. The current app contains neither an advertising SDK nor Play Billing.
- [ ] Define the supported audience. This is an administrative mailbox tool and should not be presented as designed for
  children unless the product and its data handling are deliberately changed to meet Families requirements.
- [ ] Decide which account types are supported at launch: password-based IMAP, Google, Microsoft personal accounts, and
  Microsoft work/school accounts. Store text and reviewer instructions must match the actual choice.
- [ ] Decide whether 32-bit Android hardware is intentionally unsupported. The current bundle contains only ARM64 and
  x86-64 native code.
- [ ] Assign owners for the Play Console, Google Cloud project, Microsoft Entra registration, public website, privacy
  requests, support inbox, release signing material, and incident response. Add at least two trusted administrators
  where the service permits it.

Create the Play Console developer account and complete identity, email, phone, payment-profile, and—when shown—physical
Android-device verification. New personal accounts created after November 13, 2023 must complete a closed test with at
least 12 opted-in testers continuously for 14 days before requesting production access; the Console determines whether
this rule applies to the account. See Google's [developer-account information requirements][developer-account] and
[personal-account testing requirements][personal-testing].

## 2. Close the application release-readiness gaps

- [x] Replace the prototype launcher artwork with production adaptive icons (`mipmap-anydpi-v26` foreground/background),
  legacy icons for supported older Android versions, and an Android 13 monochrome icon. Check light/dark launchers and
  round/square vendor masks.
- [x] Add an About/Privacy surface reachable without authentication. It should show the app version, support contact,
  privacy-policy link, open-source notices, and a plain-language explanation of local backup storage and deletion.
- [x] Confirm that **Disconnect** revokes or removes provider authorization as described, and that deleting a project,
  history entry, or local backup has clear and accurate semantics. Provider sign-in is not an account created by this
  app; document that distinction when answering Play's account-deletion questions.
- [x] Review all persisted data: project `.env` files, provider SDK caches, operation history, logs, imported/exported
  archives, and local mailbox backups. Verify app-private file permissions and that passwords, access/refresh tokens,
  message content, and account identifiers never enter logs, crash reports, screenshots, or history unexpectedly.

  Verification basis: the Google last-reference path calls the documented
  [`AuthorizationClient.revokeAccess`][google-revoke]; Microsoft calls MSAL `removeAccount`, whose broker behavior is
  explicitly limited to removing tokens associated with this client ([MSAL account removal][msal-remove]). Google
  Play defines an app account as a developer-provided user identity and requires every developer to answer the Data
  deletion questions even when app-account creation is absent ([Play account deletion guidance][account-deletion]).
  The persisted-data inventory and deletion matrix are maintained in [Android development and operation](android.md)
  and the [privacy policy](privacy.md).
- [x] Define uninstall, project deletion, disconnect, archive export/import, and backup deletion behavior in the privacy
  policy and user documentation. State any data the user must delete outside the app or at the mail provider.
- [ ] Review the six manifest permissions. Remove any unused permission. Keep notification permission contextual and
  explain that progress notifications are required for user-started transfers.
- [x] Reassess long transfers on Android 14 and newer. Android recommends user-initiated data-transfer jobs for long,
  user-triggered transfers; Android 15 limits `dataSync` foreground-service background time. Either migrate to the
  appropriate API or document, test, and declare the justified foreground-service behavior. See Android's
  [data-transfer decision guide][data-transfer].

  All five operations now use an immediate `JobScheduler` UIDT job on API 34+, including required-network constraints,
  an ongoing progress/Cancel notification, cooperative system-stop handling, and the available Backup payload estimate.
  API 24–33 retains the shared `dataSync` foreground-service compatibility path. Requests and credentials stay in
  process memory, so a process-killed job is intentionally restarted by the user rather than persisted or retried
  silently. The generic API 34+ device test procedure is in [Android development and operation](android.md).
- [ ] Test cancellation, process death, device restart, low storage, revoked authorization, token expiry, network loss,
  metered-network confirmation, background limits, and safe resume behavior with large mailboxes.

  Automated and emulator evidence is recorded in [Android release resilience and compatibility
  testing](android-release-testing.md). Cancellation/retry uses a synthetic 2,000-message mailbox; storage, metered
  network, UIDT constraints, system stops, token refresh/failure paths, offline launch, backgrounding, and reboot launch
  are covered. Keep this item open until revoked-provider and active-transfer interruption cases pass on the physical
  test device.
- [x] Test the minified release build on API 24, representative intermediate Android releases, API 36, a physical
  Samsung-class device, an ARM64 device, and an x86-64 emulator.

  The R8-minified release cold-launched on x86-64 API 24, API 30, and API 36 emulators, and all applicable connected
  tests passed. The same artifact also passed cold launch, background/offline launch, post-reboot launch, and all ten
  applicable tests on an ARM64 Samsung SM-G955W running API 28. See
  [Android release resilience and compatibility testing](android-release-testing.md).
- [x] Because Chaquopy packages native libraries, validate every `.so` for 16 KB page-size support and run on a 16 KB
  Android emulator. Google Play requires 16 KB support for 64-bit apps targeting Android 15+ beginning February 1,
  2027. Follow the official [16 KB compatibility checks][page-size].

  Verification on September 19, 2026: the repository validator checked all 42 ARM64/x86-64 libraries in the debug APK;
  every ELF `LOAD` segment is `0x4000` aligned and Build-Tools `zipalign -c -P 16 -v 4` passes. The app and all eight
  instrumentation tests passed on the API 35 x86-64 `google_apis_ps16k` image reporting `PAGE_SIZE=16384`. The debug
  AAB contains the same 42 aligned libraries and Bundletool reports `PAGE_ALIGNMENT_16K`. CI repeats both artifact
  audits. Repeat this evidence for the signed release AAB/APKs before publication and after every native dependency or
  build-tool update.
- [ ] Run dependency, license, vulnerability, and Play SDK Index reviews for Chaquopy/Python, Google Play Services,
  MSAL, Compose, and transitive dependencies. Record versions and data behavior used to answer Data safety.
- [ ] Confirm R8 rules preserve Chaquopy and authentication behavior. Exercise all five operations in a release build.
- [ ] Run Android lint, unit/instrumentation tests, the Python suite, and the Play pre-launch report. Resolve crashes,
  ANRs, accessibility findings, security findings, and severe compatibility warnings.

## 3. Establish production signing and reproducible releases

- [ ] Create a dedicated upload keystore and strong upload-key credentials. Do not use the Android debug key.
- [ ] Store the keystore and credentials in an organizational secrets manager with restricted access, encrypted backup,
  recovery instructions, and an ownership record. Never commit them or place them in `local.properties` in CI.
- [ ] Configure a release-only signing path that reads credentials from protected environment/CI secrets. Keep local
  developer builds functional without production secrets.
- [ ] Enroll the new application in Play App Signing. Google holds the app signing key; the locally protected upload key
  signs each `.aab`. If the same signing identity must be used in another store, make that key-ownership decision before
  enrollment. See Android's [app-signing guide][app-signing].
- [ ] In **Play Console → Setup → App integrity**, archive the SHA-1 and SHA-256 for both the **App signing key
  certificate** and **Upload key certificate**. They serve different purposes.
- [ ] Register the **app signing** certificate—not merely the upload certificate—with Google and Microsoft OAuth. Play
  users receive APKs signed by the app signing key.
- [ ] Add deterministic CI/release instructions for injecting the non-secret Microsoft client ID, redirect URI, and
  signature hash. Confirm the generated manifest and MSAL configuration before signing.
- [ ] Protect the release workflow with review/approval, immutable build logs, dependency locking, and retained
  provenance. Record the source commit, tool versions, version code/name, bundle checksum, and approver for every release.

Android Studio can create the upload key and signed bundle through **Build → Generate Signed Bundle/APK → Android App
Bundle**. A CI release should equivalently produce:

```bash
gradle -p android clean lintRelease testReleaseUnitTest bundleRelease
sha256sum android/app/build/outputs/bundle/release/app-release.aab
```

The precise task names may change when release test variants are configured. The expected upload is a signed `.aab`,
not the debug APK. Verify its certificate, bundle contents, native ABIs, download size, and absence of development
configuration before uploading. New Play applications use Android App Bundles and Play App Signing; see Google's
[bundle upload guide][upload-bundle].

## 4. Complete production identity-provider approval

### Google/Gmail

The app requests `https://mail.google.com/`, a restricted scope required for IMAP. A public app cannot remain in OAuth
Testing with a list of test users.

- [ ] Use a production Google Cloud project, or explicitly promote a project whose ownership, contacts, audit history,
  and configuration are suitable for production. Google recommends separate testing and production projects.
- [ ] Enable Gmail API; configure accurate Branding, Audience, Data Access, and project contacts; and declare only
  `https://mail.google.com/` unless another scope is proven necessary.
- [ ] Publish an app home page and privacy policy on a domain controlled by the publisher. Verify that domain in Search
  Console. The home page must describe the product and link to the privacy policy.
- [ ] Register an Android OAuth client for `com.callicode.imaptools` with the Play **app signing certificate SHA-1**.
  Keep a separate client for locally signed test builds.
- [ ] Submit brand and restricted-scope verification. Supply a clear written justification and a private demonstration
  video showing the complete consent flow and exactly how Gmail data powers Count, Compare, Backup, Restore, and Migrate.
- [ ] Obtain Google's explicit determination that the product is an approved Gmail use case. Google's Workspace policy
  lists automatic email backup as approved but lists one-time/manual email export as disallowed; do not assume that the
  current user-initiated backup/migration workflow will be approved without review.
- [ ] Explain that mail is transferred directly between the device, local app storage, and user-selected IMAP servers;
  identify any developer-controlled server if one is ever introduced. Google requires an annual independent security
  assessment when restricted data is accessed from or through a third-party server. Let Google's verification team
  determine whether an assessment applies to the final architecture.
- [ ] Keep the consent-screen text, Play listing, in-app disclosure, privacy policy, and actual data handling identical.
  Comply with Google's Limited Use requirements.
- [ ] Allow several weeks for verification and remediation. Do not launch Google authentication publicly until the
  production OAuth consent configuration is approved.

Review the official [restricted-scope verification process][restricted-scope] and
[Workspace user-data policy][workspace-policy].

### Microsoft/Exchange Online

- [ ] Confirm the Entra application's supported account types match the advertised personal and/or organizational
  account support.
- [ ] Keep only the delegated permission actually used: Exchange Online `IMAP.AccessAsUser.All`, plus any identity scope
  the final MSAL flow demonstrably requires. Remove the obsolete EAS/EWS permissions if they are still present.
- [ ] Add an Android platform entry for package `com.callicode.imaptools` using the Play app-signing certificate's
  Base64 SHA-1 signature hash; place the generated redirect URI in the production build configuration.
- [ ] Configure a verified publisher domain, support URLs, logo, terms, and privacy statement in Branding & properties.
- [ ] Complete Microsoft Publisher Verification when eligible so public consent does not show **Unverified**. This is
  particularly important for multitenant apps and enterprise consent policies. See Microsoft's
  [publisher-verification guide][microsoft-publisher].
- [ ] Test consent with a Microsoft personal account and with work/school tenants whose user-consent policy is both
  permissive and restrictive. Document when an administrator must consent.
- [ ] Test silent token renewal, revoked consent, Conditional Access, Disconnect, and account switching from the Play
  signed build.

## 5. Publish the legal and privacy material

- [ ] Publish a stable HTTPS privacy-policy URL with no login, geoblock, PDF-only presentation, or broken redirects.
- [ ] Link the same privacy policy from the Play listing, Google OAuth consent screen, Microsoft registration, public
  app home page, and an in-app screen reachable before sign-in.
- [ ] Name the application and publisher; provide a privacy contact and effective/revision dates.
- [ ] Describe each data type handled: email address/account identifier, authentication tokens, server settings,
  operation history, diagnostics, message metadata/content, attachments, and locally created backup archives.
- [ ] For each type, state purpose, source, where processing occurs, storage duration, protection, sharing, export, and
  deletion behavior. Explicitly address Google user data and Limited Use.
- [ ] Explain that passwords and short-lived tokens are not stored in projects/history; accurately describe any
  provider-managed token cache that does persist.
- [ ] Explain that mailbox data may be read, created, updated, or deleted when the user selects the corresponding
  operation, including destructive options and confirmations.
- [ ] Document third-party processors/SDKs and links to their relevant privacy material. Recheck their behavior whenever
  a dependency changes.
- [ ] Publish terms of service/support documentation appropriate for destructive mailbox migration and backup risk.
- [ ] Establish a documented process and response owner for access, deletion, support, security, and legal requests.
- [ ] Obtain qualified legal/privacy review for every launch jurisdiction. This checklist is engineering guidance, not
  legal advice.

## 6. Complete Play Console setup and declarations

Create the app in Play Console only after confirming the package ID. Select **App**, the default language, free/paid
status, and required declarations. Then complete every App content card:

- [ ] **Privacy policy:** enter the public URL and verify the in-app link.
- [ ] **Ads:** currently expected to be **No**; reassess the final dependency graph and behavior.
- [ ] **App access / sign-in details:** provide English instructions and reusable reviewer access for every protected
  path. Google requires credentials to remain valid regardless of location and disallows dependencies on expiring OTPs.
- [ ] Create dedicated, non-personal Google, Microsoft personal, Microsoft work/school, source IMAP, and destination
  IMAP review accounts as needed. Seed only synthetic, non-sensitive mail. Provide administrator consent in advance or a
  reliable bypass where policy permits it.
- [ ] **Target audience and content:** select the accurate age ranges and answer app-detail questions consistently.
- [ ] **Content rating:** complete the IARC questionnaire accurately; save the issued rating.
- [ ] **Data safety:** inventory app code and every SDK before answering. Distinguish on-device processing from data
  collected or shared off-device, disclose security practices, and complete the data-deletion questions. Never copy
  another app's answers.
- [ ] **Account deletion:** determine accurately whether the app creates developer-controlled accounts. Provider account
  connection alone is not necessarily app-account creation, but all apps must answer the deletion questions. If future
  releases create app accounts, add both in-app and web deletion paths before release.
- [ ] **Foreground service:** declare the API 24–33 `dataSync` compatibility path; describe user-triggered mailbox
  operations, the harm from interruption, and the visible progress/Cancel notification. Supply a video showing the
  fallback on a supported older device. API 34+ uses a UIDT job instead. Google's listed `dataSync` use cases include
  user-initiated backup/restore and upload/download. See the [foreground-service declaration requirements][fgs-declaration].
- [ ] Complete any additional declarations Play Console presents, such as government, financial, health, news, ads ID,
  or permissions. Do not claim a category merely to dismiss the card.
- [ ] Review the latest [Developer Program Policies][play-policy], policy status, and SDK warnings immediately before
  submission.

## 7. Build the store presence

- [ ] Choose a clear title, concise short description, full description, category, and relevant tags. Do not imply that
  Google, Gmail, Microsoft, Outlook, or any email provider endorses the app.
- [ ] Clearly explain that the tool counts, compares, backs up, restores, and migrates mailboxes; which providers are
  supported; where backups reside; and that transfers can consume storage and mobile data.
- [x] Provide the required high-resolution Play icon separately from the launcher resources. The editable source and
  generated 512 px PNG live under `android/artwork/` and intentionally omit a baked-in Play mask or outer shadow.
- [ ] Create a feature graphic and at least the required phone screenshots. Include meaningful Configure, provider
  consent/account connection, project, confirmation, live Output, formatted result, and History states in both light
  and dark themes where useful.
- [ ] Capture screenshots from production-like builds containing synthetic accounts and messages. Remove email
  addresses, tokens, notifications, device identifiers, and unrelated personal information.
- [ ] Add a captioned preview video if it materially explains migration. The OAuth and foreground-service review videos
  may be private evidence and need not be the public marketing video.
- [ ] Supply support email (required), website, and preferably phone. Test each route and define response expectations.
- [ ] Add accurate translations only when support and policy content can be maintained in those languages.
- [ ] Validate every asset and text field against Google's current [preview-asset requirements][preview-assets] and
  [store-listing guidance][store-listing].

## 8. Validate the release bundle

- [ ] Set a monotonically increasing `versionCode` and public `versionName`; commit the intended release version.
- [ ] Build from a clean checkout at the reviewed source commit using the pinned JDK, Gradle, Python, and Android SDK.
- [ ] Run all repository-required Python and Android checks.
- [ ] Build the signed release AAB and record its SHA-256 checksum.
- [ ] Inspect the merged release manifest: package, exported components, permissions, foreground-service type,
  debuggability, backup behavior, and MSAL redirect data must be intentional.
- [ ] Inspect the AAB for secrets, development hosts, debug certificates, test data, source maps, unexpected assets,
  obsolete permissions, and unintended native ABIs.
- [ ] Confirm no client secret is packaged. OAuth public/native clients use identifiers and platform signing identity,
  not an embedded confidential secret.
- [ ] Use `bundletool` to generate Play-like APKs, install them on clean representative devices, and execute the full
  physical-device checklist in [android.md](android.md#physical-device-test-checklist).
- [ ] Verify Google and Microsoft sign-in using a build signed exactly as the tested artifact requires. After the first
  Play upload, use Internal app sharing/internal testing to validate the **Play app-signed** result—not only a locally
  upload-key-signed APK.
- [ ] Inspect Play Console's App Bundle Explorer for device support, generated APKs, native libraries, warnings, and
  compressed download size. Keep the base module within the current Play limit and review the user warning shown for
  large downloads. Chaquopy makes size review especially important.
- [ ] Review the pre-launch report on all available device/API combinations and fix release-blocking findings.

## 9. Test through Play tracks

- [ ] Upload first to **Internal testing**. Add only trusted testers and confirm install/update, Play signing, OAuth,
  foreground notifications, local storage, export/import, and all operations.
- [ ] Verify an update preserves projects, provider sessions, history, and local backups. Also test uninstall/reinstall
  behavior and explain data loss accurately.
- [ ] Run **Closed testing** with users and devices representative of the target audience. Provide a test script covering
  both authentication providers, password IMAP, project switching, all operations, cancellation, failure recovery,
  metered data, low storage, backgrounding, rotation, accessibility, and light/dark themes.
- [ ] Keep a feedback log with device/API/app version, reproduction steps, expected/actual results, severity, resolution,
  and retest evidence.
- [ ] If the developer account is subject to the rule, maintain at least 12 opted-in testers continuously for 14 days;
  tester opt-out resets that tester's continuous period. Gather meaningful engagement, then answer the production-access
  questions with concrete fixes and readiness evidence.
- [ ] Keep Google OAuth testing/verification constraints synchronized with the Play tester population. A Play tester is
  not automatically a Google OAuth test user.
- [ ] Freeze a release candidate and repeat regression, security/privacy, accessibility, and policy checks without
  changing the artifact afterward.

## 10. Submit and roll out production safely

- [ ] Resolve every Play Dashboard and App content task before creating the production release.
- [ ] Confirm Google restricted-scope production approval and production OAuth state. Confirm Microsoft production
  registration and publisher presentation.
- [ ] Upload the exact approved AAB, add user-facing release notes, and recheck generated device exclusions/warnings.
- [ ] Re-read the Data safety, privacy, foreground-service, target-audience, ads, app-access, and content-rating answers
  against the final binary.
- [ ] Ensure reviewer accounts and step-by-step access instructions work from a clean device in a different network.
- [ ] Use managed publishing if launch timing matters; review approval and public rollout are separate events.
- [ ] Start with a staged rollout where available. Define stop conditions for crashes, ANRs, authentication failures,
  mailbox corruption, destructive-operation defects, data exposure, and abnormal support volume.
- [ ] Monitor Android vitals, policy status, reviews, support, OAuth dashboards, provider incidents, and staged-rollout
  metrics. Halt the rollout and communicate if a data-integrity or privacy problem appears.
- [ ] Verify the public listing, install, first run, privacy link, both provider consent screens, Count, and a small safe
  transfer from a clean production device after rollout.

## 11. Maintain the published application

- [ ] Keep Play developer identity/contact details, reviewer credentials, privacy URLs, domain ownership, and provider
  project contacts current.
- [ ] Rotate or reset a compromised upload key through Play's supported process; never rotate identifiers or keys ad hoc.
- [ ] Increase `versionCode` for every uploaded artifact, including testing tracks.
- [ ] Re-run Data safety and policy review whenever features, SDKs, permissions, storage, analytics, servers, or data
  flows change.
- [ ] Maintain target-SDK compliance before annual deadlines and test new Android background/storage behavior early.
- [ ] Renew Google restricted-scope verification/security assessment when required and respond promptly to provider
  notices. Keep multiple monitored owners/editors on the Cloud project.
- [ ] Recheck Microsoft permissions, publisher verification, redirect URIs, and consent behavior after signing-key or
  account-support changes.
- [ ] Monitor dependency/security advisories and Play SDK Index notices; ship supported SDK versions.
- [ ] Test backup/restore compatibility and migration safety across every upgrade. Preserve a rollback and incident plan,
  remembering that Play rollback still requires a new, higher version code.
- [ ] Retain release evidence and policy submissions for auditability without retaining user mailbox data or secrets.

## Final go/no-go record

Before pressing **Start rollout to production**, record links or evidence for each gate:

- [ ] Release commit, version, signed AAB checksum, CI run, and approver
- [ ] Play App Signing and production OAuth certificate registrations
- [ ] Google restricted-scope approval and any current assessment evidence
- [ ] Microsoft production consent/publisher verification result
- [ ] Public home page, privacy policy, terms, and support routes
- [ ] Approved Data safety, content rating, foreground-service, and app-access declarations
- [ ] Store listing and redacted production screenshots
- [ ] Internal/closed-test results, production-access approval when applicable, and fixed-issue list
- [ ] Play pre-launch report and physical-device release regression result
- [ ] Staged-rollout plan, monitoring owners, stop criteria, and incident contacts

If any item is missing, defer production rather than using Play review to discover the gap.

[app-signing]: https://developer.android.com/studio/publish/app-signing
[account-deletion]: https://support.google.com/googleplay/android-developer/answer/13327111
[data-transfer]: https://developer.android.com/develop/background-work/background-tasks/data-transfer-options
[developer-account]: https://support.google.com/googleplay/android-developer/answer/13628312
[fgs-declaration]: https://support.google.com/googleplay/android-developer/answer/13392821
[google-revoke]: https://developers.google.com/android/reference/com/google/android/gms/auth/api/identity/AuthorizationClient#revokeAccess(com.google.android.gms.auth.api.identity.RevokeAccessRequest)
[msal-remove]: https://learn.microsoft.com/entra/msal/android/single-multi-account#remove-an-account
[microsoft-publisher]: https://learn.microsoft.com/entra/identity-platform/mark-app-as-publisher-verified
[page-size]: https://developer.android.com/guide/practices/page-sizes
[personal-testing]: https://support.google.com/googleplay/android-developer/answer/14151465
[play-policy]: https://play.google.com/about/developer-content-policy/
[preview-assets]: https://support.google.com/googleplay/android-developer/answer/9866151
[restricted-scope]: https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
[store-listing]: https://support.google.com/googleplay/android-developer/answer/13393723
[upload-bundle]: https://developer.android.com/studio/publish/upload-bundle
[workspace-policy]: https://developers.google.com/workspace/workspace-api-user-data-developer-policy
