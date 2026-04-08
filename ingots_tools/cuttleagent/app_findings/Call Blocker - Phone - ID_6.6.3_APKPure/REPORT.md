# Call Blocker - Phone - ID 6.6.3 (APKPure build)

## App identification

- Primary APK inside XAPK: `/data/workdir/call_blocker/com.cuiet.blockCalls.apk`
- Package name: `com.cuiet.blockCalls`
- Version code: `663`
- Version name: `6.6.3`
- Min SDK: 23
- Target SDK: 32

Evidence: `aapt dump badging` on the primary APK.

## Bundled native libraries

I fully extracted the base APK to `/data/workdir/call_blocker/base` and enumerated all `.so` files.

- Result: **no `.so` files are present** in this APK.

So there are no native libraries to fingerprint for CVEs.

## Third‑party components (Java/Kotlin)

From `META-INF/*.version` and `.properties` files, this build clearly uses common AndroidX, Google Play Services, Firebase, OkHttp, and other Java/Kotlin libraries, for example:

- AndroidX appcompat, core-ktx, fragment, lifecycle, Room, WorkManager, etc.
- Google Play services: ads, ads-identifier, appset, auth, cloud messaging, FIDO, location, measurement, places, stats, tasks
- Firebase: analytics, crashlytics, messaging, config, etc.
- OkHttp 3 (package `okhttp3` directory at root of APK)
- Mozilla, Kotlin stdlib, kotlinx-coroutines, etc.

However, the `.version` and `.properties` files are named generically (e.g., `androidx.appcompat_appcompat.version`) and do **not** embed explicit semantic versions; without decompilation, I cannot derive precise library versions, only that they are modern AndroidX/Play/Firebase components consistent with a targetSdk 32 app.

Because version numbers for these Java/Kotlin dependencies are missing, mapping them to specific CVEs would be speculative. I therefore do **not** claim any CVEs for these third‑party libraries.

## App manifest: exported components and permissions

Manifest summary (from `aapt`):

### Declared permissions

- `android.permission.READ_CALL_LOG`
- `android.permission.WRITE_CALL_LOG`
- `android.permission.WAKE_LOCK`
- `android.permission.ACCESS_NETWORK_STATE`
- `android.permission.INTERNET`
- `android.permission.FOREGROUND_SERVICE`
- `android.permission.READ_CONTACTS`
- `android.permission.READ_PHONE_STATE`
- `android.permission.CALL_PHONE`
- `android.permission.RECEIVE_BOOT_COMPLETED`
- `com.android.vending.BILLING`
- `android.permission.VIBRATE`
- `android.permission.ACCESS_NOTIFICATION_POLICY` (runtime, SDK 23+)
- `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` (runtime, SDK 23+)
- `android.permission.POST_NOTIFICATIONS`
- `android.permission.GET_TASKS`
- `android.permission.PACKAGE_USAGE_STATS`

Several of these (call log, contacts, phone state, usage stats, ignore battery optimizations) are high‑sensitivity permissions but are expected for a call‑blocking/ID application.

### Exported/intent‑related behavior

I did not perform a full decompilation, but given the nature of a dialer/call‑blocker app and the presence of many layout XMLs for activities, fragments, and services (e.g., after‑call UI, blocking UI, ad mediation UIs), it is very likely that:

- The app exports one or more `BroadcastReceiver` components to listen for phone state changes or incoming calls.
- It registers background services (including foreground services) to implement caller ID overlays and ad‑related behavior.

Without decompiling `AndroidManifest.xml` fully, I cannot safely enumerate every exported component or their exact intent filters, so I avoid claiming specific exported activities/services.

## Known public vulnerabilities

### CVE-2023-29728 – Call Blocker 6.6.3 EoP via feature‑data tampering

- **CVE ID**: CVE-2023-29728
- **Affected component**: This specific application, Call Blocker, package `com.cuiet.blockCalls`, version 6.6.3.
- **Relevance**: The NVD entry explicitly lists:
  - Product: Call Blocker application 6.6.3 for Android
  - CPE: `cpe:2.3:a:applika:call_blocker:6.6.3:::::android::`
  - Description: "The Call Blocker application 6.6.3 for Android allows attackers to tamper with feature‑related data, resulting in a severe elevation of privilege attack."
- **Why it matches this APK**:
  - Package and product name are the same Call Blocker Android app.
  - The version matches exactly: 6.6.3.
  - There is no evidence this XAPK is a fundamentally different fork; it appears to be the official Call Blocker 6.6.3 packaged for APKPure.
  - Therefore this APK should be considered **vulnerable** to CVE‑2023‑29728.
- **Affected version range**:
  - NVD explicitly calls out 6.6.3; no broader range is stated.
  - It is unknown whether earlier or later versions are also affected, but 6.6.3 is confirmed.
- **Trigger conditions (high‑level)**:
  - An attacker can tamper with "feature‑related data" used by the app in a way that leads to elevation of privilege.
  - The public CVE description is brief and does not specify whether tampering occurs through:
    - Local app data / shared preferences
    - External storage files
    - IPC (intents, bound services, content providers)
  - Given the CVSS 3.1 score of 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) from NVD enrichment, the attack is modeled as **remotely exploitable without prior authentication or user interaction**, likely via exposed IPC or remotely synchronized configuration/feature data.
  - Without the original advisory or exploit details, I cannot state the exact attack surface, just that the data integrity of critical "feature" state can be abused.
- **Impact (high‑level)**:
  - Severe elevation of privilege within the Android environment:
    - Potential ability to gain capabilities equivalent to the app's own powerful permissions (read/write call logs, read contacts, initiate calls, etc.).
    - Because the app has access to call logs and contacts and can place calls, misuse could include:
      - Exfiltration of call history and contacts.
      - Fraudulent or malicious calls (e.g., premium numbers, phishing calls).
      - Manipulation of call‑blocking behavior (e.g., allow/block specific numbers or override user settings).
  - NVD CVSS 3.1 vector suggests compromise of confidentiality, integrity, and availability at a critical level.
- **Confidence level**: **High** — this APK matches the exact product and version cited in NVD.
- **References**:
  - NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2023-29728

### Other candidate CVEs

I searched for additional vulnerabilities tied to this package or version and did not find other CVEs for `com.cuiet.blockCalls`.

For bundled components (AndroidX, Play Services, Firebase, OkHttp, libphonenumber assets, ad SDKs such as AppLovin/Facebook/Google Ads), there are **many** historical CVEs, but due to lack of explicit version numbers in the APK, any mapping to specific CVEs would be speculative. I therefore make **no** additional CVE claims here.

## Open questions / uncertainties

- Exact exploit path for CVE‑2023‑29728:
  - The CVE description mentions "feature‑related data" but does not describe whether the vulnerable surface is IPC, external storage, or network‑synchronized data.
  - Without decompilation or the original researcher advisory, I cannot specify the exact component or data structure to target.
- Third‑party library versions:
  - If more tooling were available (e.g., full decompilation plus build metadata), we might infer exact versions of OkHttp, Firebase, and Play Services and align them with known CVEs.

## Compact summary

- **App**: Call Blocker – Phone – ID
- **Package**: `com.cuiet.blockCalls`
- **Version**: 6.6.3 (versionCode 663)
- **Native libraries**: none (.so files absent)
- **Key Java/Kotlin libraries**: modern AndroidX stack, Google Play Services (ads, auth, location, measurement, etc.), Firebase (analytics, crashlytics, messaging), OkHttp3, libphonenumber assets, multiple ad SDK/mediation components.
- **Primary CVE**: **CVE‑2023‑29728** – confirmed severe elevation of privilege vulnerability specific to Call Blocker 6.6.3 for Android, due to tampering with feature‑related data.
- **Overall confidence**: high for app identification and CVE‑2023‑29728 applicability; low/no claims for other dependencies due to missing version data.