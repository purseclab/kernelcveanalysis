# Home Assistant Companion for Android 2023.8.1 – APK Security Analysis

## App identification
- **APK path:** `/data/apps/home-assistant_2023.8.1.apk`
- **Package name:** `io.homeassistant.companion.android`
- **Version code:** `10920`
- **Version name:** `2023.8.1-full`
- **Min SDK:** 21
- **Target SDK:** 33

## Declared permissions (from manifest)
Notable requested permissions (subset):
- Network & background
  - `android.permission.INTERNET`
  - `android.permission.ACCESS_NETWORK_STATE`
  - `android.permission.ACCESS_WIFI_STATE`
  - `android.permission.CHANGE_WIFI_MULTICAST_STATE`
  - `android.permission.RECEIVE_BOOT_COMPLETED`
  - `android.permission.FOREGROUND_SERVICE`
  - `android.permission.SCHEDULE_EXACT_ALARM`
  - `android.permission.WAKE_LOCK`
- Location & activity
  - `android.permission.ACCESS_FINE_LOCATION`
  - `android.permission.ACCESS_COARSE_LOCATION`
  - `android.permission.ACCESS_BACKGROUND_LOCATION`
  - `android.permission.ACTIVITY_RECOGNITION`
  - `com.google.android.gms.permission.ACTIVITY_RECOGNITION`
- Bluetooth & nearby
  - `android.permission.BLUETOOTH` (maxSdkVersion=30)
  - `android.permission.BLUETOOTH_ADMIN` (maxSdkVersion=30)
  - `android.permission.BLUETOOTH_ADVERTISE`
  - `android.permission.BLUETOOTH_CONNECT`
  - `android.permission.BLUETOOTH_SCAN`
- Sensors & device control
  - `android.permission.CAMERA`
  - `android.permission.RECORD_AUDIO`
  - `android.permission.MODIFY_AUDIO_SETTINGS`
  - `android.permission.CALL_PHONE`
  - `android.permission.NFC`
  - `android.permission.READ_PHONE_STATE`
  - `android.permission.ACCESS_NOTIFICATION_POLICY`
  - `android.permission.SYSTEM_ALERT_WINDOW`
  - `android.permission.PACKAGE_USAGE_STATS`
  - `android.permission.WRITE_SETTINGS`
  - `android.permission.WRITE_EXTERNAL_STORAGE` (maxSdkVersion=28)
  - `android.permission.POST_NOTIFICATIONS`
  - `android.permission.USE_BIOMETRIC`
  - `android.permission.USE_FINGERPRINT`
- App-specific
  - `io.homeassistant.companion.android.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`

The permission set is broad and consistent with a powerful companion app capable of automation, presence detection, and overlay UI.

## Exported components and intents
- Manifest contains an activity:
  - `io.homeassistant.companion.android.launch.my.MyActivity`
- Public advisories for CVE-2023-41898 (see below) state this activity is **exported** and processes attacker-controlled URLs via `Intent` data, loading them into a WebView.
- This makes the app reachable from other apps on the same device via crafted `Intent`s.

## Native libraries inventory
From `/data/workdir/home-assistant/lib/arm64-v8a`:

1. **`lib/arm64-v8a/libsentry-android.so`**
   - **Architecture:** ELF 64-bit, ARM aarch64
   - **SONAME:** `libsentry-android.so`
   - **Dependencies (NEEDED):** `libsentry.so`, `libm.so`, `libdl.so`, `libc.so`
   - **Likely upstream component:** Sentry Android NDK glue library
   - **Version clues:**
     - JNI symbols like `Java_io_sentry_android_ndk_SentryNdk_initSentryNative`
     - Strings: `.sentry-native`
   - **Version not directly encoded** (no obvious semver string); likely corresponds to whatever Sentry Android NDK version was current around mid‑2023, but exact version cannot be determined from the binary alone.
   - **Identification confidence:** High (based on symbol names and SONAME).

2. **`lib/arm64-v8a/libsentry.so`**
   - **Architecture:** ELF 64-bit, ARM aarch64
   - **SONAME:** `libsentry.so`
   - **Dependencies (NEEDED):** `libdl.so`, `liblog.so`, `libm.so`, `libc.so`
   - **Likely upstream component:** `sentry-native` (core native SDK used by Sentry Android NDK)
   - **Version clues:**
     - Contains strings:
       - `sentry-native`
       - `github:getsentry/sentry-native`
       - Paths like `sentry-android-ndk/sentry-native/external/libunwindstack-ndk/...`
     - Symbols for Sentry options such as `sentry_options_get_dsn`, `sentry_options_set_dsn`.
   - No explicit version number is embedded; without additional tooling (e.g., mapping build IDs to released versions), we cannot pinpoint the exact `sentry-native` version.
   - **Identification confidence:** High for component, low for exact version.

No other `.so` files were present in the extracted `lib` directory for this APK.

### Native library CVE considerations
- Public Sentry CVEs (e.g., vulnerabilities in Sentry server, Sentry SaaS, or SAML SSO) generally affect **backend Sentry deployments**, not mobile client SDKs.
- I could not find any CVEs specifically affecting **`sentry-android` or `sentry-native` client libraries on Android** for the 2023 timeframe.
- Therefore, while Sentry is present, there is **no strong evidence** of a known exploitable CVE tied to these particular native libraries inside the mobile app.

**Conclusion for native libs:**
- The app ships Sentry Android NDK (`libsentry-android.so` + `libsentry.so`) for crash/error reporting.
- No directly applicable public CVEs were found for these client libraries; risk from them appears secondary compared to the main app vulnerability described next.

## App-level known vulnerability

### CVE-2023-41898 – Arbitrary URL loading in WebView (Home Assistant Companion for Android)

- **Component:** Home Assistant Companion for Android (`io.homeassistant.companion.android`)
- **Affected versions (per NVD / vendor advisory):**
  - “Home Assistant Companion for Android app **up to version 2023.8.2**”
  - Fixed in **2023.9.2**.
- **This APK:**
  - Version `2023.8.1-full` → **within the vulnerable range**.
- **CVE description (summarized from NVD & Home Assistant security page):**
  - The app is vulnerable to **arbitrary URL loading** in an Android `WebView`.
  - An exported activity (documented as `MyActivity` – here: `io.homeassistant.companion.android.launch.my.MyActivity`) loads a URL derived from the `Intent` data into a WebView without sufficient validation.
  - This allows loading attacker-controlled URLs with arbitrary schemes/hosts.
- **Impact (from CVE-2023-41898 notes):**
  - Arbitrary JavaScript execution inside the WebView.
  - “Limited native code execution” possibilities (e.g., via exposed JS bridges or deep link handlers).
  - Potential **credential theft** (e.g., stealing Home Assistant tokens or session data accessible via the WebView).
- **Attack prerequisites and trigger:**
  - Local attack: another **malicious Android app on the same device** can send an `Intent` targeting `MyActivity` and control the loaded URL.
  - The user may or may not see the attack depending on how the WebView UI is presented.
  - No special permissions required by the attacker beyond ability to start activities.
- **CVSS v3.1 (NVD):** `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` – Score 8.6 (High).
- **References:**
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-41898
  - Home Assistant security page: https://www.home-assistant.io/security/
  - GitHub Security Lab writeup: “Securing our home labs: Home Assistant code review” – section on `CVE-2023-41898/GHSL-2023-142` with PoC.
- **Confidence this APK is affected:** **High**
  - Version `2023.8.1` is explicitly within “up to 2023.8.2” range.
  - Manifest clearly contains `io.homeassistant.companion.android.launch.my.MyActivity`, matching advisory naming.

### Other Home Assistant–related CVEs
- Several other CVEs (e.g., CVE-2023-41894, CVE-2023-41897, CVE-2023-41899, CVE-2023-27482) affect **Home Assistant Core** and the **Supervisor**, not this mobile companion app directly.
- They may still matter in a full deployment scenario but are **out of scope** for this specific APK binary and are not directly exploitable via the app alone.

## Cross-app / intent considerations
- The vulnerable `MyActivity` is exported and can be triggered via explicit `Intent` from other apps.
- This means:
  - A seemingly benign app installed on the same device can exploit CVE-2023-41898 without needing network access.
  - The presence of powerful permissions (camera, microphone, overlay, location, notification access) raises the potential impact if the WebView can be driven to abuse features or steal auth tokens that then allow further actions in Home Assistant Core.

## Overall assessment

- **Confirmed component & version:** Home Assistant Companion for Android `2023.8.1-full`, package `io.homeassistant.companion.android`.
- **Native libs:**
  - `libsentry-android.so` (Sentry Android NDK glue)
  - `libsentry.so` (Sentry Native core)
  - No specific client-SDK CVEs identified.
- **Primary known vulnerability:**
  - **CVE-2023-41898** – Arbitrary URL loading in exported WebView activity `MyActivity`, enabling arbitrary JS execution and credential theft.
  - This APK is **within the documented vulnerable range** and should be considered affected.

**Recommended mitigations for this APK:**
- Prefer upgrading to **Home Assistant Companion for Android 2023.9.2 or later**, which contains the upstream fix.
- Until updated:
  - Limit installation of untrusted apps on the same device, since exploitation is via local Intents.
  - Where possible, reduce exposure of Home Assistant Core (e.g., avoid exposing it directly to the internet without strong authentication and TLS), as stolen tokens could be used against the backend.
