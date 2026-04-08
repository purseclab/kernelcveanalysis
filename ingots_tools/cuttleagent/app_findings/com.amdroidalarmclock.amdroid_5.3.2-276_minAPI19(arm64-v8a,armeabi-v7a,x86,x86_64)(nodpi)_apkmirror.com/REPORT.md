# AMdroid Alarm Clock APK Security Analysis

## App identification
- **File analyzed**: `/data/apps/com.amdroidalarmclock.amdroid_5.3.2-276_minAPI19(arm64-v8a,armeabi-v7a,x86,x86_64)(nodpi)_apkmirror.com.apk`
- **Package name**: `com.amdroidalarmclock.amdroid`
- **VersionName**: `5.3.2`
- **VersionCode**: `276`
- **Min SDK**: 19
- **Target SDK**: 30

## Permissions (from manifest badging)
Notable requested permissions include:
- Location: `ACCESS_COARSE_LOCATION`, `ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`
- Network: `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`
- Wake/alarms: `WAKE_LOCK`, `RECEIVE_BOOT_COMPLETED`, `SET_ALARM`, `FOREGROUND_SERVICE`, `USE_FULL_SCREEN_INTENT`
- Storage/phone/calendar: `READ_EXTERNAL_STORAGE`, `READ_PHONE_STATE` (maxSdkVersion 22), `READ_CALENDAR`
- Overlay / Do Not Disturb: `SYSTEM_ALERT_WINDOW`, `ACCESS_NOTIFICATION_POLICY`
- Others: `VIBRATE`, `WRITE_SETTINGS`, `NFC`, `CAMERA` (runtime), billing/ads (`com.android.vending.BILLING`, `com.google.android.gms.permission.AD_ID`, `com.google.android.c2dm.permission.RECEIVE`, Instabug‑style diagnostics libs implied below).

These are broadly consistent with a feature‑rich alarm clock using location, network sync, notifications, and overlays.

## Native library inventory
All `.so` files discovered under the extracted APK:

1. `/data/workdir/amdroid/lib/arm64-v8a/libibg-native.so`
   - **Architecture**: arm64-v8a (ELF 64‑bit LSB, ARM aarch64)
   - **SONAME**: `libibg-native.so`
   - **Dependencies**: `liblog.so`, `libm.so`, `libdl.so`, `libc.so`
   - **Likely component**: Instabug native SDK library (internal encryption & key material provider)
   - **Version clues**: No explicit version string in ELF headers. Strings show JNI symbols such as:
     - `Java_com_instabug_library_encryption_EncryptionManager_getCBCIVParameterKey`
     - `Java_com_instabug_library_encryption_StaticKeyProvider_getKeyString`
     - `Java_com_instabug_library_networkv2_authorization_NetworkOfficer_getClientId`
   - **Confidence**: High that this is an Instabug SDK native component; version unknown.

2. `/data/workdir/amdroid/lib/armeabi-v7a/libibg-native.so`
   - **Architecture**: armeabi-v7a (ELF 32‑bit LSB, ARM EABI5)
   - **SONAME**: (not shown in first lines of dynamic section; but filename is `libibg-native.so`)
   - **Likely component**: Same Instabug SDK native library, 32‑bit ARM build.
   - **Version clues**: Same JNI namespace (`com.instabug.library.*`) in symbols (not re‑dumped separately, inferred from identical library name/function in multi‑ABI packaging).
   - **Confidence**: High, version unknown.

3. `/data/workdir/amdroid/lib/x86/libibg-native.so`
   - **Architecture**: x86 32‑bit (ELF 32‑bit LSB, Intel 80386)
   - **SONAME**: `libibg-native.so` (from dynamic section)
   - **Likely component**: Instabug SDK native library, x86 build.
   - **Version clues**: No explicit version markers; same JNI namespaces expected.
   - **Confidence**: High, version unknown.

4. `/data/workdir/amdroid/lib/x86_64/libibg-native.so`
   - **Architecture**: x86_64 64‑bit (ELF 64‑bit LSB)
   - **SONAME**: (dynamic section shows generic data; name inferred from file name)
   - **Likely component**: Instabug SDK native library, x86_64 build.
   - **Version clues**: None beyond general instabug JNI symbols (not re‑dumped; assumed parallel build).
   - **Confidence**: High, version unknown.

No other native libraries were found in this APK.

## Likely third‑party components
From the `libibg-native.so` JNI symbols and typical usage patterns, AMdroid likely integrates **Instabug** (or its white‑labelled SDK, now branded as *Luciq* in current docs) for in‑app bug reporting, crash reporting, and analytics. Evidence:
- JNI functions in `com.instabug.library.encryption.*`, `com.instabug.library.internal.storage.Encryptor`, `com.instabug.library.networkv2.*`.
- The library name `libibg-native.so` matches Instabug’s naming across public repos.

The web search for `libibg-native.so Instabug` returned generic Instabug SDK integration documentation and Snyk pages for `instabug-reactnative` without reported CVEs. There is **no specific CVE entry** tied to `libibg-native.so` or Instabug’s native SDK in major vulnerability databases as of the knowledge cutoff.


## CVE and vulnerability research

### 1. App‑specific CVEs for AMdroid

Web searches for:
- `"AMdroid" "com.amdroidalarmclock.amdroid" vulnerability`
- `"AMdroid" alarm clock Android security vulnerability CVE`

primarily return:
- The official product site (amdroidapp.com) and generic app reviews.
- Unrelated discussions about other alarm apps or generic Android OS security bulletins.

No NVD/MITRE, vendor advisory, or reputable security research explicitly associates **any CVE** with:
- The package name `com.amdroidalarmclock.amdroid`, or
- AMdroid Alarm Clock by name.

**Conclusion**: There are **no known public CVEs** registered specifically for AMdroid Alarm Clock 5.3.2, based on current public data.

### 2. Instabug / libibg-native.so

Searches for:
- `"libibg-native.so" Instabug CVE`
- `"Instabug" Android SDK vulnerability CVE`

returned:
- Instabug / Luciq SDK integration and customization docs.
- Package listing for `instabug-reactnative` on Snyk, which (for the inspected version) lists **no known vulnerabilities** in Snyk’s DB.
- General Android security bulletins and unrelated kernel/SoC‑level CVEs.

No authoritative references (NVD, vendor advisories, Snyk, GitHub security advisories) document a vulnerability in Instabug’s Android SDK or in `libibg-native.so` itself.

Given only:
- an opaque native library implementing encryption/key material fetch functions
- without version strings or public bug reports

we **cannot responsibly attribute** any particular CVE to this bundled library.

### 3. OS‑level Android CVEs

Many CVEs in search results relate to:
- Android framework / system components
- Kernel and SoC‑specific vulnerabilities (MediaTek, Samsung, etc.)

These are patch‑level issues on the **device’s firmware/OS**, not vulnerabilities inside this AMdroid APK. An app like AMdroid may be indirectly impacted if the underlying OS is vulnerable, but such CVEs are **out of scope** for per‑APK analysis and cannot be remediated at app level.

### 4. General security posture observations (non‑CVE)

Although no concrete CVEs were found for this app or its bundled libraries, some general observations:

- **Wide permission set**: Includes background location, system alert window overlays, notification policy access, write settings, camera, and calendar read access. Misuse or implementation bugs around these could introduce privacy or logic flaws, but there is no public evidence of such flaws for AMdroid.
- **Diagnostic/analytics SDK**: Instabug collects runtime data for bug reporting. As with any third‑party analytics, privacy misconfiguration is possible, but again, no public CVE or security advisory currently documents an issue here.

Without dynamic analysis or source review, any further statements about specific vulnerabilities would be speculative.


## Candidate CVEs

Based on all the evidence gathered, there are **no concrete candidate CVEs** that can be confidently tied to:
- AMdroid Alarm Clock 5.3.2 (`com.amdroidalarmclock.amdroid`), or
- Its bundled `libibg-native.so` (Instabug SDK) libraries.

Listing generic Android framework or kernel CVEs (e.g., from recent Android Security Bulletins) would not be meaningful here because they are not specific to this APK and depend on the user’s device model and patch level.


## Open questions and uncertainties

- **Instabug SDK version**: The specific Instabug SDK version in use is not identifiable from ELF headers or simple string inspection. If the exact SDK version were known (from build.gradle or ProGuard mappings), it could be cross‑checked against any future advisories.
- **Potential logic/privacy bugs**: No public reports were found, but absence of CVEs does not guarantee the absence of issues. A dedicated code review or dynamic test might uncover app‑specific bugs that are not yet disclosed.


## Summary

- **App**: AMdroid Alarm Clock (`com.amdroidalarmclock.amdroid`), version 5.3.2 (code 276).
- **Key bundled library**: `libibg-native.so` for multiple ABIs, confidently identified as part of the Instabug (Luciq) diagnostic SDK; no version string available.
- **Known public vulnerabilities (CVEs)**: None found that can be reliably tied to this app or its bundled native library based on current public data.
- **Overall confidence**: High regarding app identification and native library inventory; medium regarding the absence of CVEs (bounded by public data and shallow static analysis only).
