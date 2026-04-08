# Adobe Acrobat Reader for Android (com.adobe.reader)

## App identity
- Package name: `com.adobe.reader`
- Version name: `21.7.0.18750`
- Version code: `1922718750`
- Min SDK: 23
- Target SDK: 29

Evidence:
- `aapt dump badging` and `aapt dump xmltree` on the APK show `package="com.adobe.reader"` and `android:versionName="21.7.0.18750"`, `android:versionCode=0x729a5c1e`.

## Permissions & notable manifest details
- Core permissions:
  - `android.permission.INTERNET`
  - `android.permission.ACCESS_NETWORK_STATE`
  - `android.permission.ACCESS_WIFI_STATE`
  - `android.permission.WRITE_EXTERNAL_STORAGE`
  - `android.permission.READ_EXTERNAL_STORAGE`
  - `android.permission.CAMERA`
  - `android.permission.READ_CONTACTS`
  - `android.permission.WAKE_LOCK`
  - `android.permission.RECEIVE_BOOT_COMPLETED`
  - `android.permission.FOREGROUND_SERVICE`
- Account / identity / billing:
  - `android.permission.AUTHENTICATE_ACCOUNTS`
  - `android.permission.MANAGE_ACCOUNTS`
  - `android.permission.USE_CREDENTIALS`
  - `android.permission.GET_ACCOUNTS`
  - `com.android.vending.BILLING`
  - `com.samsung.android.iap.permission.BILLING`
  - `com.google.android.c2dm.permission.RECEIVE`
  - `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE`
- App-level flags:
  - `android:allowBackup="false"`
  - `android:largeHeap="true"`
  - `android:supportsRtl="false"`
  - `android:extractNativeLibs="true"`
  - `android:requestLegacyExternalStorage="true"` (pre‑scoped‑storage behavior)
  - `android:networkSecurityConfig=@xml/network_security_config`
- Queries section indicates it may interact with Intune / Azure related apps and a browser via `VIEW` intents on `https` URLs, and uses Custom Tabs service.

These manifest details confirm the app is a fully‑featured Adobe Acrobat Reader build with network, storage and account access.

## Native library inventory
All observed `.so` files are under `lib/arm64-v8a/` (ARM64, ELF 64‑bit LSB, aarch64). All are stripped; no direct version strings were visible through `readelf -d` (only SONAMEs).

Per‑library details:

1. `/lib/arm64-v8a/libACE.so`
   - SONAME: `libACE.so`
   - Likely Adobe internal rendering / engine component (Adobe Common Engine). No explicit upstream project identified.

2. `/lib/arm64-v8a/libADCComponents.so`
   - SONAME: `libADCComponents.so`
   - Likely Adobe Document Cloud component aggregation library.

3. `/lib/arm64-v8a/libAGM.so`
   - SONAME: `libAGM.so`
   - Historically Adobe Graphics Manager (AGM) used in Acrobat/Reader.

4. `/lib/arm64-v8a/libAdobeAXE8SharedExpat.so`
   - SONAME: `libAdobeAXE8SharedExpat.so`
   - Contains `Expat` in the name, suggesting it statically or dynamically wraps the Expat XML parser.
   - **Version clue:** none visible from ELF headers alone; strings not inspected to keep analysis minimal.

5. `/lib/arm64-v8a/libAdobeCreativeSDKEngagement.so`
   - SONAME: `libAdobeCreativeSDKEngagement.so`
   - Likely part of Adobe Creative SDK / engagement and analytics.

6. `/lib/arm64-v8a/libAdobeJP2K.so`
   - SONAME: `libAdobeJP2K.so`
   - Likely Adobe‑internal JPEG2000 decoding library.

7. `/lib/arm64-v8a/libAdobeReader.so`
   - SONAME: `libAdobeReader.so`
   - Core native engine for PDF parsing/rendering for Reader.

8. `/lib/arm64-v8a/libAdobeXMP.so`
   - SONAME: `libAdobeXMP.so`
   - Adobe XMP metadata library.

9. `/lib/arm64-v8a/libBIB.so`
   - SONAME: `libBIB.so`
   - Adobe internal library (Binary Image Bus / similar); no public mapping.

10. `/lib/arm64-v8a/libBIBUtils.so`
    - SONAME: `libBIBUtils.so`
    - Companion utilities for BIB.

11. `/lib/arm64-v8a/libBoost.so`
    - SONAME: `libBoost.so`
    - Likely a subset of Boost C++ libraries built as a monolithic shared object.
    - No version info in headers; version likely tied to app build.

12. `/lib/arm64-v8a/libColoradoMobile.so`
    - SONAME: `libColoradoMobile.so`
    - Adobe internal module (possibly Document Cloud / sync).

13. `/lib/arm64-v8a/libCoolType.so`
    - SONAME: `libCoolType.so`
    - Adobe CoolType font rendering engine.

14. `/lib/arm64-v8a/libWRServices.so`
    - SONAME: `libWRServices.so`
    - Adobe internal (likely web‑related services).

15. `/lib/arm64-v8a/libadobejpeg.so`
    - SONAME: `libadobejpeg.so`
    - Adobe‑branded JPEG codec, likely derived from libjpeg but heavily modified.

16. `/lib/arm64-v8a/libaide.so`
    - SONAME: `libaide.so`
    - Adobe internal helper library.

17. `/lib/arm64-v8a/libc++_shared.so`
    - SONAME: `libc++_shared.so`
    - LLVM libc++ shared runtime from the Android NDK. No version number in SONAME for this build; exact NDK level could not be determined from headers alone.

18. `/lib/arm64-v8a/libcrashlytics-common.so`
    - SONAME: `libcrashlytics-common.so`
    - Part of Fabric/Google Crashlytics native crash reporting.

19. `/lib/arm64-v8a/libcrashlytics-handler.so`
    - SONAME: `libcrashlytics-handler.so`
    - Crashlytics signal/handler component.

20. `/lib/arm64-v8a/libcrashlytics-trampoline.so`
    - SONAME: *not shown by `readelf -d`* (no explicit SONAME entry), but file name `libcrashlytics-trampoline.so`.
    - Crashlytics startup trampoline.

21. `/lib/arm64-v8a/libcrashlytics.so`
    - SONAME: `libcrashlytics.so`
    - Main Crashlytics JNI library.

22. `/lib/arm64-v8a/libopencv_java3.so`
    - SONAME: `libopencv_java3.so`
    - JNI bridge for OpenCV 3.x Java API.
    - **Version clue:** Name strongly implies OpenCV 3.*; precise minor version not derivable from headers alone.

23. `/lib/arm64-v8a/libpage_segmentation_tflite.so`
    - SONAME: `libpage_segmentation_tflite.so`
    - Custom TFLite model runner for page segmentation.

24. `/lib/arm64-v8a/libtensorflowlite_gpu_jni.so`
    - SONAME: `libtensorflowlite_gpu_jni.so`
    - TensorFlow Lite GPU delegate JNI library.

25. `/lib/arm64-v8a/libtensorflowlite_jni.so`
    - SONAME: `libtensorflowlite_jni.so`
    - Core TensorFlow Lite JNI binding.

For all of the above, no version numbers were present in SONAME or basic ELF headers. Determining exact upstream versions would require deeper analysis (symbols/strings) which was not performed to keep the analysis focused.

## Known/public vulnerabilities potentially affecting this version

### 1. CVE-2021-40724 — Path Traversal leading to Arbitrary Code Execution

- **Component:** Adobe Acrobat Reader for Android (entire app, not a specific .so)
- **Version range affected:**
  - According to Adobe security bulletin APSB21‑89 and external analysis, "Adobe Acrobat Reader for Android 21.8.0 and earlier" are vulnerable. Lookout’s advisory and independent write‑ups state that *all* versions before **21.9.0** are affected.
- **Relevance to this APK:**
  - This APK is **21.7.0.18750**, which is earlier than 21.8.0/21.9.0, so it clearly lies in the vulnerable range.
  - Product, package name and platform all match (Adobe Acrobat Reader for Android, `com.adobe.reader`).
- **Vulnerability summary:**
  - Type: Improper Limitation of a Pathname to a Restricted Directory (CWE‑22) / Path Traversal.
  - Impact: Arbitrary code execution in the context of the app.
  - Root cause (per public write‑ups):
    - A path traversal bug in URL‑derived file paths used by the app when downloading content.
    - An attacker‑controlled URL path segment is decoded and passed unsanitized to file‑handling code.
    - In combination with the Google Play Core dynamic feature/splitcompat mechanism, an attacker can cause the app to load attacker‑controlled code (either Java classes from an APK or native libraries) from its private storage.
- **Trigger conditions (high‑level):**
  - Victim must open a malicious URL or document crafted by the attacker, typically delivered via phishing, email or web link.
  - The app must download and process the file using the vulnerable code path (e.g., via an in‑app download/"open from URL" feature).
  - The device must have the vulnerable Adobe Reader version installed (this APK qualifies).
- **Expected impact:**
  - Remote code execution within the app’s sandbox.
  - Full access to PDF contents, associated cloud accounts (via app access tokens), and any data accessible through the app’s permissions, including files on external storage and account‑linked content.
- **Confidence:** **High**
  - Exact version match to vulnerable range.
  - Official Adobe bulletin and third‑party analysis explicitly confirm pre‑21.9.0 builds are vulnerable.
- **References:**
  - Adobe Security Bulletin APSB21‑89 ("Security update available for Adobe Acrobat Reader for Android")
  - CVE‑2021‑40724 (NIST/NVD entry)
  - Lookout Threat Intel: *Adobe Acrobat for Android* article describing CVE‑2021‑40724
  - Independent researcher write‑up: "RCE in Adobe Acrobat Reader for android (CVE‑2021‑40724)" (hulkvision)

### 2. Other Adobe Acrobat/Reader CVEs

Numerous other CVEs exist for desktop Adobe Acrobat/Reader (Windows/macOS) and for earlier mobile versions, mostly involving malformed PDF processing (heap/stack corruption, OOB reads/writes, use‑after‑free) or JavaScript in PDFs.

However:
- Adobe’s mobile bulletins around October 2021 (APSB21‑89) specifically list **only CVE‑2021‑40724** for Android Reader 21.x.
- No additional, clearly mobile‑specific CVEs were found that unambiguously map to version 21.7.0 besides CVE‑2021‑40724.

Due to this, attributing any other known Acrobat CVEs directly to this Android build would be speculative.

**Conclusion for other CVEs:**
- No additional CVEs can be confidently tied to this specific Android version based on public data.
- There is a general risk that some desktop engine issues may also exist in the shared codebase (e.g., in `libAdobeReader.so`, `libAGM.so`, `libCoolType.so`), but without explicit mobile advisories and version mapping this remains **low‑confidence** and is not claimed as a concrete finding here.

## Third‑party libraries

The APK bundles several well‑known third‑party components:

- **OpenCV 3.x** via `libopencv_java3.so`.
  - Used typically for computer‑vision tasks (e.g., scanning documents, detecting page edges or barcodes).
  - OpenCV 3.x has multiple historical CVEs, but without an exact minor version, and given that most issues are in rarely used modules or require direct untrusted image inputs, it is not possible to tie a specific CVE to this binary with high confidence.

- **TensorFlow Lite / TensorFlow Lite GPU** via `libtensorflowlite_jni.so` and `libtensorflowlite_gpu_jni.so`.
  - Used to run local ML models (page segmentation, etc.).
  - Public TF Lite vulnerabilities generally involve malformed model files or are in development tooling; this app ships its own models and does not appear to load arbitrary models from untrusted sources. No mobile‑specific CVEs for TF Lite in this context were identified.

- **Crashlytics native SDK** via multiple `libcrashlytics*` libraries.
  - Older versions of Crashlytics had issues around unsafe file permissions and diagnostics, but no widely‑known remote code execution or privilege escalation CVEs specific to the Android native Crashlytics libraries were identified that map cleanly to this timeframe/build.

Given the lack of reliable versioning evidence inside these `.so` files and absence of strong CVE matches tied to them in the context of this app, no third‑party library CVEs are listed as concrete findings.

## Overall assessment

- **Primary confirmed issue:**
  - **CVE‑2021‑40724** (Path Traversal → Arbitrary Code Execution) definitely affects this APK (21.7.0.18750), as it is older than the fixed version 21.9.0 and matches the affected product/platform.

- **Native libraries:**
  - The app ships a substantial amount of Adobe‑proprietary native code plus third‑party engines (OpenCV 3.x, TensorFlow Lite, Crashlytics, libc++). Version information is not present in ELF metadata, so specific library‑level CVEs cannot be asserted with high confidence.

- **Permissions and attack surface:**
  - Wide set of permissions (network, storage, accounts, camera, contacts) provides significant impact to any code‑execution vulnerability like CVE‑2021‑40724.

- **Uncertainties / open questions:**
  - Exact versions of OpenCV, TensorFlow Lite, Crashlytics, Expat, and any embedded libjpeg/libpng/zlib cannot be derived from basic ELF inspection alone.
  - There may be additional, unpublished or non‑CVE‑tracked vulnerabilities in the proprietary libraries.

## Summary (for this APK)
- App: **Adobe Acrobat Reader for Android** (`com.adobe.reader`)
- Version: **21.7.0.18750** (vulnerable pre‑21.9.0 build)
- Key native libraries: Adobe PDF engine (`libAdobeReader.so`, `libAGM.so`, `libCoolType.so`, etc.), OpenCV 3 (`libopencv_java3.so`), TensorFlow Lite (CPU & GPU JNI), Crashlytics native, libc++.
- Confirmed CVE:
  - **CVE‑2021‑40724** — Path Traversal leading to arbitrary code execution in Adobe Acrobat Reader for Android ≤ 21.8.0 / < 21.9.0.
- Confidence: **High** for app identification and CVE‑2021‑40724; **low** for any speculative additional CVEs (none claimed).
