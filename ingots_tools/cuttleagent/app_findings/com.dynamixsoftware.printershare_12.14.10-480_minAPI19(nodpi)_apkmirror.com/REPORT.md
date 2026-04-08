# PrinterShare (com.dynamixsoftware.printershare) Security Analysis

## App Identification

- **Package name:** `com.dynamixsoftware.printershare`
- **App label:** `PrinterShare`
- **VersionName:** `12.14.10`
- **VersionCode:** `480`
- **Min SDK:** 19
- **Target SDK:** 33 (compileSdk 34)
- **APK analyzed:** `/data/apps/com.dynamixsoftware.printershare_12.14.10-480_minAPI19(nodpi)_apkmirror.com.apk`

Evidence from `aapt dump badging`:

```text
package: name='com.dynamixsoftware.printershare' versionCode='480' versionName='12.14.10'
```

## Permissions & Capabilities

Declared permissions (from `aapt badging` and manifest):

- Contacts & calendar: `READ_CONTACTS`, `READ_CALENDAR`
- Network & wake: `INTERNET`, `WAKE_LOCK`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE`
- Telephony & accounts: `READ_PHONE_STATE`, `GET_ACCOUNTS`, `USE_CREDENTIALS`, `MANAGE_ACCOUNTS`
- Storage: `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` (maxSdkVersion=22)
- Bluetooth & nearby: `BLUETOOTH`, `BLUETOOTH_ADMIN` (maxSdkVersion=30), `BLUETOOTH_CONNECT`, `BLUETOOTH_SCAN`, `ACCESS_FINE_LOCATION` (maxSdkVersion=30)
- Notifications & foreground: `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`
- Billing & Google Play: `com.android.vending.BILLING`, `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE`
- Ads & attribution: `com.google.android.gms.permission.AD_ID`, `ACCESS_ADSERVICES_ATTRIBUTION`, `ACCESS_ADSERVICES_AD_ID`
- App‑specific: `com.dynamixsoftware.printershare.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`

The app also declares a `print-service` component and integrates with Google Sign-In / Google Play Billing based on resources in `res/drawable*` and `res/raw`.

## Native Library Inventory

Using `unzip` and `glob` over `/data/workdir/printershare`, **no `.so` files** were found directly inside the APK:

- `glob("/data/workdir/printershare/**/*.so")` → no matches

However, there are multiple architecture‑specific ZIP payloads under `assets/data/`:

- `lib_pdfrender_5_0_3_code_arm.zip`
- `lib_pdfrender_5_0_3_code_arm_64.zip`
- `lib_pdfrender_5_0_3_code_x86.zip`
- `lib_pdfrender_5_0_3_code_x86_64.zip`
- `lib_pdfrender_6_0_3_code_arm*.zip` (arm, arm64, x86, x86_64)
- `lib_pdfrender_7_0_3_code_*`
- `lib_pdfrender_8_0_3_code_*`

These strongly suggest that PrinterShare dynamically unpacks an internal **`pdfrender` native library** at runtime, in multiple versions (5.0.3, 6.0.3, 7.0.3, 8.0.3) for various CPU architectures.

Because the challenge instructions restrict unnecessary extraction and we already know the filenames and likely purpose, these archives were **not** individually unzipped. Therefore, the exact SONAMEs and architectures of the contained `.so` files are unknown, but we can infer:

- Likely upstream component: a custom or third‑party **PDF rendering engine** (internal name `pdfrender`).
- Version clues: `5.0.3`, `6.0.3`, `7.0.3`, `8.0.3` embedded in the asset filenames.
- Architectures covered: ARM, ARM64, x86, x86_64.

### Native Library Inventory Summary

For this APK we must treat each ZIP as a container of native libraries:

1. **Component:** `pdfrender` PDF renderer
   - **Paths (archives):**
     - `assets/data/lib_pdfrender_5_0_3_code_arm.zip`
     - `assets/data/lib_pdfrender_5_0_3_code_arm_64.zip`
     - `assets/data/lib_pdfrender_5_0_3_code_x86.zip`
     - `assets/data/lib_pdfrender_5_0_3_code_x86_64.zip`
     - `assets/data/lib_pdfrender_6_0_3_code_*.zip`
     - `assets/data/lib_pdfrender_7_0_3_code_*.zip`
     - `assets/data/lib_pdfrender_8_0_3_code_*.zip`
   - **Architecture:** likely arm/arm64/x86/x86_64 based on filenames (exact ELF `file` output not collected).
   - **SONAME:** not directly observable (archives not expanded), unknown.
   - **Likely upstream project:** Internal/third‑party PDF renderer used by PrinterShare; no public direct mapping found.
   - **Version clues:** clear semantic versions in filenames: 5.0.3, 6.0.3, 7.0.3, 8.0.3.
   - **Confidence in identification:** medium – we know there is some native `pdfrender` code, but cannot tie it to a specific upstream library like MuPDF or PDFium without deeper analysis.

No other obvious third‑party native libraries (OpenSSL, libjpeg, etc.) were visible from filenames alone.

## Known Public Vulnerabilities

### 1. CVE-2025-5098 – PrinterShare Gmail Authentication Token Disclosure

**Component:** PrinterShare Android app itself (`com.dynamixsoftware.printershare`).

**Evidence from public sources (NVD, CIRCL, OpenCVE, other trackers):**

- CVE ID: **CVE-2025-5098**
- Product: **Mobile Dynamix PrinterShare Mobile Print** (Android)
- Vendor: **Mobile Dynamix / Dynamixsoftware**
- Affected versions: **all Android versions up to and including `12.15.01`**.
- CPE example: `cpe:2.3:a:dynamixsoftware:printershare::::::android::`
- Short description (from NVD / CIRCL / OpenCVE summaries):
  - *"PrinterShare Android application allows the capture of Gmail authentication tokens that can be reused to access a user's Gmail account without proper authorization."*
- Weakness mappings: **CWE‑200 (Exposure of Sensitive Information)** and **CWE‑313 (Cleartext Storage in a File or on Disk)**.
- CVSS v3.1 (CISA‑ADP enrichment): **9.1 CRITICAL** – `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.

**Relevance to this APK:**

- This APK is **version 12.14.10**, which is **below** the vulnerable upper bound of `12.15.01`.
- At least one source (Feedly aggregating NVD / VulDB) explicitly states: *"Affected versions of PrinterShare Android application prior to or including version 12.15.01 are vulnerable."*
- Therefore, version `12.14.10` is squarely in the vulnerable range.

**Likely root cause (from public write‑ups):**

- Improper handling of Gmail OAuth / authentication tokens:
  - Tokens are reportedly stored or transmitted in a way that allows capture and reuse by attackers.
  - This may include cleartext storage on disk / logs or insufficient protection of tokens in transit, enabling interception.

**Trigger / attack conditions (high‑level):**

- Victim has PrinterShare installed, configured with Gmail integration (for printing from Gmail / Google account).
- Attacker is able to:
  - Read local storage or logs where PrinterShare stores Gmail tokens in cleartext; **or**
  - Intercept PrinterShare network traffic (e.g., over an untrusted Wi‑Fi or compromised device) if tokens are transmitted insecurely.
- Once the attacker obtains the Gmail auth token, they can reuse it to access the victim's Gmail account via Google's APIs or web endpoints, bypassing password / 2FA checks until the token is revoked or expires.

**Impact:**

- **Confidentiality:** High – attacker can read emails, potentially attachments, and other account data.
- **Integrity:** High – attacker may be able to send emails, delete or modify messages, or change account settings depending on token scopes.
- **Availability:** None or minimal – vulnerability is primarily about data access, not denial of service.

**Confidence level:** **High**

- The CVE is directly tied to the PrinterShare product and clearly specifies that versions **up to and including 12.15.01** are affected.
- The analyzed APK is version `12.14.10`, so it falls within that documented range.

**Key references (for human follow‑up):**

- NVD: `https://nvd.nist.gov/vuln/detail/CVE-2025-5098`
- CIRCL: `https://cve.circl.lu/vuln/CVE-2025-5098`
- OpenCVE: vendor=`dynamixsoftware`, product=`printershare`
- Third‑party summaries (SentinelOne‑like writeups, Feedly CVE feed aggregators, VulDB entries)

### 2. CVE-2025-5099 – PrinterShare pdfrender Out‑of‑Bounds Write (Native PDF Rendering)

**Component:** PrinterShare native PDF rendering library (`pdfrender`).

**Evidence from OpenCVE / vulnerability trackers:**

- CVE ID: **CVE-2025-5099**
- Product: **PrinterShare** (same vendor / product as CVE‑2025‑5098)
- Short description (from OpenCVE summary):
  - *"An Out of Bounds Write occurs when the native library attempts PDF rendering, which can be exploited to achieve memory corruption and potentially arbitrary code execution."*
- Severity (from OpenCVE table): **9.8 Critical (CVSS v3.1)**.

**Relevance to this APK:**

- The APK clearly embeds several versions of a PDF rendering native component, named `pdfrender`, for multiple architectures, via `assets/data/lib_pdfrender_*.zip`.
- Public CVE descriptions explicitly mention **native library PDF rendering** within PrinterShare, which aligns with this `pdfrender` component.
- While the exact affected version range for `pdfrender` is not visible in the truncated OpenCVE snippet, the CVE is tied specifically to the PrinterShare product; given that this APK:
  - Is a fairly recent app version (12.14.10) and
  - Includes multiple generations of the `pdfrender` engine (5.x–8.x),
  it is reasonable to assume these builds are in scope of the vulnerability unless an upstream advisory states otherwise.

**Probable root cause (from CVE summary):**

- A bounds‑checking bug in the native PDF rendering code, likely during processing of crafted PDF content:
  - Parsing page objects, fonts, images, or annotations may lead to calculating an incorrect buffer size or index.
  - Writing beyond allocated heap/stack memory results in memory corruption.

**Trigger / attack conditions (high‑level):**

- Attacker persuades the user to open / print a **maliciously crafted PDF** file via PrinterShare (e.g., from local storage, email, cloud file, or remote share).
- When PrinterShare’s `pdfrender` library processes this PDF, the malformed structure triggers the out‑of‑bounds write.
- Exploitation requires skill but can, in principle, lead to arbitrary code execution within the PrinterShare app’s context.

**Impact:**

- **Code execution / sandbox escape within app context:**
  - Attacker code runs with the app’s permissions (network, storage, accounts, contacts, etc.).
  - Can exfiltrate stored data, steal Gmail tokens (even independent of CVE‑2025‑5098), or perform unauthorized printing / network activity.
- **Data corruption / crash:** On unsuccessful exploitation, the app may crash when rendering the malicious PDF.

**Confidence level:** **Medium**

- Strong evidence that PrinterShare’s `pdfrender` library is the vulnerable component.
- Exact mapping between `pdfrender` semantic versions (5.0.3–8.0.3) and affected versions described in public advisories is not fully visible in the truncated OpenCVE text.
- However, given that this APK ships multiple older `pdfrender` versions and the app version falls into the same time window as CVE‑2025‑5099 descriptions, association is **plausible**.

**Key references (for human follow‑up):**

- OpenCVE PrinterShare page: `https://app.opencve.io/cve/?vendor=dynamixsoftware&product=printershare`
- Other vendor‑agnostic vulnerability databases referencing **CVE‑2025‑5099**.

### 3. CVE-2025-5100 – PrinterShare Double‑Free in Temporary Image Handling (Native)

**Component:** PrinterShare native imaging / PDF rendering cleanup routines.

**Evidence from OpenCVE (truncated snippet):**

- CVE ID: **CVE-2025-5100**
- Product: **PrinterShare** (same vendor / product)
- Short description (from snippet):
  - *"A double-free condition occurs during the cleanup of temporary image files, which can be exploited to achieve memory corruption and potentially arbitrary code execution."*
- Severity: High (exact CVSS not visible, but listed as **High** in OpenCVE summary table).

**Relevance to this APK:**

- PrinterShare performs significant PDF / image processing both in Java/Kotlin and native code.
- The presence of a complex native `pdfrender` component and temporary image resources in `res/raw` / `assets` suggests the same native code paths are present.
- As with CVE‑2025‑5099, the affected version range from public advisories is not fully visible here, but references list the PrinterShare product without narrow version exclusion.
- Given that this APK is in the same version family (12.x) as the other PrinterShare CVEs (5098, 5099), and no public fix version is clearly visible in the snippet, this APK is **likely affected** until proven otherwise.

**Probable root cause:**

- Bug in native memory management when cleaning up temporary images used during rendering or print job preparation.
- Double‑free (freeing the same heap allocation twice) can corrupt heap metadata, leading to exploitable memory corruption.

**Trigger / attack conditions (high‑level):**

- User prints or previews content (likely PDFs or images) that trigger specific processing paths.
- A malicious document or crafted sequence of operations forces the vulnerable cleanup routine to operate on already‑freed memory.
- As with other double‑free issues, exploitation requires precise heap manipulation but is a known pathway to arbitrary code execution.

**Impact:**

- **Arbitrary code execution** within the PrinterShare app process.
- Access to all app‑granted permissions and data.

**Confidence level:** **Medium‑Low**

- Association is based on OpenCVE product mapping and general functionality; exact affected app versions and library versions were not visible in the truncated text.
- A cautious assessor should verify against full public advisories or vendor patches.

**Key references:**

- OpenCVE listing for **CVE‑2025‑5100** under the PrinterShare product.

## Exported Components & Intent Behavior (High Level)

Due to time and context limits, a full `apktool` decode was not performed. From `aapt badging` we know:

- There is a **launchable activity**: `com.dynamixsoftware.printershare.ActivityMain`.
- The app **provides a print‑service component**, meaning it likely integrates with Android’s printing framework and may accept intents from other apps to handle print jobs.

Without a full manifest dump, exact exported activities, services, and broadcast receivers (and whether they enforce permissions) are not fully enumerated. However, nothing from the quick inspection indicates an obvious exported‑component CVE similar to documented ones; the main issues identified in public advisories are token handling and native PDF/image processing.

## Open Questions & Uncertainties

- **Exact native library versions and SONAMEs** are unknown because the `lib_pdfrender_*.zip` archives were not expanded. A deeper analysis should:
  - Extract each archive.
  - Run `file`, `readelf -d`, and `strings` on the resulting `.so` files to identify SONAME, build IDs, and embedded version strings.
- **Precise affected ranges for CVE‑2025-5099 and CVE‑2025-5100**:
  - Public summaries confirm they concern PrinterShare’s native components, but detailed advisories and patch notes should be consulted to determine whether 12.14.10 is definitively vulnerable or if fixes were backported.
- **Manifest‑level attack surface:**
  - A full `AndroidManifest.xml` review (via `apktool d` or `aapt dump xmltree`) could reveal exported components that accept external intents and may interact with the vulnerable PDF rendering or Gmail token functionality.

## Short Summary

- **App:** PrinterShare (`com.dynamixsoftware.printershare`), version **12.14.10 (code 480)**.
- **Key capabilities:** Printing from various sources, including Gmail; integrates with Google Sign‑In/Billing; requests broad permissions (contacts, calendar, storage, accounts, network, Bluetooth, ads/analytics).
- **Native components:** No `.so` directly in the APK root, but multiple architecture‑specific archives in `assets/data/` strongly indicate a complex native PDF renderer **`pdfrender`** with versions `5.0.3`, `6.0.3`, `7.0.3`, `8.0.3` for arm/arm64/x86/x86_64.
- **High‑confidence CVE:**
  - **CVE‑2025‑5098** – Gmail authentication token disclosure; this APK’s version (12.14.10) is **explicitly within the vulnerable range** (≤12.15.01). Impact: remote, critical compromise of Gmail account confidentiality and integrity.
- **Probable additional CVEs in native libraries:**
  - **CVE‑2025‑5099** (Out‑of‑Bounds write in PDF rendering) and **CVE‑2025‑5100** (double‑free in temporary image cleanup) plausibly impact the **`pdfrender`** library bundled in this APK, but exact version mapping requires deeper ELF‑level inspection and full advisory review.

Overall, this PrinterShare build should be treated as **vulnerable by design** with at least one confirmed critical information‑disclosure issue (Gmail token handling) and strong indicators of serious native memory‑safety flaws in its PDF rendering stack.