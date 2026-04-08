# HTTP File Server (+WebDAV) 1.4.1 – APK Security Analysis

## App identification

- **APK file**: `/data/apps/HTTP File Server (+WebDAV)_1.4.1_APKPure.apk`
- **Package name**: `slowscript.httpfileserver`
- **Version**: `1.4.1` (versionCode `141`)
- **minSdkVersion**: 15
- **targetSdkVersion**: 30
- **App label**: `HTTP File Server`

This is an Android HTTP/WebDAV file server app that exposes a file-sharing HTTP server from the device.

## Permissions

From `AndroidManifest.xml` / `aapt dump badging`:

- `android.permission.ACCESS_WIFI_STATE`
- `android.permission.INTERNET`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.MANAGE_EXTERNAL_STORAGE`
- `android.permission.ACCESS_NETWORK_STATE`

Notable points:
- `MANAGE_EXTERNAL_STORAGE` and legacy external storage flags indicate broad filesystem access, which makes any path traversal or directory escape issues more impactful.

## Components & exported behavior

From `AndroidManifest.xml`:

- **Activities**:
  - `slowscript.httpfileserver.MainActivity`
    - Has `MAIN` + `LAUNCHER` intent filter (entry point).
  - `slowscript.httpfileserver.ShareActivity`
    - Intent filter:
      - `action.SEND`, `action.SEND_MULTIPLE`
      - Category: `DEFAULT`
      - Data: `*/*`
    - This activity is implicitly exported, so other apps can send arbitrary content to be shared via this HTTP server.
  - `slowscript.httpfileserver.SettingsActivity`
  - `slowscript.httpfileserver.TextViewActivity`
  - `slowscript.httpfileserver.About`
  - `slowscript.httpfileserver.ChooseDirectory`

- **Service**:
  - `slowscript.httpfileserver.ServerService`
    - Likely hosts the HTTP/WebDAV server.

- **Broadcast receiver**:
  - `slowscript.httpfileserver.ServerService$ConfirmConnectionReceiver`
    - `android:exported="false"` (explicitly not exported).
    - Intent actions: `action_confirm`, `action_deny` (internal control of connections).

Intent-related behavior:
- The app can receive `SEND` / `SEND_MULTIPLE` from any app for any MIME type; this is the primary cross-app interaction route.

## Native library inventory

Using `unzip -l` over the APK and filtering for `.so` files, no native libraries were found:

- **Result**: `NO_SO_FILES`

Therefore, this app appears to be **pure Java/Kotlin**, with no bundled `.so` files, and there is no native-library CVE surface inside the APK itself.

## Third-party libraries (high-level)

From the assets `licenses` directory:

- `assets/licenses/nanohttpd.txt` – indicates use of **NanoHTTPD**, a small Java HTTP(S) server.
- `assets/licenses/zxing.txt` – indicates use of **ZXing** (barcode/QR code scanning library).
- `assets/licenses/bc.txt` – likely **Bouncy Castle** crypto library.

The exact versions of these libraries are **not evident** from the APK file names or metadata we used. Determining specific versions would require deeper code/strings analysis beyond the scope of the current instructions, so any mapping from these libraries to CVEs would be speculative.

## Known public vulnerabilities

### 1. CVE-2021-40668 – Path Traversal in HTTP File Server Android app

- **Component**: HTTP File Server Android application by `slowscript` (package `slowscript.httpfileserver`).
- **Version**: 1.4.1 (this APK) and likely earlier versions.
- **Reference evidence**:
  - Public advisory: *“Path Traversal in slowscript.httpfileserver”* (ProjectBlack writeup).
  - CVE entry: CVE-2021-40668 on CVE and CVE tracking sites.
  - The advisory explicitly states that **“The Android application HTTP File Server (Version 1.4.1) by 'slowscript' is affected by a path traversal vulnerability that permits arbitrary directory listing, file read, and file write.”*

- **Vulnerability type**: Path traversal / directory traversal (CWE-22 – Improper Limitation of a Pathname to a Restricted Directory).

- **Trigger conditions (high level)**:
  - An attacker can send crafted HTTP requests to the HTTP/WebDAV server exposed by the app (i.e., can reach the device on the network and the server is running).
  - The app allows configuring a “root directory” for file sharing, but due to insufficient normalization and checks, user-supplied paths containing traversal sequences (e.g., `../`) can escape this root.

- **Impact (high level)**:
  - Arbitrary directory listing outside the configured root directory.
  - Arbitrary file **read** outside the configured root directory.
  - Arbitrary file **write** outside the configured root directory (depending on HTTP/WebDAV methods and implementation details).
  - If the server is reachable from untrusted networks (e.g., via port-forwarding, VPN, or Wi‑Fi guest networks), an attacker can exfiltrate or overwrite files on the device’s external storage.
  - Because the app holds `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, and `MANAGE_EXTERNAL_STORAGE`, the HTTP server effectively becomes a remote file system proxy with excessive privileges.

- **Affected version range**:
  - The ProjectBlack advisory notes version **1.4.1** as affected and suggests older versions are also probably impacted, though not validated.
  - The CVE product listing includes `http_file_server_project:http_file_server:1.4.1`.

- **Confidence**: **High**
  - Exact package name, app name, and version match the APK under analysis.

- **Representative references**:
  - CVE details: `https://www.cvedetails.com/cve/CVE-2021-40668`
  - Advisory / writeup: `https://projectblack.io/blog/path-traversal-in-slowscript-httpfileserver`

### 2. Potential library CVEs (NanoHTTPD, ZXing, Bouncy Castle)

- **NanoHTTPD** (`assets/licenses/nanohttpd.txt`)
  - The app uses NanoHTTPD as its embedded HTTP server. Various security issues have been reported against NanoHTTPD over time, but:
    - The license file in this APK does **not** contain a clear version string.
    - No explicit NanoHTTPD version could be extracted based solely on the cheap-evidence methods (filename, manifest, basic asset inspection).
    - Without knowing the NanoHTTPD version (or a tight version range), mapping to specific CVEs (e.g., issues involving malformed headers or request smuggling) would be speculative.

- **ZXing** (`assets/licenses/zxing.txt`)
  - ZXing has had some memory and denial-of-service style issues in certain formats and versions, but they are typically exploitable only via crafted barcodes when the app actively scans them.
  - This app appears primarily to be a file server; ZXing may be used for QR-code URLs or sharing, not clear from metadata alone.
  - Version unknown; therefore, no concrete CVE can be confidently attributed.

- **Bouncy Castle** (`assets/licenses/bc.txt`)
  - Bouncy Castle has multiple CVEs across versions (cryptographic flaws, side channels, etc.).
  - Again, no version string is available via low-cost inspection; the presence of the library is known, but its exact version is not.

Given the lack of precise version information for these libraries with our allowed level of inspection, I **do not assign any specific CVEs** to them in this report.

## Cross-app / intent interactions

- The app exposes an activity `ShareActivity` with an `ACTION_SEND` and `ACTION_SEND_MULTIPLE` intent filter for `*/*` MIME type and `DEFAULT` category.
- This means **any other app** can send files/content to HTTP File Server to share them over the embedded HTTP/WebDAV server.
- If a malicious or compromised local app can influence what root directory or which paths are used by the server, it could potentially help an attacker exploit CVE-2021-40668 to reach sensitive paths on storage more easily.

## Open questions / uncertainties

- **NanoHTTPD version**: No clear indication of the exact version in the APK using quick inspection. Without this, we can’t reliably tie to specific NanoHTTPD CVEs.
- **ZXing and Bouncy Castle versions**: Same limitation; only generic presence is known.
- **Fix status**: Newer versions (e.g., 1.7 per Aptoide listing) may have addressed CVE-2021-40668, but this APK is explicitly the vulnerable 1.4.1 release.

## Compact summary

- **App**: HTTP File Server (+WebDAV) (`slowscript.httpfileserver`)
- **Version analyzed**: 1.4.1 (versionCode 141)
- **Native libraries**: None – pure Java/Kotlin APK (no `.so` files bundled).
- **Notable third-party libs**: NanoHTTPD (HTTP server), ZXing, Bouncy Castle (versions unknown).
- **Key permissions**: INTERNET, MANAGE_EXTERNAL_STORAGE, READ/WRITE_EXTERNAL_STORAGE.
- **Exported behavior**: `ShareActivity` accepts `SEND` / `SEND_MULTIPLE` intents with arbitrary MIME type from other apps; main UI and HTTP server service run locally on the device.
- **Confirmed CVE**:
  - **CVE-2021-40668** – Path traversal vulnerability in HTTP File Server 1.4.1 (this app/version). Allows arbitrary directory listing, file read, and file write outside the configured root directory via crafted HTTP/WebDAV requests. Impact amplified by broad storage permissions.
- **Overall confidence**: **High** for CVE-2021-40668 affecting this APK; **low/uncertain** for any specific NanoHTTPD/ZXing/Bouncy Castle CVEs due to missing version details.