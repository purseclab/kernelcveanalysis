# Documents To Go (com.dataviz.docstogo) – APK Analysis

## App identification

- Package name: `com.dataviz.docstogo`
- App name (application class): `com.dataviz.dxtg.common.android.DocsToGoApp`
- VersionCode: `1582`
- VersionName: `4.003`
- Min SDK: 19 (Android 4.4)
- Target SDK: 29 (Android 10)
- Shared user ID: `com.dataviz.docstogoapp`

Evidence: `aapt dump badging` and `aapt dump xmltree` on AndroidManifest.xml.

## Manifest-Visible Behavior

### Exported activities / intent surface

From `AndroidManifest.xml` (partial, via `aapt dump xmltree`):

- `com.dataviz.dxtg.common.launcher.android.LauncherActivity`
  - Intent filters:
    - `android.intent.action.MAIN` + `android.intent.category.LAUNCHER`
    - Custom action `com.dataviz.dxtg.common.launcher.android.LauncherActivity` + `android.intent.category.DEFAULT`

- `com.dataviz.dxtg.stg.control.android.SheetToGoActivity`
  - Intent filters:
    - `android.intent.action.VIEW`, `android.intent.action.EDIT`
    - `android.intent.category.DEFAULT`
    - Data MIME types include multiple Excel / Office types, for example:
      - `application/vnd.ms-excel`
      - `application/ms-excel`
      - `application/msexcel`
      - `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`
      - `application/vnd.openxmlformats-officedocument.spreadsheetml.template`
      - `application/vnd.ms-excel.sheet.macroEnabled.12`
      - `application/vnd.ms-excel.template.macroEnabled.12`

This means the app will handle VIEW / EDIT intents for Excel / Office documents coming from other apps (email, file managers, browsers, etc.), which can be relevant for file‑parsing attack surfaces.

### Permissions

From manifest dump:

- `android.permission.INTERNET`
- `android.permission.ACCESS_NETWORK_STATE`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.ACCESS_WIFI_STATE`
- `com.android.email.permission.READ_ATTACHMENT`
- `com.google.android.providers.gmail.permission.READ_GMAIL`
- `com.google.android.providers.gsf.permission.READ_GSERVICES`
- `com.google.android.gms.permission.ACTIVITY_RECOGNITION`
- `android.permission.GET_ACCOUNTS`
- `android.permission.USE_CREDENTIALS`
- `com.android.vending.BILLING`
- `com.sec.android.iap.permission.BILLING`
- `android.permission.WAKE_LOCK`
- `android.permission.MANAGE_ACCOUNTS`
- `com.sony.mobile.permission.SYSTEM_UI_VISIBILITY_EXTENSION`

Notable points:

- Access to external storage (read/write) combined with handling of document VIEW/EDIT intents means the app can read files provided by other apps or from shared storage.
- Permissions to read Gmail and generic email attachments (`READ_GMAIL`, `READ_ATTACHMENT`) imply tight integration with email clients and additional document ingestion surfaces.

### Libraries referenced in manifest

- Uses optional library `org.apache.http.legacy` (Android’s legacy Apache HTTP client wrapper).
- Integrates Google Play Services / Ads via:
  - Meta‑data `com.google.android.gms.version`
  - Meta‑data `com.google.android.gms.ads.APPLICATION_ID`

## Native library inventory

Steps:

- Extracted `lib/*` from the APK to `/data/workdir/docstogo`.
- Listed directory contents; only `AndroidManifest.xml` is present, and there is no `lib/` directory and no `.so` files.
- Verified with glob search for `**/*.so` under `/data/workdir/docstogo` – result: **no matches**.

Conclusion: **This specific APK bundle contains no native `.so` libraries.** All code appears to be Java/Kotlin (or at least non‑native) from the APK inspection steps performed.

Because there are no `.so` files, there is no per‑library ELF/SONAME/version analysis to perform.

## Third‑party SDKs and components (non‑native)

Based on manifest only (no decompilation done in this run):

- Google Play Services / Google Mobile Ads (GMS / AdMob)
- Legacy Apache HTTP client via `org.apache.http.legacy`

Exact versions of these Java libs are **not visible from manifest alone** and would require deeper decompilation/inspection, which was not performed here.

## Known vulnerabilities / CVEs

### 1. App‑specific CVEs for Documents To Go

Targeted web search for combinations of the product and version, e.g.:

- `"Documents To Go" Android 4.003 CVE`

did **not** return any credible, product‑specific CVEs for `com.dataviz.docstogo` or “Documents To Go” Android app version 4.003.

No entries were found in major public advisory resources linking CVE identifiers directly to this app or vendor **Dataviz** for mobile.

**Conclusion:**
- **No app‑specific public CVEs** could be identified for Documents To Go 4.003 (Android) based on available public sources.
- Confidence: **medium‑high** (given targeted searches, but always possible that niche or non‑CVE‑tracked advisories exist elsewhere).

### 2. Platform / generic Android issues

This APK targets Android 10 (SDK 29) and can run on Android 4.4+ (SDK 19+). Generic Android OS vulnerabilities (across frameworks, kernel, etc.) are tracked extensively, but they apply to the **device OS**, not the app itself. Examples include issues listed in Android Security Bulletins and CVE aggregators.

Because those affect the OS and not this APK as a product, they are **out of scope** for app‑specific vulnerability reporting here.

### 3. Third‑party component CVEs (potential but unconfirmed)

#### 3.1 Google Play Services / AdMob

- The manifest indicates use of Google Play Services and Google Mobile Ads.
- Many CVEs have historically affected Google Play Services or the broader Android ecosystem, but they are generally fixed via Google Play updates on the device or OS updates, not via bundling in third‑party APKs.
- Without exact library versions from the `classes.dex` or build configuration, mapping to specific CVEs (e.g., for precise `com.google.android.gms:play-services-ads` versions) is speculative.

**Conclusion:**
- While Google Play Services / Ads have had vulnerabilities historically, there is **insufficient evidence** here to tie this APK to any specific CVE.
- Confidence: **low** for any specific mapping.

#### 3.2 Apache HTTP client (`org.apache.http.legacy`)

- The app declares use of `org.apache.http.legacy`, which is the legacy Apache HTTP client packaged with newer Android versions.
- Known security concerns exist around outdated HTTP clients and TLS handling practices, but they are usually:
  - OS‑level component issues, or
  - Application‑specific misuse (e.g., accepting all certificates), which would require code auditing rather than CVE mapping from metadata.

No clear CVEs can be mapped to this app without evidence of a specific vulnerable Apache HTTP library version bundled inside the APK (and we did not extract code beyond the manifest), so any mapping would be speculative.

**Conclusion:**
- No specific CVE can be responsibly claimed for the app regarding Apache HTTP client usage from manifest data alone.
- Confidence: **low** for any specific mapping.

## Open questions / limitations

- No decompilation or Java‑bytecode–level analysis was performed, so:
  - Exact versions of Google Play Services / Ads and other third‑party libs are unknown.
  - Potential logic bugs (e.g., insecure WebView usage, certificate pinning mistakes, path traversal in file handling) were not evaluated.
- No `.so` files are present in this APK, so there is no native code attack surface to map to known library CVEs.
- No app‑specific official security advisories from Dataviz or common CVE databases were identified for this version.

## Summary

- **App**: Documents To Go (package `com.dataviz.docstogo`)
- **Version**: 4.003 (versionCode 1582)
- **Native libs**: None found – APK has no bundled `.so` files.
- **Key components**:
  - Handles VIEW/EDIT intents for Excel and related Office document MIME types.
  - Integrates with email apps and Gmail for reading attachments.
  - Uses Google Play Services / Ads and the legacy Apache HTTP library (`org.apache.http.legacy`).
- **Candidate CVEs**:
  - No app‑specific CVEs found.
  - No specific third‑party library CVEs can be mapped with high confidence from manifest‑only evidence.

Overall confidence: **Medium‑high** that there are **no currently known public CVEs that can be definitively associated with this exact APK build** based solely on accessible metadata and high‑level inspection performed here.