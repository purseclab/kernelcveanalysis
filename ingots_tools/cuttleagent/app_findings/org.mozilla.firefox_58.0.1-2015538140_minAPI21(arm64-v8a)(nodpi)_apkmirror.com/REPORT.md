# Firefox for Android 58.0.1 – APK Security Analysis

## App identification
- **APK**: `org.mozilla.firefox_58.0.1-2015538140_minAPI21(arm64-v8a)(nodpi)_apkmirror.com.apk`
- **Package name**: `org.mozilla.firefox`
- **VersionCode**: `2015538140`
- **VersionName**: `58.0.1`
- **Min SDK**: 21
- **Target SDK**: 23

Evidence from `aapt dump badging`:
```text
package: name='org.mozilla.firefox' versionCode='2015538140' versionName='58.0.1' platformBuildVersionName='6.0-2704002' platformBuildVersionCode='23'
install-location:'internalOnly'
sdkVersion:'21'
targetSdkVersion:'23'
```

## Manifest highlights

Key attributes from `AndroidManifest.xml`:

- `package="org.mozilla.firefox"`
- `android:sharedUserId="org.mozilla.firefox.sharedID"`
- `android:debuggable="false"`
- `android:allowBackup="false"`

### Permissions
The app requests many permissions typical for a full browser. Notable ones:

- Network & internet:
  - `android.permission.INTERNET`
  - `android.permission.ACCESS_NETWORK_STATE`
  - `android.permission.ACCESS_WIFI_STATE`
  - `android.permission.CHANGE_WIFI_STATE`
- Storage:
  - `android.permission.READ_EXTERNAL_STORAGE`
  - `android.permission.WRITE_EXTERNAL_STORAGE`
- Accounts & sync:
  - `android.permission.GET_ACCOUNTS`
  - `android.permission.MANAGE_ACCOUNTS`
  - `android.permission.USE_CREDENTIALS`
  - `android.permission.AUTHENTICATE_ACCOUNTS`
  - `android.permission.WRITE_SYNC_SETTINGS`
  - `android.permission.READ_SYNC_SETTINGS`
  - `android.permission.READ_SYNC_STATS`
- Other:
  - `android.permission.RECEIVE_BOOT_COMPLETED`
  - `android.permission.WAKE_LOCK`
  - `android.permission.VIBRATE`
  - `android.permission.DOWNLOAD_WITHOUT_NOTIFICATION`
  - `android.permission.SYSTEM_ALERT_WINDOW`
  - `android.permission.NFC`
  - `android.permission.RECORD_AUDIO`
  - `android.permission.CAMERA`
  - `com.android.launcher.permission.INSTALL_SHORTCUT`
  - `com.android.launcher.permission.UNINSTALL_SHORTCUT`
  - `com.google.android.c2dm.permission.RECEIVE`
  - App-specific permissions like `org.mozilla.firefox_fxaccount.permission.PER_ACCOUNT_TYPE`, `org.mozilla.firefox.permission.C2D_MESSAGE` (all signature-level)

### Exported components / intents

From the manifest excerpt:

- **Activities**
  - `org.mozilla.gecko.LauncherActivity` – exported, translucent, used as entry point.
  - `org.mozilla.gecko.BrowserApp` – exported, main browser activity.
  - Activity alias `.App` (label "Firefox") targeting `LauncherActivity` with:
    - `MAIN` + `LAUNCHER` + `APP_BROWSER` categories
    - Multiple `VIEW` intent filters for:
      - `http`, `https`, `about`, `javascript`, `firefox` schemes
      - `file` scheme
      - mime types: `text/html`, `text/plain`, `application/xhtml+xml`, `image/svg+xml`, `application/x-xpinstall`
      - `file` paths ending with `.xpi`
    - `WEB_SEARCH` handling
    - NFC NDEF intents for `http`/`https`
    - Custom actions: `org.mozilla.gecko.ACTION_ALERT_CALLBACK`, `org.mozilla.gecko.GUEST_SESSION_INPROGRESS`, `org.mozilla.gecko.UPDATE`, `org.mozilla.gecko.DEBUG`

- **Services** (selection)
  - `org.mozilla.gecko.GeckoService`
  - `org.mozilla.gecko.RemotePresentationService`
  - `org.mozilla.gecko.tabqueue.TabQueueService`
  - `org.mozilla.gecko.Restarter` (separate process `org.mozilla.firefox.Restarter`)
  - `org.mozilla.gecko.media.MediaControlService`

- **Broadcast Receivers** (selection)
  - `org.mozilla.gecko.restrictions.RestrictionProvider` – for `GET_RESTRICTION_ENTRIES` (Android restrictions provider)
  - `com.android.internal.app.ResolverActivity` alias (exported, uses `BrowserApp`)
  - `org.mozilla.gecko.GeckoUpdateReceiver` – `org.mozilla.firefox.CHECK_UPDATE_RESULT`
  - `org.mozilla.gecko.distribution.ReferrerReceiver` – handles `com.android.vending.INSTALL_REFERRER`
  - Notification-related receivers (`WhatsNewReceiver`, `NotificationReceiver`, etc.)

These exported components mean the app can be invoked by other apps via standard `VIEW`, `WEB_SEARCH`, NFC, and some Mozilla-specific custom actions.

## Native library inventory

All `.so` files (as packaged/decompressed by apktool):

1. `/data/workdir/firefox58/assets/arm64-v8a/libfreebl3.so`
2. `/data/workdir/firefox58/assets/arm64-v8a/liblgpllibs.so`
3. `/data/workdir/firefox58/assets/arm64-v8a/libmozavcodec.so`
4. `/data/workdir/firefox58/assets/arm64-v8a/libmozavutil.so`
5. `/data/workdir/firefox58/assets/arm64-v8a/libnss3.so`
6. `/data/workdir/firefox58/assets/arm64-v8a/libnssckbi.so`
7. `/data/workdir/firefox58/assets/arm64-v8a/libsoftokn3.so`
8. `/data/workdir/firefox58/assets/arm64-v8a/libxul.so`
9. `/data/workdir/firefox58/lib/arm64-v8a/libmozglue.so`
10. `/data/workdir/firefox58/lib/arm64-v8a/libplugin-container-pie.so`
11. `/data/workdir/firefox58/lib/arm64-v8a/libplugin-container.so`

### Note on assets-located `.so` files

Files under `assets/arm64-v8a/` are **XZ-compressed** blobs, not bare ELF binaries in the decoded output. `file` and `readelf` output:

```text
/data/workdir/firefox58/assets/arm64-v8a/libfreebl3.so: XZ compressed data, checksum CRC64
... (same for liblgpllibs.so, libmozavcodec.so, libmozavutil.so, libnss3.so, libnssckbi.so, libsoftokn3.so, libxul.so)
readelf: Error: Not an ELF file - it has the wrong magic bytes at the start
```

At runtime, Gecko's loader will decompress these and `dlopen` the result. Based on names and Firefox architecture, they can still be mapped to upstream components as below.

## Per-library analysis

### 1. `libmozglue.so`

- **Path**: `/data/workdir/firefox58/lib/arm64-v8a/libmozglue.so`
- **Arch**: `ELF 64-bit LSB shared object, ARM aarch64`
- **SONAME**: `libmozglue.so`
- **Dependencies (NEEDED)**: `liblog.so`, `libstdc++.so`, `libm.so`, `libdl.so`, `libc.so`
- **Likely component**: Firefox/Gecko runtime support library (memory allocator, startup glue, etc.).
- **Version clue**: Implied by app version – matches Firefox for Android 58.0.1.
- **Confidence**: High – this is a standard Firefox core library.

### 2. `libplugin-container-pie.so`

- **Path**: `/data/workdir/firefox58/lib/arm64-v8a/libplugin-container-pie.so`
- **Arch**: `ELF 64-bit LSB shared object, ARM aarch64`, interpreter `/system/bin/linker64` (position-independent executable style)
- **Dependencies**: `liblog.so`, `libstdc++.so`, `libm.so`, `libdl.so`, `libc.so`
- **Likely component**: Firefox plugin/content process container binary (multi-process architecture).
- **Version clue**: Tied to Firefox 58.0.1 build.
- **Confidence**: High.

### 3. `libplugin-container.so`

- **Path**: `/data/workdir/firefox58/lib/arm64-v8a/libplugin-container.so`
- **Arch**: `ELF 64-bit LSB executable, ARM aarch64`, interpreter `/system/bin/linker64`
- **Dependencies**: Same as `libplugin-container-pie.so`.
- **Likely component**: Alternative / legacy plugin-container binary.
- **Version clue**: Tied to Firefox 58.0.1.
- **Confidence**: High.

### 4. `libxul.so` (compressed in assets)

- **Path**: `/data/workdir/firefox58/assets/arm64-v8a/libxul.so`
- **Status**: XZ-compressed payload, not directly analyzable as ELF in decoded tree.
- **Likely component**: Main Gecko engine library (layout, JS engine, networking, etc.) used by Firefox.
- **Version clue**: Strongly tied to Firefox core version 58.0.1.
- **Confidence**: High on identity, low on exact internal subcomponent versions since we did not decompress.

### 5. NSS / softoken libraries (compressed in assets)

- **`libnss3.so`**
  - Network Security Services (NSS) core crypto/TLS library.
  - Version: Almost certainly aligned with Firefox 58.0.1 desktop NSS version (roughly NSS 3.34.x era), but cannot confirm build number from this artifact alone.
  - Confidence: High on component, low on precise version.

- **`libnssckbi.so`**
  - NSS built-in root CA module.
  - Confidence: High on component, low on precise version.

- **`libsoftokn3.so`, `libfreebl3.so`**
  - NSS software token and freebl (low-level crypto) libraries.
  - Confidence: High on component, low on precise version.

### 6. AV libraries (compressed in assets)

- **`libmozavcodec.so`, `libmozavutil.so`**
  - Firefox/Gecko multimedia codec wrappers and utilities, historically incorporating FFmpeg/libav functionality, though typically statically linked or heavily modified.
  - Version clues: None visible in compressed form; likely match Gecko 58 multimedia stack.
  - Confidence: Medium on them being Mozilla-modified AV codec wrappers rather than stock FFmpeg.

### 7. `liblgpllibs.so` (compressed in assets)

- Likely contains LGPL-licensed third-party components bundled together (e.g., parts of media / graphics / networking libs).
- Without decompression, individual upstream projects and versions are not visible.
- Confidence: Low on exact library list; only that it is Firefox's standard `liblgpllibs.so` container.

### 8. Summary of native stack

- Core Gecko/Firefox engine: `libxul.so`, `libmozglue.so`, `libplugin-container*.so`.
- Crypto/TLS: `libnss3.so`, `libnssckbi.so`, `libsoftokn3.so`, `libfreebl3.so`.
- Media/AV: `libmozavcodec.so`, `libmozavutil.so`.
- Misc LGPL bundle: `liblgpllibs.so`.

No clear evidence of separately-versioned third-party libraries (e.g., a standalone `libssl.so` or `libsqlite3.so`) outside Mozilla’s consolidated binaries, at least not visible due to compression.

## Known vulnerabilities relevant to Firefox 58.0.1

### Context

- This APK is specifically **Firefox for Android 58.0.1**.
- Security advisories for desktop Firefox 58 (MFSA 2018-02) list many CVEs affecting the core Gecko engine (which Android shares largely with desktop at the source level), but mobile can differ in exploitability.
- A separate critical vulnerability **CVE-2018-5124** (unsanitized UI output leading to RCE) was patched in **Firefox 58.0.1 on desktop**; public writeups explicitly state it **does not affect Firefox for Android**.

#### CVE-2018-5124 – Unsanitized output in browser UI (desktop only)
- **Component**: Firefox desktop UI (chrome-privileged documents in browser UI).
- **Source**: Mozilla advisories and third-party writeups (e.g., BleepingComputer, Bitdefender, Neowin).
- **Relevance to this APK**: Public advisories state that **Firefox for Android is not impacted**.
- **Conclusion**: **Not applicable** to this Android APK.

### MFSA 2018-02 – Security vulnerabilities fixed in Firefox 58

Mozilla’s MFSA 2018-02 ("Security vulnerabilities fixed in Firefox 58")
(https://www.mozilla.org/en-US/security/advisories/mfsa2018-02/) lists a large set of CVEs, including:

- **CVE-2018-5089, CVE-2018-5090** – General memory safety bugs fixed in Firefox 58 and ESR 52.6.
- **CVE-2018-5091** – Use-after-free with DTMF timers in WebRTC.
- **CVE-2018-5092** – Use-after-free in Web Workers during fetch cancellation.
- **CVE-2018-5093** – Buffer overflow in WebAssembly during Memory/Table resizing.
- **CVE-2018-5094–5119, 5121–5122, etc.** – Numerous use-after-free, buffer overflow, and information disclosure issues in layout, DOM, WebGL, editor, Reader Mode, Activity Stream, WebExtensions, WebCrypto, etc.

These advisories are for **Firefox 58 desktop** (Windows, macOS, Linux). However:

- Firefox for Android 58.0.1 shares much of the same **Gecko engine** (implemented largely in `libxul.so`, `libmozjs` portions inside it, and supporting libraries).
- Many of these bugs are at the **engine level** and are not obviously desktop-only (e.g., WebRTC, WebAssembly, DOM, layout).
- Mozilla advisories often include a note when a given CVE does not affect Android; some do, some don’t.

Given that:

- This APK is **exactly version 58.0.1**, it is reasonable to assume that engine-level vulnerabilities present in Firefox 57 were *mostly fixed* in 58, and any residual engine bugs fixed in later versions may still be present here.
- MFSA 2018-02 describes bugs **fixed by upgrading to 58**, so 58.0.1 should **already include those fixes**, not remain vulnerable to them.

Therefore:

- **CVE-2018-5089–5122** as listed under MFSA 2018-02 primarily describe issues in **earlier versions that were fixed in 58/58.0.1**.
- This APK (58.0.1) is **likely not vulnerable to that specific set**, but may still contain engine-level vulnerabilities fixed in **later** Firefox versions (59+), which are out of scope of the immediate advisory and would require mapping to later MFSAs.

Because the exact vulnerability state of Firefox for Android 58.0.1 vs all later MFSAs is complex and not easily mapped without full Mozilla internal data, we can only make **high-level statements**:

- As of its 2018 timeframe, Firefox 58.0.1 was **not the latest** for very long and subsequent releases fixed additional issues.
- It is plausible that many engine-level CVEs from **MFSA 2018-04 / 05 / 06, etc.** (Firefox 59, 60, etc.) still affect this version.
- Without precise per-platform notes in each MFSA, we cannot assert exact CVE applicability.

### CVEs tied to Android specifically

Review of Mozilla advisories around early 2018 shows that:

- Some advisories mark **Android-specific** issues (e.g., around address bar spoofing, file URL handling, profile file access) but mostly for older versions (Firefox 40–50 era) or much newer ones.
- The 58.0.1 period did **not** feature a prominently documented Android-only critical bug analogous to CVE-2018-5124 for desktop.

Thus, at this granularity, no single **Android-only CVE** can be concretely attributed to Firefox 58.0.1 using just public advisory summaries, other than knowing that it shares many of the same engine bugs as its desktop counterpart within that release cycle.

## Assessment of third-party / bundled library CVEs

Because `libxul.so`, `liblgpllibs.so`, and the NSS libraries are **Mozilla-curated builds**, mapping them to exact upstream versions (e.g., a particular NSS 3.XX or libvpx, libvorbis, or libpng version) is difficult without symbol strings or version exports, which are hidden by XZ compression in this decoded tree.

General expectations based on Firefox 58 timeframe:

- **NSS**: Likely in the **3.34.x** family, which had some known vulnerabilities fixed in subsequent updates. However, Mozilla’s advisories for Firefox 58 do not call out NSS-specific CVEs unique to this version.
- **Media codecs / LGPL libs**: Firefox historically embeds libraries such as **libvpx**, **libvorbis**, **libtheora**, **libspeex**, **libopus**, **libpng**, **zlib**, etc., often with backported fixes. Public mapping of Firefox 58.0.1 to exact third-party library versions is not straightforward here.

Given the lack of direct evidence from the binary blobs, any attempt to attribute specific third-party CVEs (e.g., a particular libvpx memory corruption) to this APK would be **speculation**.

## Overall security posture for this APK

- Firefox for Android 58.0.1 is a **historically old** browser (early 2018).
- It includes a large attack surface:
  - Full web engine (`libxul.so`) with JavaScript, WebAssembly, WebRTC, etc.
  - Permissions for internet access, storage, audio, camera, NFC, overlay windows, and account management.
  - Many exported intent filters for `VIEW`, `WEB_SEARCH`, and NFC actions, meaning any app can easily direct traffic into it.
- While specific CVEs during its lifecycle were patched by moving to **newer versions**, we cannot cleanly enumerate all those later CVEs from here.

From a CTF / exploit-hunting perspective, realistic attack lines include:

- **Browser engine exploitation** via malicious web content:
  - Targeting known (or historically known) engine bugs in Gecko 58.x (JS engine, layout, WebRTC, WebAssembly, etc.).
  - Exploits would typically be agnostic to desktop vs Android once the underlying engine code is shared.

- **File / content handling quirks**:
  - Handling of `file:` URLs, `about:`, `javascript:` URLs, `.xpi` files, and NFC-dispatched URLs, as exposed by manifest intent filters.

- **Privilege boundary considerations**:
  - The app runs with a shared user ID `org.mozilla.firefox.sharedID`, which could be interesting if other Firefox-family apps are installed sharing that UID.

However, none of these can be clearly tied to a single CVE with **high confidence** using only this APK and public summaries.

## Candidate CVE list (informational, not asserted exploitable here)

Below is a **non-exhaustive list** of notable CVEs related to the Firefox 57–58 timeframe. These are provided for reference and potential further research, but we do **not** claim that this 58.0.1 Android APK is vulnerable to (or even affected by) each specific item:

- **MFSA 2018-02 (Firefox 58)** – engine-level issues generally fixed *by* Firefox 58 (thus affecting earlier versions):
  - `CVE-2018-5089`, `CVE-2018-5090` – General memory safety bugs.
  - `CVE-2018-5091` – Use-after-free with DTMF timers in WebRTC.
  - `CVE-2018-5092` – Use-after-free in Web Workers.
  - `CVE-2018-5093` – Heap buffer overflow in WebAssembly Memory/Table resizing.
  - `CVE-2018-5103` – Use-after-free during mouse event handling.
  - `CVE-2018-5104` – Use-after-free during font face manipulation.
  - `CVE-2018-5105` – WebExtensions can save and execute local files without prompts.
  - `CVE-2018-5118` – Activity Stream images can attempt to load local content via `file:` URLs.
  - `CVE-2018-5119` – Reader view CORS bypass for cross-origin content.
  - `CVE-2018-5121` – WebExtensions can read local files from private browsing.
  - `CVE-2018-5122` – WebCrypto DoCrypt integer overflow (theoretical OOB write).

- **CVE-2018-5124** – Unsanitized output in browser UI leading to RCE.
  - Explicitly **not affecting Firefox for Android** per public reports.

Again, the main takeaway for this APK is the **age** of the Gecko engine; newer Firefox releases fix dozens of additional engine-level and sometimes Android-specific issues not enumerated here.

## Open questions / uncertainties

- Exact internal versions of **NSS**, **media codecs**, and other third-party libraries within `libxul.so` and `liblgpllibs.so` cannot be determined from compressed assets alone.
- Per-CVE applicability to **Firefox for Android vs desktop** cannot be resolved without detailed MFSA platform notes and/or source/binary diffs, which are not present here.
- We did not decompress the XZ-packed `.so` payloads; doing so could reveal useful version strings and symbol names for more fine-grained CVE mapping.

## Concise summary

- **App**: Firefox for Android
- **Package**: `org.mozilla.firefox`
- **Version**: 58.0.1 (minSdk 21, targetSdk 23)
- **Key libraries**:
  - Gecko core: `libxul.so` (compressed), `libmozglue.so`, `libplugin-container*.so`
  - Crypto/TLS: `libnss3.so`, `libsoftokn3.so`, `libfreebl3.so`, `libnssckbi.so` (all compressed in assets)
  - Media: `libmozavcodec.so`, `libmozavutil.so`, plus `liblgpllibs.so` bundle (compressed)
- **CVEs**:
  - `CVE-2018-5124` (critical UI RCE) – explicitly **not applicable** to Firefox for Android.
  - Numerous engine-level CVEs around the Firefox 57–58 timeframe exist, but **MFSA 2018-02 issues are generally fixed by 58/58.0.1**.
  - Additional later CVEs likely affect 58.0.1 relative to newer versions, but exact mapping is uncertain without more detailed Mozilla data.
- **Overall confidence**:
  - High on app identification and native library inventory.
  - High on mapping of core components (Gecko, NSS, AV libs).
  - Low-to-medium on precise CVE applicability to this specific Android build beyond what Mozilla explicitly states in advisories.