# Overall Vulnerability Summary – /data/apps Corpus

This report summarizes the per‑app analyses already written in the app‑specific reports under `/data/output/*/REPORT.md`. It focuses on:

- Highest‑confidence, version‑matched vulnerabilities
- Reused or repeated vulnerable components
- Cross‑app interaction and potential exploitation chains (especially via intents)
- Avoiding re‑doing raw APK or ELF analysis

---

## 1. Highest‑confidence findings (by app)

### 1.1 PrinterShare – com.dynamixsoftware.printershare 12.14.10

**Status:** Multiple credible, high‑impact issues.

- **Confirmed CVE – Gmail token disclosure**  
  - **CVE‑2025‑5098** – PrinterShare Android app stores/transmits Gmail authentication tokens insecurely.  
  - Affected versions: *up to and including* **12.15.01** → this APK (12.14.10) is clearly in scope.  
  - Impact: Critical compromise of Gmail account confidentiality and integrity (read/send/delete emails, modify data) once a token is captured (e.g., via local file access or traffic interception, depending on how the token is mishandled).

- **Probable native RCEs in PDF engine (medium confidence)**  
  Based on public writeups and OpenCVE entries:
  - **CVE‑2025‑5099** – Out‑of‑bounds write in the `pdfrender` native library during PDF rendering.  
  - **CVE‑2025‑5100** – Double‑free in temporary image handling in the same native stack.
  - APK evidence: multiple `assets/data/lib_pdfrender_{5,6,7,8}_0_3_code_*.zip` archives for arm/arm64/x86/x86_64 strongly indicate the affected library is present and used.  
  - Impact: Memory corruption → likely code execution in the PrinterShare process when a user prints or previews crafted PDFs.

**Why high‑priority:**
- Tokens exposed from PrinterShare can be used by *any other code on the device* (or attacker off‑device) to access Gmail; combined with native RCE this enables full compromise of the account and PrinterShare’s data.

---

### 1.2 Adobe Acrobat Reader – com.adobe.reader 21.7.0.18750

**Status:** One well‑documented RCE affects this exact version range.

- **CVE‑2021‑40724 – Path traversal → arbitrary code execution**  
  - Product: Adobe Acrobat Reader for Android.  
  - Vulnerable versions: **≤ 21.8.0 / < 21.9.0** (per APSB21‑89 and third‑party analyses).  
  - This APK: **21.7.0.18750** → squarely in the vulnerable range.  
  - Root cause: Path traversal when handling attacker‑controlled URLs/files; in combination with dynamic feature loading this can be abused to load attacker‑controlled code from private storage.  
  - Impact: Remote code execution within the Reader sandbox, with access to external storage, accounts, camera, contacts, etc.

**Why high‑priority:**
- Ubiquitous app with powerful permissions; simple delivery vector (malicious URL or PDF).

---

promising:

### 1.3 Home Assistant Companion – io.homeassistant.companion.android 2023.8.1

**Status:** One high‑impact, app‑specific CVE confirmed.

- **CVE‑2023‑41898 – Arbitrary URL loading in exported WebView activity**  
  - Product: Home Assistant Companion for Android.  
  - Vulnerable versions: **up to 2023.8.2**, fixed in **2023.9.2**.  
  - This APK: **2023.8.1‑full** → in vulnerable range.  
  - Issue: Exported activity `io.homeassistant.companion.android.launch.my.MyActivity` loads URLs from `Intent` data into a WebView without proper validation.  
  - Attack: A *local* malicious app sends a crafted intent to `MyActivity` causing it to load an attacker‑controlled URL.  
  - Impact: Arbitrary JavaScript execution in the Companion WebView; credential theft and possible “limited native code execution” via JS bridges or token abuse against Home Assistant Core.

**Why high‑priority:**
- Direct, documented cross‑app attack path via exported activity; only requires a second, unprivileged app on device.

---

promising:

### 1.4 HTTP File Server (+WebDAV) – slowscript.httpfileserver 1.4.1

**Status:** One critical, network‑exposed vulnerability confirmed.

- **CVE‑2021‑40668 – Path traversal in Android HTTP File Server**  
  - Product: HTTP File Server (+WebDAV) by `slowscript` (`slowscript.httpfileserver`).  
  - Version: **1.4.1**, explicitly called out as vulnerable.  
  - Issue: Directory traversal in HTTP/WebDAV path handling escapes the configured root directory.  
  - Impact: Remote client on the network can list, read, and potentially write files *outside* the intended share root. Amplified by app permissions (`MANAGE_EXTERNAL_STORAGE`, READ/WRITE external storage).  
  - Attack: Any reachable device running the server is exposed to crafted HTTP/WebDAV requests.

**Why high‑priority:**
- Exposes the device’s external storage contents over HTTP to any reachable network attacker.

---

promising:

### 1.5 Call Blocker – com.cuiet.blockCalls 6.6.3

**Status:** One exact product/version CVE.

- **CVE‑2023‑29728 – Feature‑data tampering → elevation of privilege**  
  - Product: Call Blocker application 6.6.3 for Android (`com.cuiet.blockCalls`).  
  - Version: This APK is exactly **6.6.3**.  
  - CVSS: 9.8 Critical (NVD).  
  - Issue: Attacker can tamper with feature‑related data; details of the data channel are sparse.  
  - Modeled as remotely exploitable with no privileges or user interaction.  
  - Impact: Severe elevation of privilege to the app’s own power set (read/write call logs, read contacts, place calls, etc.).

**Why high‑priority:**
- Direct EoP in a highly privileged app; pairs well with any local foothold.

---

### 1.6 VLC for Android – org.videolan.vlc 3.0.5

**Status:** Multiple engine‑level media parsing vulnerabilities likely present.

- **CVE‑2019‑13602 – MP4 EIA‑608 integer underflow**  
  - Affected: VLC media player **through 3.0.7.1**.  
  - This APK’s engine: VLC 3.0.x (3.0.5) embedded in `libvlcjni.so`.  
  - Impact: Integer underflow → heap overflow while parsing specially crafted MP4 with EIA‑608 captions; DoS and plausible code execution.

- **CVE‑2024‑46461 – MMS integer overflow**  
  - Affected: VLC media player **3.0.20 and earlier**.  
  - 3.0.5 is in scope.  
  - Impact: Integer overflow processing crafted MMS responses → heap overflow → DoS/RCE.  

- **CVE‑2022‑41325 – VNC module integer overflow** (medium confidence)  
  - Affected: VLC media player **through 3.0.17.4**.  
  - Applicability depends on whether Android build includes and exposes the VNC module.

**Why high‑priority:**
- VLC accepts arbitrary remote and local media via intents; these bugs are triggered by crafted media/streams that any other app or attacker can feed to it.

---

promising:

### 1.7 mpv‑android – is.xyz.mpv 2021‑03‑10

**Status:** Strong candidate for at least one mpv‑core CVE; many FFmpeg issues plausible.

- **CVE‑2021‑30145 – mpv M3U format string vulnerability** (medium confidence)  
  - Affected mpv: **≤ 0.33.0**.  
  - This APK: 2021‑03‑10 build, almost certainly based on mpv 0.32–0.33.  
  - Attack: User opens a crafted `.m3u` playlist; format‑string bug leads to code execution in the player.  
  - Impact: RCE within mpv’s sandbox; can be combined with the app’s storage/network permissions.

- Numerous FFmpeg CVEs from the era are likely relevant but cannot be pinpointed to exact IDs without more version data.

**Why important:**
- Very broad intent surface: MPVActivity accepts many schemes (rtmp/rtsp/mms/http/https/etc.) and content/file URIs from other apps.

---

### 1.8 Firefox for Android – org.mozilla.firefox 58.0.1

**Status:** Old browser engine; no single Android‑specific CVE confidently tied, but clearly lagging behind many MFSA fixes.

- Shares Gecko/NSS/JS engine with Firefox 58 desktop; MFSA 2018‑02 issues are *fixed* by 58, but later advisories (59+) likely contain vulnerabilities that still affect this version.  
- **CVE‑2018‑5124** (desktop RCE) is explicitly *not applicable* to Android.  
- In general, treat this as an **outdated browser** with multiple historical engine bugs exploitable via web content.

**Why it matters:**
- If used as a system browser, can be driven via intents/URLs from other apps or remote content.

---

### 1.9 Trichrome Library – com.google.android.trichromelibrary 100.0.4896.127

**Status:** Engine build that *fixes* a major Chrome 100 0‑day; not clearly vulnerable itself.

- Underlying engine: Chromium 100.0.4896.127 (Chrome/WebView).  
- **CVE‑2022‑1364 – V8 type confusion** is fixed *by* this version; earlier 100.x builds were vulnerable.  
- No additional Chrome‑100‑specific CVE can be firmly attributed solely from this build’s metadata.

**Why relevant context:**
- This shared library underpins Chrome and Android System WebView on the device; but the actual exploitable surface is in the client browsers, not this static APK by itself.

---

### 1.10 Apps with no mapped CVEs yet

- **AMdroid Alarm Clock – com.amdroidalarmclock.amdroid 5.3.2**  
  - Bundles Instabug `libibg-native.so` but no known CVEs for app or SDK.  
  - High‑privilege app (alarms, overlays, background location) but no public vulnerabilities.

- **Documents To Go – com.dataviz.docstogo 4.003**  
  - Handles Excel/Office documents via intents; no known public CVEs for the Android app; pure Java (no `.so` libraries).

- **BestWeather – com.icoolme.android.weather 7.3.0**  
  - Heavy mix of Chinese ad/analytics SDKs and AMap 9.3.0, but no version‑matched CVEs identified.  
  - Lots of permissions and a custom `READ_CONTENTPROVIDER` permission (normal) but no documented CVE.

- **Weather M8 – pro.burgerz.miweather8 2.5.0**  
  - Modern AndroidX stack, many ad SDKs (Appodeal, MMKV, ttEncrypt, Pangle, etc.), and a custom `libweatherm8.so` with embedded API secrets.  
  - No public CVEs mapped; primary concerns are API key exposure and privacy, which are not CVE‑tracked.

---

## 2. Reused / common components & patterns

This section notes components or patterns that appear across multiple apps, and what is known about vulnerabilities associated with them.

### 2.1 Media engines and demuxers

- **VLC core (libvlc)**  
  - Present only in VLC for Android.  
  - Numerous engine‑level parsing bugs (MP4, MMS, VNC, MKV, etc.) with confirmed CVEs; see VLC section above.

- **mpv + FFmpeg**  
  - Present in mpv‑android only (`libmpv.so` + `libav*` libs).  
  - mpv: candidate for CVE‑2021‑30145.  
  - FFmpeg: many historical CVEs; concrete IDs in this build are uncertain.

- **Mozilla Gecko + NSS + media stack**  
  - Present in Firefox 58 under Mozilla’s own `libxul` and friends; shared codebase with desktop but compressed and hard to version precisely.  
  - Known to have numerous engine bugs historically, but mapping to exact CVEs per Android build is weak.

- **Adobe PDF engine**  
  - Present in Adobe Reader; core libraries like `libAdobeReader.so`, `libAGM.so`, `libCoolType.so`, `libAdobeJP2K.so`.  
  - CVE‑2021‑40724 is confirmed; other desktop CVEs might share code paths but cannot be confidently claimed from mobile metadata.

- **PrinterShare `pdfrender`**  
  - Unique to PrinterShare, but appears in multiple versioned archives within the APK; associated with CVE‑2025‑5099 and CVE‑2025‑5100.

### 2.2 Crash & analytics SDKs

- **Sentry Native / Sentry Android NDK**  
  - Used only by Home Assistant Companion (`libsentry.so`, `libsentry-android.so`).  
  - No public client‑side CVEs identified.

- **Instabug (libibg-native.so)**  
  - Used by AMdroid Alarm Clock only.  
  - No known CVEs; mostly analytics and bug‑reporting functions.

- **APMInsight‑style libraries (`libapminsight*.so`)**  
  - Used by Weather M8 and BestWeather (and likely other Chinese apps in general).  
  - No CVEs found; they expand attack surface but are not tied to specific known bugs.

- **Crashlytics native**  
  - Present in Adobe Reader (`libcrashlytics*.so`).  
  - No distinctive CVEs directly referencing those libraries.

### 2.3 Storage / key‑value libraries

- **Tencent MMKV (`libmmkv.so`)**  
  - Weather M8 and BestWeather both embed MMKV; possibly other apps too.  
  - Public CVE **CVE‑2024‑21668** affects *react‑native‑mmkv* wrapper (logging of encryption keys), not raw `libmmkv.so`.  
  - No CVE explicitly on MMKV core.

- **Custom/proprietary key‑value helpers**  
  - BestWeather and Weather M8 both use additional native KV libraries (`libnativekv.so` in BestWeather; `libweatherm8.so` in Weather M8) primarily to hide secrets.

### 2.4 Ad/mediation SDKs

- **Pangle / Bytedance (`libpangleflipped.so`, `libtt*` libs, `libEncryptorP.so`)**  
  - BestWeather and Weather M8 both include Bytedance/Pangle and ttEncrypt‑style modules.  
  - No specific CVEs identified; privacy and obfuscation concerns only.

- **Appodeal / BidMachine / multi‑network mediation**  
  - Heavy in Weather M8 (Java side + `libapd_native_watcher.so`).  
  - BestWeather uses a different but similarly complex ad stack.  
  - No public CVEs; security issues here are more likely around data collection & logic than memory safety.

### 2.5 System/runtime components

- **libc++_shared.so (LLVM C++ runtime)**  
  - Present in Adobe Reader, mpv‑android, VLC, and others.  
  - No widely known, app‑specific CVEs; vulnerabilities would more likely be in consumer code.

---

## 3. Cross‑app interaction and possible chains

Here we outline ways vulnerabilities could chain across apps via intents, shared data, or platform components.

### 3.1 Local intent chains (app‑to‑app)

- **Home Assistant Companion (CVE‑2023‑41898) as a target**  
  - Any unprivileged local app can trigger `MyActivity` with a malicious `Intent` to load an attacker‑controlled URL.  
  - Candidate attackers: any installed app, including benign‑looking flashlight, game, or even another CTF app.  
  - Potential follow‑on: stolen Home Assistant tokens could then be used from other apps or external devices to control a user’s smart‑home installation.

- **HTTP File Server’s `ShareActivity` as a pivot**  
  - Any app can send `ACTION_SEND` / `SEND_MULTIPLE` intents to HTTP File Server’s `ShareActivity`.  
  - If an attacker controls another app, they can cause arbitrary local files to be shared to the server, which is vulnerable to path traversal (CVE‑2021‑40668).  
  - Combined chain: malicious local app → instruct HTTP File Server to host sensitive directories → remote attacker abuses path traversal to exfiltrate broader storage.

- **VLC & mpv as media backends for other apps**  
  - Many apps rely on `ACTION_VIEW` intents to offload media playback to a player.  
  - For instance, a compromised browser (Firefox 58) or HTTP File Server page could offer a malicious media file/playlist that, when opened, launches VLC or mpv via a `VIEW` intent, triggering VLC’s or mpv/FFmpeg’s parsing bugs.

- **Call Blocker 6.6.3 (CVE‑2023‑29728) abused by a second app**  
  - CVSS scoring suggests no privileges/user interaction needed; one likely vector is manipulation of app data or IPC.  
  - A local malicious app could attempt to tamper with Call Blocker’s feature configuration files/URIs to gain call‑related powers (reading logs, placing calls).  
  - That second app could be installed by a browser exploit (Firefox, WebView) or via a malicious PDF (Adobe Reader) if the device is rooted or if an app store trust boundary is crossed.

### 3.2 Network‑delivered chains

- **Browser or WebView delivers payloads to media/PDF apps**  
  - Firefox 58 (old Gecko) or Chrome/WebView using Trichrome Library 100 can be used as first‑stage code‑execution or content delivery.  
  - They can download and hand off malicious PDFs (to Adobe Reader, PrinterShare), M3U playlists (to mpv), or MP4/MMS streams (to VLC) by simply responding to content‑type or `VIEW` requests.

- **PrinterShare’s Gmail token reuse**  
  - A network or local attacker who obtains tokens (e.g., via local file read, HTTP File Server traversal, or some OS‑level compromise) can then directly access Gmail services from any system.  
  - This is more of a *post‑exploitation* primitive but significantly raises impact.

- **HTTP File Server as a bridge to local storage**  
  - If the device exposes HTTP File Server on a reachable network, a remote attacker can list and steal arbitrary files and potentially place payloads on external storage.  
  - Those payloads can then be opened by VLC/mpv/Adobe Reader/PrinterShare via user interaction or tricked `VIEW` intents.

### 3.3 Shared engine/library chains

- **Chromium engine (Trichrome Library) → WebView clients**  
  - Any app embedding WebView or Chrome Custom Tabs can feed content to the Chromium engine supplied by the Trichrome APK.  
  - If a Chromium RCE or sandbox‑escape applicable to 100.0.4896.127 were identified beyond the public fixes, it would affect *all* these clients at once.

- **NSS / Gecko in Firefox 58**  
  - Shared core engine means that a single discovered exploit in `libxul` could compromise Firefox; from there, stored credentials or tokens might be used to open/drive other apps via intents or content URIs.

### 3.4 Token and credential leverage

- **PrinterShare’s Gmail tokens + other apps**  
  - Once an attacker has Gmail OAuth tokens, they can use them from any environment (not limited to Android), but on‑device malware could also pivot:  
    - Malicious Home Assistant WebView content or mpv/VLC RCE could drop a second‑stage payload that scans PrinterShare storage for tokens.

- **Home Assistant Companion tokens**  
  - Through CVE‑2023‑41898, a local app can steal Home Assistant tokens and then act as the owner from another device or app.

---

## 4. Low‑confidence or contextual leads

These are observations where evidence is too weak to assert concrete CVEs but worth keeping in mind for manual review or further reversing.

- **mpv‑android & FFmpeg CVEs** – FFmpeg heavy; many CVEs in 4.3/4.4 era. Specific IDs for this build are uncertain without exact library versions.
- **Firefox 58.0.1** – almost certainly susceptible to multiple MFSA‑listed Gecko/NSS bugs fixed in later releases; mapping each CVE to mobile is non‑trivial.
- **Bytedance/Pangle (`libtt*`, `libpangleflipped.so`, `libEncryptorP.so`)** – present in BestWeather and Weather M8; no CVEs found but high complexity and obfuscation. Good candidates for manual reversing/fuzzing.
- **ApmInsight/Appodeal SDKs** – crash/analytics libs in Weather M8 and BestWeather. No CVEs, but they run native code in privileged apps and deserve scrutiny.
- **Custom weather API secret libraries** – `libweatherm8.so` for Weather M8 and similar constructs in BestWeather; leaking those secrets is operationally bad but not CVE‑tracked.

---

## 5. Cross‑app observations & recommendations

1. **High‑risk apps (definite CVEs with clear exploits)**  
   - PrinterShare 12.14.10 (CVE‑2025‑5098 + likely 5099/5100).  
   - Adobe Reader 21.7.0 (CVE‑2021‑40724).  
   - Home Assistant Companion 2023.8.1 (CVE‑2023‑41898).  
   - HTTP File Server 1.4.1 (CVE‑2021‑40668).  
   - Call Blocker 6.6.3 (CVE‑2023‑29728).  
   - VLC 3.0.5 and mpv‑android 2021‑03‑10 (multiple engine‑level CVEs).

2. **Apps that primarily expand attack surface but have no mapped CVEs yet**  
   - BestWeather, Weather M8, AMdroid, Documents To Go – broad permissions and rich parsing/SDK stacks, ideal hunting ground for new bugs.

3. **Intent‑driven exploitation surface**  
   - Many apps accept generic `VIEW`/`SEND`/`BROWSABLE` intents for arbitrary URLs and file types: VLC, mpv, Firefox, HTTP File Server, PrinterShare, Adobe Reader, Home Assistant Companion.  
   - These make it easy for one compromised app to funnel malicious payloads into another app’s vulnerable parser.

4. **Shared vulnerable components**  
   - While there is no single `.so` reused across multiple APKs with a known CVE, there are repeated libraries (MMKV, Bytedance’s ttEncrypt/Pangle stack, ApmInsight) that could, if one vulnerability were found, impact several apps at once.

5. **Token & data exfiltration risk**  
   - PrinterShare’s Gmail token handling and Home Assistant’s WebView bug both give ways to steal powerful authentication tokens.  
   - Combined with storage‑oriented vulnerabilities (HTTP File Server traversal, VLC/mpv RCE with filesystem access), these create strong chains for multi‑step compromise.

In a CTF or audit setting, focusing on the high‑confidence CVEs above and then exploring intent‑based chains between apps will likely yield the most interesting exploit scenarios.
