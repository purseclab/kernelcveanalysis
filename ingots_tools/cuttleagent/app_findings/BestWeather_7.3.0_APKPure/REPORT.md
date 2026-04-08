# BestWeather 7.3.0 (com.icoolme.android.weather) – Vulnerability Recon

## App identity
- APK: `/data/apps/BestWeather_7.3.0_APKPure.apk`
- Package name: `com.icoolme.android.weather`
- Version name: `7.3.0`
- Version code: `2052000090` (0x7a4f095a)
- minSdkVersion: 21 (Android 5.0)
- targetSdkVersion: 30 (Android 11)

## Permissions and capabilities (high level)
The manifest requests a broad set of permissions, notably:
- Network & storage: `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `CHANGE_WIFI_STATE`, `CHANGE_NETWORK_STATE`, `WRITE_EXTERNAL_STORAGE`, `READ_EXTERNAL_STORAGE`, `FOREGROUND_SERVICE`, `REQUEST_INSTALL_PACKAGES`
- Location: `ACCESS_COARSE_LOCATION`, `ACCESS_FINE_LOCATION`, `ACCESS_LOCATION_EXTRA_COMMANDS`
- Phone & wake: `READ_PHONE_STATE`, `WAKE_LOCK`, `RECEIVE_BOOT_COMPLETED`, `RECEIVE_USER_PRESENT`, `DISABLE_KEYGUARD`, `SCHEDULE_EXACT_ALARM`
- Camera & Bluetooth: `CAMERA`, `BLUETOOTH`, `BLUETOOTH_ADMIN`
- Launcher / shortcuts: `com.android.launcher.permission.INSTALL_SHORTCUT`, `UNINSTALL_SHORTCUT`
- OEM / ad-tracking / ecosystem integration: `com.heytap.wearable.oms.permission.TRACSPORT`, `com.huawei.appmarket.service.commondata.permission.GET_COMMON_DATA`
- Custom permission defined by app: `com.icoolme.android.weather.READ_CONTENTPROVIDER` (protectionLevel `normal`), potentially allowing other apps to read from a content provider this app exposes.

The manifest also declares `<queries>` entries for many third‑party apps (WeChat, QQ, Weibo, Alipay variants, Huawei Health, device ID providers, etc.), indicating cross‑app interaction for sharing, payments, or device‑ID retrieval.

## Native library inventory

All libraries are bundled for both `arm64-v8a` and `armeabi-v7a`.

### 1. `libAMapSDK_MAP_v9_3_0.so`
- Paths:
  - `/data/workdir/bestweather/lib/arm64-v8a/libAMapSDK_MAP_v9_3_0.so` (aarch64)
  - `/data/workdir/bestweather/lib/armeabi-v7a/libAMapSDK_MAP_v9_3_0.so` (ARMv7)
- Type: ELF shared library
- Likely component: Gaode/AMap Android map SDK
- Version evidence:
  - Filename embeds `v9_3_0` → strong indicator this is AMap SDK 9.3.0.
  - Web search for `libAMapSDK_MAP_v9_3_0.so` finds crash reports and developer posts referencing AMap 9.3.0; no CVE‑style security advisories.
- Known CVEs:
  - I could not find any CVEs or official security advisories specifically naming AMap Android SDK 9.3.0.
  - Existing public posts discuss stability issues (crashes, potential memory leaks) but not exploitable vulnerabilities.
- Assessment: no mapped CVEs; any memory‑safety issues would require more reverse engineering or fuzzing data than available here.

### 2. `libCtaApiLib.so`
- Paths: arm64/armeabi-v7a
- Type: ELF shared object
- Likely component: OEM or regional “CTA” (China Telecom Authority) compliance / telemetry library used by many Chinese OEM ROMs and apps.
- Version evidence: none in filename; no obvious symbols inspected.
- Public CVEs:
  - No direct matches for `libCtaApiLib.so` as a product in CVE/NVD/CVE Details.
- Assessment: identity is somewhat clear (CTA API), but without version strings or vendor documentation, no CVEs can be reliably mapped.

### 3. `libEncryptorP.so`
- Paths: arm64/armeabi-v7a
- Likely component: custom encryption helper used by the app or an SDK (possibly for asset or config protection).
- Public CVEs: none found for this exact component name.
- Assessment: proprietary; no version info; cannot correlate to public vulnerabilities.

### 4. `libads-ac.so`, `libads-c.so`
- Paths: arm64/armeabi-v7a
- Likely component: advertising SDK native components from a Chinese ad network (naming similar to various in‑app ad SDKs).
- Public CVEs:
  - No CVE entries under these exact library names.
  - Many ad SDKs have had privacy and configuration issues, but those are usually documented in blogs, not CVE‑tracked.
- Assessment: we can only say these are ad‑related; no specific CVEs.

### 5. `libapminsighta.so`, `libapminsightb.so`
- Paths: arm64/armeabi-v7a
- Type:
  - `libapminsighta.so`: regular shared object
  - `libapminsightb.so`: PIE executable (still packaged as `.so`) with interpreter `/system/bin/linker` or `/system/bin/linker64`
- Likely component: Bytedance/TikTok “APMInsight” performance / crash analytics SDK (name matches public documentation and SDK artifacts used in other apps).
- Public CVEs:
  - No CVEs in NVD that explicitly reference “APMInsight” or these `.so` names.
- Assessment: telemetry/monitoring code with system‑level privileges only via host app; no mapped CVEs.

### 6. `libavmdl.so`
- Paths: arm64/armeabi-v7a
- Likely component: unknown; the name appears in other Chinese apps but without public vendor docs. Could be part of a download/patching or AV/anti‑tamper module.
- Public CVEs: none found.
- Assessment: cannot reliably identify upstream project or version.

### 7. `libbdsword.so`
- Paths: arm64/armeabi-v7a
- Likely component: unknown; the `bds` prefix appears sometimes in Baidu SDKs, but there is insufficient evidence to assert that here.
- Public CVEs: none under this library name.
- Assessment: identity uncertain.

### 8. `libboost_multidex.so`
- Paths: armeabi-v7a only
- Likely component: helper for Boost MultiDex / Tencent “Boost” loader or similar; common in Chinese apps for multi‑dex loading.
- Public CVEs:
  - There have been research posts about insecure multi‑dex loaders and code‑loading logic, but no widely accepted CVE specifically for this component name.
- Assessment: could expand the app’s dynamic‑code‑loading surface, but no specific CVE mapping.

### 9. `libcrashsdk.so`
- Paths: arm64/armeabi-v7a
- Likely component: an OEM or third‑party crash‑collection SDK (name is generic; several unrelated vendors use `crashsdk`).
- Public CVEs: no product‑specific vulnerability entries found that can be confidently tied to this build.
- Assessment: without vendor or version strings, no dependable CVE mapping.

### 10. `libmmkv.so`
- Paths: arm64/armeabi-v7a
- Likely component: Tencent MMKV key–value storage library (widely used; name and context match).
- Version evidence: none visible from filename or our limited ELF inspection.
- Public CVEs:
  - No CVEs reference MMKV specifically as of the latest data available.
- Assessment: treat as generic third‑party storage component; no mapped CVEs.

### 11. `libmsaoaidauth.so`, `libmsaoaidsec.so`
- Paths: arm64/armeabi-v7a
- Likely component: MSA (Mobile Security Alliance) OAID (Open Anonymous Device Identifier) SDK for China app‑tracking.
- Public CVEs:
  - No NVD/CVE entries explicitly tied to these libraries or OAID SDKs.
- Assessment: identifiable but not mapped to known vulnerabilities.

### 12. `libnativekv.so`
- Paths: arm64/armeabi-v7a
- Likely component: custom native key–value storage.
- Public CVEs: none found.
- Assessment: project and version unknown.

### 13. `libnotpluginpro.so`, `libnovelencrypt.so`
- Paths: arm64/armeabi-v7a
- Likely component: proprietary logic (possibly content decryption / “novel” reader or ad‑related plugin stubs).
- Public CVEs: none.
- Assessment: cannot identify upstream.

### 14. `libopluslog.so`
- Paths: arm64/armeabi-v7a
- Likely component: Oppo / Oplus logging library commonly present on ColorOS/Realme devices and some OEM‑bundled apps.
- Public CVEs:
  - No direct CVEs for `libopluslog` itself.
- Assessment: OEM telemetry/logging helper; no mapped CVEs.

### 15. `libpangleflipped.so`
- Paths: arm64/armeabi-v7a
- Likely component: Pangle (Bytedance ad network) native SDK; “flipped” variants are used in some regions.
- Public CVEs:
  - No CVE entries explicitly targeting Pangle native libraries.
- Assessment: ad SDK; privacy/abuse risks exist in general but not captured as public CVEs we can tie to this exact version.

### 16. `libpl_droidsonroids_gif.so`
- Paths: arm64/armeabi-v7a
- Likely component: `android-gif-drawable` (droidsonroids GIF) library; the library name matches the project’s documented JNI .so.
- Version evidence: version not apparent from filename.
- Public CVEs:
  - No CVEs published for `android-gif-drawable`/`pl.droidsonroids.gif` native component.
- Assessment: known open‑source project; no mapped CVEs.

### 17. `libscorpion.so`
- Paths: arm64/armeabi-v7a
- Likely component: anti‑debugging / “Scorpion” protection module used in various Chinese apps.
- Public CVEs: none found.
- Assessment: proprietary; version unknown.

### 18. `libsgcore.so`
- Paths: arm64/armeabi-v7a
- Likely component: “SecurityGuard core” SDK from Alibaba (commonly named `libsgmain`, `libsgsecuritybody`, or `libsgcore`).
- Public CVEs:
  - SecurityGuard has been analyzed in some research, but there are no well‑established CVE entries mapping to `libsgcore` specifically.
- Assessment: we can tentatively associate this with Alibaba SecurityGuard, but without version info and specific advisories this remains low‑confidence and cannot be tied to concrete CVEs.

### 19. `libtanx.so`
- Paths: arm64/armeabi-v7a
- Likely component: Alibaba Tanx (Taobao advertising / bidding) SDK.
- Public CVEs:
  - No CVEs clearly referencing Tanx SDK.
- Assessment: ad network SDK.

### 20. `libtobEmbedEncryptForM.so`
- Paths: arm64/armeabi-v7a
- Likely component: Bytedance/Toutiao “TOB” embedded encryption module for media or ad payloads.
- Public CVEs: none.

### 21. `libttboringssl.so`, `libttcrypto.so`, `libttffmpeg.so`, `libttmplayer.so`, `libttmverify.so`
- Paths: arm64/armeabi-v7a
- Likely component: ByteDance “TT” media stack (fork of BoringSSL, crypto, ffmpeg, proprietary media player and verification modules) used by Pangle / Bytedance ads and video playback.
- Version evidence:
  - No explicit version in filenames; would require symbol or string inspection.
- Public CVEs:
  - No CVEs specifically reference these TT‑prefixed forks.
  - BoringSSL itself generally does not use CVEs in the same way as OpenSSL, and the TT fork is even less likely to be individually tracked.
- Assessment: potential for typical media/crypto bugs, but no specific published CVEs.

### 22. `libumeng-spy.so`
- Paths: arm64/armeabi-v7a
- Likely component: Umeng analytics/“spy” native helper, often for behavior collection and anti‑fraud.
- Public CVEs: none directly tied to this `.so`.

### 23. `libvcn.so`, `libvcnverify.so`, `libvideodec.so`
- Paths: arm64/armeabi-v7a
- Likely component: proprietary video codec / verification modules (possibly networked video or ad video decoding pipeline).
- Public CVEs: none found by name.

## App‑level CVE research

### Search for app‑specific CVEs
- Queries used:
  - `"com.icoolme.android.weather" 7.3.0 security vulnerability`
  - `"com.icoolme.android.weather" CVE`
  - `"Best Weather" Android app 7.3.0 vulnerability`
- Results:
  - Search results were generic (Android monthly security bulletins, general Android vulnerability pages, unrelated products like FortiSIEM 7.3.0, etc.).
  - No result tied a CVE ID to this package name, developer, or APKPure distribution.

Given this, there is currently **no public CVE associated with Best Weather / `com.icoolme.android.weather` 7.3.0** itself.

### Third‑party SDK CVEs
- For each likely third‑party component (AMap SDK, Pangle, MMKV, Umeng, Alibaba SecurityGuard/Tanx, APMInsight, OAID, droidsonroids GIF), I attempted to locate:
  - Component‑name + CVE
  - Component‑name + "Android SDK vulnerability"
- None of these searches produced authoritative CVE entries clearly tied to the specific component names and Android context used here.
- Some blog posts and crash reports were found (for example, instability in AMap SDK 9.3.0), but nothing meeting the criteria of a *known public CVE*.

## Security observations (non‑CVE)

Even without mapped CVEs, several aspects are noteworthy from a security perspective:

1. **Large attack surface via SDKs**
   - The app bundles a significant number of third‑party native SDKs (ads, analytics, mapping, encryption, anti‑tamper, OAID, OEM logging). Each of these increases potential for exploitable bugs, though we cannot point to specific published vulnerabilities.

2. **Broad permissions**
   - Combined permissions (fine location, phone state, external storage, camera, Bluetooth, boot receivers, install‑packages) make this app a high‑value target if any exploitable vulnerability were discovered in its exposed components or native code.

3. **Custom normal‑protection permission for content provider**
   - `com.icoolme.android.weather.READ_CONTENTPROVIDER` is defined with `protectionLevel="normal"`, meaning any installed app can request it without user prompt.
   - If the associated content provider exposes sensitive user data (e.g., location history, weather favorites tied to accounts) and its internal access control trusts only this permission, other apps could read that data. However, without decompiled code and provider definitions this remains a hypothetical risk, not a known CVE.

4. **Cross‑app interactions**
   - The `<queries>` section shows explicit integration with major social and payment apps (WeChat, QQ, Alipay, JD app, Huawei Health, device ID services). Mis‑use of Intents, deep links, or exported components could cause logic flaws, but again there is no public CVE documenting such an issue for this app.

## Conclusions

- **CVE status**: As of the research performed here, **no specific CVEs can be confidently associated with BestWeather 7.3.0 or its bundled native libraries**.
- **Native libraries**: The APK contains many third‑party and proprietary native libraries (AMap maps 9.3.0, Pangle/Bytedance media & APMInsight, MMKV, Umeng, OAID, droidsonroids GIF, Alibaba SecurityGuard/Tanx, OEM logging, etc.), but none of them have well‑documented, version‑matched CVEs available in public databases.
- **Overall confidence**:
  - App identity and native‑library inventory: **high confidence**
  - Library upstream attribution (e.g., AMap 9.3.0, Pangle, MMKV, Umeng, OAID, Alibaba SecurityGuard): **medium–high confidence**
  - Existence of public CVEs affecting these exact builds: **low confidence that any exist**; extensive search did not reveal any.

In summary, this APK appears to be a typical heavily‑instrumented, ad‑ and analytics‑rich consumer weather app. It exposes a large potential attack and privacy surface, but there are **no currently known public CVEs** that can be tied to the app or its native components based on filenames and limited metadata alone.