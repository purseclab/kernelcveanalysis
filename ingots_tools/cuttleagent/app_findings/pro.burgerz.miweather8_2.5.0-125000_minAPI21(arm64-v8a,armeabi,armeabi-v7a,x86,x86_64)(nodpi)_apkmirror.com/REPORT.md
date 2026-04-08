# Weather M8 (pro.burgerz.miweather8) – Security & Component Analysis

## App identity
- **Package name:** `pro.burgerz.miweather8`
- **App label:** Weather M8
- **VersionName:** 2.5.0
- **VersionCode:** 125000
- **Min SDK:** 21
- **Target SDK:** 31
- **Source APK:** `pro.burgerz.miweather8_2.5.0-125000_minAPI21(arm64-v8a,armeabi,armeabi-v7a,x86,x86_64)(nodpi)_apkmirror.com.apk`

## Manifest overview

### Key permissions
- `android.permission.INTERNET`
- `android.permission.ACCESS_COARSE_LOCATION`
- `android.permission.ACCESS_FINE_LOCATION`
- `android.permission.ACCESS_BACKGROUND_LOCATION`
- `android.permission.ACCESS_NETWORK_STATE`
- `android.permission.ACCESS_WIFI_STATE`
- `android.permission.WAKE_LOCK`
- `android.permission.RECEIVE_BOOT_COMPLETED`
- `android.permission.FOREGROUND_SERVICE`
- `android.permission.VIBRATE`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `com.android.vending.BILLING`
- `com.google.android.gms.permission.AD_ID`
- `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE`
- `com.android.alarm.permission.SET_ALARM`

Notes:
- Uses fine & background location for weather; combined with ad/analytics SDKs this has privacy implications but this is a general data‑protection concern, not a specific CVE.
- Legacy external storage permissions are requested (READ/WRITE_EXTERNAL_STORAGE), which may increase attack surface for file‑based vulnerabilities if other bugs exist.

### Exported components & intents

- **Launchable activities:**
  - `bz.zaa.weather.ui.activity.SplashActivity` – `exported=true`, MAIN/LAUNCHER
  - `pro.burgerz.miweather8.ActivityWeatherMain` – `exported=true`, MAIN (no LAUNCHER category)
- **Other notable activities** (not exported unless stated):
  - `bz.zaa.weather.ui.activity.CityManagerActivity` – exported=false, custom action `bz.zaa.weatherm8.CITY_CONTROL` (DEFAULT category)
  - `bz.zaa.weather.ui.activity.ThemeActivity` – exported=false, custom action `bz.zaa.weatherm8.THEME_SETTING`
  - Multiple additional internal settings/info activities are non‑exported.
- **Services:**
  - `bz.zaa.weather.service.WidgetUpdateService` (no explicit `exported` flag → defaults to false on targetSdk 31 if no intent filter).
- **Content provider:**
  - `androidx.core.content.FileProvider` with authorities `pro.burgerz.miweather8.fileprovider`, `exported=false`, `grantUriPermissions=true` and custom `file_paths.xml`.
- **Broadcast receivers (exported):**
  - `bz.zaa.weather.service.BootReceiver` – `exported=true`, receives `BOOT_COMPLETED`, QuickBoot, and alarm‑related actions plus custom widget action.
  - `bz.zaa.weather.widget.*` app‑widget receivers (several classes), all `exported=true` with `android.appwidget.action.APPWIDGET_UPDATE` and widget provider metadata.

### Queries section & cross‑app interactions

The app declares `queries` for:
- Generic `VIEW`/`SEND`/`SENDTO`/`DIAL`/`MEDIA_SCANNER_SCAN_FILE` intents.
- Specific packages: `com.google.android.apps.maps`, `com.android.chrome`, `com.facebook.katana`.

This indicates it may:
- Open URLs in a browser (Chrome or others).
- Launch Maps for location display.
- Share content to other apps (email, social networks, dialer).
These are normal behaviors and not inherently a vulnerability.

## Native library inventory

All architectures (arm64‑v8a, armeabi‑v7a, x86, x86_64) ship similar sets of native binaries. `armeabi` contains only `libEncryptorP.so`.

For each library, the following describes the **arm64‑v8a** variant; other ABIs are analogous.

### 1. `libEncryptorP.so`
- **Paths:**
  - `lib/arm64-v8a/libEncryptorP.so`
  - `lib/armeabi-v7a/libEncryptorP.so`
  - `lib/armeabi/libEncryptorP.so`
  - `lib/x86/libEncryptorP.so`
  - `lib/x86_64/libEncryptorP.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:** `libEncryptorP.so`
- **Dependencies:** `liblog.so`, `libc.so`, `libm.so`, `libstdc++.so`, `libdl.so`
- **Version clues:**
  - Strings: `libEncryptorP.so`, `ttEncrypt`.
  - This matches the ByteDance/"ttEncrypt" native encryption VM often bundled with ad SDKs such as Pangle/TikTok ads.
- **Likely upstream:** Proprietary ByteDance `ttEncrypt` module (used for obfuscation and HTTP body encryption). No public semantic version is embedded.
- **Known CVEs:**
  - I could not find any CVE or vendor advisory specific to `libEncryptorP.so` or `ttEncrypt` as a standalone component. Public research focuses mainly on reverse‑engineering, not on memory‑safety bugs.
- **Confidence in identification:** Medium (string match + context from other Pangle/Bytedance ad layouts in resources).

### 2. `libapd_native_watcher.so`
- **Paths:** all main ABIs under `lib/<abi>/libapd_native_watcher.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:** `libapd_native_watcher.so`
- **Dependencies:** `liblog.so`, `libm.so`, `libdl.so`, `libc.so`
- **Version clues:**
  - Strings include:  
    `Java_com_appodeal_ads_services_stack_analytics_crash_hunter_NativeWatcher_00024Companion_exampleNativeException`  
    `com/appodeal/ads/services/stack_analytics/crash_hunter/NativeWatcher`  
    path pattern `/apd-%Y-%m-%d-%H-%M-%S`.
  - Strong indication this is part of **Appodeal** SDK (crash watcher/analytics).
- **Likely upstream:** Appodeal SDK – native crash watcher component.
- **Known CVEs:**
  - Searches for this exact library name and Appodeal SDK did not reveal any CVEs or advisories tied to this native module.
  - Snyk’s pages for `react-native-appodeal` show **no direct vulnerabilities** (just dependency‑level issues unrelated to this `.so`).
- **Confidence in identification:** High.

### 3. `libapminsighta.so` and `libapminsightb.so`
- **Paths:** all main ABIs under `lib/<abi>/libapminsighta.so` and `lib/<abi>/libapminsightb.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:**
  - `libapminsighta.so` → SONAME reported as `libnpth.so` (likely obfuscation or build artifact).
  - `libapminsightb.so` → PIE executable‑style shared object with dynamic linker `/system/bin/linker` or `/system/bin/linker64`.
- **Dependencies (both):** `liblog.so`, `libc.so`, `libm.so`, `libstdc++.so`, `libdl.so`.
- **Version clues:**
  - Strings in `libapminsighta.so`: `com/apm/insight/nativecrash/NativeImpl`, references to `libapminsightb.so`.
  - This matches the **ApmInsight** / performance and crash‑analytics SDK commonly used for monitoring.
- **Likely upstream:** An APM/analytics SDK (ApmInsight, used by some ad/analytics vendors). No semantic version string visible in the binary.
- **Known CVEs:**
  - Web searches for `com.apm.insight.nativecrash.NativeImpl` and variants did **not** yield specific CVEs.
  - No public reports of exploitable issues in this native SDK component were found.
- **Confidence in identification:** Medium‑high (exact Java class name match).

### 4. `libmmkv.so`
- **Paths:** all main ABIs under `lib/<abi>/libmmkv.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:** `libmmkv.so`
- **Dependencies:** `liblog.so`, `libm.so`, `libdl.so`, `libc.so`
- **Version clues:**
  - Strings: `libmmkv.so`, `getDefaultMMKV`, `getMMKVWithID`, `mmkvClose`, `mmkvInitialize`, etc.
  - META‑INF contains standard MMKV metadata via Gradle, but no exact version maven coordinate is directly visible in the provided snippet. However, the `.version` files list only Java/AndroidX artifacts, not MMKV itself.
- **Likely upstream:** **Tencent MMKV** (mobile key‑value store used by WeChat).
- **Known CVEs / issues:**
  - I did not find any CVE specifically assigned to Tencent MMKV native library.
  - Related CVE **CVE‑2024‑21668** concerns *react-native-mmkv* (a React Native wrapper) logging encryption keys to Android logs. That issue is in the wrapper logic, not the underlying `libmmkv.so`. Weather M8 does not use React Native; it uses native Android/Kotlin, so this CVE does **not** directly apply.
- **Confidence in identification:** High.

### 5. `libnms.so`
- **Paths:** all main ABIs under `lib/<abi>/libnms.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:** `libnms.so`
- **Dependencies:** `liblog.so`, `libstdc++.so`, `libc.so`, `libm.so`, `libdl.so`
- **Version clues:**
  - Very few strings; only `libnms.so` itself.
  - Web search for `libnms.so` turns up a generic object‑detection NMS (non‑maximum suppression) library on GitHub, and unrelated results. Nothing clearly ties this specific binary to a public project.
  - Given proximity to Appodeal / ad SDK libs, it may be an internal helper for native ad rendering or ML, but that is speculative.
- **Likely upstream:** Unknown (possibly an internal or vendored NMS implementation for ads/graphics).
- **Known CVEs:** None found; no mention of this library name in CVE databases.
- **Confidence in identification:** Low; only the name is known.

### 6. `libweatherm8.so`
- **Paths:** all main ABIs under `lib/<abi>/libweatherm8.so`
- **Architecture:** aarch64 / ARMv7 / x86 / x86_64
- **SONAME:** `libweatherm8.so`
- **Dependencies:** `libm.so`, `libdl.so`, `libc.so`
- **Version clues:**
  - Strings clearly show JNI bindings for secrets used to access weather APIs:
    - `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret1TheWeatherChannel`
    - `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret2TheWeatherChannel`
    - `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret3TheWeatherChannel`
    - `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecretOpenWeatherMap`
    - `Java_bz_zaa_weather_lib_utils_Secrets_getCityApiSecretAccuweather`
  - This appears to be a custom library authored for Weather M8 to hide API keys and perhaps perform some math.
- **Likely upstream:** Proprietary `Weather M8` native helper.
- **Known CVEs:**
  - No public vulnerability records for `Weather M8` or this library were found.
  - However, the presence of embedded API secrets in a native binary means **static recovery of API keys is trivial for an attacker** (common but not tracked as a CVE).
- **Confidence in identification:** High.

## Third‑party SDK and library versions (Java/Kotlin level)

Based on `META-INF/*.version` files and bundled properties, the app uses:

- **AndroidX / Google UI stack** (typical for modern apps):
  - `androidx.appcompat:appcompat:1.4.2`
  - `androidx.core:core-ktx:1.8.0`
  - `androidx.fragment:fragment-ktx:1.3.6`
  - `androidx.recyclerview:recyclerview:1.2.1`
  - `androidx.preference:preference-ktx:1.2.0`
  - `androidx.room:room-runtime/room-ktx:2.4.2`
  - `androidx.work:work-runtime/work-runtime-ktx:2.7.1`
  - Many other support components (emoji2 1.0.0, lifecycle 2.3.x–2.5.0, etc.).
- **Material Components:** `com.google.android.material:material:1.6.1`
- **Dagger/Hilt:** `com.google.dagger:dagger` & `hilt-android` 2.42
- **Kotlin coroutines:** `kotlinx-coroutines-core` / `kotlinx-coroutines-android` 1.6.3
- **Google Play Services:** via properties files (ads, ads-lite, ads-identifier, appset, base, basement, location, maps, measurement, stats, tasks).
- **Firebase:** analytics, config, installations, etc. (identified by `firebase-*.properties`).
- **OkHttp:** presence of `okhttp3/internal/publicsuffix/NOTICE` and `META-INF/native-image/okhttp/okhttp` → modern OkHttp 3/4, but exact minor version not resolved from the small snippets.
- **Ad & mediation SDKs:**
  - Appodeal (native libs + `assets/apd_adapters/*`).
  - BidMachine (`assets/bm_networks/*`).
  - Amazon, Criteo, Meta Audience Network, MyTarget, Pangle, Vungle, Yandex, Unity Ads, etc., via adapter files.

### Known CVEs for these versions

I performed targeted searches for:
- `Weather M8` / `pro.burgerz.miweather8` app‑specific vulnerabilities.
- AndroidX libraries (appcompat 1.4.2, core-ktx 1.8.0, room 2.4.2, work-runtime 2.7.1).
- Material Components 1.6.1.
- Dagger/Hilt 2.42.
- Kotlin coroutines 1.6.3.
- OkHttp (modern 3.x/4.x range).
- Appodeal / APM Insight / MMKV.

No CVE entries were found that are:
- Clearly and specifically tied to these exact library versions **and** exploitable purely via this app’s usage patterns, nor
- Specific to the `Weather M8` app.

Some general observations:
- **OkHttp** and **Google Play services** have had security fixes historically, but I did not find a CVE clearly binding to a version range that must include the version here, given the limited metadata (and googling for `okhttp 3.x CVE` returns sparse, mostly non‑critical issues). Without exact version numbers from POMs or class manifests, asserting a concrete CVE would be speculative.
- **AndroidX / Material / Dagger / Coroutines**: no high‑profile remote‑exploitable CVEs were located for the listed versions. Most security advisories around this era are about logic bugs in specific apps, not core libraries.
- **MMKV**: only wrapper‑level vulnerability `CVE‑2024‑21668` in `react-native-mmkv`; not applicable here.
- **Appodeal / APM Insight / Pangle / Yandex ads**: I did not find public CVEs referencing these SDKs specifically. Ad SDK issues more often surface as privacy or policy violations rather than memory‑safety CVEs.

Given the above, I **cannot confidently map any public CVE directly to this APK** or its bundled third‑party components without over‑speculating.

## Potential (non‑CVE) security considerations

Even though no concrete CVE was identified, several security‑relevant aspects are worth noting:

1. **Hard‑coded API secrets in native code**
   - `libweatherm8.so` exposes JNI methods that likely return API keys for external weather providers (The Weather Channel, OpenWeatherMap, AccuWeather).
   - Extracting these secrets from the `.so` is straightforward for a motivated attacker. This can enable:
     - Abuse of paid weather APIs.
     - Attribution of abusive traffic to this app’s key, potentially leading to service throttling.
   - This is common practice but not best‑practice; usually mitigated via backend proxies and rate‑limiting.

2. **Heavy ad/analytics stack with location access**
   - Multiple ad networks, Appodeal mediation, and analytics plus `ACCESS_FINE_LOCATION`/`ACCESS_BACKGROUND_LOCATION` imply extensive data collection potential.
   - This may raise privacy or regulatory concerns (GDPR/CCPA) if consent flows are insufficient, but such issues are not tracked as CVEs.

3. **Exported broadcast receivers and widgets**
   - Several widget receivers are exported and react to `APPWIDGET_UPDATE`. This is by design for app widgets and not inherently dangerous.
   - `BootReceiver` is exported and listens to boot‑related intents; if combined with logic flaws, it could be abused, but no such flaw is identifiable from the manifest alone.

4. **Legacy external storage permissions**
   - `READ/WRITE_EXTERNAL_STORAGE` combined with file operations can sometimes lead to path‑traversal or confused‑deputy bugs. Without source or behavioral analysis, no specific issue can be asserted.

## CVE summary

After targeted research:

- **No high‑confidence CVEs** can be mapped to:
  - `Weather M8` (`pro.burgerz.miweather8`) as a product, or
  - Its embedded native libraries (`libEncryptorP.so`, `libapd_native_watcher.so`, `libapminsight[a|b].so`, `libmmkv.so`, `libnms.so`, `libweatherm8.so`), or
  - Its clearly‑identified third‑party Java/Kotlin dependencies, in a way that is demonstrably exploitable in this app.

- Some **related but not directly applicable** items:
  - **CVE‑2024‑21668** – `react-native-mmkv` logs encryption keys to Android logs. Weather M8 does use MMKV but *not* via this React Native wrapper, so this CVE should **not** be claimed as affecting this APK.

## Overall assessment

- The APK is a fairly modern Android app (targetSdk 31) using standard AndroidX, Material, Dagger/Hilt, coroutines, and a large ad/analytics stack.
- Native libraries are mostly SDK components (MMKV, Appodeal/ApmInsight, ttEncrypt) plus a custom library carrying API secrets.
- No concrete public vulnerabilities (CVEs) can be confidently attributed to the app or its third‑party components based on available version evidence.
- Security concerns are more around **exposed API secrets**, **privacy/telemetry behavior**, and **general increased attack surface** from many third‑party SDKs rather than known exploitable CVEs.

**Confidence level of "no concrete CVE mapping found":** Medium‑high (based on targeted searches and available metadata, but not exhaustive static/dynamic analysis of all code).