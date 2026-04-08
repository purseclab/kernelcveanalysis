# Weather M8 (pro.burgerz.miweather8) – Proof‑of‑Concept Notes

No concrete public CVEs could be confidently linked to this specific APK or its embedded libraries.

However, the following non‑CVE behaviors may be of interest in a CTF or security‑research context.

## 1. Extracting embedded weather‑API secrets from `libweatherm8.so`

### Idea

`libweatherm8.so` exposes JNI methods named like:
- `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret1TheWeatherChannel`
- `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret2TheWeatherChannel`
- `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecret3TheWeatherChannel`
- `Java_bz_zaa_weather_lib_utils_Secrets_getApiSecretOpenWeatherMap`
- `Java_bz_zaa_weather_lib_utils_Secrets_getCityApiSecretAccuweather`

A PoC can demonstrate that the API keys are retrievable either by:
1) Direct static extraction from the `.so` file; or
2) Dynamic invocation of the JNI methods in an instrumented environment.

### Static extraction sketch

1. Copy `libweatherm8.so` from the APK (already located under `lib/<abi>/libweatherm8.so`).
2. Use standard reverse‑engineering tools such as `strings`, `ghidra`, or `radare2` (outside this environment) to locate the methods above.
3. Follow the function implementations to find embedded key material (often stored as arrays of bytes/strings and XOR‑decoded at runtime).

Because such tools are not available inside this sandbox, the detailed reversing is left as an exercise, but this is typically straightforward.

### Dynamic JNI invocation sketch

On a rooted/emulator test device with the app installed:

```java
// Example instrumentation snippet (e.g., in a small helper app on the same device)
Class<?> secrets = Class.forName("bz.zaa.weather.lib.utils.Secrets");
Method m = secrets.getDeclaredMethod("getApiSecretOpenWeatherMap");
m.setAccessible(true);
String key = (String) m.invoke(null);
Log.i("POC", "OpenWeatherMap key: " + key);
```

This assumes the `Secrets` class exposes static native methods backed by `libweatherm8.so`.

Impact: abuse of provider API quotas; not tracked as a CVE but useful for a CTF.

## 2. Verifying native‑crash reporting paths (Appodeal / APM Insight)

The presence of:
- `libapd_native_watcher.so` (Appodeal crash hunter), and
- `libapminsight[a|b].so` (`com.apm.insight.nativecrash.NativeImpl`)

suggests the app registers native crash handlers that may write diagnostic files under paths like `/apd-%Y-%m-%d-%H-%M-%S`.

### PoC idea

1. Trigger a deliberate native crash through an ad‑SDK code path (difficult inside this environment, but plausible on a device with network access and ads enabled).
2. Observe where crash dumps or logs are written (e.g., app‑private storage vs external storage).
3. Check for:
   - World‑readable log files.
   - Sensitive information leaks (tokens, location, user identifiers).

Again, this is more a privacy/forensics angle than a classic memory‑corruption exploit.

## 3. General external‑storage misuse checks

Because the app holds `READ_EXTERNAL_STORAGE` and `WRITE_EXTERNAL_STORAGE`, any file‑based logic could be audited for path‑traversal or confused‑deputy bugs.

### Generic black‑box PoC directions

- Monitor how the app reads/writes files on external storage (via `logcat` or filesystem diff) while using features like:
  - Export/import settings (if present).
  - Saving screenshots or widgets.
- Attempt to craft malicious files on external storage that the app may parse or trust (e.g., configuration, cached weather data), then look for crashes or unexpected behavior.

No specific vulnerable endpoints were identified statically, so this remains exploratory rather than a known exploit.

---

**Note:** All PoCs above are generic research directions, not tied to any public CVE. In particular, no proven remote‑code‑execution or privilege‑escalation paths were inferred from the static analysis alone.