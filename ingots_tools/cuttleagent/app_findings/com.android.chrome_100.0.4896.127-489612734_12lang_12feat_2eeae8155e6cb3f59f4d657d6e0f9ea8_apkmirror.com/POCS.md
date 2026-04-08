# Chrome 100.0.4896.127 (Android) – Proof-of-Concept Notes

This APK corresponds to Google Chrome for Android version **100.0.4896.127**, package **com.android.chrome**.

Public advisories (e.g., Chrome Releases blog, BornCity, NVD) make clear that **100.0.4896.127 is the patched version that fixes the actively exploited V8 type confusion CVE-2022-1364** for desktop and Android.

As such, known public PoCs target **versions prior to 100.0.4896.127**. A generic exploit PoC for CVE-2022-1364 would:

- Use a crafted JavaScript snippet to trigger a **type confusion in V8 Turbofan**, leading to heap corruption and arbitrary code execution in the renderer process.
- Be delivered through **remote web content** (e.g., a malicious webpage or ad) loaded in Chrome.
- Typically rely on JIT spraying, out-of-bounds access, or forged objects to achieve **read/write primitives** and then escape the V8 sandbox or gain native code execution inside the renderer.

However:

- NVD entry for CVE-2022-1364: **"Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127"**.
- That implies **100.0.4896.127 is not vulnerable** to this issue.
- Any public PoCs for CVE-2022-1364 (or scanners like Tenable plugin 159740) are intended to detect or exploit **Chrome < 100.0.4896.127**, not this APK.

Therefore, for this specific APK version:

- **CVE-2022-1364 is relevant historically** (it motivated this release) but
- **The vulnerability should be considered fixed in this build**, and public PoCs should **not** succeed against a correctly built and unmodified Chrome 100.0.4896.127.

Because there are no strong version-identifying strings inside the tiny native libraries bundled here (libchromium_android_linker.so, libelements.so, libyoga.so, libdummy.so), and they appear to be Chrome-specific components rather than standalone third‑party libraries like OpenSSL/zlib/etc., **no separate PoCs for independent third-party libraries can be reliably associated** from this static APK inspection alone.

In summary, from publicly available information:

- This APK version is **primarily the fix** for CVE-2022-1364.
- Existing exploit PoCs for that CVE should be treated as **"not expected to work"** against this particular version.
- No additional, clearly identifiable third‑party native libraries were found that can be confidently mapped to public CVEs with actionable PoCs based solely on the artifacts available in this APK.