# PrinterShare (com.dynamixsoftware.printershare) – Proof‑of‑Concept Ideas

> NOTE: These PoCs are high‑level, based **only on public vulnerability descriptions** and static APK analysis. They are not tested exploits.

## 1. CVE-2025-5098 – Gmail Authentication Token Disclosure

**Goal:** Demonstrate that PrinterShare mishandles Gmail OAuth/access tokens such that they can be captured and reused.

### Environment

- Device with Android 7+ (API 24+) for good debugging capabilities.
- Target APK: `com.dynamixsoftware.printershare_12.14.10-480_minAPI19(nodpi)_apkmirror.com.apk`.
- Gmail account under your control.
- Tools:
  - `adb` (Android SDK)
  - Rooted device or emulator (to inspect app private storage easily), or
  - Frida / Xposed / LSPosed for runtime instrumentation, and
  - Network interception stack (Burp Suite / mitmproxy) with a custom CA installed on the device.

### PoC Path A – On‑device Storage / Logs

1. Install and configure PrinterShare:
   - Install the provided APK on the test device.
   - Open the app and add a Gmail/Google account when prompted (e.g., for printing from Gmail or Google Drive).
   - Complete any OAuth consent / login flows.

2. Search app storage for tokens:
   - If rooted:
     - Inspect `shared_prefs`, databases, and files:
       ```bash
       adb shell su -c 'ls -R /data/data/com.dynamixsoftware.printershare'
       adb shell su -c 'grep -R "oauth" /data/data/com.dynamixsoftware.printershare'
       adb shell su -c 'grep -R "ya29" /data/data/com.dynamixsoftware.printershare'
       ```
     - Look for any strings resembling Google OAuth access tokens (e.g., starting with `ya29.` or JWT‑like structures).
   - On a non‑rooted device:
     - Use `adb backup` or `run-as` if available:
       ```bash
       adb shell run-as com.dynamixsoftware.printershare ls files
       adb shell run-as com.dynamixsoftware.printershare cat files/<candidate_file>
       ```

3. Check logs:
   - Run PrinterShare while `logcat` is capturing:
     ```bash
     adb logcat | grep -i printershare
     ```
   - Look for debug logging that prints tokens, authorization codes, or HTTP Authorization headers.

4. Token reuse:
   - If you find an access/refresh token in plaintext:
     - Attempt to call Gmail / Google APIs directly from another host using `curl` or a small script.
     - Example (assuming OAuth token `TOKEN` with sufficient scopes):
       ```bash
       curl -H 'Authorization: Bearer TOKEN' \
            'https://gmail.googleapis.com/gmail/v1/users/me/profile'
       ```
   - Successful API calls using the harvested token confirm the information‑disclosure impact.

### PoC Path B – Network Capture

1. Set up a mitmproxy/Burp instance and install its CA certificate on the device.
2. Route device traffic through the proxy.
3. Re‑perform the Gmail login/printing flow in PrinterShare.
4. Inspect captured HTTP(S) requests for:
   - Authorization headers (`Authorization: Bearer <token>`),
   - Tokens in query parameters or JSON bodies,
   - Any non‑TLS or improperly pinned channel that leaks sensitive tokens.

5. As above, attempt to reuse captured tokens against Gmail APIs.

**Success criteria:**

- Ability to locate and reuse a Gmail token obtained from PrinterShare (disk or network) to access the Gmail account outside of the app.

---

## 2. CVE-2025-5099 – Out‑of‑Bounds Write in Native PDF Rendering (`pdfrender`)

**Goal:** Show that a crafted PDF can crash PrinterShare’s native `pdfrender` library, demonstrating memory corruption.

### Environment

- Same device / APK as above.
- Tools:
  - PDF generator (Python `pikepdf`, `qpdf`, or manual hex editing)
  - `adb logcat` for crash traces
  - Optionally `ndk-stack` or Breakpad/LLDB on rooted device for native stacks

### Steps

1. Identify a baseline PDF flow:
   - Use PrinterShare to print a benign PDF file and note the behavior.
   - Confirm the rendering path is working (preview, page thumbnails, etc.).

2. Create fuzzed PDFs:
   - Start from a simple PDF.
   - Use a script to mutate critical structures known to stress PDF renderers, e.g.:
     - XObject image dimensions and lengths
     - Font dictionary entries (e.g., `ToUnicode` maps)
     - Page content streams (add extremely large or negative coordinates)
     - XRef entries and object counts
   - Example high‑level pseudo‑fuzzer:
     ```python
     from pikepdf import Pdf
     from random import randint

     base = Pdf.open('base.pdf')
     for i in range(1000):
         pdf = Pdf.open('base.pdf')
         # mutate page box
         page = pdf.pages[0]
         page.mediabox = [0, 0, randint(10, 10**6), randint(10, 10**6)]
         pdf.save(f'out_{i}.pdf')
     ```

3. Feed fuzzed PDFs into PrinterShare:
   - Push them to the device:
     ```bash
     adb push out_*.pdf /sdcard/Download/
     ```
   - Open each PDF via PrinterShare (either from a file manager using "Share" or directly, depending on UI).

4. Monitor for crashes:
   - Run:
     ```bash
     adb logcat | grep -iE 'printershare|crash|fatal signal'
     ```
   - A native crash will typically show `Fatal signal 11 (SIGSEGV)` or similar originating in `libpdfrender.so` (exact name depends on extracted .so).

5. Optional: Stack unwinding
   - If symbols are available or you have the `.so` files:
     - Use `ndk-stack` with the app’s `libpdfrender*.so` to map addresses to functions.

**Success criteria:**

- Reproducible native crash in `pdfrender` when a specific malformed PDF is loaded.
- Logcat shows access errors consistent with out‑of‑bounds writes (segfaults, heap corruption, aborts in allocator, etc.).

---

## 3. CVE-2025-5100 – Double‑Free in Temporary Image Handling

**Goal:** Trigger the double‑free condition via crafted image/PDF inputs, observing heap‑corruption symptoms.

### Environment

- Same as above; focus on operations where PrinterShare converts or rasterizes pages/images (thumbnail previews, image printing, etc.).

### Steps

1. Identify workflows that exercise image pipelines:
   - Print large, multi‑page PDFs with many embedded images.
   - Print individual images (JPEG, PNG) from gallery.

2. Create stress‑test documents:
   - Construct a PDF containing many large or unusual images:
     - Images with odd dimensions (e.g., 1xN, Nx1, very large sizes).
     - Different color spaces (CMYK, Indexed with tricky palettes, embedded ICC profiles).
     - Multiple layers / transparency.
   - Alternatively, create a directory of pathological image files.

3. Send them through PrinterShare:
   - Use the app to generate previews or start print jobs.

4. Observe behavior:
   - Look for crashes during cleanup or after rendering completes:
     ```bash
     adb logcat | grep -iE 'printershare|F/libc|double free|corruption'
     ```
   - Double‑free issues often manifest as aborts with messages like `*** error for object 0x...: double free` or generic heap corruption diagnostics.

5. (Advanced) Heap grooming for exploit research:
   - Use repeated allocations (by repeatedly opening/closing documents) to try to make the bug deterministic.
   - Combine with ASLR/PIE and allocator behavior knowledge on the particular Android version.

**Success criteria:**

- Consistent crashes when handling specific crafted inputs, with log messages or debugger traces indicating heap corruption / double free.

---

## 4. General Sandboxed Exploit Development Notes

If any of the above PoCs confirm crashes or token exposure, a deeper exploit development process could:

- Combine CVE‑2025‑5098 and a native RCE (5099/5100) to:
  - Achieve code execution within PrinterShare.
  - Programmatically enumerate and exfiltrate Gmail tokens or invoke Gmail APIs.
- Leverage the app’s broad permissions (contacts, calendar, storage, accounts, network) to demonstrate full compromise of user data within the app sandbox.

All exploitation experiments must be **confined to your own test accounts and devices** and comply with relevant laws and policies.