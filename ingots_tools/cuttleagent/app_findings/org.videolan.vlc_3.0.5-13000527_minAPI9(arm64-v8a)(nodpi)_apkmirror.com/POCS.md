# VLC for Android 3.0.5 – Proof-of-Concept Notes

These PoCs are **high-level** descriptions intended for security testing in a controlled environment. They are not complete exploit scripts, but rather guidance on how a tester could attempt to reproduce the suspected vulnerabilities against this APK.

Target APK:

- `/data/apps/org.videolan.vlc_3.0.5-13000527_minAPI9(arm64-v8a)(nodpi)_apkmirror.com.apk`
- Package: `org.videolan.vlc`
- Version: `3.0.5`


## PoC 1 – MP4 EIA-608 Integer Underflow (CVE-2019-13602)

**Goal**: Trigger a crash or memory corruption by exploiting the MP4 EIA‑608 caption parsing bug.

1. **Craft a malicious MP4 file** with:
   - Valid MP4 container structure.
   - EIA‑608/CEA‑608 closed-caption data placed in the appropriate MP4 boxes (as per VLC’s `MP4_EIA608_Convert` expectations).
   - Malformed size / offset values that can cause an integer underflow when VLC calculates buffer sizes.

2. **Test steps**:
   - Install the APK on an arm64 Android device or emulator (API ≥ 21 recommended).
   - Copy the crafted MP4 file to local storage (e.g., `/sdcard/Movies/bad_eia608.mp4`).
   - Open VLC, browse to the file and start playback.

3. **Expected observable behavior**:
   - VLC crashes during parsing or early playback of the file.
   - Repeated crashes on each open strongly suggest the vulnerable path is being hit.

4. **Notes**:
   - Use `adb logcat` filtered on `org.videolan.vlc` and native crash tags to confirm a native crash and collect backtrace.
   - A full exploit would require precise control over heap layout; this PoC focuses only on demonstrating the bug.


## PoC 2 – MMS Integer Overflow / Heap Overflow (CVE-2024-46461)

**Goal**: Trigger the MMS-related integer overflow that can cause a heap overflow and DoS / potential RCE.

1. **Set up a test MMS-like server**:
   - Implement a simple TCP server that mimics an MMS server (Microsoft Media Server / related protocol) enough to get VLC to talk to it.
   - The server should respond with a specially crafted `0x01` response that exercises the vulnerable code path (as referenced in public advisories).
   - Ensure response fields that influence buffer sizes/lengths are set so they cause an integer overflow in VLC’s MMS parsing.

2. **Expose the malicious stream**:
   - Make the stream addressable via a URL VLC will accept, e.g. `mms://<device-ip>:<port>/test` or possibly `mmstu://` depending on VLC’s scheme.

3. **Test steps**:
   - Ensure phone/emulator can reach the test server (same LAN or via port forwarding).
   - In VLC for Android, use *Open MRL* / *Network Stream* and input the malicious MMS URL.
   - Start playback/connection.

4. **Expected observable behavior**:
   - VLC crashes or becomes unresponsive soon after attempting to connect and parse the MMS stream.
   - Logcat shows a native crash in the MMS module (e.g., references to MMS / `mmstu` code or suspicious heap corruption reports).

5. **Notes**:
   - This requires some protocol reverse‑engineering or following public PoCs for CVE-2024-46461.
   - Focus is on causing a reliable crash, not full code execution.


## PoC 3 – VNC Module Integer Overflow (CVE-2022-41325) – Conditional

**Goal**: If the VNC module is present and accessible in this build, trigger its integer overflow via a crafted VNC server or playlist.

1. **Check module availability**:
   - From VLC for Android UI, look for any way to open VNC streams (e.g., entering `vnc://` URLs in network stream UI).
   - Alternatively, use an `.xspf` or `.m3u` playlist that references a `vnc://` URL and open it in VLC.

2. **Set up a malicious VNC server**:
   - Modify an open‑source VNC server or build your own minimal implementation to respond with malformed data designed per CVE-2022-41325 write‑ups.
   - The server should send fields that cause integer overflow when VLC parses them.

3. **Test steps**:
   - Ensure connectivity between Android device and the test VNC server.
   - In VLC, open the `vnc://<server-ip>:<port>` URL directly or via playlist.

4. **Expected observable behavior**:
   - VLC crashes shortly after attempting to connect to the malicious server.
   - Logcat indicates a crash in VNC-related code.

5. **Notes**:
   - If VLC for Android does not recognize `vnc://` URLs or no VNC access is exposed, this PoC may not be applicable to this specific build.


## General Testing Methodology

For all PoCs:

- Use **non‑production devices** and **isolated networks**.
- Always monitor logs:
  - `adb logcat | grep -iE "vlc|libvlc|crash"`
- Consider enabling native crash symbolization (if you have symbols) or at least collect tombstones from `/data/tombstones` for analysis.
- Validate that the crash only occurs with the crafted inputs and not with normal files/streams, to rule out environmental issues.


## Disclaimer

These PoCs are for **defensive security research and testing only**. They are intentionally incomplete and generalized to avoid providing turnkey exploit code. Use them only in environments where you have explicit permission to test and never against systems or users you do not own or administer.