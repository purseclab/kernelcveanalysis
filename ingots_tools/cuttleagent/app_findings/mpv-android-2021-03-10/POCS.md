# mpv-android 2021-03-10 – Candidate PoC Ideas

This file outlines *conceptual* proof-of-concept approaches based on public vulnerability information. They are not guaranteed to work against this exact APK but are plausible starting points.

## 1. CVE-2021-30145 – mpv format string via M3U playlist

**Goal:** Trigger the mpv format string vulnerability in playlist handling to achieve memory corruption / potential code execution inside mpv-android.

### High-level idea

- Craft an `.m3u` playlist file that abuses a format-string bug in mpv's handling of certain metadata.
- Deliver that playlist to mpv-android via:
  - `content://` or `file://` URI from another Android app using an `ACTION_VIEW` intent, or
  - Hosting it at an `http(s)://` URL and tapping it in a browser with mpv-android chosen as handler.

### Minimal PoC outline

1. Create a malicious playlist file on disk, e.g. `/sdcard/Download/poc.m3u`:

   ```text
   #EXTM3U
   #EXTINF:123,AAAA%p%x%n
   http://example.com/dummy.mp4
   ```

   The exact payload will depend on the vulnerable code path; real PoCs use more precise format strings to leak or corrupt memory. Public writeups of CVE-2021-30145 (if available) should be consulted for the exact vulnerable field and escaping rules.

2. From a helper Android app, send an intent:

   ```java
   Intent i = new Intent(Intent.ACTION_VIEW);
   i.setDataAndType(Uri.parse("file:///sdcard/Download/poc.m3u"), "application/vnd.apple.mpegurl");
   i.setPackage("is.xyz.mpv");
   startActivity(i);
   ```

   Or use `content://` URI from a `FileProvider` with the same MIME type.

3. Observe mpv-android behavior:
   - Crashes (SIGSEGV / SIGABRT) during playlist parsing.
   - Unexpected memory accesses (if under debugger).

4. For a more advanced exploit, adjust the format string to read/write memory in a controlled way. This is highly target-specific and requires knowledge of the exact mpv build and platform ASLR / stack canary state.

**Notes/limitations:**
- This PoC relies on the assumption that mpv-android 2021-03-10 embeds a vulnerable mpv (≤0.33.0) and that its playlist parsing path is reachable for local or remote `.m3u` files.
- Without the precise source diff for the affected mpv version, this PoC is a template and may need adaptation.

## 2. FFmpeg malformed media test-cases

Because this APK bundles FFmpeg libraries (`libavcodec`, `libavformat`, etc.), known FFmpeg corpus test-cases for vulnerabilities from ~2020–2021 can be replayed through mpv-android as a fuzzer-lite approach.

**Goal:** Detect whether any known FFmpeg vulnerabilities are still present by causing controlled crashes.

### High-level PoC structure

1. Collect sample PoC files from public FFmpeg CVE reports around 2020–2021 (e.g., from FFmpeg, oss-fuzz, or security advisories). Examples might include malformed:
   - AVI / MKV / MP4 / FLV files
   - Specific codec containers (e.g., `mov`, `rm`, `vob`, etc.)

2. Place PoC files under `/sdcard/Movies/ffmpeg-pocs/`.

3. From a helper app, or via file manager, send `ACTION_VIEW` intents to mpv-android:

   ```java
   Intent i = new Intent(Intent.ACTION_VIEW);
   i.setDataAndType(uriToPocFile, "video/*");
   i.setPackage("is.xyz.mpv");
   startActivity(i);
   ```

4. Observe app behavior:
   - If mpv-android crashes consistently on a specific PoC where the upstream FFmpeg bug is known and fixed in later versions, this suggests that the embedded FFmpeg may still be vulnerable.

**Notes:**
- This does not map to a *specific* CVE without correlating to the exact PoC and FFmpeg version range.
- Useful mainly as a practical check that old FFmpeg issues survive in this build.

## 3. General media/URL fuzzing through exported VIEW intents

Even without precise CVE knowledge, the exposed `ACTION_VIEW` intents provide an opportunity to fuzz the media pipeline.

### URL-based fuzzing

- mpv-android registers for `http`, `https`, `rtsp`, `rtmp`, `mms`, `udp`, `tcp` schemes.
- A test harness app can rapidly fire `ACTION_VIEW` intents with randomized or crafted URLs, e.g.:

  ```java
  String[] schemes = {"http", "https", "rtsp", "rtmp", "mms", "udp", "tcp"};
  for (String scheme : schemes) {
      Uri u = Uri.parse(scheme + "://example.com/" + randomPath());
      Intent i = new Intent(Intent.ACTION_VIEW, u);
      i.addCategory(Intent.CATEGORY_BROWSABLE);
      i.setPackage("is.xyz.mpv");
      context.startActivity(i);
  }
  ```

- Back the URLs with a custom server that serves malformed headers, partial media, or corrupted containers to exercise boundary conditions.

### Local file fuzzing

- Generate random MKV/MP4/WEBM/AVI/FLAC/MP3/OGG containers with slight structural corruptions and feed them via the file or content scheme, using the extensive `pathPattern` matches declared in the manifest.

---

## Caveats

- All PoCs above are *hypothetical* and based on the assumption that this build uses mpv ≤0.33.0 and an older FFmpeg snapshot.
- They are intended for controlled testing on dedicated devices or emulators.
- Exact exploitability on this APK depends on address space layout randomization, compiler hardening, and whether the vulnerable code paths are actually present in the mpv / FFmpeg versions that were built into `2021-03-10-release`.