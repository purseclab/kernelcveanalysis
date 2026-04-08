# mpv-android 2021-03-10 APK Analysis

## App identity
- Package name: `is.xyz.mpv`
- Version name: `2021-03-10-release`
- Version code: `24`
- Min SDK: 21 (Android 5.0)
- Target SDK: 29 (Android 10)

Evidence:
- `aapt dump badging` and `aapt dump xmltree` on `/data/apps/mpv-android-2021-03-10.apk`.
- Matches public metadata for this release on APKPure / APKMirror.

## Permissions
- `android.permission.INTERNET`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `android.permission.FOREGROUND_SERVICE`

No dangerous custom permissions exported to other apps were observed; there is an internal-looking permission `is.xyz.mpv.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` documented on F-Droid for later versions, but this 2021-03-10 APK's manifest (as dumped) does not show it.

## Exported components / intents

Primary activity: `is.xyz.mpv.MPVActivity`

This activity is exported via multiple VIEW intent filters and can be invoked by other apps or browsers.

Intent-filters (high level):
- `android.intent.action.VIEW` + categories `DEFAULT`, `BROWSABLE` for schemes:
  - `rtmp`, `rtmps`, `rtp`, `rtsp`, `mms`, `mmst`, `mmsh`, `tcp`, `udp`
- `android.intent.action.VIEW` for `content://` and `file://` URIs with `video/*` and `audio/*` MIME types.
- `android.intent.action.VIEW` for `http://` and `https://` URLs with:
  - `video/*`, `audio/*`, `application/vnd.apple.mpegurl` (HLS)
  - Many `pathPattern` matchers for common file extensions: `.mkv`, `.mp4`, `.webm`, `.avi`, `.flac`, `.mp3`, `.ogg`, `.m3u8*` etc.

Impact:
- Other apps or browsers can send it media URLs or local file URIs for playback. That is the main attack surface for malformed media or playlist files.

---

## Native library inventory

The APK bundles two architectures: `arm64-v8a` and `armeabi-v7a`. For each, the following libraries are present:

### Common library set (both ABIs)
- `libavcodec.so`
- `libavdevice.so`
- `libavfilter.so`
- `libavformat.so`
- `libavutil.so`
- `libc++_shared.so`
- `libmpv.so`
- `libplayer.so` (app-specific glue)
- `libpostproc.so`
- `libswresample.so`
- `libswscale.so`

### ELF / SONAME / dependency details

All libs are ET_DYN shared objects built for Android (System V ABI), no explicit version numbers in SONAMEs.

#### arm64-v8a
- `/data/workdir/mpv/lib/arm64-v8a/libavcodec.so`
  - Arch: 64-bit (ELF64, arm64-v8a)
  - SONAME: `libavcodec.so`
  - NEEDED: `libswresample.so`, `libavutil.so`, `libm.so`, `libz.so`, `libc.so`
  - Likely upstream: FFmpeg `libavcodec`.
  - Version clues: none embedded in SONAME; must infer from app release date and upstream metadata.

- `/data/workdir/mpv/lib/arm64-v8a/libavdevice.so`
  - Arch: 64-bit
  - SONAME: `libavdevice.so`
  - NEEDED: `libavformat.so`, `libavutil.so`, `libc.so`
  - Upstream: FFmpeg `libavdevice`.

- `/data/workdir/mpv/lib/arm64-v8a/libavfilter.so`
  - Arch: 64-bit
  - SONAME: `libavfilter.so`
  - NEEDED: `libswscale.so`, `libpostproc.so`, `libavformat.so`, `libavcodec.so`, `libswresample.so`, `libavutil.so`, `libm.so`, `libc.so`
  - Upstream: FFmpeg `libavfilter`.

- `/data/workdir/mpv/lib/arm64-v8a/libavformat.so`
  - Arch: 64-bit
  - SONAME: `libavformat.so`
  - NEEDED: `libavcodec.so`, `libavutil.so`, `libm.so`, `libz.so`, `libc.so`
  - Upstream: FFmpeg `libavformat`.

- `/data/workdir/mpv/lib/arm64-v8a/libavutil.so`
  - Arch: 64-bit
  - SONAME: `libavutil.so`
  - NEEDED: `libm.so`, `libc.so`
  - Upstream: FFmpeg `libavutil`.

- `/data/workdir/mpv/lib/arm64-v8a/libpostproc.so`
  - Arch: 64-bit
  - SONAME: `libpostproc.so`
  - NEEDED: `libavutil.so`, `libc.so`
  - Upstream: FFmpeg `libpostproc`.

- `/data/workdir/mpv/lib/arm64-v8a/libswresample.so`
  - Arch: 64-bit
  - SONAME: `libswresample.so`
  - NEEDED: `libavutil.so`, `libm.so`, `libc.so`
  - Upstream: FFmpeg `libswresample`.

- `/data/workdir/mpv/lib/arm64-v8a/libswscale.so`
  - Arch: 64-bit
  - SONAME: `libswscale.so`
  - NEEDED: `libavutil.so`, `libm.so`, `libc.so`
  - Upstream: FFmpeg `libswscale`.

- `/data/workdir/mpv/lib/arm64-v8a/libc++_shared.so`
  - Arch: 64-bit
  - SONAME: `libc++_shared.so`
  - NEEDED: `libc.so`, `libdl.so`
  - Upstream: LLVM libc++ shared runtime.

- `/data/workdir/mpv/lib/arm64-v8a/libmpv.so`
  - Arch: 64-bit
  - SONAME: `libmpv.so`
  - NEEDED: `libandroid.so`, `libEGL.so`, `libavutil.so`, `libm.so`, `libavcodec.so`, `libdl.so`, `libz.so`, `libswresample.so`, `libswscale.so`, `libavfilter.so`, `libpostproc.so`, `libavformat.so`, `libavdevice.so`, `libOpenSLES.so`, `libc.so`
  - Upstream: `libmpv` from the mpv player project.

- `/data/workdir/mpv/lib/arm64-v8a/libplayer.so`
  - Arch: 64-bit
  - SONAME: `libplayer.so`
  - NEEDED: `libswscale.so`, `libavcodec.so`, `libmpv.so`, `libc++_shared.so`, `liblog.so`, `libGLESv3.so`, `libEGL.so`, `libc.so`, `libm.so`, `libdl.so`
  - Upstream: app-specific JNI/frontend glue (likely mpv-android project code), no public upstream project beyond mpv-android.

#### armeabi-v7a
- `/data/workdir/mpv/lib/armeabi-v7a/libavcodec.so`
  - Arch: 32-bit (ELF32)
  - SONAME: `libavcodec.so`
  - NEEDED: `libswresample.so`, `libavutil.so`, `libm.so`, `libdl.so`, `libz.so`, `libc.so`
  - Upstream: FFmpeg `libavcodec`.

- `/data/workdir/mpv/lib/armeabi-v7a/libavdevice.so`
  - Arch: 32-bit
  - SONAME: `libavdevice.so`
  - NEEDED: `libavformat.so`, `libavutil.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libavfilter.so`
  - Arch: 32-bit
  - SONAME: `libavfilter.so`
  - NEEDED: `libswscale.so`, `libpostproc.so`, `libavformat.so`, `libavcodec.so`, `libswresample.so`, `libavutil.so`, `libm.so`, `libdl.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libavformat.so`
  - Arch: 32-bit
  - SONAME: `libavformat.so`
  - NEEDED: `libavcodec.so`, `libavutil.so`, `libm.so`, `libz.so`, `libdl.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libavutil.so`
  - Arch: 32-bit
  - SONAME: `libavutil.so`
  - NEEDED: `libm.so`, `libdl.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libpostproc.so`
  - Arch: 32-bit
  - SONAME: `libpostproc.so`
  - NEEDED: `libavutil.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libswresample.so`
  - Arch: 32-bit
  - SONAME: `libswresample.so`
  - NEEDED: `libavutil.so`, `libm.so`, `libdl.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libswscale.so`
  - Arch: 32-bit
  - SONAME: `libswscale.so`
  - NEEDED: `libavutil.so`, `libm.so`, `libdl.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libc++_shared.so`
  - Arch: 32-bit
  - SONAME: `libc++_shared.so`
  - NEEDED: `libc.so`, `libdl.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libmpv.so`
  - Arch: 32-bit
  - SONAME: `libmpv.so`
  - NEEDED: `libandroid.so`, `libEGL.so`, `libavutil.so`, `libm.so`, `libavcodec.so`, `libdl.so`, `libz.so`, `libswresample.so`, `libswscale.so`, `libavfilter.so`, `libpostproc.so`, `libavformat.so`, `libavdevice.so`, `libOpenSLES.so`, `libc.so`

- `/data/workdir/mpv/lib/armeabi-v7a/libplayer.so`
  - Arch: 32-bit
  - SONAME: `libplayer.so`
  - NEEDED: `libdl.so`, `libswscale.so`, `libavcodec.so`, `libmpv.so`, `libc++_shared.so`, `liblog.so`, `libGLESv3.so`, `libEGL.so`, `libc.so`, `libm.so`

No additional third‑party native libraries (e.g. OpenSSL, ffmpeg-prefixed with versions, etc.) are visible beyond:
- FFmpeg libraries (`libav*`, `libsw*`, `libpostproc`)
- mpv (`libmpv`)
- C++ runtime and Android system libs.

Version numbers for FFmpeg and libmpv cannot be inferred directly from ELF metadata; they must be correlated from release notes.

---

## Likely upstream versions

Using public release metadata for mpv-android around 2021-03-10:

- A search for "mpv-android 2021-03-10-release dependencies" leads to the mpv-android GitHub releases page, but current releases only show dependencies for newer builds (e.g. ffmpeg 7.0/8.1, libmpv specific commits). For the 2021-03-10 release specifically, the exact FFmpeg and libmpv versions are not trivially visible from the latest GitHub release notes.
- Based on mpv project history and typical mpv-android packaging around 2020–2021, mpv-android 2021-03-10 likely embeds:
  - `libmpv` from mpv around 0.32–0.33.
  - FFmpeg snapshot somewhere between FFmpeg 4.3.x and 4.4.

This is an informed but not exact mapping; without the historical build log for this specific release we cannot assert the exact versions.

Confidence on version range:
- `libmpv`: medium (project version mapping via timeframe)
- FFmpeg libs: low–medium (no explicit build-info in binary; timeframe‑based inference only).

---

## Known relevant vulnerabilities (candidate CVEs)

### 1. CVE-2021-30145 – mpv format string vulnerability

- Component: `mpv` player (`libmpv` / core mpv), not Android-specific.
- Description: format string vulnerability in mpv through 0.33.0 allows user-assisted remote attackers to achieve code execution via a crafted M3U playlist file.
- Reference:
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-30145
  - GitHub Advisory: https://github.com/advisories/GHSA-mf25-jq7f-vx34
- Affected versions: mpv up to and including 0.33.0.
- Fix: patched in mpv after 0.33.0 (0.33.1+ / later git).

**Relevance to this APK**
- Timing: The mpv-android `2021-03-10-release` is dated March 10, 2021. CVE-2021-30145 was disclosed in April 2021 and affects mpv "through 0.33.0". mpv-android is described as "video player for Android based on libmpv"; earlier mpv-android releases around 2020–early 2021 were known to bundle mpv 0.32–0.33.
- Given the close timing and description, it is plausible that this APK embeds an affected libmpv version.
- Trigger conditions:
  - User opens a crafted `.m3u` playlist file (local or remote) via mpv-android.
  - mpv parses the playlist and hits the vulnerable format-string path.
- Impact:
  - Potential remote code execution in the app process, with the app's privileges (read/write external storage, internet, foreground service). On Android this is typically limited to the app sandbox but could expose user media or enable network-based actions.

**Confidence: medium**
- Pro:
  - mpv-android definitely embeds libmpv.
  - The release timeframe and marketing text (based on libmpv, advanced mpv features) match the affected mpv line.
- Con:
  - Exact libmpv version and commit hash for this precise APK not recovered from local artifacts.
  - It is *possible* (though unlikely given dates) that it already included the fix.

### 2. FFmpeg library vulnerabilities (generic)

Many FFmpeg versions before and around 4.3/4.4 contain numerous memory safety issues (use-after-free, out-of-bounds reads/writes, integer overflows) in `libavcodec`, `libavformat`, `libavfilter`, etc., often triggerable by malformed media files. Examples (non‑exhaustive and not all necessarily applicable to the embedded version):

- CVE-2020-20448, CVE-2020-20453, CVE-2020-20448, CVE-2020-12284, CVE-2020-35964, etc.

Given the lack of precise version identification from the ELF binaries, mapping specific CVEs to this build is speculative.

**Relevance to this APK**
- The app clearly embeds FFmpeg libraries and exposes them to potentially untrusted media via VIEW intents (including remote HTTP(S) URLs and arbitrary content/file URIs shared by other apps).
- However, without knowing the exact FFmpeg commit or major/minor version, it is not defensible to assert particular CVEs as definitely present.

**Confidence: low per-CVE, medium that *some* known FFmpeg issues from that era apply.**

### 3. Other components

- `libc++_shared.so` (LLVM libc++) – no version string present; likely brought in by NDK. Public libc++ vulnerabilities are rare and typically not directly exploitable from media parsing alone; no specific CVEs can be confidently mapped from available evidence.
- App-specific `libplayer.so` – appears to be thin JNI/UI glue on top of `libmpv` + FFmpeg; no public CVEs specific to mpv-android native glue code were found.
- The Android Java/Kotlin layer (manifest, permissions, intents) shows no obvious misconfigurations like exported custom permissions or world-readable content providers. No public CVEs specific to mpv-android 2021-03-10 were found.

---

## Overall risk summary

- Main attack surface:
  - Malicious or malformed media/playlist files delivered via:
    - Opening remote HTTP(S) or streaming URLs in mpv-android.
    - Sharing local files or `content://` URIs from other apps into mpv-android.
  - Playback engine: libmpv + FFmpeg libraries (libavcodec, libavformat, etc.).

- Strongest candidate vulnerability:
  - CVE-2021-30145 (mpv format string in M3U playlist handling), likely affecting mpv versions up to 0.33.0. Given the timeframe and the nature of mpv-android, this APK is a plausible candidate for being affected, but this cannot be proven from ELF metadata alone.

- Additional likely issues:
  - Whatever media-parsing vulnerabilities existed in the specific FFmpeg snapshot bundled in March 2021 builds. Exact CVE list is uncertain without historical mpv-android build logs.

---

## Open questions / uncertainties

1. Exact libmpv and FFmpeg versions used for `2021-03-10-release`.
   - Would require either:
     - mpv-android Git tag + build logs for that date, or
     - version strings embedded in the binary (not visible from simple ELF headers; would need symbol/string inspection).

2. Whether the CVE-2021-30145 fix was already backported into the libmpv used in this build.
   - Public CVE description states "through 0.33.0", implying fixed in later versions; given build date (before disclosure), the more likely scenario is that this build is vulnerable.

3. Exact list of applicable FFmpeg CVEs.
   - Needs cross-referencing the exact FFmpeg version used.

---

## Compact summary

- App: mpv-android (`is.xyz.mpv`)
- Version: `2021-03-10-release` (code 24), minSdk 21, targetSdk 29.
- Key libraries:
  - libmpv (core mpv player engine)
  - FFmpeg: `libavcodec`, `libavformat`, `libavfilter`, `libavdevice`, `libavutil`, `libswscale`, `libswresample`, `libpostproc`
  - libc++_shared, app glue `libplayer.so`.
- Candidate CVEs:
  - CVE-2021-30145 (mpv format string via crafted M3U) – **medium confidence** that this applies.
  - Various FFmpeg parsing issues from ~FFmpeg 4.3/4.4 era – **low confidence per specific CVE**, but **medium confidence** that some known FFmpeg vulnerabilities from that timeframe exist in this build.
- Overall confidence in analysis: medium; primary limitation is lack of explicit version identifiers for libmpv and FFmpeg in the extracted binaries.