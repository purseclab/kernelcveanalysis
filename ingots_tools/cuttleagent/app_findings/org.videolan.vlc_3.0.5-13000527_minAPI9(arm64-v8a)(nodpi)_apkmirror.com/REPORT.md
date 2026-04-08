# VLC for Android 3.0.5 (org.videolan.vlc)

## App identification

- **APK**: `/data/apps/org.videolan.vlc_3.0.5-13000527_minAPI9(arm64-v8a)(nodpi)_apkmirror.com.apk`
- **Package name**: `org.videolan.vlc`
- **VersionName**: `3.0.5`
- **VersionCode**: `13000527`
- **Min SDK**: 9
- **Target SDK**: 26
- **Label**: `VLC`

## Permissions

Declared (from `aapt dump badging`):

- `org.videolan.vlc.permission.READ_EXTENSION_DATA`
- `org.videolan.vlc.permission.BIND_DATA_CONSUMER`
- `android.permission.VIBRATE`
- `android.permission.WRITE_SETTINGS`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `android.permission.INTERNET`
- `android.permission.RECEIVE_BOOT_COMPLETED`
- `android.permission.ACCESS_NETWORK_STATE`
- `android.permission.WAKE_LOCK`
- `android.permission.MODIFY_AUDIO_SETTINGS`
- `android.permission.BLUETOOTH`
- `android.permission.SYSTEM_ALERT_WINDOW`
- `android.permission.READ_EXTERNAL_STORAGE`

These are consistent with a media player that accesses local/network content, shows overlays (popup video), runs background playback, and exposes an extension interface.

## Exported / intent-related behavior (high level)

From `aapt`:

- **Launchable activity**: `org.videolan.vlc.StartActivity`
- **Leanback launchable (Android TV)**: same activity
- `provides-component:'app-widget'` and `'search'` indicate app widget(s) and searchable interface.

Full manifest component export flags were not dumped here; no evidence from this quick pass of obviously misconfigured exported components, but a deeper `aapt dump xmltree`/`apktool` pass would be needed for a complete assessment.


## Native library inventory

APK `native-code` section lists `arm64-v8a`. Unpacked under `/data/workdir/vlc/lib/arm64-v8a`:

1. `/data/workdir/vlc/lib/arm64-v8a/libvlcjni.so`
   - **Architecture**: `ELF 64-bit LSB shared object, ARM aarch64`
   - **SONAME**: not shown in short dump (likely internal VLC JNI bridge)
   - **Dependencies** (from `readelf -d`):
     - `libEGL.so`
     - `libm.so`
     - `libGLESv2.so`
     - `libstdc++.so`
     - `libdl.so`
     - `liblog.so`
     - `libc.so`
   - **Likely upstream project**: VideoLAN VLC core + modules (Android JNI wrapper). This is the main multimedia engine plus JNI glue.
   - **Version clues**:
     - Tied to app version **3.0.5** (VLC for Android 3.0.5). VLC upstream for Android 3.0.x historically embeds VLC 3.0.x core. Exact embedded VLC core minor revision is not visible from ELF metadata here, but very likely in the VLC 3.0.x line.
   - **Confidence**: High that this is VLC's own native engine and thus subject to VLC core CVEs affecting VLC 3.0.x.

2. `/data/workdir/vlc/lib/arm64-v8a/libjniloader.so`
   - **Architecture**: `ELF 64-bit LSB shared object, ARM aarch64`
   - **SONAME**: `libjniloader.so`
   - **Dependencies**:
     - `libdl.so`, `liblog.so`, `libc.so`, `libm.so`, `libstdc++.so`
   - **Likely upstream project**: VLC Android JNI bootstrap/helper (small loader for `libvlcjni.so`). No strong version information beyond app version.
   - **Version clues**: Ships alongside VLC for Android 3.0.5.
   - **Confidence**: High for identification; no evidence that this is a third‑party component.

3. `/data/workdir/vlc/lib/arm64-v8a/libanw.21.so`
   - **Architecture**: `ELF 64-bit LSB shared object, ARM aarch64`
   - **SONAME**: `libanw.21.so`
   - **Dependencies**:
     - `liblog.so`, `libhardware.so`, `libc.so`, `libm.so`, `libstdc++.so`, `libdl.so`
   - **Likely upstream project**: internal Android native window / hardware integration helper used by VLC (the name suggests an "Android Native Window" helper targeting API 21+).
   - **Version clues**: none beyond SONAME; tied to this VLC build.
   - **Confidence**: Medium – clearly an internal helper, but upstream project name is not confirmed from metadata alone.

No additional `.so` files for other ABIs were present in this APK (only `arm64-v8a`).


## Likely third‑party components

Based on file structure and typical VLC builds (plus Kotlin modules in `META-INF`):

- **Kotlin stdlib**: presence of `kotlin-stdlib.kotlin_module`, `kotlin-stdlib-jre7.kotlin_module`, `kotlinx-coroutines-core`, `kotlinx-coroutines-android`.
  - These are standard Kotlin libraries embedded in the DEX, not separate `.so` files. Version cannot be read reliably from the provided metadata alone here. No CVEs are commonly associated to these versions that are specific to the mobile client when used as regular libraries.
- **VLC core and plugins**: bundled within `libvlcjni.so` and resources (`assets/lua/...`, etc.). This means all VLC demuxers/codecs are present and usable via crafted media inputs.


## Candidate CVEs for VLC core affecting this build

VLC for Android 3.0.5 corresponds roughly to VLC 3.0.x era. Public advisories and NVD entries list many vulnerabilities affecting **VLC 3.0.0–3.0.7.x** and generally phrased as affecting "VLC media player 3.0.x" or "VLC media player through 3.0.7.1".

Because this Android package embeds the VLC engine in `libvlcjni.so`, it is reasonable to assume most engine‑level parsing vulnerabilities apply here as long as the vulnerable module is present and reachable (which it usually is).

Below is a non‑exhaustive list of selected relevant CVEs, focusing on ones clearly applying to **3.0.x before later fixed versions** and not confined to Windows‑only features or installers. All of these are **remote, file/stream driven**: an attacker needs to trick the user into opening a crafted media file or stream/playlist.

> Note: Exact mapping from VLC for Android 3.0.5 to a specific VLC core minor release (for example 3.0.3 vs 3.0.4) is not visible here, so the applicability for each CVE is rated by version range and general 3.0.x status. Where a CVE is explicitly fixed before 3.0.3 or only present in 3.0.7.1, that is called out.

### CVE-2019-13602 – MP4 EIA-608 integer underflow

- **Component**: VLC media player core (MP4 demuxer, function `MP4_EIA608_Convert()` in `modules/demux/mp4/mp4.c`).
- **Affected versions**: "VideoLAN VLC media player through 3.0.7.1" according to public advisories (not limited to desktop; this is engine code).
- **Why relevant**:
  - This APK embeds a VLC 3.0.x engine in `libvlcjni.so`.
  - There is no evidence that Android builds exclude the MP4 demuxer or EIA‑608 handling; these are standard.
  - Version 3.0.5 < 3.0.8 and is squarely inside the "through 3.0.7.1" vulnerable range.
- **Trigger**:
  - User opens a specially crafted MP4 file containing malformed EIA‑608 closed‑caption data.
  - Or opens a crafted playlist/URL that leads VLC to download and parse such media.
- **Impact**:
  - Integer underflow leading to **heap-based buffer overflow** and potential crash (DoS).
  - Depending on environment and mitigation, may allow **arbitrary code execution** in the app's context.
- **Confidence**: **High** that this vulnerability (or its underlying bug) affects this Android build.
- **References**:
  - ABB advisory summarizing MP4 EIA608 issue: notes CVE-2019-13602 in VLC components through 3.0.7.1.

### CVE-2019-13615 – MKV / libebml heap-based buffer over-read

- **Component**: `libebml` < 1.3.6 as used in VLC's MKV demuxer (`modules/demux/mkv`).
- **NVD description (current)**: "libebml before 1.3.6, as used in the MKV module in VideoLAN VLC Media Player binaries before 3.0.3, has a heap-based buffer over-read in EbmlElement::FindNextElement." (The CVE text was updated; earlier described 3.0.7.1, but root cause was in libebml.)
- **Affected versions** (practical impact): VLC binaries **before 3.0.3** with affected libebml.
- **Why relevant / uncertain**:
  - VLC for Android 3.0.5 is **after** the fixed 3.0.3 binary for desktop; Android may have updated as well.
  - Without ELF symbol or string inspection for `libebml` version in `libvlcjni.so`, it's unclear whether Android 3.0.5 still shipped a vulnerable libebml.
- **Trigger**:
  - Opening a crafted MKV file with malformed EBML structure.
- **Impact**:
  - Heap-based buffer over-read, likely crash/DoS; some reports considered possible code execution.
- **Confidence**: **Low/uncertain** for this specific APK version:
  - Evidence suggests the bug was fixed in VLC binaries before 3.0.3 on desktop; Android 3.0.5 probably inherits the fix, but this is not directly verifiable from this APK alone.
- **References**:
  - NVD: CVE-2019-13615.

### CVE-2022-41325 – VNC module integer overflow

- **Component**: VLC media player VNC module.
- **Affected versions**: "VideoLAN VLC Media Player through 3.0.17.4".
- **Why relevant**:
  - VLC's VNC input module (if compiled in) allows connecting to remote VNC servers; vulnerable versions can be triggered by a **crafted playlist** or by connecting to a **rogue VNC server**.
  - VLC 3.0.5 is within the affected range.
  - Android builds typically ship a wide set of access/demux modules; however, some desktop‑only modules might be omitted. Without detailed module listing from `libvlcjni.so`, we cannot conclusively prove presence of VNC, but core VLC usually includes it.
- **Trigger**:
  - User opens a crafted playlist that references a VNC resource, or manually connects to a malicious VNC server from within VLC (if UI supports it on Android).
- **Impact**:
  - Integer overflow → crash or **possible code execution** in the player context.
- **Confidence**: **Medium**:
  - Version fits; component is part of generic VLC; uncertainty is only whether Android build ships VNC module and exposes it.
- **References**:
  - Ubuntu security tracker (`vlc` package, CVE-2022-41325) listing affected versions through 3.0.17.4.

### CVE-2024-46461 – MMS integer overflow (heap overflow, DoS/RCE)

- **Component**: VLC MMS stream handling (`mmstu.c` / MMS module).
- **Affected versions**: "VLC media player 3.0.20 and earlier" (per NVD, general to all platforms using this module).
- **Why relevant**:
  - This APK embeds a VLC 3.0.x engine, which is **earlier than 3.0.20** and thus inside the affected interval.
  - MMS module (Microsoft Media Server streaming protocol) is typically present in VLC builds across platforms, including Android, unless specifically disabled.
- **Trigger**:
  - User opens a maliciously crafted MMS stream / URL in VLC.
  - The crafted server response with a particular 0x01 response can trigger the integer overflow.
- **Impact**:
  - Integer overflow → **heap-based buffer overflow** → **denial of service** and potentially arbitrary code execution with VLC app’s privileges.
- **Confidence**: **High** that the underlying vulnerable code is present, given broad version range and lack of platform limitation.
- **References**:
  - NVD: CVE-2024-46461.
  - Ubuntu tracker (package `vlc`) lists VLC package as affected until patched.

### Other VLC 3.x engine CVEs (not exhaustively enumerated)

There are numerous other VLC 3.x CVEs (2018–2025) in areas such as:

- Various demuxers and codecs (ASF, MKV, OGG, MP4, AVI, etc.).
- Subtitle parsing (e.g., crafted subtitle files).
- Network access modules (RTSP, MMS variations, VNC, HTTP, etc.).

Given that this build is **3.0.5**, any CVE whose affected range is “through 3.0.5“ or “through 3.0.7.1“ and that targets generic engine code (not Windows‑specific GUI or installer) is *likely* relevant. Due to time and context limits, a full catalog is not reproduced here, but the overall risk pattern is:

- If a CVE applies to **VLC 3.0.x on all platforms / generic engine**, it is **likely applicable** to this APK.
- If a CVE is **Windows‑specific** (e.g., path hijacking in installer, DLL loading), it is **not applicable**.
- If a CVE references only modules not built on Android (e.g., some desktop interfaces), applicability is uncertain.


## App‑specific / Android‑specific vulnerabilities

No Android‑specific CVEs were found that target **VLC for Android 3.0.5** as a distinct product (e.g., insecure exported components, content provider issues, or permission misuse) in public databases.

Known VLC CVEs for this era almost all concern engine‑level parsing and thus generally affect the Android build when the corresponding module is present.


## Proof-of-concept (PoC) ideas (high-level, not full exploits)

> Detailed PoCs are in `POCS.md`. Here we only summarize the idea space.

- Craft malicious **MP4** files targeting the MP4 EIA‑608 integer underflow (CVE-2019-13602) and test for crashes / memory corruptions when opened in this APK.
- Craft malicious **MMS streams** or servers that trigger MMS integer overflow (CVE-2024-46461) when opened from VLC for Android.
- Build **crafted VNC servers or playlists** that exercise the VNC module overflow (CVE-2022-41325) if VNC access is possible from Android UI.


## Open questions / uncertainties

- Exact VLC core version compiled into `libvlcjni.so` (e.g., 3.0.3 vs 3.0.4) is not visible from ELF metadata alone.
- Android build configuration (enabled/disabled modules) is unknown; this mainly affects whether some network‑centric modules (VNC, certain MMS variants) are reachable.
- No direct evidence of third‑party native libraries (e.g., FFmpeg, libpng) as separate `.so`s. VLC usually statically links or ships its own copies inside the main engine. Mapping their exact versions from this binary alone would require heavier static analysis (strings/symbols) which was not done here.


## Summary

- **App**: VLC for Android `org.videolan.vlc` **3.0.5** (versionCode 13000527), arm64‑v8a
- **Native libs**: `libvlcjni.so` (VLC engine + JNI), `libjniloader.so` (loader), `libanw.21.so` (Android native window / hardware helper).
- **Key CVE exposure** (engine-level, file/stream-driven):
  - **CVE-2019-13602** – MP4 EIA-608 integer underflow → heap overflow (high confidence applicable).
  - **CVE-2022-41325** – VNC module integer overflow (medium confidence; depends on module presence/usage on Android).
  - **CVE-2024-46461** – MMS integer overflow → heap overflow (high confidence applicable).
- **Android-specific issues**: None found in public CVE databases for this app/version; permissions and manifest behavior look typical for a media player.

Overall, the main security concern for this APK is the set of **engine-level parsing vulnerabilities** in VLC 3.0.x that can be exercised via malicious media files, playlists, or network streams, rather than Android-specific misconfigurations.