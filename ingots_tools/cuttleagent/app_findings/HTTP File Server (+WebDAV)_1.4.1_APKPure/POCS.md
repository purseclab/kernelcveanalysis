# HTTP File Server (+WebDAV) 1.4.1 – Proof-of-Concept Ideas

> WARNING: These PoCs are for defensive testing and CTF/lab usage only. Do not use against systems without explicit authorization.

The following PoC concepts target **CVE-2021-40668** (path traversal) in `slowscript.httpfileserver` version 1.4.1.

---

## 1. Discovery: Identify running HTTP File Server instance

1. Start the HTTP File Server on the device from the app UI.
2. Determine the device IP and port (from the app UI, or via `adb` / network scan):
   - Example from host machine: `nmap -p 8080 192.168.1.0/24` (replace port as shown in app).
3. Visit `http://DEVICE_IP:PORT/` in a browser to confirm the index page from `assets/data/index.html` loads.

This confirms that the HTTP server is reachable and sets the base URL for further PoCs.

---

## 2. Path traversal – arbitrary directory listing

Assume the app is configured with a root directory such as `/sdcard/Download`.

Craft URLs using `../` segments to escape this root. Example (from host machine):

```bash
# Try to list the parent of the configured root
curl -v "http://DEVICE_IP:PORT/../" 

# Try to list /sdcard or storage root
curl -v "http://DEVICE_IP:PORT/../../" 
```

Expected behavior on a vulnerable 1.4.1 instance:
- You receive a directory index-style HTML response for paths outside the user-configured root directory, showing files/folders that are not supposed to be shared.

Notes:
- Exact number of `../` segments needed depends on how the app maps the HTTP path to the filesystem path. Experiment with multiple repetitions, e.g. `/../../../../`.

---

## 3. Path traversal – arbitrary file read

Once traversal is confirmed, attempt to read specific files using the same technique.

Examples (adjust paths based on directory structure observed in step 2):

```bash
# Attempt to read a text file in /sdcard
curl -v "http://DEVICE_IP:PORT/../../somefile.txt" 

# Attempt to read app-specific configuration or token files under external storage
curl -v "http://DEVICE_IP:PORT/../../../Android/data/" 
```

Indicators of success:
- Response body contains the content of the target file, even though it is outside the configured share root.

---

## 4. Path traversal – arbitrary file write (WebDAV / upload)

If WebDAV or upload features are enabled, the same path traversal patterns may be usable when writing files.

### 4.1. Using WebDAV clients

1. Configure a WebDAV client (e.g., `cadaver`, Cyberduck, or a mobile WebDAV app) to point to:
   - `http://DEVICE_IP:PORT/`
2. Use the client to upload a file but specify a path containing `../` sequences (the exact method depends on the client – some allow you to "change directory" to a path that includes `../`).

If vulnerable, you may be able to place arbitrary files in directories outside the configured root (e.g., under `/sdcard/` parent folders), leading to overwriting or planting new files.

### 4.2. HTTP-based upload endpoint (if present)

If the app exposes an HTTP POST upload endpoint (e.g., as visible in `assets/data/upload-fab.png` / UI), you can try a crafted POST request with `../` in the target path parameter.

Pseudo-example (parameters must be adjusted based on the real endpoint):

```bash
curl -v -X POST "http://DEVICE_IP:PORT/upload?path=../../" \
  -F "file=@evil.txt"
```

Signs of vulnerability:
- The uploaded file appears outside the configured share root, as verified via directory listing or direct read.

---

## 5. Leveraging the vulnerable server from another Android app

Because `ShareActivity` is exported and accepts `ACTION_SEND` and `ACTION_SEND_MULTIPLE` intents with `*/*` MIME types, a malicious app on the same device can:

1. Use an `Intent` to start `slowscript.httpfileserver.ShareActivity` with a chosen file URI, causing HTTP File Server to share that file.
2. Once the HTTP server is running and reachable on the LAN, an external attacker can exploit CVE-2021-40668 from the network side as shown above.

Example pseudo-code (Java/Kotlin) that another app could use:

```kotlin
val intent = Intent(Intent.ACTION_SEND).apply {
    type = "*/*"
    putExtra(Intent.EXTRA_STREAM, fileUri) // content:// or file:// URI
    `package` = "slowscript.httpfileserver"
}
startActivity(intent)
```

This doesn’t directly exploit the traversal, but makes it easier for an unprivileged local app to ensure the vulnerable HTTP server is running and exposing a port to the network.

---

## 6. Defensive checks

When testing in a lab or CTF environment, defenders can validate whether a patch is effective by ensuring:

- Any URL containing `../` is either rejected (4xx) or normalized back into the configured root without leaking or accessing external directories.
- Directory listings never show entries outside the configured root.
- Uploads or WebDAV writes cannot escape the designated share directory.

If all traversal attempts fail while the server otherwise functions normally, the instance is likely not vulnerable to CVE-2021-40668 (or has been patched).
