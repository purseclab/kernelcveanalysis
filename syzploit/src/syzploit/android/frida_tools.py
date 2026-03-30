"""
frida_tools — Frida integration for dynamic Android app analysis.

Provides:
    - Frida server management on device
    - Script injection and result collection
    - Pre-built security analysis scripts (SSL bypass, root detection, etc.)
    - Function hooking with argument/return value capture
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Data Models ──────────────────────────────────────────────────────


@dataclass
class FridaResult:
    """Result from a Frida script execution."""
    success: bool = False
    messages: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    hooked_calls: List[Dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "messages": self.messages,
            "errors": self.errors,
            "hooked_calls": self.hooked_calls,
            "duration_ms": self.duration_ms,
        }


# ── Frida Server Management ─────────────────────────────────────────


def check_frida_server(
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> bool:
    """Check if frida-server is running on the device."""
    try:
        rc = subprocess.run(
            [adb_binary, "-s", adb_serial, "shell", "ps -A | grep frida-server"],
            capture_output=True, text=True, timeout=10,
        )
        return "frida-server" in rc.stdout
    except Exception:
        return False


def start_frida_server(
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
    server_path: str = "/data/local/tmp/frida-server",
) -> bool:
    """Start frida-server on the device (must already be pushed)."""
    if check_frida_server(adb_serial, adb_binary):
        return True

    try:
        # Start in background
        subprocess.Popen(
            [adb_binary, "-s", adb_serial, "shell",
             f"su 0 {server_path} -D &"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
        return check_frida_server(adb_serial, adb_binary)
    except Exception:
        return False


def auto_setup_frida(
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> bool:
    """
    Automatically download, push, and start frida-server on the device.

    Detects device architecture and downloads the matching frida-server
    release from GitHub if not already present.
    """
    # Check if already running
    if check_frida_server(adb_serial, adb_binary):
        return True

    server_remote = "/data/local/tmp/frida-server"

    # Check if binary exists on device
    try:
        rc = subprocess.run(
            [adb_binary, "-s", adb_serial, "shell",
             f"ls -la {server_remote}"],
            capture_output=True, text=True, timeout=10,
        )
        if rc.returncode == 0 and "frida-server" in rc.stdout:
            # Binary exists, just start it
            return start_frida_server(adb_serial, adb_binary, server_remote)
    except Exception:
        pass

    # Detect device architecture
    try:
        rc = subprocess.run(
            [adb_binary, "-s", adb_serial, "shell", "getprop ro.product.cpu.abi"],
            capture_output=True, text=True, timeout=10,
        )
        abi = rc.stdout.strip()
    except Exception:
        abi = "arm64-v8a"

    arch_map = {
        "arm64-v8a": "arm64",
        "armeabi-v7a": "arm",
        "x86_64": "x86_64",
        "x86": "x86",
    }
    frida_arch = arch_map.get(abi, "arm64")

    # Download frida-server
    import frida
    frida_version = frida.__version__

    url = (f"https://github.com/frida/frida/releases/download/"
           f"{frida_version}/frida-server-{frida_version}-android-{frida_arch}.xz")

    import tempfile
    from pathlib import Path

    try:
        import urllib.request
        local_xz = Path(tempfile.gettempdir()) / f"frida-server-{frida_version}-{frida_arch}.xz"
        local_bin = local_xz.with_suffix("")

        if not local_bin.exists():
            print(f"  Downloading frida-server {frida_version} for {frida_arch}...")
            urllib.request.urlretrieve(url, str(local_xz))

            # Decompress xz
            import lzma
            with lzma.open(str(local_xz)) as f_in:
                local_bin.write_bytes(f_in.read())
            local_xz.unlink(missing_ok=True)

        # Push to device
        print(f"  Pushing frida-server to {server_remote}...")
        subprocess.run(
            [adb_binary, "-s", adb_serial, "push",
             str(local_bin), server_remote],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            [adb_binary, "-s", adb_serial, "shell",
             f"chmod 755 {server_remote}"],
            capture_output=True, timeout=10,
        )

        return start_frida_server(adb_serial, adb_binary, server_remote)

    except Exception as exc:
        print(f"  Failed to auto-setup frida: {exc}")
        return False


# ── Script Execution ─────────────────────────────────────────────────


def run_frida_script(
    package_name: str,
    script_code: str,
    device_id: Optional[str] = None,
    timeout: int = 30,
    spawn: bool = True,
) -> FridaResult:
    """
    Inject and run a Frida JavaScript snippet in the target app.

    Args:
        package_name: Target app package name
        script_code: JavaScript code to inject
        device_id: Frida device ID (None for USB/default)
        timeout: Max execution time in seconds
        spawn: True to spawn app, False to attach to running process
    """
    result = FridaResult()
    start_time = time.time()

    try:
        import frida

        # Get device
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device(timeout=5)

        # Spawn or attach
        if spawn:
            pid = device.spawn([package_name])
            session = device.attach(pid)
        else:
            session = device.attach(package_name)

        # Create script
        script = session.create_script(script_code)

        # Message handler
        def on_message(message: Dict, data: Any) -> None:
            if message["type"] == "send":
                payload = message.get("payload", "")
                if isinstance(payload, dict):
                    if payload.get("type") == "hook_call":
                        result.hooked_calls.append(payload)
                    else:
                        result.messages.append(payload)
                else:
                    result.messages.append({"raw": str(payload)})
            elif message["type"] == "error":
                result.errors.append(message.get("description", str(message)))

        script.on("message", on_message)
        script.load()

        # Resume if spawned
        if spawn:
            device.resume(pid)

        # Wait for timeout or completion
        time.sleep(min(timeout, 30))

        # Cleanup
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

        result.success = len(result.errors) == 0
        result.duration_ms = int((time.time() - start_time) * 1000)

    except ImportError:
        result.errors.append("frida not installed: pip install frida-tools")
    except Exception as exc:
        result.errors.append(str(exc))
        result.duration_ms = int((time.time() - start_time) * 1000)

    return result


# ── ADB-based Script Execution (no frida-server needed) ─────────────


def run_adb_frida_script(
    package_name: str,
    script_code: str,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
    timeout: int = 30,
) -> FridaResult:
    """
    Run a Frida script via frida CLI over ADB (uses frida-tools, not Python API).
    This avoids needing the frida Python bindings on the host if frida CLI is available.
    """
    result = FridaResult()
    start_time = time.time()

    # Write script to temp file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(script_code)
        script_path = f.name

    try:
        rc = subprocess.run(
            ["frida", "-D", adb_serial, "-f", package_name,
             "-l", script_path, "--no-pause", "-q"],
            capture_output=True, text=True, timeout=timeout,
        )
        # Parse output for JSON messages
        for line in rc.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    msg = json.loads(line)
                    if msg.get("type") == "hook_call":
                        result.hooked_calls.append(msg)
                    else:
                        result.messages.append(msg)
                except json.JSONDecodeError:
                    result.messages.append({"raw": line})
            elif line:
                result.messages.append({"raw": line})

        if rc.stderr:
            result.errors.append(rc.stderr[:500])
        result.success = rc.returncode == 0

    except FileNotFoundError:
        result.errors.append("frida CLI not found. Install: pip install frida-tools")
    except subprocess.TimeoutExpired:
        result.messages.append({"raw": f"Script timed out after {timeout}s"})
        result.success = True  # timeout is expected for monitoring scripts
    except Exception as exc:
        result.errors.append(str(exc))
    finally:
        Path(script_path).unlink(missing_ok=True)

    result.duration_ms = int((time.time() - start_time) * 1000)
    return result


# ── Pre-built Security Scripts ───────────────────────────────────────


FRIDA_SCRIPTS = {
    "ssl_pinning_bypass": """
// SSL Pinning Bypass (OkHttp + HttpsURLConnection + TrustManager)
Java.perform(function() {
    // OkHttp3 CertificatePinner
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            send({type: 'hook_call', method: 'CertificatePinner.check', args: [hostname], bypassed: true});
            return;
        };
    } catch(e) {}

    // TrustManagerImpl (Android)
    try {
        var TrustMgr = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustMgr.verifyChain.implementation = function() {
            send({type: 'hook_call', method: 'TrustManagerImpl.verifyChain', bypassed: true});
            return arguments[0];
        };
    } catch(e) {}

    // X509TrustManager
    try {
        var X509 = Java.use('javax.net.ssl.X509TrustManager');
        var TrustAll = Java.registerClass({
            name: 'syzploit.TrustAll',
            implements: [X509 ],
            methods: {
                checkClientTrusted: function(chain, type) {},
                checkServerTrusted: function(chain, type) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}

    send({type: 'status', message: 'SSL pinning bypass loaded'});
});
""",

    "root_detection_bypass": """
// Root / SafetyNet / Integrity detection bypass
Java.perform(function() {
    // Common root detection file checks
    var File = Java.use('java.io.File');
    var origExists = File.exists;
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/bin/su', '/system/xbin/su', '/sbin/su',
                         '/system/app/Superuser.apk', '/data/local/tmp/su',
                         '/system/bin/magisk', '/sbin/magiskd'];
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) {
                send({type: 'hook_call', method: 'File.exists', args: [path], spoofed: true});
                return false;
            }
        }
        return origExists.call(this);
    };

    // Runtime.exec bypass for 'which su', 'su -c id'
    var Runtime = Java.use('java.lang.Runtime');
    var origExec = Runtime.exec.overload('java.lang.String');
    origExec.implementation = function(cmd) {
        if (cmd.indexOf('su') >= 0 || cmd.indexOf('magisk') >= 0) {
            send({type: 'hook_call', method: 'Runtime.exec', args: [cmd], blocked: true});
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return origExec.call(this, cmd);
    };

    // Build.TAGS spoofing (no 'test-keys')
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        send({type: 'hook_call', method: 'Build.TAGS', spoofed: 'release-keys'});
    } catch(e) {}

    send({type: 'status', message: 'Root detection bypass loaded'});
});
""",

    "crypto_key_extractor": """
// Extract encryption keys and crypto operations
Java.perform(function() {
    // SecretKeySpec (AES, DES, etc.)
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        var keyHex = '';
        for (var i = 0; i < key.length; i++) {
            keyHex += ('0' + (key[i] & 0xff).toString(16)).slice(-2);
        }
        send({type: 'hook_call', method: 'SecretKeySpec', algorithm: algo,
              key_hex: keyHex, key_length: key.length * 8});
        return this.$init(key, algo);
    };

    // Cipher.init
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function(mode, key) {
        var modeStr = mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : 'mode=' + mode;
        send({type: 'hook_call', method: 'Cipher.init', mode: modeStr,
              algorithm: this.getAlgorithm()});
        return this.init(mode, key);
    };

    // SharedPreferences (for stored credentials)
    var SharedPrefs = Java.use('android.app.SharedPreferencesImpl');
    SharedPrefs.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        if (key.toLowerCase().match(/(token|key|secret|pass|auth|api|session|jwt)/)) {
            send({type: 'hook_call', method: 'SharedPreferences.getString',
                  key: key, value: value ? value.substring(0, 50) : null});
        }
        return value;
    };

    send({type: 'status', message: 'Crypto key extractor loaded'});
});
""",

    "function_tracer": """
// Generic function tracer — customize TARGET_CLASS and TARGET_METHODS
// Usage: replace TARGET_CLASS with the fully-qualified Java class name
Java.perform(function() {
    // CUSTOMIZE THESE:
    var TARGET_CLASS = 'PLACEHOLDER_CLASS';
    var TARGET_METHODS = ['PLACEHOLDER_METHOD'];

    try {
        var clazz = Java.use(TARGET_CLASS);
        TARGET_METHODS.forEach(function(methodName) {
            var overloads = clazz[methodName].overloads;
            overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var args = [];
                    for (var i = 0; i < arguments.length; i++) {
                        args.push(String(arguments[i]));
                    }
                    send({type: 'hook_call', class: TARGET_CLASS,
                          method: methodName, args: args});
                    return this[methodName].apply(this, arguments);
                };
            });
        });
        send({type: 'status', message: 'Function tracer loaded for ' + TARGET_CLASS});
    } catch(e) {
        send({type: 'error', message: 'Failed to hook ' + TARGET_CLASS + ': ' + e});
    }
});
""",

    "activity_lifecycle_monitor": """
// Monitor Activity lifecycle events
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');

    Activity.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
        send({type: 'hook_call', method: 'onCreate', activity: this.getClass().getName()});
        return this.onCreate(bundle);
    };

    Activity.onResume.implementation = function() {
        send({type: 'hook_call', method: 'onResume', activity: this.getClass().getName()});
        return this.onResume();
    };

    var Intent = Java.use('android.content.Intent');
    var origGetStringExtra = Intent.getStringExtra;
    origGetStringExtra.implementation = function(name) {
        var value = origGetStringExtra.call(this, name);
        if (value) {
            send({type: 'hook_call', method: 'Intent.getStringExtra',
                  name: name, value: value.substring(0, 100)});
        }
        return value;
    };

    send({type: 'status', message: 'Activity lifecycle monitor loaded'});
});
""",

    "webview_inspector": """
// WebView security inspection
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');

    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        send({type: 'hook_call', method: 'WebView.loadUrl', url: url});
        return this.loadUrl(url);
    };

    WebView.addJavascriptInterface.implementation = function(obj, name) {
        send({type: 'hook_call', method: 'WebView.addJavascriptInterface',
              interface_name: name, object_class: obj.getClass().getName(),
              severity: 'HIGH'});
        return this.addJavascriptInterface(obj, name);
    };

    // Check WebSettings
    var WebSettings = Java.use('android.webkit.WebSettings');
    var origSetJSEnabled = WebSettings.setJavaScriptEnabled;
    origSetJSEnabled.implementation = function(enabled) {
        send({type: 'hook_call', method: 'WebSettings.setJavaScriptEnabled',
              enabled: enabled});
        return origSetJSEnabled.call(this, enabled);
    };

    send({type: 'status', message: 'WebView inspector loaded'});
});
""",
}


def get_frida_script(name: str) -> Optional[str]:
    """Get a pre-built Frida script by name."""
    return FRIDA_SCRIPTS.get(name)


def list_frida_scripts() -> List[str]:
    """List available pre-built Frida script names."""
    return sorted(FRIDA_SCRIPTS.keys())
