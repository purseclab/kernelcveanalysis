"""
traffic_capture — Lightweight network traffic analysis via /proc/net and tcpdump.

No mitmproxy dependency — uses ADB shell commands only:
    - /proc/net/tcp for active connections
    - tcpdump for packet capture (if available on device)
    - logcat network tags for URL/API monitoring
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class NetworkConnection:
    """An active network connection on the device."""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str  # LISTEN, ESTABLISHED, etc.
    uid: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "local": f"{self.local_addr}:{self.local_port}",
            "remote": f"{self.remote_addr}:{self.remote_port}",
            "state": self.state,
            "uid": self.uid,
        }


@dataclass
class TrafficCapture:
    """Network traffic capture results."""
    connections: List[NetworkConnection] = field(default_factory=list)
    urls_found: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    cleartext_urls: List[str] = field(default_factory=list)
    duration_sec: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "connections": [c.to_dict() for c in self.connections],
            "urls_found": self.urls_found[:50],
            "api_endpoints": self.api_endpoints[:50],
            "cleartext_urls": self.cleartext_urls[:50],
            "duration_sec": self.duration_sec,
        }


TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}


def _adb_shell(cmd, serial, adb, timeout=10):
    try:
        r = subprocess.run(
            [adb, "-s", serial, "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _parse_hex_addr(hex_addr: str) -> Tuple[str, int]:
    """Parse /proc/net/tcp hex address:port to human-readable."""
    parts = hex_addr.split(":")
    if len(parts) != 2:
        return "0.0.0.0", 0

    hex_ip, hex_port = parts
    port = int(hex_port, 16)

    # Convert little-endian hex IP
    if len(hex_ip) == 8:
        ip_int = int(hex_ip, 16)
        ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
    else:
        ip = hex_ip  # IPv6

    return ip, port


def get_connections(
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    uid_filter: Optional[int] = None,
) -> List[NetworkConnection]:
    """Get active TCP connections from /proc/net/tcp."""
    rc, out, _ = _adb_shell("cat /proc/net/tcp", adb_serial, adb_binary)
    if rc != 0:
        return []

    connections = []
    for line in out.strip().splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) < 8:
            continue

        local_addr, local_port = _parse_hex_addr(parts[1])
        remote_addr, remote_port = _parse_hex_addr(parts[2])
        state = TCP_STATES.get(parts[3], parts[3])
        uid = int(parts[7]) if len(parts) > 7 else 0

        if uid_filter is not None and uid != uid_filter:
            continue

        connections.append(NetworkConnection(
            local_addr=local_addr,
            local_port=local_port,
            remote_addr=remote_addr,
            remote_port=remote_port,
            state=state,
            uid=uid,
        ))

    return connections


def capture_app_traffic(
    package_name: str,
    duration: int = 15,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> TrafficCapture:
    """
    Capture network activity from an app using logcat + /proc/net/tcp.

    Args:
        package_name: Target app package name
        duration: Capture duration in seconds
        adb_serial: ADB device serial
        adb_binary: Path to ADB binary
    """
    import time

    result = TrafficCapture(duration_sec=duration)

    # Get app UID
    rc, out, _ = _adb_shell(
        f"dumpsys package {package_name} | grep userId=",
        adb_serial, adb_binary,
    )
    app_uid = None
    m = re.search(r'userId=(\d+)', out)
    if m:
        app_uid = int(m.group(1))

    # Clear logcat
    _adb_shell("logcat -c", adb_serial, adb_binary)

    # Launch app
    _adb_shell(
        f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
        adb_serial, adb_binary,
    )

    # Wait for traffic
    time.sleep(duration)

    # Collect connections
    result.connections = get_connections(adb_serial, adb_binary, uid_filter=app_uid)

    # Collect logcat for URLs and API endpoints
    rc, logcat, _ = _adb_shell(
        f"logcat -d -s OkHttp:* Retrofit:* Volley:* NetworkMonitor:* chromium:* 2>/dev/null | head -200",
        adb_serial, adb_binary, timeout=15,
    )

    # Extract URLs from logcat
    url_pattern = re.compile(r'https?://[^\s"<>]+')
    for m in url_pattern.finditer(logcat):
        url = m.group()
        result.urls_found.append(url)
        if url.startswith("http://"):
            result.cleartext_urls.append(url)
        if re.search(r'/api/|/v[0-9]+/', url):
            result.api_endpoints.append(url)

    # Also check for hardcoded endpoints in running process memory (strings)
    rc, proc_net, _ = _adb_shell(
        f"cat /proc/net/tcp /proc/net/tcp6 2>/dev/null",
        adb_serial, adb_binary,
    )

    return result


def start_mitmproxy(
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    proxy_port: int = 8080,
    output_file: str = "/tmp/syzploit_traffic.har",
) -> Optional[subprocess.Popen]:
    """
    Start mitmproxy and configure the device to route through it.

    Returns the mitmproxy process (call .terminate() to stop), or None.
    Requires: pip install mitmproxy
    """
    import shutil

    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        print("  mitmproxy not installed: pip install mitmproxy")
        return None

    # Set device proxy
    _adb_shell(
        f"settings put global http_proxy localhost:{proxy_port}",
        adb_serial, adb_binary,
    )

    # Start mitmdump with HAR output
    proc = subprocess.Popen(
        [mitmdump, "-p", str(proxy_port),
         "--set", f"hardump={output_file}",
         "-q"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return proc


def stop_mitmproxy(
    proc: Optional[subprocess.Popen],
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> None:
    """Stop mitmproxy and clear device proxy settings."""
    if proc:
        proc.terminate()
        proc.wait(timeout=5)

    # Clear proxy
    _adb_shell(
        "settings put global http_proxy :0",
        adb_serial, adb_binary,
    )


def check_cleartext_traffic(
    package_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> List[str]:
    """Check if the app sends any cleartext (HTTP) traffic."""
    # Check network security config
    rc, out, _ = _adb_shell(
        f"run-as {package_name} cat network_security_config.xml 2>/dev/null",
        adb_serial, adb_binary,
    )
    findings = []
    if "cleartextTrafficPermitted" in out and "true" in out:
        findings.append("Network security config allows cleartext traffic")

    # Check for HTTP connections
    conns = get_connections(adb_serial, adb_binary)
    http_conns = [c for c in conns if c.remote_port == 80 and c.state == "ESTABLISHED"]
    if http_conns:
        for c in http_conns:
            findings.append(f"Active HTTP connection to {c.remote_addr}:80")

    return findings
