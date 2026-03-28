"""
intent_crafter — Craft and send Android intents for security testing.

Tests exported components by sending crafted intents via ADB:
    - Launch exported activities with specific extras
    - Send broadcasts to exported receivers
    - Query exported content providers
    - Start exported services
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IntentResult:
    """Result from sending a crafted intent."""
    command: str = ""
    success: bool = False
    output: str = ""
    error: str = ""
    component: str = ""
    intent_type: str = ""  # "activity", "broadcast", "service", "provider"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "success": self.success,
            "output": self.output[:2000],
            "error": self.error[:500],
            "component": self.component,
            "intent_type": self.intent_type,
        }


def _adb_shell(
    cmd: str,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
    timeout: int = 10,
) -> Tuple[int, str, str]:
    """Run an ADB shell command."""
    try:
        rc = subprocess.run(
            [adb_binary, "-s", adb_serial, "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return rc.returncode, rc.stdout, rc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as exc:
        return -1, "", str(exc)


def launch_activity(
    component: str,
    extras: Optional[Dict[str, str]] = None,
    data_uri: Optional[str] = None,
    action: Optional[str] = None,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> IntentResult:
    """Launch an exported activity with crafted extras."""
    cmd_parts = ["am", "start", "-n", component]

    if action:
        cmd_parts.extend(["-a", action])
    if data_uri:
        cmd_parts.extend(["-d", f"'{data_uri}'"])
    if extras:
        for key, value in extras.items():
            cmd_parts.extend(["--es", key, f"'{value}'"])

    cmd = " ".join(cmd_parts)
    rc, stdout, stderr = _adb_shell(cmd, adb_serial, adb_binary)

    return IntentResult(
        command=cmd,
        success=rc == 0 and "Error" not in stdout,
        output=stdout,
        error=stderr or (stdout if "Error" in stdout else ""),
        component=component,
        intent_type="activity",
    )


def send_broadcast(
    action: str,
    component: Optional[str] = None,
    extras: Optional[Dict[str, str]] = None,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> IntentResult:
    """Send a broadcast to an exported receiver."""
    cmd_parts = ["am", "broadcast", "-a", action]

    if component:
        cmd_parts.extend(["-n", component])
    if extras:
        for key, value in extras.items():
            cmd_parts.extend(["--es", key, f"'{value}'"])

    cmd = " ".join(cmd_parts)
    rc, stdout, stderr = _adb_shell(cmd, adb_serial, adb_binary)

    return IntentResult(
        command=cmd,
        success=rc == 0,
        output=stdout,
        error=stderr,
        component=component or action,
        intent_type="broadcast",
    )


def query_content_provider(
    uri: str,
    projection: Optional[List[str]] = None,
    selection: Optional[str] = None,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> IntentResult:
    """Query an exported content provider."""
    cmd_parts = ["content", "query", "--uri", uri]

    if projection:
        cmd_parts.extend(["--projection", ":".join(projection)])
    if selection:
        cmd_parts.extend(["--where", f"'{selection}'"])

    cmd = " ".join(cmd_parts)
    rc, stdout, stderr = _adb_shell(cmd, adb_serial, adb_binary, timeout=15)

    return IntentResult(
        command=cmd,
        success=rc == 0 and "No result" not in stdout,
        output=stdout,
        error=stderr,
        component=uri,
        intent_type="provider",
    )


def start_service(
    component: str,
    action: Optional[str] = None,
    extras: Optional[Dict[str, str]] = None,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> IntentResult:
    """Start an exported service."""
    cmd_parts = ["am", "startservice", "-n", component]

    if action:
        cmd_parts.extend(["-a", action])
    if extras:
        for key, value in extras.items():
            cmd_parts.extend(["--es", key, f"'{value}'"])

    cmd = " ".join(cmd_parts)
    rc, stdout, stderr = _adb_shell(cmd, adb_serial, adb_binary)

    return IntentResult(
        command=cmd,
        success=rc == 0 and "Error" not in stdout,
        output=stdout,
        error=stderr or (stdout if "Error" in stdout else ""),
        component=component,
        intent_type="service",
    )


def test_deeplink(
    deeplink_url: str,
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> IntentResult:
    """Test a deep link URL."""
    cmd = f"am start -a android.intent.action.VIEW -d '{deeplink_url}'"
    rc, stdout, stderr = _adb_shell(cmd, adb_serial, adb_binary)

    return IntentResult(
        command=cmd,
        success=rc == 0 and "Error" not in stdout,
        output=stdout,
        error=stderr or (stdout if "Error" in stdout else ""),
        component=deeplink_url,
        intent_type="activity",
    )


def test_exported_components(
    package_name: str,
    components: List[Dict[str, Any]],
    adb_serial: str = "localhost:6538",
    adb_binary: str = "adb",
) -> List[IntentResult]:
    """Test all exported components of an app."""
    results = []

    for comp in components:
        name = comp.get("name", "")
        comp_type = comp.get("type", "")
        full_name = f"{package_name}/{name}" if "/" not in name else name

        if comp_type == "activity":
            result = launch_activity(full_name, adb_serial=adb_serial, adb_binary=adb_binary)
            results.append(result)
        elif comp_type == "receiver":
            # Try with common actions from intent filters
            for filt in comp.get("intent_filters", []):
                if filt.get("type") == "action":
                    result = send_broadcast(
                        filt["value"], component=full_name,
                        adb_serial=adb_serial, adb_binary=adb_binary,
                    )
                    results.append(result)
        elif comp_type == "provider":
            auth = comp.get("authorities", "")
            if auth:
                result = query_content_provider(
                    f"content://{auth}/",
                    adb_serial=adb_serial, adb_binary=adb_binary,
                )
                results.append(result)
        elif comp_type == "service":
            result = start_service(full_name, adb_serial=adb_serial, adb_binary=adb_binary)
            results.append(result)

        # Test deeplinks
        for dl in comp.get("deeplinks", []):
            result = test_deeplink(dl, adb_serial=adb_serial, adb_binary=adb_binary)
            results.append(result)

    return results
