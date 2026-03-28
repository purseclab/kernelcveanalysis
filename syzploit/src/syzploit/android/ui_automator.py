"""
ui_automator — ADB-based Android UI interaction.

Provides UI automation without requiring UIAutomator2 Python library:
    - Dump UI hierarchy (accessibility tree)
    - Tap, swipe, type text
    - Launch apps, press buttons
    - Take screenshots
    - Find elements by text/resource-id/class

All interactions use raw ADB commands — no additional device-side deps needed.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET


@dataclass
class UIElement:
    """A UI element from the accessibility tree."""
    text: str = ""
    resource_id: str = ""
    class_name: str = ""
    package: str = ""
    content_desc: str = ""
    bounds: Tuple[int, int, int, int] = (0, 0, 0, 0)  # left, top, right, bottom
    clickable: bool = False
    enabled: bool = True
    focused: bool = False
    scrollable: bool = False
    checkable: bool = False
    checked: bool = False

    @property
    def center(self) -> Tuple[int, int]:
        return ((self.bounds[0] + self.bounds[2]) // 2,
                (self.bounds[1] + self.bounds[3]) // 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "resource_id": self.resource_id,
            "class_name": self.class_name,
            "package": self.package,
            "content_desc": self.content_desc,
            "bounds": list(self.bounds),
            "center": list(self.center),
            "clickable": self.clickable,
            "enabled": self.enabled,
        }


def _adb_cmd(
    cmd: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    timeout: int = 10,
) -> Tuple[int, str, str]:
    """Run ADB shell command."""
    try:
        r = subprocess.run(
            [adb_binary, "-s", adb_serial, "shell", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


# ── UI Hierarchy ─────────────────────────────────────────────────────


def dump_ui(
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> List[UIElement]:
    """Dump the current UI hierarchy as a list of UIElements."""
    # Dump UI XML to device
    _adb_cmd("uiautomator dump /data/local/tmp/ui_dump.xml", adb_serial, adb_binary, timeout=15)

    # Pull XML content
    rc, xml_content, _ = _adb_cmd("cat /data/local/tmp/ui_dump.xml", adb_serial, adb_binary)
    if rc != 0 or not xml_content.strip():
        return []

    # Parse XML
    elements = []
    try:
        root = ET.fromstring(xml_content)
        for node in root.iter("node"):
            bounds_str = node.get("bounds", "[0,0][0,0]")
            bounds_match = re.findall(r'\[(\d+),(\d+)\]', bounds_str)
            bounds = (0, 0, 0, 0)
            if len(bounds_match) == 2:
                bounds = (int(bounds_match[0][0]), int(bounds_match[0][1]),
                         int(bounds_match[1][0]), int(bounds_match[1][1]))

            elements.append(UIElement(
                text=node.get("text", ""),
                resource_id=node.get("resource-id", ""),
                class_name=node.get("class", ""),
                package=node.get("package", ""),
                content_desc=node.get("content-desc", ""),
                bounds=bounds,
                clickable=node.get("clickable") == "true",
                enabled=node.get("enabled") == "true",
                focused=node.get("focused") == "true",
                scrollable=node.get("scrollable") == "true",
                checkable=node.get("checkable") == "true",
                checked=node.get("checked") == "true",
            ))
    except ET.ParseError:
        pass

    return elements


def find_elements(
    elements: List[UIElement],
    text: Optional[str] = None,
    resource_id: Optional[str] = None,
    class_name: Optional[str] = None,
    clickable: Optional[bool] = None,
) -> List[UIElement]:
    """Filter UI elements by criteria."""
    results = elements
    if text is not None:
        results = [e for e in results if text.lower() in e.text.lower()]
    if resource_id is not None:
        results = [e for e in results if resource_id in e.resource_id]
    if class_name is not None:
        results = [e for e in results if class_name in e.class_name]
    if clickable is not None:
        results = [e for e in results if e.clickable == clickable]
    return results


# ── Touch/Input Actions ──────────────────────────────────────────────


def tap(
    x: int, y: int,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Tap at screen coordinates."""
    rc, _, _ = _adb_cmd(f"input tap {x} {y}", adb_serial, adb_binary)
    return rc == 0


def tap_element(
    element: UIElement,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Tap the center of a UI element."""
    cx, cy = element.center
    return tap(cx, cy, adb_serial, adb_binary)


def long_press(
    x: int, y: int, duration_ms: int = 1000,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Long press at coordinates."""
    rc, _, _ = _adb_cmd(f"input swipe {x} {y} {x} {y} {duration_ms}", adb_serial, adb_binary)
    return rc == 0


def swipe(
    x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Swipe from (x1,y1) to (x2,y2)."""
    rc, _, _ = _adb_cmd(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}", adb_serial, adb_binary)
    return rc == 0


def type_text(
    text: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Type text into the currently focused input field."""
    # Escape special characters for ADB shell
    escaped = text.replace(" ", "%s").replace("&", "\\&").replace("<", "\\<").replace(">", "\\>")
    rc, _, _ = _adb_cmd(f"input text '{escaped}'", adb_serial, adb_binary)
    return rc == 0


def press_key(
    key: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Press a device key. Common keys: BACK, HOME, MENU, ENTER, DEL, TAB."""
    key_codes = {
        "BACK": 4, "HOME": 3, "MENU": 82, "ENTER": 66,
        "DEL": 67, "TAB": 61, "POWER": 26,
        "VOLUME_UP": 24, "VOLUME_DOWN": 25,
        "DPAD_UP": 19, "DPAD_DOWN": 20, "DPAD_LEFT": 21, "DPAD_RIGHT": 22,
        "DPAD_CENTER": 23,
    }
    code = key_codes.get(key.upper(), key)
    rc, _, _ = _adb_cmd(f"input keyevent {code}", adb_serial, adb_binary)
    return rc == 0


# ── App Management ───────────────────────────────────────────────────


def launch_app(
    package_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Launch an app by package name."""
    rc, _, _ = _adb_cmd(
        f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
        adb_serial, adb_binary,
    )
    return rc == 0


def stop_app(
    package_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Force stop an app."""
    rc, _, _ = _adb_cmd(f"am force-stop {package_name}", adb_serial, adb_binary)
    return rc == 0


def get_current_activity(
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> str:
    """Get the currently focused activity."""
    rc, out, _ = _adb_cmd(
        "dumpsys activity activities | grep mResumedActivity",
        adb_serial, adb_binary,
    )
    if rc == 0 and out.strip():
        m = re.search(r'([a-zA-Z0-9_.]+/[a-zA-Z0-9_.]+)', out)
        if m:
            return m.group(1)
    return ""


# ── Screenshot ───────────────────────────────────────────────────────


def take_screenshot(
    local_path: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> bool:
    """Take a screenshot and save to local path."""
    remote = "/data/local/tmp/screenshot.png"
    _adb_cmd(f"screencap -p {remote}", adb_serial, adb_binary, timeout=10)
    try:
        r = subprocess.run(
            [adb_binary, "-s", adb_serial, "pull", remote, local_path],
            capture_output=True, timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


# ── Screen Info ──────────────────────────────────────────────────────


def get_screen_size(
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> Tuple[int, int]:
    """Get screen resolution (width, height)."""
    rc, out, _ = _adb_cmd("wm size", adb_serial, adb_binary)
    m = re.search(r'(\d+)x(\d+)', out)
    if m:
        return int(m.group(1)), int(m.group(2))
    return 0, 0
