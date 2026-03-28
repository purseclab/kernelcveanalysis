"""
ipc_fuzzer — Android IPC fuzzing for intent/content provider/broadcast vulnerabilities.

Systematically sends malformed inputs to exported components:
    - Activities: malformed extras, oversized strings, null values
    - Content providers: SQL injection payloads, path traversal
    - Broadcast receivers: spoofed actions, crafted extras
    - Services: binding with malicious intents
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FuzzResult:
    """Result from a single fuzz attempt."""
    component: str
    component_type: str
    payload: str
    crashed: bool = False
    error_output: str = ""
    success: bool = False  # True if the payload triggered unexpected behavior
    response: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "type": self.component_type,
            "payload": self.payload[:200],
            "crashed": self.crashed,
            "error_output": self.error_output[:500],
            "success": self.success,
            "response": self.response[:500],
        }


@dataclass
class FuzzReport:
    """Complete fuzz testing report."""
    package_name: str
    total_tests: int = 0
    crashes: int = 0
    interesting: int = 0  # non-crash but unexpected behavior
    results: List[FuzzResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "total_tests": self.total_tests,
            "crashes": self.crashes,
            "interesting": self.interesting,
            "results": [r.to_dict() for r in self.results],
        }


def _adb_shell(
    cmd: str,
    adb_serial: str,
    adb_binary: str,
    timeout: int = 10,
) -> Tuple[int, str, str]:
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


# ── Fuzz Payloads ────────────────────────────────────────────────────

# String payloads for extras
STRING_PAYLOADS = [
    "",                          # Empty string
    "A" * 10000,                 # Oversized string
    "null",                      # Null-like
    "'OR 1=1--",                 # SQL injection
    "<script>alert(1)</script>", # XSS
    "../../../etc/hosts",        # Path traversal
    "%00",                       # Null byte
    "{{7*7}}",                   # Template injection
    "-1",                        # Negative number
    "999999999999",              # Large number
    "file:///etc/passwd",        # File URI
    "javascript:alert(1)",      # JavaScript URI
    "content://com.android.contacts/contacts", # Content URI injection
]

# SQL injection payloads for content providers
SQL_PAYLOADS = [
    "' OR '1'='1",
    "1 UNION SELECT null--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND (SELECT count(*) FROM sqlite_master)>0--",
    "1 UNION SELECT sql FROM sqlite_master--",
    "') OR ('1'='1",
]

# Path traversal payloads for content providers
PATH_PAYLOADS = [
    "../",
    "../../",
    "../../../etc/hosts",
    "..%2F..%2F..%2Fetc%2Fhosts",
    "%2e%2e/%2e%2e/%2e%2e/etc/hosts",
    "....//....//....//etc/hosts",
]


# ── Fuzz Functions ───────────────────────────────────────────────────


def fuzz_activity(
    package_name: str,
    activity_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> List[FuzzResult]:
    """Fuzz an exported activity with various intent extras."""
    results = []
    component = f"{package_name}/{activity_name}"

    for payload in STRING_PAYLOADS:
        # Send intent with different extra types
        for key in ["url", "data", "query", "input", "text", "path", "redirect"]:
            cmd = f"am start -n {component} --es {key} '{payload}'"
            rc, out, err = _adb_shell(cmd, adb_serial, adb_binary)

            crashed = "FATAL EXCEPTION" in out or "ANR" in out or rc == -1
            interesting = "Error" in out and "SecurityException" not in out

            result = FuzzResult(
                component=component,
                component_type="activity",
                payload=f"--es {key} '{payload[:50]}'",
                crashed=crashed,
                error_output=err[:200] if err else "",
                success=crashed or interesting,
                response=out[:200],
            )
            results.append(result)

            # Stop between tests to avoid ANR
            if crashed:
                _adb_shell(f"am force-stop {package_name}", adb_serial, adb_binary)
                time.sleep(1)

    return results


def fuzz_content_provider(
    authority: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> List[FuzzResult]:
    """Fuzz a content provider with SQL injection and path traversal."""
    results = []

    # SQL injection via --where
    for payload in SQL_PAYLOADS:
        cmd = f"content query --uri content://{authority}/ --where \"{payload}\""
        rc, out, err = _adb_shell(cmd, adb_serial, adb_binary, timeout=5)

        interesting = "Row" in out  # data returned = possibly injectable
        crashed = rc == -1 or "FATAL" in out

        results.append(FuzzResult(
            component=f"content://{authority}/",
            component_type="provider",
            payload=f"SQL: {payload}",
            crashed=crashed,
            error_output=err[:200],
            success=interesting or crashed,
            response=out[:200],
        ))

    # Path traversal
    for payload in PATH_PAYLOADS:
        cmd = f"content read --uri content://{authority}/{payload}"
        rc, out, err = _adb_shell(cmd, adb_serial, adb_binary, timeout=5)

        interesting = len(out) > 10 and "No result" not in out
        results.append(FuzzResult(
            component=f"content://{authority}/",
            component_type="provider",
            payload=f"PATH: {payload}",
            crashed=rc == -1,
            success=interesting,
            response=out[:200],
        ))

    return results


def fuzz_broadcast_receiver(
    package_name: str,
    receiver_name: str,
    action: str = "",
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> List[FuzzResult]:
    """Fuzz a broadcast receiver with crafted intents."""
    results = []
    component = f"{package_name}/{receiver_name}"

    actions = [action] if action else [
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.USER_PRESENT",
        f"{package_name}.CUSTOM_ACTION",
        "android.intent.action.PACKAGE_REPLACED",
    ]

    for act in actions:
        for payload in STRING_PAYLOADS[:5]:  # Use fewer payloads for broadcasts
            cmd = f"am broadcast -a {act} -n {component} --es data '{payload}'"
            rc, out, err = _adb_shell(cmd, adb_serial, adb_binary)

            results.append(FuzzResult(
                component=component,
                component_type="receiver",
                payload=f"action={act} data='{payload[:30]}'",
                crashed="FATAL" in out or rc == -1,
                success="result=0" not in out and rc == 0,
                response=out[:200],
            ))

    return results


def fuzz_exported_components(
    package_name: str,
    components: List[Dict[str, Any]],
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    max_tests_per_component: int = 20,
) -> FuzzReport:
    """Fuzz all exported components of an app."""
    report = FuzzReport(package_name=package_name)

    for comp in components:
        name = comp.get("name", "")
        comp_type = comp.get("type", "")
        authorities = comp.get("authorities", "")

        if comp_type == "activity":
            results = fuzz_activity(package_name, name, adb_serial, adb_binary)
            results = results[:max_tests_per_component]
        elif comp_type == "provider" and authorities:
            results = fuzz_content_provider(authorities, adb_serial, adb_binary)
        elif comp_type == "receiver":
            action = ""
            for f in comp.get("intent_filters", []):
                if f.get("type") == "action":
                    action = f["value"]
                    break
            results = fuzz_broadcast_receiver(
                package_name, name, action, adb_serial, adb_binary
            )
        else:
            continue

        for r in results:
            report.results.append(r)
            report.total_tests += 1
            if r.crashed:
                report.crashes += 1
            elif r.success:
                report.interesting += 1

    return report
