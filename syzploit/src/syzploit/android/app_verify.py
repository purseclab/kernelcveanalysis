"""
app_verify — Multi-criteria exploit verification for Android apps.

Verifies exploit success by checking multiple indicators:
    - Data exfiltration (content provider returned data)
    - Authentication bypass (accessed protected activity)
    - Code execution (Frida hooks triggered)
    - Crash triggered (app/process died)
    - Privilege gained (accessed restricted resource)
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .exploit_generator import ExploitScript


@dataclass
class VerifyResult:
    """Result from verifying an exploit."""
    exploit_name: str
    success: bool = False
    indicators: List[str] = field(default_factory=list)
    output: str = ""
    duration_ms: int = 0
    crash_detected: bool = False
    data_leaked: bool = False
    auth_bypassed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exploit_name": self.exploit_name,
            "success": self.success,
            "indicators": self.indicators,
            "output": self.output[:2000],
            "duration_ms": self.duration_ms,
            "crash_detected": self.crash_detected,
            "data_leaked": self.data_leaked,
            "auth_bypassed": self.auth_bypassed,
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


def verify_exploit(
    exploit: ExploitScript,
    package_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    timeout: int = 30,
) -> VerifyResult:
    """
    Run an exploit script and verify if it succeeded.

    Supports ADB shell scripts and Frida scripts.
    """
    start = time.time()
    result = VerifyResult(exploit_name=exploit.name)

    # Check app is running before exploit
    _adb_shell(
        f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
        adb_serial, adb_binary,
    )
    time.sleep(2)

    # Get initial logcat marker
    _adb_shell("logcat -c", adb_serial, adb_binary)

    # Run the exploit
    if exploit.script_type == "adb":
        _run_adb_exploit(exploit, result, adb_serial, adb_binary, timeout)
    elif exploit.script_type == "frida":
        _run_frida_exploit(exploit, result, package_name, adb_serial, adb_binary, timeout)

    # Post-exploit checks
    _check_crash(result, package_name, adb_serial, adb_binary)
    _check_data_leak(result)
    _check_auth_bypass(result)

    # Determine overall success
    result.success = bool(result.indicators)
    result.duration_ms = int((time.time() - start) * 1000)

    return result


def _run_adb_exploit(
    exploit: ExploitScript,
    result: VerifyResult,
    adb_serial: str,
    adb_binary: str,
    timeout: int,
) -> None:
    """Execute ADB shell exploit script."""
    import tempfile
    from pathlib import Path

    # Write script to temp file and execute via shell
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write(exploit.code)
        script_path = f.name

    try:
        # Push and execute on device
        remote_path = "/data/local/tmp/syzploit_exploit.sh"
        subprocess.run(
            [adb_binary, "-s", adb_serial, "push", script_path, remote_path],
            capture_output=True, timeout=15,
        )
        _adb_shell(f"chmod 755 {remote_path}", adb_serial, adb_binary)

        rc, out, err = _adb_shell(
            f"sh {remote_path}", adb_serial, adb_binary, timeout=timeout
        )
        result.output = out + err

        # Check success indicator
        if exploit.success_indicator and exploit.success_indicator in out:
            result.indicators.append(f"Success indicator found: {exploit.success_indicator}")

    except Exception as e:
        result.output = f"Execution error: {e}"
    finally:
        Path(script_path).unlink(missing_ok=True)


def _run_frida_exploit(
    exploit: ExploitScript,
    result: VerifyResult,
    package_name: str,
    adb_serial: str,
    adb_binary: str,
    timeout: int,
) -> None:
    """Execute Frida exploit script."""
    try:
        from .frida_tools import run_adb_frida_script
        frida_result = run_adb_frida_script(
            package_name, exploit.code,
            adb_serial=adb_serial, adb_binary=adb_binary,
            timeout=timeout,
        )

        result.output = json.dumps(frida_result.to_dict(), indent=2)

        # Check for exploit-phase messages
        for call in frida_result.hooked_calls:
            phase = call.get("phase", "")
            if phase in ("api_key_captured", "key_extracted", "method_found",
                        "stored_key", "cipher_usage"):
                result.indicators.append(f"Frida: {phase} - {json.dumps(call)[:100]}")
                if "key" in phase or "captured" in phase:
                    result.data_leaked = True

        if exploit.success_indicator:
            for call in frida_result.hooked_calls:
                if exploit.success_indicator in json.dumps(call):
                    result.indicators.append(f"Success indicator: {exploit.success_indicator}")

    except Exception as e:
        result.output = f"Frida error: {e}"


def _check_crash(
    result: VerifyResult,
    package_name: str,
    adb_serial: str,
    adb_binary: str,
) -> None:
    """Check if the exploit crashed the app."""
    # Check logcat for FATAL EXCEPTION
    rc, out, _ = _adb_shell(
        "logcat -d -s AndroidRuntime:E 2>/dev/null | tail -20",
        adb_serial, adb_binary, timeout=5,
    )
    if "FATAL EXCEPTION" in out and package_name in out:
        result.crash_detected = True
        result.indicators.append("App crashed (FATAL EXCEPTION)")

    # Check if app is still running
    rc, out, _ = _adb_shell(
        f"pidof {package_name}", adb_serial, adb_binary, timeout=5,
    )
    if not out.strip():
        result.crash_detected = True
        result.indicators.append("App process died during exploit")


def _check_data_leak(result: VerifyResult) -> None:
    """Check if the exploit leaked data."""
    data_indicators = ["Row ", "value=", "key_hex=", "api_key_captured", "stored_key"]
    for indicator in data_indicators:
        if indicator in result.output:
            result.data_leaked = True
            if f"Data leaked ({indicator})" not in result.indicators:
                result.indicators.append(f"Data leaked ({indicator})")


def _check_auth_bypass(result: VerifyResult) -> None:
    """Check if authentication was bypassed."""
    bypass_indicators = ["bypassed", "unauthorized", "without permission"]
    for indicator in bypass_indicators:
        if indicator.lower() in result.output.lower():
            result.auth_bypassed = True
            result.indicators.append(f"Auth bypass detected ({indicator})")


def verify_all_exploits(
    exploits: List[ExploitScript],
    package_name: str,
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    timeout: int = 30,
) -> List[VerifyResult]:
    """Run and verify all generated exploits."""
    results = []
    for exploit in exploits:
        result = verify_exploit(exploit, package_name, adb_serial, adb_binary, timeout)
        results.append(result)
        # Brief pause between exploits
        time.sleep(2)
    return results
