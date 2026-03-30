"""
app_analyzer — Android APK security analysis.

Provides static analysis of Android APKs:
    - Manifest parsing (exported components, permissions, intent filters)
    - Attack surface enumeration
    - Common vulnerability pattern detection
    - Security configuration analysis

Uses androguard for APK parsing (no Java/JADX dependency).
"""

from __future__ import annotations

import logging
import re

# Suppress androguard's extremely verbose DEBUG output (thousands of XML lines)
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core.axml").setLevel(logging.ERROR)
logging.getLogger("androguard.core.dex").setLevel(logging.ERROR)
logging.getLogger("androguard.core.apk").setLevel(logging.ERROR)
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET


# ── Data Models ──────────────────────────────────────────────────────


@dataclass
class AppComponent:
    """An Android component (activity, service, receiver, provider)."""
    name: str
    component_type: str  # "activity", "service", "receiver", "provider"
    exported: bool = False
    permission: str = ""
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    authorities: str = ""  # For content providers
    deeplinks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.component_type,
            "exported": self.exported,
            "permission": self.permission,
            "intent_filters": self.intent_filters,
            "authorities": self.authorities,
            "deeplinks": self.deeplinks,
        }


@dataclass
class AppVulnerability:
    """A discovered vulnerability in an Android app."""
    name: str
    severity: str  # "critical", "high", "medium", "low", "info"
    category: str  # "manifest", "permission", "crypto", "storage", "network", "ipc", "webview"
    description: str
    evidence: str = ""
    recommendation: str = ""
    owasp_masvs: str = ""  # e.g. "MSTG-PLATFORM-1"
    component: str = ""  # affected component name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "owasp_masvs": self.owasp_masvs,
            "component": self.component,
        }


@dataclass
class AppAnalysisResult:
    """Complete APK analysis result."""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    components: List[AppComponent] = field(default_factory=list)
    exported_components: List[AppComponent] = field(default_factory=list)
    vulnerabilities: List[AppVulnerability] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = False
    cleartext_traffic: bool = False
    network_security_config: str = ""
    native_libraries: List[str] = field(default_factory=list)
    dex_classes_count: int = 0
    apk_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": self.permissions,
            "dangerous_permissions": self.dangerous_permissions,
            "components": [c.to_dict() for c in self.components],
            "exported_components": [c.to_dict() for c in self.exported_components],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "cleartext_traffic": self.cleartext_traffic,
            "network_security_config": self.network_security_config,
            "native_libraries": self.native_libraries,
            "dex_classes_count": self.dex_classes_count,
            "apk_size": self.apk_size,
        }

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "high")


# ── Dangerous Permissions ────────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
}


# ── APK Analysis ─────────────────────────────────────────────────────


def analyze_apk(apk_path: str) -> AppAnalysisResult:
    """
    Analyze an Android APK for security vulnerabilities.

    Uses androguard for parsing. Falls back to zipfile + XML parsing
    if androguard is not available.
    """
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    result = AppAnalysisResult(apk_size=path.stat().st_size)

    # Suppress androguard's verbose DEBUG logging
    import logging
    logging.getLogger("androguard").setLevel(logging.WARNING)

    try:
        result = _analyze_with_androguard(path, result)
    except ImportError:
        result = _analyze_with_zipfile(path, result)
    except Exception:
        # Androguard can fail on some APKs (missing permissions dir, etc.)
        result = _analyze_with_zipfile(path, result)

    # Run vulnerability checks
    _check_manifest_vulnerabilities(result)
    _check_permission_vulnerabilities(result)
    _check_component_vulnerabilities(result)

    return result


def _analyze_with_androguard(path: Path, result: AppAnalysisResult) -> AppAnalysisResult:
    """Full analysis using androguard."""
    from androguard.core.apk import APK

    apk = APK(str(path))

    result.package_name = apk.get_package() or ""
    result.version_name = apk.get_androidversion_name() or ""
    result.version_code = apk.get_androidversion_code() or ""
    result.min_sdk = int(apk.get_min_sdk_version() or 0)
    result.target_sdk = int(apk.get_target_sdk_version() or 0)

    # Permissions
    result.permissions = list(apk.get_permissions())
    result.dangerous_permissions = [
        p for p in result.permissions if p in DANGEROUS_PERMISSIONS
    ]

    # Application flags
    result.debuggable = apk.get_attribute_value("application", "debuggable") == "true"
    result.allow_backup = apk.get_attribute_value("application", "allowBackup") != "false"
    result.cleartext_traffic = apk.get_attribute_value(
        "application", "usesCleartextTraffic"
    ) == "true"

    # Network security config
    nsc = apk.get_attribute_value("application", "networkSecurityConfig")
    if nsc:
        result.network_security_config = nsc

    # Components
    _ns = "{http://schemas.android.com/apk/res/android}"

    for activity in apk.get_activities():
        comp = _parse_component(apk, activity, "activity", _ns)
        result.components.append(comp)
        if comp.exported:
            result.exported_components.append(comp)

    for service in apk.get_services():
        comp = _parse_component(apk, service, "service", _ns)
        result.components.append(comp)
        if comp.exported:
            result.exported_components.append(comp)

    for receiver in apk.get_receivers():
        comp = _parse_component(apk, receiver, "receiver", _ns)
        result.components.append(comp)
        if comp.exported:
            result.exported_components.append(comp)

    for provider in apk.get_providers():
        comp = _parse_component(apk, provider, "provider", _ns)
        result.components.append(comp)
        if comp.exported:
            result.exported_components.append(comp)

    # Native libraries
    for f in apk.get_files():
        if f.endswith(".so"):
            result.native_libraries.append(f)

    # DEX class count
    try:
        result.dex_classes_count = len(apk.get_dex_names())
    except Exception:
        pass

    return result


def _parse_component(apk, name: str, comp_type: str, ns: str) -> AppComponent:
    """Parse a component from the APK manifest."""
    comp = AppComponent(name=name, component_type=comp_type)

    try:
        # Check exported attribute
        exported_val = apk.get_attribute_value(comp_type, "exported", name=name)
        has_intent_filter = bool(apk.get_intent_filters(comp_type, name))

        if exported_val == "true":
            comp.exported = True
        elif exported_val == "false":
            comp.exported = False
        elif has_intent_filter:
            # If no explicit exported and has intent-filter, default is exported
            comp.exported = True

        # Permission
        perm = apk.get_attribute_value(comp_type, "permission", name=name)
        if perm:
            comp.permission = perm

        # Content provider authorities
        if comp_type == "provider":
            auth = apk.get_attribute_value(comp_type, "authorities", name=name)
            if auth:
                comp.authorities = auth

        # Intent filters
        filters = apk.get_intent_filters(comp_type, name)
        if filters:
            for action in filters.get("action", []):
                comp.intent_filters.append({"type": "action", "value": action})
            for category in filters.get("category", []):
                comp.intent_filters.append({"type": "category", "value": category})
            # Extract deeplinks from data elements
            for data in filters.get("data", []):
                if isinstance(data, dict):
                    scheme = data.get("scheme", "")
                    host = data.get("host", "")
                    path = data.get("path", "") or data.get("pathPrefix", "")
                    if scheme:
                        deeplink = f"{scheme}://{host}{path}" if host else f"{scheme}://"
                        comp.deeplinks.append(deeplink)

    except Exception:
        pass

    return comp


def _analyze_with_zipfile(path: Path, result: AppAnalysisResult) -> AppAnalysisResult:
    """Fallback analysis using zipfile when androguard is not available."""
    with zipfile.ZipFile(str(path), "r") as zf:
        # List native libraries
        for name in zf.namelist():
            if name.endswith(".so"):
                result.native_libraries.append(name)

        # Count DEX files
        result.dex_classes_count = sum(
            1 for n in zf.namelist() if n.endswith(".dex")
        )

        # Try to parse AndroidManifest.xml (binary XML — limited without androguard)
        if "AndroidManifest.xml" in zf.namelist():
            # Binary XML can't be parsed with stdlib ElementTree
            # Just note that it exists
            pass

    return result


# ── Vulnerability Checks ─────────────────────────────────────────────


def _check_manifest_vulnerabilities(result: AppAnalysisResult) -> None:
    """Check for manifest-level security issues."""

    if result.debuggable:
        result.vulnerabilities.append(AppVulnerability(
            name="Debuggable Application",
            severity="critical",
            category="manifest",
            description="Application has android:debuggable=true. This allows "
                        "attaching a debugger, bypassing security controls, and "
                        "accessing app data.",
            evidence="android:debuggable=\"true\" in AndroidManifest.xml",
            recommendation="Set android:debuggable=\"false\" in release builds.",
            owasp_masvs="MSTG-RESILIENCE-2",
        ))

    if result.allow_backup and result.target_sdk < 31:
        result.vulnerabilities.append(AppVulnerability(
            name="Backup Enabled",
            severity="medium",
            category="manifest",
            description="Application allows backup via adb. An attacker with "
                        "physical access can extract app data including tokens, "
                        "credentials, and databases.",
            evidence="android:allowBackup is not set to false",
            recommendation="Set android:allowBackup=\"false\" or use "
                          "android:fullBackupContent with restrictions.",
            owasp_masvs="MSTG-STORAGE-8",
        ))

    if result.cleartext_traffic:
        result.vulnerabilities.append(AppVulnerability(
            name="Cleartext Traffic Allowed",
            severity="high",
            category="network",
            description="Application explicitly allows cleartext (HTTP) traffic. "
                        "Network traffic can be intercepted and modified.",
            evidence="android:usesCleartextTraffic=\"true\"",
            recommendation="Use HTTPS only. Set usesCleartextTraffic to false "
                          "and configure a network security config.",
            owasp_masvs="MSTG-NETWORK-1",
        ))

    if result.min_sdk > 0 and result.min_sdk < 23:
        result.vulnerabilities.append(AppVulnerability(
            name="Low Minimum SDK Version",
            severity="low",
            category="manifest",
            description=f"App targets minSdkVersion={result.min_sdk} which lacks "
                        "runtime permission model and many security patches.",
            evidence=f"minSdkVersion=\"{result.min_sdk}\"",
            recommendation="Raise minSdkVersion to at least 23 (Android 6.0).",
            owasp_masvs="MSTG-PLATFORM-1",
        ))


def _check_permission_vulnerabilities(result: AppAnalysisResult) -> None:
    """Check for permission-related vulnerabilities."""

    if len(result.dangerous_permissions) > 5:
        result.vulnerabilities.append(AppVulnerability(
            name="Excessive Dangerous Permissions",
            severity="medium",
            category="permission",
            description=f"App requests {len(result.dangerous_permissions)} dangerous "
                        "permissions. Over-permissioned apps increase attack surface.",
            evidence=", ".join(result.dangerous_permissions[:5]) + "...",
            recommendation="Remove unnecessary dangerous permissions. Follow "
                          "principle of least privilege.",
            owasp_masvs="MSTG-PLATFORM-1",
        ))

    # Check for specific risky permission combos
    perms_set = set(result.permissions)
    if ("android.permission.READ_SMS" in perms_set and
            "android.permission.INTERNET" in perms_set):
        result.vulnerabilities.append(AppVulnerability(
            name="SMS + Internet Permission Combo",
            severity="high",
            category="permission",
            description="App has both READ_SMS and INTERNET permissions. This "
                        "combination enables SMS exfiltration.",
            evidence="READ_SMS + INTERNET",
            recommendation="Verify SMS access is necessary. Consider using "
                          "SMS Retriever API instead.",
            owasp_masvs="MSTG-PLATFORM-1",
        ))


def _check_component_vulnerabilities(result: AppAnalysisResult) -> None:
    """Check for exported component vulnerabilities."""

    for comp in result.exported_components:
        # Exported without permission protection
        if not comp.permission and comp.component_type != "activity":
            severity = "high" if comp.component_type == "provider" else "medium"
            result.vulnerabilities.append(AppVulnerability(
                name=f"Unprotected Exported {comp.component_type.title()}",
                severity=severity,
                category="ipc",
                description=f"Exported {comp.component_type} '{comp.name}' has no "
                            "permission protection. Any app on the device can "
                            "interact with it.",
                evidence=f"exported=true, permission=none for {comp.name}",
                recommendation=f"Add android:permission to protect this "
                              f"{comp.component_type}, or set exported=false.",
                owasp_masvs="MSTG-PLATFORM-1",
                component=comp.name,
            ))

        # Content provider without proper access control
        if comp.component_type == "provider" and comp.exported:
            result.vulnerabilities.append(AppVulnerability(
                name="Exported Content Provider",
                severity="high",
                category="ipc",
                description=f"Content provider '{comp.name}' is exported "
                            f"(authority: {comp.authorities}). This may expose "
                            "sensitive data or allow SQL injection.",
                evidence=f"authorities={comp.authorities}, exported=true",
                recommendation="Set grantUriPermissions carefully. Validate all "
                              "queries. Consider setting exported=false.",
                owasp_masvs="MSTG-PLATFORM-2",
                component=comp.name,
            ))

        # Deeplink handlers
        if comp.deeplinks:
            for dl in comp.deeplinks:
                result.vulnerabilities.append(AppVulnerability(
                    name="Deep Link Handler",
                    severity="info",
                    category="ipc",
                    description=f"Component '{comp.name}' handles deep link: {dl}. "
                                "Deep links can be used for phishing or "
                                "parameter injection.",
                    evidence=f"deeplink={dl}",
                    recommendation="Validate all parameters from deep links. "
                                  "Don't trust deep link data for auth decisions.",
                    owasp_masvs="MSTG-PLATFORM-3",
                    component=comp.name,
                ))


# ── Pull APK from Device ─────────────────────────────────────────────


def pull_apk_from_device(
    package_name: str,
    output_path: str,
    adb_port: int = 6520,
    adb_binary: str = "adb",
) -> Optional[str]:
    """Pull an installed APK from a connected Android device."""
    import subprocess

    serial = f"localhost:{adb_port}"

    # Get APK path on device
    rc = subprocess.run(
        [adb_binary, "-s", serial, "shell", f"pm path {package_name}"],
        capture_output=True, text=True, timeout=10,
    )
    if rc.returncode != 0 or not rc.stdout.strip():
        return None

    # Parse: "package:/data/app/.../base.apk"
    apk_device_path = rc.stdout.strip().replace("package:", "")

    # Pull to local
    pull_rc = subprocess.run(
        [adb_binary, "-s", serial, "pull", apk_device_path, output_path],
        capture_output=True, text=True, timeout=60,
    )
    if pull_rc.returncode == 0:
        return output_path
    return None
