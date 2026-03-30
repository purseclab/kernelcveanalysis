"""
android — Android-specific exploit analysis and attack surface tools.

Provides:
    AttackSurfaceAnalyzer    SELinux + syscall + binder service enumeration
    BinderFuzzer             Binder transaction C code generator
    analyze_apk              APK security analysis (manifest, permissions, vulns)
    FridaResult              Result from Frida script execution
    run_frida_script         Inject Frida scripts into running apps
    IntentResult             Result from intent crafting
    test_exported_components Test exported components via ADB
"""

# Suppress androguard's verbose DEBUG logging globally before any imports
import logging as _logging
for _lg in ("androguard", "androguard.core.axml", "androguard.core.dex",
            "androguard.core.apk", "androguard.core.api_specific_resources"):
    _logging.getLogger(_lg).setLevel(_logging.ERROR)

from .surface_analyzer import AttackSurfaceAnalyzer
from .binder_fuzzer import BinderFuzzer
from .app_analyzer import analyze_apk, AppAnalysisResult, AppVulnerability
from .frida_tools import (
    run_frida_script, run_adb_frida_script, FridaResult,
    get_frida_script, list_frida_scripts,
    check_frida_server, start_frida_server, auto_setup_frida,
)
from .intent_crafter import (
    IntentResult, launch_activity, send_broadcast,
    query_content_provider, test_exported_components, test_deeplink,
)
from .vuln_scanner import scan_static, scan_with_llm, scan_hybrid, VULN_RULES
from .ui_automator import (
    dump_ui, find_elements, tap, tap_element, swipe, type_text,
    press_key, launch_app, stop_app, get_current_activity,
    take_screenshot, get_screen_size, UIElement,
)
from .exploit_generator import (
    generate_exploit, generate_all_exploits, save_exploits, ExploitScript,
)
from .ipc_fuzzer import (
    fuzz_activity, fuzz_content_provider, fuzz_broadcast_receiver,
    fuzz_exported_components, FuzzResult, FuzzReport,
)
from .traffic_capture import (
    get_connections, capture_app_traffic, check_cleartext_traffic,
    NetworkConnection, TrafficCapture,
)
from .app_verify import (
    verify_exploit as verify_app_exploit, verify_all_exploits,
    VerifyResult,
)
from .app_agent import run_app_agent, AppAgentConfig, AppAgentResult
from .decompiler import decompile_apk as decompile_apk_source
from .device_scanner import scan_device, full_device_audit, list_installed_apps, DeviceScanResult
from .hybrid_mode import (
    identify_chains, generate_chain_script, run_hybrid_analysis,
    HybridChain, HybridResult, DELIVERY_TEMPLATES,
)
from .app_decision import decide_next_action, AVAILABLE_ACTIONS

__all__ = [
    "AttackSurfaceAnalyzer",
    "BinderFuzzer",
    "analyze_apk",
    "AppAnalysisResult",
    "AppVulnerability",
    "run_frida_script",
    "run_adb_frida_script",
    "FridaResult",
    "get_frida_script",
    "list_frida_scripts",
    "check_frida_server",
    "start_frida_server",
    "IntentResult",
    "launch_activity",
    "send_broadcast",
    "query_content_provider",
    "test_exported_components",
    "test_deeplink",
]
