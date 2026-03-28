# Extending Syzploit to Android Application Security

## Executive Summary

Syzploit currently targets **kernel-level vulnerabilities** (UAF, race conditions, OOB in kernel subsystems). This document proposes extending it to **Android application-level security** — analyzing APKs, discovering vulnerabilities in app code, generating exploits (Frida scripts, intent-based attacks, IPC exploitation), and verifying them on real/emulated devices.

The key insight: syzploit's existing infrastructure (ADB integration, VM management, GDB debugging, LLM-driven agentic loop, verification framework) transfers directly to app-level security with the addition of new analysis tools, attack surface enumerators, and exploit primitives.

---

## 1. Architecture Overview

```
                    ┌──────────────────────────────────┐
                    │      Syzploit Agent (existing)    │
                    │  LLM Decision Loop + Tool Gating  │
                    └──────────┬───────────────────────┘
                               │
            ┌──────────────────┼──────────────────────┐
            │                  │                       │
   ┌────────▼────────┐ ┌──────▼──────┐ ┌──────────────▼───────────┐
   │  Kernel Pipeline │ │ App Pipeline│ │  Hybrid Pipeline         │
   │  (existing)      │ │ (NEW)       │ │  (kernel + app combined) │
   └─────────────────┘ └──────┬──────┘ └──────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                      │
  ┌──────▼──────┐    ┌────────▼────────┐   ┌────────▼────────┐
  │ Static       │    │ Dynamic         │   │ Exploit          │
  │ Analysis     │    │ Analysis        │   │ Generation       │
  │ (APK decom-  │    │ (Frida, ADB,   │   │ (Frida scripts,  │
  │  pile, JADX, │    │  UI Automator,  │   │  intent crafting, │
  │  manifest)   │    │  traffic sniff) │   │  IPC fuzzing)    │
  └──────────────┘    └─────────────────┘   └──────────────────┘
```

### What Changes vs. What Stays the Same

| Component | Kernel Pipeline | App Pipeline | Reusable? |
|-----------|----------------|--------------|-----------|
| LLM orchestrator (agent.py) | CVE analysis → exploit | APK analysis → exploit | **Yes — same loop** |
| ADB infrastructure | Push kernel exploit, check UID | Push APK/Frida scripts, interact with UI | **Yes** |
| VM management | Boot Cuttlefish | Boot Cuttlefish + install app | **Yes** |
| GDB debugging | Kernel breakpoints | Frida hooks (analogous) | **Partially** |
| Verification | UID change detection | Data exfil / privesc / bypass detection | **Framework reuse** |
| Templates | Kernel exploit primitives | Frida script templates, intent templates | **New templates needed** |
| Source fetching | kernel.org / googlesource | APK decompilation / JADX | **New tools needed** |

---

## 2. New Tools to Add

### 2.1 Static Analysis Tools

#### `decompile_apk` — APK Decompilation
Decompile an APK into analyzable formats using JADX (Java) and Apktool (Smali/resources).

```python
class DecompileAPK(Tool):
    """Decompile an Android APK into Java source code and resources."""

    def execute(self, apk_path: str, output_dir: str):
        # 1. Run JADX to get Java source
        # 2. Run Apktool to get Smali + AndroidManifest.xml
        # 3. Parse AndroidManifest.xml for:
        #    - Exported activities/services/receivers/providers
        #    - Permission declarations and usage
        #    - Intent filters
        #    - Deeplinks and URL schemes
        # 4. Return structured analysis
```

**Why**: The kernel pipeline fetches source from googlesource. The app pipeline needs to extract source from the APK itself since most apps are closed-source.

#### `analyze_manifest` — Android Manifest Analysis
Parse AndroidManifest.xml to identify the app's attack surface.

```python
class AnalyzeManifest(Tool):
    """Extract and analyze the Android manifest for security-relevant configurations."""

    def execute(self, manifest_path: str):
        # Returns:
        # - Exported components (activities, services, receivers, providers)
        # - Permission model (custom permissions, protection levels)
        # - Intent filters (implicit intents = attack surface)
        # - Backup/debuggable flags
        # - Network security config
        # - Deep links / app links
```

**Why**: The manifest is the Android equivalent of `/proc/kallsyms` — it maps the attack surface.

#### `scan_vulnerabilities` — LLM-Powered Code Analysis
Use the LLM to analyze decompiled source for vulnerabilities (similar to how syzploit analyzes kernel source for root cause).

```python
class ScanVulnerabilities(Tool):
    """LLM-powered vulnerability scanning of decompiled Android app code."""

    def execute(self, source_dir: str, focus_areas: list[str]):
        # 1. Filter library code (androidx, google, kotlin stdlib)
        # 2. Identify high-risk files:
        #    - WebView usage (XSS, JavaScript interface)
        #    - Crypto operations (weak algorithms, hardcoded keys)
        #    - IPC handlers (intent parsing, content providers)
        #    - Network operations (certificate pinning, cleartext)
        #    - Storage operations (shared prefs, SQLite injection)
        #    - LLM API integrations (hardcoded API keys, prompt injection)
        # 3. Send to LLM with vulnerability-specific prompts
        # 4. Return structured findings with OWASP MASVS mapping
```

**Why**: Analogous to `root_cause.py` for kernel CVEs, but for app-level code.

### 2.2 Dynamic Analysis Tools

#### `frida_hook` — Frida Script Execution
Run Frida scripts on the target app for dynamic instrumentation.

```python
class FridaHook(Tool):
    """Inject and execute Frida scripts into a running Android app."""

    def execute(self, package_name: str, script: str, timeout: int = 30):
        # 1. Check if Frida server is running on device
        # 2. Attach to the target process
        # 3. Inject the JavaScript hook
        # 4. Collect output (hooked function calls, return values, arguments)
        # 5. Return structured results
```

**Why**: Frida is the app-level equivalent of GDB for kernel debugging. It lets the LLM observe runtime behavior — function arguments, return values, crypto operations, network traffic — without modifying the APK.

#### `ui_interact` — UI Automator Integration
Interact with the app's UI via ADB and UI Automator (leveraging MCP server patterns).

```python
class UIInteract(Tool):
    """Interact with Android app UI via accessibility tree and touch events."""

    def execute(self, action: str, **kwargs):
        # Actions:
        # - "dump_ui": Get accessibility tree XML
        # - "tap": Tap at coordinates or element text
        # - "type": Input text into focused field
        # - "swipe": Swipe gesture
        # - "screenshot": Capture current screen
        # - "launch_app": Start an app by package name
        # - "press_back": Press back button
        # - "scroll": Scroll in a direction
```

**Why**: Many app vulnerabilities require specific UI flows to trigger (e.g., navigating to a WebView, entering specific input). The LLM needs to interact with the app just like a human pentester would.

#### `capture_traffic` — Network Traffic Analysis
Capture and analyze app network traffic using mitmproxy or tcpdump.

```python
class CaptureTraffic(Tool):
    """Capture network traffic from a specific Android app."""

    def execute(self, package_name: str, duration: int = 30):
        # 1. Set up mitmproxy with Android CA cert
        # 2. Start packet capture filtered to app's UID
        # 3. Return HAR-format traffic log
        # 4. LLM analyzes for:
        #    - Hardcoded API keys in headers
        #    - Cleartext credentials
        #    - Insecure API endpoints
        #    - Certificate pinning bypass opportunities
```

**Why**: Network analysis reveals server-side vulnerabilities, API key leakage, and authentication weaknesses that aren't visible in static analysis.

#### `run_target_app_command` — Execute Commands in App Context
Run commands within the app's security context (via `run-as` or Frida).

```python
class RunInAppContext(Tool):
    """Execute commands in the target app's security context."""

    def execute(self, package_name: str, command: str):
        # Uses: adb shell run-as <package> <command>
        # Accesses: app's private data directory, shared preferences, databases
        # Can read: /data/data/<package>/ files
```

### 2.3 Exploit Generation Tools

#### `generate_frida_exploit` — Frida Exploit Script Generation
Generate Frida scripts that exploit discovered vulnerabilities.

```python
class GenerateFridaExploit(Tool):
    """Generate a Frida script to exploit a discovered vulnerability."""

    # Template library includes:
    # - SSL pinning bypass
    # - Root/jailbreak detection bypass
    # - Authentication token extraction
    # - Crypto key extraction
    # - Function return value manipulation
    # - Intent spoofing via instrumentation
    # - WebView JavaScript injection
```

#### `craft_intent` — Malicious Intent Construction
Build and send crafted intents to exploit exported components.

```python
class CraftIntent(Tool):
    """Construct and deliver a malicious intent to an exported Android component."""

    def execute(self, target_component: str, intent_type: str, extras: dict):
        # Generates: adb shell am start/broadcast/startservice
        # with crafted extras, data URIs, and flags
        # for targeting exported activities/services/receivers
```

#### `fuzz_ipc` — IPC Fuzzing
Fuzz inter-process communication channels (Intents, Content Providers, Bound Services).

```python
class FuzzIPC(Tool):
    """Fuzz Android IPC mechanisms to discover input validation vulnerabilities."""

    def execute(self, package_name: str, component: str, method: str):
        # 1. Enumerate IPC interface (AIDL methods, ContentProvider URIs)
        # 2. Generate fuzz inputs based on parameter types
        # 3. Send via adb shell or Frida
        # 4. Monitor for crashes (logcat), data leaks, or unexpected behavior
```

---

## 3. New Template Library

### 3.1 Frida Script Templates

| Template | Purpose | Analogous Kernel Template |
|----------|---------|--------------------------|
| `ssl_pinning_bypass.js` | Bypass certificate pinning | — |
| `root_detection_bypass.js` | Bypass root/jailbreak checks | — |
| `crypto_key_extractor.js` | Hook crypto APIs, extract keys | `arb_rw.c` (data extraction) |
| `auth_token_stealer.js` | Hook auth functions, capture tokens | `post_exploit.c` (cred theft) |
| `webview_injector.js` | Inject JS into WebViews | — |
| `intent_interceptor.js` | Hook intent dispatch, modify extras | `binder_client.c` (IPC interception) |
| `shared_prefs_dumper.js` | Dump all SharedPreferences | — |
| `sqlite_dumper.js` | Dump all SQLite databases | — |
| `function_tracer.js` | Trace specified method calls with args | `trigger.c` (vulnerability trigger) |
| `return_value_modifier.js` | Change function return values | `rw_primitive.c` (data manipulation) |

### 3.2 Intent/IPC Templates

| Template | Purpose |
|----------|---------|
| `exported_activity_launcher.sh` | Launch exported activities with crafted extras |
| `content_provider_query.sh` | Query/insert/update/delete content providers |
| `broadcast_spoofer.sh` | Send spoofed broadcasts to receivers |
| `deeplink_exploiter.sh` | Craft malicious deeplinks for WebView injection |
| `pending_intent_hijacker.js` | Frida script to hijack PendingIntents |

### 3.3 Combined Attack Templates

| Template | Attack Chain |
|----------|-------------|
| `webview_to_rce.js` | WebView JS interface → arbitrary code execution |
| `provider_to_file_read.sh` | Content provider path traversal → sensitive file read |
| `intent_redirect_chain.sh` | Intent redirection → privilege escalation |
| `token_to_account_takeover.js` | Auth token extraction → API impersonation |

---

## 4. Pipeline Design: App Security Pipeline

### 4.1 Pipeline Stages

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ 1. ANALYZE   │ →  │ 2. ENUMERATE  │ →  │ 3. DISCOVER   │ →  │ 4. EXPLOIT    │
│              │    │              │    │              │    │              │
│ Decompile    │    │ Attack       │    │ Vulnerability │    │ Generate     │
│ APK, parse   │    │ surface      │    │ scanning     │    │ Frida/intent │
│ manifest,    │    │ mapping      │    │ (static +    │    │ exploits     │
│ identify     │    │ (exported    │    │  dynamic)    │    │              │
│ frameworks   │    │  components, │    │              │    │              │
│              │    │  deeplinks)  │    │              │    │              │
└─────────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                                  │
                                                                  ▼
                                                           ┌──────────────┐
                                                           │ 5. VERIFY     │
                                                           │              │
                                                           │ Run exploit  │
                                                           │ on device,   │
                                                           │ check for    │
                                                           │ data exfil,  │
                                                           │ auth bypass, │
                                                           │ code exec    │
                                                           └──────────────┘
```

### 4.2 Detailed Stage Description

#### Stage 1: Analyze APK
- **Input**: APK file path or package name (can pull from device via `adb shell pm path`)
- **Tools**: `decompile_apk`, `analyze_manifest`
- **Output**: Decompiled source, manifest analysis, framework detection
- **LLM role**: Classify app type, identify high-risk areas, determine analysis strategy

#### Stage 2: Enumerate Attack Surface
- **Input**: Decompiled source + manifest
- **Tools**: `analyze_manifest`, `scan_vulnerabilities` (surface-level)
- **Output**: List of exported components, deeplinks, IPC interfaces, WebViews, native libraries
- **LLM role**: Prioritize attack vectors based on app architecture

#### Stage 3: Discover Vulnerabilities
- **Input**: Attack surface map + decompiled source
- **Tools**: `scan_vulnerabilities`, `frida_hook` (dynamic validation), `capture_traffic`, `ui_interact`
- **Output**: Confirmed vulnerability list with evidence
- **LLM role**: Analyze code for vulnerabilities, generate hypotheses, validate via dynamic testing
- **Feedback loop**: Static finding → dynamic confirmation → refine analysis

#### Stage 4: Generate Exploits
- **Input**: Confirmed vulnerabilities + templates
- **Tools**: `generate_frida_exploit`, `craft_intent`, `fuzz_ipc`
- **Output**: Executable exploit scripts (Frida JS, shell scripts, Python scripts)
- **LLM role**: Select appropriate template, customize for the specific vulnerability, generate exploit code
- **Template selection**: Same mechanism as kernel pipeline — keyword matching + LLM selection

#### Stage 5: Verify Exploits
- **Input**: Generated exploit scripts
- **Tools**: `frida_hook` (run exploit), `ui_interact` (trigger conditions), `capture_traffic` (observe results)
- **Output**: Verification report with evidence (screenshots, traffic captures, data dumps)
- **LLM role**: Analyze verification results, determine success/failure, iterate if needed
- **Success criteria**: Data exfiltration confirmed, authentication bypassed, code execution achieved, etc.

---

## 5. Integration with Existing Syzploit

### 5.1 CLI Extension

```bash
# Existing kernel commands (unchanged)
syzploit agent CVE-2023-20938 --platform android ...
syzploit pipeline CVE-2024-36971 ...

# NEW: App-level analysis
syzploit app-analyze com.example.app --apk ./target.apk --device DEVICE_SERIAL
syzploit app-agent com.example.app --apk ./target.apk --ssh-host INGOTS-ARM --instance 19
syzploit app-fuzz com.example.app --focus ipc,webview
syzploit app-verify ./exploit_scripts/ --package com.example.app
```

### 5.2 Shared Infrastructure

```python
# In orchestrator/agent.py — add app tools to the tool registry
APP_TOOLS = {
    "decompile_apk": decompile_apk_tool,
    "analyze_manifest": analyze_manifest_tool,
    "scan_vulnerabilities": scan_vulnerabilities_tool,
    "frida_hook": frida_hook_tool,
    "ui_interact": ui_interact_tool,
    "capture_traffic": capture_traffic_tool,
    "craft_intent": craft_intent_tool,
    "generate_frida_exploit": generate_frida_exploit_tool,
    "fuzz_ipc": fuzz_ipc_tool,
    "run_in_app_context": run_in_app_context_tool,
}

# Agent decides which tools to use based on target type
if ctx.target_type == "app":
    available_tools = {**COMMON_TOOLS, **APP_TOOLS}
elif ctx.target_type == "kernel":
    available_tools = {**COMMON_TOOLS, **KERNEL_TOOLS}
else:  # hybrid
    available_tools = {**COMMON_TOOLS, **KERNEL_TOOLS, **APP_TOOLS}
```

### 5.3 Hybrid Mode: Kernel + App Combined

Some attacks chain app-level and kernel-level vulnerabilities:

```
App vulnerability (e.g., arbitrary file write via content provider)
    → Write to /data/local/tmp/exploit
    → Trigger kernel vulnerability from app context
    → Kernel privilege escalation
    → Full device compromise
```

Syzploit's hybrid mode would:
1. Discover app-level vulnerabilities (Stage 1-3 of app pipeline)
2. Use app vulnerability as delivery mechanism for kernel exploit
3. Verify end-to-end chain (app entry → kernel privesc → root)

---

## 6. Device Setup and Prerequisites

### 6.1 Required on Target Device

| Component | Purpose | Installation |
|-----------|---------|-------------|
| Frida server | Dynamic instrumentation | `adb push frida-server /data/local/tmp/` |
| mitmproxy CA cert | Traffic interception | Install via Settings → Security |
| JADX | Decompilation | Host-side tool |
| Apktool | Resource extraction | Host-side tool |
| iptables rules | Traffic redirect to proxy | `adb shell iptables -t nat ...` |

### 6.2 Required on Host

| Component | Purpose |
|-----------|---------|
| `frida-tools` | Python bindings for Frida |
| `jadx` | Java decompiler |
| `apktool` | APK resource decoder |
| `mitmproxy` | HTTPS traffic interception |
| `uiautomator2` (Python) | UI automation library |

---

## 7. Example Walkthrough: Analyzing a Vulnerable App

```
$ syzploit app-agent com.example.banking --apk ./banking.apk \
    --ssh-host INGOTS-ARM --instance 19 --debug

Step 1: decompile_apk — Decompiling banking.apk with JADX...
  Found 342 Java source files
  AndroidManifest.xml: 12 activities, 3 services, 2 receivers, 1 provider
  Framework detected: OkHttp, Retrofit, Room, Firebase

Step 2: analyze_manifest — Mapping attack surface...
  Exported: LoginActivity (deeplink: mybank://login?redirect={url})
  Exported: ContentProvider (authority: com.example.banking.data)
  Exported: BroadcastReceiver (action: com.example.banking.NOTIFY)
  Debuggable: false, Backup: true, Network cleartext: false

Step 3: scan_vulnerabilities — LLM analyzing 342 files...
  CRITICAL: SQL injection in ContentProvider query() method
  HIGH: WebView JavaScript interface with @JavascriptInterface annotation
  HIGH: Hardcoded API key in BuildConfig.java
  MEDIUM: Certificate pinning implemented but bypassable (OkHttp interceptor)
  LOW: Insecure SharedPreferences storage (MODE_WORLD_READABLE removed in API 24+)

Step 4: generate_frida_exploit — Creating exploit for SQL injection...
  Template: content_provider_query.sh
  Customized for: authority=com.example.banking.data, path=/accounts
  Generated: exploit_scripts/sqli_provider.sh

Step 5: verify — Running exploit on device...
  $ adb shell content query --uri content://com.example.banking.data/accounts
  Rows: 3
  Row 0: _id=1, name=John Doe, balance=15000.00, account_no=****4521
  ✓ SQL injection confirmed — extracted 3 account records
  ✓ Verification: 1/1 exploits confirmed
```

---

## 8. Comparison with Existing Tools

| Tool | Approach | Syzploit App Extension Advantage |
|------|----------|----------------------------------|
| **Drozer** | Manual IPC testing | LLM-automated, template-driven |
| **MobSF** | Static analysis only | Static + dynamic + exploit generation |
| **Frida** | Manual script writing | LLM generates + validates Frida scripts |
| **Droid LLM Hunter** | APK scanning | Full pipeline: scan → exploit → verify |
| **LM-Scout** | LLM API key extraction | Broader scope: all app vulns, not just LLM |
| **Android MCP servers** | UI automation only | Security-focused: vuln discovery + exploitation |

### Key Differentiator

No existing tool combines ALL of these in a single agentic loop:
1. Automated APK decompilation + analysis
2. LLM-powered vulnerability discovery
3. Template-based exploit generation
4. Dynamic verification on real devices
5. Iterative feedback (fail → analyze → fix → retry)

Syzploit's agent architecture (`agent.py`) already implements #5 for kernel exploits. Extending it to apps requires adding new tools (#1-4) while reusing the orchestration, ADB infrastructure, and verification framework.

---

## 9. Implementation Roadmap

### Phase 1: Foundation — COMPLETE (tested on live Cuttlefish instance)
- [x] Add `decompile_apk` and `analyze_manifest` tools → `app_analyzer.py` (tested with F-Droid + Music APK)
- [x] Add `frida_hook` tool with Frida server management → `frida_tools.py` (6 scripts, tested)
- [x] Add `ui_interact` tool (ADB-based) → `ui_automator.py` (dump_ui, tap, screenshot — all tested live)
- [x] Create 6 Frida templates (SSL bypass, root bypass, function tracer, key extractor, activity monitor, WebView inspector)
- [x] Add `analyze-app` CLI command (tested end-to-end)

### Phase 2: Vulnerability Discovery — COMPLETE (tested on live Cuttlefish instance)
- [x] Add `scan_vulnerabilities` with static (19 rules) + LLM + hybrid modes → `vuln_scanner.py` (9/9 test vulns detected)
- [x] Add `craft_intent` / `test-intents` for exported component testing → `intent_crafter.py` (5/6 intents succeeded live)
- [x] Add `capture_traffic` via /proc/net/tcp + logcat → `traffic_capture.py` (no mitmproxy dep needed)
- [x] Add `scan-app` CLI command (tested)
- [ ] Add `app-agent` CLI command (full agentic loop) — deferred to Phase 4

### Phase 3: Exploit Generation — COMPLETE (tested on live Cuttlefish instance)
- [x] Add `generate_exploit` with template-based exploit generation → `exploit_generator.py` (7 exploit templates)
- [x] Add `fuzz_ipc` for IPC fuzzing → `ipc_fuzzer.py` (91 fuzz tests ran on Settings app)
- [x] Add `app-verify` with multi-criteria success detection → `app_verify.py` (crash, data leak, auth bypass)
- [x] Add `fuzz-app` CLI command (tested live)
- [x] Add `exploit-app` CLI command (tested: analyze → generate → save pipeline)
- [x] Add `capture-traffic` CLI command (tested)

### Phase 4: App Agent + Hybrid Mode + LLM Decisions — COMPLETE (all tested on live Cuttlefish)
- [x] Add `app-agent` CLI command → `app_agent.py` (8-step pipeline: analyze → scan → intent → exploit → fuzz → traffic → verify → hybrid)
- [x] Hybrid kernel + app mode → `hybrid_mode.py` (5 delivery templates: file_drop, intent_trigger, binder_chain, webview_to_native, permission_escalation)
- [x] Chain identification: maps app vulns to kernel exploit delivery methods
- [x] App-to-kernel delivery templates with script generation
- [x] LLM-driven decision engine → `app_decision.py` (12 actions, rule-based fallback, LLM optional)
- [x] Tested: `--kernel-cve CVE-2023-20938` identified 5 hybrid chains (3 delivery methods)
- [x] Full pipeline: 8 steps, 6s, 0 errors, 5 reports including `hybrid_report.json`

---

## 10. References and Inspiration

- **Android MCP Servers**: [CursorTouch/Android-MCP](https://github.com/CursorTouch/Android-MCP), [mobile-next/mobile-mcp](https://github.com/mobile-next/mobile-mcp), [nim444/mcp-android-server-python](https://github.com/nim444/mcp-android-server-python)
- **LLM-Powered Android Security**: [Droid LLM Hunter](https://github.com/roomkangali/droid-llm-hunter), [LM-Scout (arxiv)](https://arxiv.org/html/2505.08204v1)
- **Android Security Training**: [RingZer0 2025 - Applied AI/LLM for Android APK Analysis](https://fuzzinglabs.com/ringzer0-2025-applied-ai-llm-for-android-apk-reversing-and-analysis/)
- **Android MCP Server in Python**: [Simone Mutti's Medium article](https://medium.com/@simo.mut105/how-i-built-an-android-mcp-server-in-python-part-1-0774476e4fdc)
- **Breaking Android with AI**: [ResearchGate paper on LLM-Powered Exploitation](https://www.researchgate.net/publication/395389029_Breaking_Android_with_AI_A_Deep_Dive_into_LLM-Powered_Exploitation)
