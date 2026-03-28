# syzploit

Agentic kernel and Android application security analysis toolkit.

syzploit takes a CVE identifier, syzbot bug URL, crash log, security blog post,
or Android device and automatically analyzes vulnerabilities, generates exploits,
and verifies privilege escalation — all driven by LLM reasoning.

## Quick start

```bash
# Install dependencies
uv sync

# Copy the example .env and add your API key
cp env.example .env
# Edit .env — set at least: OPENROUTER_API_KEY=sk-or-v1-...

# Run kernel exploit generation
uv run syzploit agent CVE-2023-20938 \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host INGOTS-ARM --no-persistent --setup-tunnels --instance 19 \
  --kernel-image /path/to/kernel/Image \
  --start-cmd "cd /path && ./gdb_run.sh 19" \
  --stop-cmd "cd /path && ./stop.sh 19" \
  --exploit-start-cmd "cd /path && ./run.sh 19" \
  --platform android --arch arm64 \
  --model openrouter/anthropic/claude-sonnet-4.6 --debug

# Scan all apps on a device (one command)
uv run syzploit audit-device \
  --ssh-host INGOTS-ARM --instance 18 \
  --exploit-start-cmd "cd /path && ./run.sh 18" \
  --stop-cmd "cd /path && ./stop.sh 18" \
  --deep-scan 3 --output-dir ./device_audit

# Full audit: kernel CVE + all apps + hybrid chains
uv run syzploit audit-device \
  --ssh-host INGOTS-ARM --instance 18 \
  --kernel-cve CVE-2023-20938 \
  --start-cmd "cd /path && ./gdb_run.sh 18" \
  --stop-cmd "cd /path && ./stop.sh 18" \
  --exploit-start-cmd "cd /path && ./run.sh 18" \
  --kernel-image /path/to/kernel/Image \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --output-dir ./full_audit
```

## Architecture

```
syzploit/src/syzploit/
├── core/               ← Shared foundations (models, config, LLM client, logging)
├── orchestrator/       ← Agent + deterministic pipeline + tool registry
├── analysis/           ← Crash parsing, CVE/blog analysis, root cause, feasibility
├── reproducer/         ← LLM code generation, cross-compilation, SSH verification
├── exploit/            ← Exploit planning, code generation, templates, stitching
├── infra/              ← ADB, SSH, VM control (QEMU/Cuttlefish), GDB
├── android/            ← Android app security (APK analysis, Frida, fuzzing, exploits)
├── data/               ← Bug DB (SQLite), syzbot scraper, file storage
└── cli/                ← Typer CLI commands
```

## Commands

### Kernel Security

| Command | Description |
|---------|-------------|
| `syzploit agent <CVE>` | LLM-driven kernel exploit pipeline (recommended) |
| `syzploit pipeline <CVE>` | Deterministic 3-stage: analyze → reproduce → exploit |
| `syzploit analyze-cve <CVE>` | CVE analysis from NVD/MITRE with LLM classification |
| `syzploit investigate <CVE>` | Deep investigation: scrape exploits, blogs, patches, source |
| `syzploit analyze-blog <URL>` | Analyze a security blog post |
| `syzploit analyze-crash <file>` | Parse and analyze a kernel crash log |
| `syzploit check-feasibility <file>` | Check vulnerability presence on target kernel |
| `syzploit verify-exploit <binary>` | Manually verify an exploit binary on target |
| `syzploit verify-reproducer <binary>` | Manually verify a reproducer on target |
| `syzploit hunt <version>` | Autonomous CVE hunter for a kernel version |
| `syzploit compare-runs <dir1> <dir2>` | Compare execution traces from multiple runs |

### Android App Security

| Command | Description |
|---------|-------------|
| `syzploit audit-device` | **Full device audit** — kernel + all apps in one command |
| `syzploit scan-device` | Scan all apps, rank by risk, deep-dive top N |
| `syzploit app-agent <apk>` | Full agentic app analysis pipeline |
| `syzploit analyze-app <apk>` | Static APK analysis (manifest, permissions, vulns) |
| `syzploit decompile-app <apk>` | Decompile APK to Java source (JADX/androguard) |
| `syzploit scan-app <source_dir>` | Scan decompiled source for vulnerabilities |
| `syzploit exploit-app <apk>` | Generate + verify exploits for an app |
| `syzploit fuzz-app <apk>` | Fuzz exported components (intents, providers, services) |
| `syzploit test-intents <apk>` | Test exported components via crafted intents |
| `syzploit frida-hook <package>` | Run Frida hook scripts on a running app |
| `syzploit capture-traffic <package>` | Capture and analyze app network traffic |

---

## Kernel Exploit Pipeline (`syzploit agent`)

The kernel agent is an LLM-driven loop that:
1. **Investigates** the CVE (NVD, GitHub PoCs, patches, kernel source)
2. **Collects target info** (boots VM, gets kernel version, kallsyms, 140K+ symbols)
3. **Resolves kernel offsets** (init_task, prepare_kernel_cred, struct layouts)
4. **Generates exploit** (direct reference adaptation or LLM template-based codegen)
5. **Verifies on target** (deploys binary, monitors with GDB HW breakpoints, checks UID change)
6. **Iterates** (runtime feedback loop: diagnose failure → fix → recompile → retry)

### Key features

- **Direct reference adaptation**: When a working exploit exists for the same CVE and kernel family, copies it directly with only offset substitution — no LLM codegen needed (~12 min to root)
- **HW breakpoint monitoring**: Uses ARM64 hardware breakpoints (not software) for reliable GDB tracing on KVM
- **Template library**: 20+ exploit primitive templates (heap spray, cross-cache, arb R/W, binder client, post-exploit, etc.)
- **Multi-model support**: Separate models for decisions, analysis, planning, and codegen
- **Early termination**: Stops immediately when privilege escalation is confirmed
- **ADB retry with host kernel rejection**: Detects when SSH fallback returns build host kernel instead of target device

### Example

```bash
uv run syzploit agent CVE-2023-20938 \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host INGOTS-ARM --no-persistent --setup-tunnels --instance 19 \
  --kernel-image /home/purdue-ext/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/purdue-ext/challenge-4/challenge-4.1 && ./gdb_run.sh 19" \
  --stop-cmd "cd /home/purdue-ext/challenge-4/challenge-4.1 && ./stop.sh 19" \
  --exploit-start-cmd "cd /home/purdue-ext/challenge-4/challenge-4.1 && ./run.sh 19" \
  --platform android --arch arm64 \
  --model openrouter/anthropic/claude-sonnet-4.6 --debug
```

**Output** (~12 min, 12 LLM calls):
```
Step 1: investigate — CVE-2023-20938 (CVSS 7.8, UAF in binder)
Step 2: collect_target_info — kernel 5.10.107-maybe-dirty, 140K symbols
Step 3: resolve_kernel_offsets — 4KB kernel_offsets.h generated
Step 4: exploit — Direct reference adaptation compiled (static, 3.3MB)
Step 5: verify_exploit — ✓ privilege escalation confirmed! (UID 2000→0)
```

---

## Android App Security

### Full Device Audit (`syzploit audit-device`)

One command to analyze everything on a device — kernel CVE + all installed apps:

```bash
# Apps only (no kernel analysis)
uv run syzploit audit-device \
  --ssh-host INGOTS-ARM --instance 18 \
  --exploit-start-cmd "cd /path && ./run.sh 18" \
  --stop-cmd "cd /path && ./stop.sh 18" \
  --deep-scan 3 \
  --output-dir ./device_audit

# Full audit: kernel + apps + hybrid chains
uv run syzploit audit-device \
  --ssh-host INGOTS-ARM --instance 18 \
  --kernel-cve CVE-2023-20938 \
  --start-cmd "cd /path && ./gdb_run.sh 18" \
  --stop-cmd "cd /path && ./stop.sh 18" \
  --exploit-start-cmd "cd /path && ./run.sh 18" \
  --kernel-image /path/to/kernel/Image \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --output-dir ./full_audit
```

**What it does automatically:**
1. Boots VM, connects ADB
2. (Optional) Runs kernel CVE analysis + exploit generation + privilege escalation verification
3. Scans all installed apps (pull APK, analyze manifest, check permissions, find vulns)
4. Ranks apps by risk score (weighted: critical=25, high=10, medium=3, exported=2)
5. Deep-scans top N riskiest apps (fuzz IPC, capture traffic, generate exploits, verify)
6. Identifies hybrid kernel+app exploit chains
7. Saves comprehensive report, stops VM

### App Agent Pipeline (`syzploit app-agent`)

8-step agentic analysis for a single APK:

```bash
uv run syzploit app-agent ./target.apk \
  --device localhost:6537 \
  --output-dir ./app_analysis \
  --kernel-cve CVE-2023-20938 \
  --kernel-exploit ./badnode_working/badnode
```

| Step | What it does |
|------|-------------|
| 1. Analyze APK | Parse manifest, permissions, components, initial vuln checks |
| 2. Scan vulnerabilities | 19 static rules + optional LLM deep analysis |
| 3. Test intents | Send crafted intents to all exported components |
| 4. Generate exploits | Template-based exploit script generation |
| 5. Fuzz IPC | Fuzz activities, providers, receivers with malformed inputs |
| 6. Capture traffic | Monitor network connections and cleartext URLs |
| 7. Verify exploits | Run generated exploits and check for data leak/crash/bypass |
| 8. Hybrid analysis | Identify kernel+app exploit chains |

### Vulnerability Scanner

19 built-in static detection rules covering:

| Category | Rules |
|----------|-------|
| **SQL Injection** | rawQuery, execSQL with string concatenation |
| **WebView XSS** | JavaScript enabled, JS interface, file access |
| **Hardcoded Secrets** | API keys, passwords, tokens in source |
| **Insecure Crypto** | ECB mode, DES, insecure random, hardcoded IV |
| **Insecure Storage** | World-readable files, external storage, log leaks |
| **Network** | TrustManager override, hostname verifier bypass |
| **IPC** | Implicit intents with sensitive data, clipboard |
| **Path Traversal** | ContentProvider openFile path traversal |

All findings mapped to OWASP MASVS standards.

### Frida Integration

6 pre-built security scripts:

| Script | Purpose |
|--------|---------|
| `ssl_pinning_bypass` | Bypass OkHttp + TrustManager certificate pinning |
| `root_detection_bypass` | Bypass root/SafetyNet checks (File.exists, Runtime.exec, Build.TAGS) |
| `crypto_key_extractor` | Hook SecretKeySpec, Cipher, SharedPreferences for key extraction |
| `function_tracer` | Generic method hooking with argument/return capture |
| `activity_lifecycle_monitor` | Track Activity lifecycle + Intent extras |
| `webview_inspector` | Monitor loadUrl, addJavascriptInterface, WebSettings |

```bash
# List available scripts
uv run syzploit frida-hook dummy --list

# Run SSL pinning bypass on an app
uv run syzploit frida-hook com.example.app --script ssl_pinning_bypass --device localhost:6537
```

Auto-setup: `auto_setup_frida()` automatically downloads, pushes, and starts frida-server on the device.

### IPC Fuzzer

Systematically sends malformed inputs to exported components:

```bash
uv run syzploit fuzz-app ./target.apk --device localhost:6537 --output-dir ./fuzz_results
```

- **Activities**: Malformed extras, oversized strings, null values, SQL injection payloads
- **Content Providers**: SQL injection via --where, path traversal via URI
- **Broadcast Receivers**: Spoofed actions, crafted extras
- **Services**: Binding with malicious intents

### Exploit Templates

7 app exploit templates covering:
- SQL injection (ContentProvider)
- WebView JavaScript interface exploitation
- API key extraction and abuse
- Content provider data extraction
- Unprotected service exploitation
- ADB backup data extraction
- Deep link parameter injection

### Hybrid Mode (Kernel + App)

5 delivery templates for chaining app vulnerabilities with kernel exploits:

| Template | Chain |
|----------|-------|
| `file_drop` | App ContentProvider → write exploit binary → kernel privesc |
| `intent_trigger` | App intent → triggers native code → kernel vuln |
| `binder_chain` | App service → controlled binder txn → kernel binder UAF |
| `webview_to_native` | WebView JS interface → native code → kernel exploit |
| `permission_escalation` | App permissions → stage kernel exploit → root |

### UI Automation

ADB-based UI interaction (no UIAutomator2 dependency):
- Dump accessibility tree (XML hierarchy)
- Tap, swipe, long press at coordinates or elements
- Type text, press keys (BACK, HOME, etc.)
- Launch/stop apps
- Take screenshots
- Get screen size and current activity

---

## Output Structure

### Kernel analysis
```
analysis_CVE-2023-20938/
├── root_cause_analysis_report.json
├── target_system_info_report.json
├── kernel_offsets.h
├── exploit_plan_report.json
├── exploit_result_report.json
├── exploit_src/
│   ├── exploit              # Compiled ARM64 static binary
│   ├── exploit.c            # Source code
│   └── ...
├── verification_exploit_attempt_*.json
├── pipeline_summary.json
├── execution_trace_*.json
└── output.log               # Full pipeline output
```

### Device audit
```
full_audit/
├── full_audit_report.json          # Overall summary
├── kernel_analysis/                # Kernel CVE results
│   ├── exploit_src/exploit
│   └── *.json
└── app_analysis/                   # App security results
    ├── device_security_report.json # Ranked app list
    ├── apks/                       # Pulled APK files
    ├── per_app/                    # Top 10 risk reports
    └── deep_analysis/              # Full agent for top N apps
        ├── com.risky.app/
        │   ├── app_security_report.json
        │   ├── exploits/
        │   ├── fuzz_report.json
        │   ├── traffic_report.json
        │   └── hybrid_report.json
        └── ...
```

---

## Installation

```bash
# Clone
git clone git@github.com:purseclab/kernelcveanalysis.git
cd kernelcveanalysis/syzploit

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .

# For Android app analysis features
uv sync --extra android
# Or: pip install -e ".[android]"
```

### Dependencies

| Component | Required for |
|-----------|-------------|
| `androguard` | APK parsing (auto-installed) |
| `frida-tools` | Dynamic app instrumentation |
| `aarch64-linux-gnu-gcc` | ARM64 cross-compilation |
| `gdb-multiarch` | Kernel debugging |
| Android NDK | Exploit compilation |
| JADX (optional) | Better Java decompilation |

### Environment variables

```bash
OPENROUTER_API_KEY=sk-or-v1-...     # Required for LLM analysis
ANDROID_NDK_HOME=/path/to/ndk       # Optional: for NDK compilation
SYZPLOIT_SSH_HOST=hostname           # Default SSH host
SYZPLOIT_SSH_PORT=22                 # Default SSH port
```

---

## Cost optimization

| Approach | Savings |
|----------|---------|
| Use `--decision-model openrouter/openai/gpt-4o-mini` | ~60% on decision calls |
| Use `--replay` for demos (zero LLM cost) | 100% on repeat runs |
| Direct reference adaptation (automatic) | Skips all codegen LLM calls |
| Early termination (automatic) | Stops after first successful verification |

Typical costs:
- Kernel CVE analysis with direct adaptation: **~$0.50** (12 calls, 96K tokens)
- Full app audit (50 apps): **$0** (no LLM needed for static analysis)
- Full kernel + app audit: **~$0.50-1.00**
