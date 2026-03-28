# Syzploit Extension Proposals

This document covers proposed capabilities and architectural extensions for syzploit, organized by domain.

---

## 1. Android App Analysis & Cross-Layer Exploit Chaining

### Current State
Syzploit operates exclusively at the kernel level: it analyzes kernel CVEs, generates kernel exploits (C compiled with NDK), and verifies privilege escalation via UID changes. It has no visibility into Android userspace, the Java/Kotlin app layer, or the system service attack surface between apps and the kernel.

### Proposed Extensions

#### 1.1 Android App Attack Surface Scanner
**Purpose**: Identify app-level entry points that reach vulnerable kernel code paths.

**Implementation**:
- New module `analysis/android_app.py`:
  - Parse APK manifests for exported components (activities, services, broadcast receivers, content providers)
  - Extract intent filters, permissions, and inter-process communication (IPC) surfaces
  - Use `aapt2 dump` or `apktool` for static analysis
  - Map binder interfaces exposed by the app (via AIDL stubs)
  - Identify JNI native libraries that make syscalls reaching kernel subsystems

- New agent tool `scan_android_app`:
  - Input: APK path or package name on device
  - Output: attack surface map stored in `analysis_data["app_attack_surface"]`
  - Identifies which app components can reach binder, ioctl, socket, or filesystem kernel paths

**Effort**: Medium (1-2 weeks). Requires `apktool` and `jadx` as optional deps.

#### 1.2 Cross-Layer Exploit Chain Planner
**Purpose**: Plan multi-stage exploit chains: App vulnerability → System service compromise → Kernel privilege escalation.

**Implementation**:
- New module `exploit/chain_planner.py`:
  - Chain stages: `APP_VULN → BINDER_ESCAPE → KERNEL_EXPLOIT → ROOT`
  - LLM-driven chain planning prompt that takes:
    - App attack surface (exported components, permissions)
    - System service vulnerabilities (e.g., `system_server` bugs, `mediaserver` parser bugs)
    - Kernel CVE root cause
  - Generates a `ChainPlan` with per-stage exploit steps
  - Handles SELinux domain transitions (e.g., `untrusted_app` → `system_server` → `kernel`)

- New agent tool `plan_exploit_chain`:
  - Combines app surface, known service vulns, and kernel CVE
  - Stores chain plan in context for multi-stage generation

**Effort**: High (3-4 weeks). Requires significant prompt engineering for multi-stage reasoning.

#### 1.3 System Service Fuzzer Integration
**Purpose**: Discover bugs in Android system services (Java/native) that bridge app→kernel.

**Implementation**:
- Integrate with existing tools: `Frida` for runtime hooking, `droidefuzz` for Binder fuzzing
- New module `analysis/service_fuzzer.py`:
  - Target specific binder interfaces via `service list` on device
  - Generate and send malformed binder transactions
  - Monitor for crashes in `system_server`, `surfaceflinger`, `mediaserver`
  - Parse tombstones and ANR traces
  - Feed discovered service bugs into the chain planner

**Effort**: High (4-6 weeks). This is a significant new capability.

#### 1.4 Android App Vulnerability Database
**Purpose**: Catalog known Android framework/service vulnerabilities for chain planning.

**Implementation**:
- New data file `data/android_service_vulns.json`:
  - Curated list of known system service vulnerabilities by Android version
  - Each entry: CVE ID, affected service, SELinux domain, binder interface, exploit technique
  - Used by chain planner to find service-level stepping stones

- New agent tool `query_android_vulns`:
  - Search by Android version, service name, or SELinux domain
  - Returns matching vulnerabilities for chain planning

**Effort**: Low for the database, medium for the tool (1 week).

---

## 2. EDK2/UEFI Firmware Extension

### Current State
Syzploit targets Linux/Android kernels exclusively. All compilation, verification, and analysis paths assume a kernel exploit running in a Linux userspace context. UEFI firmware operates in a fundamentally different environment (no syscalls, no userspace, ring 0 from boot, SMM for highest privilege).

### Proposed Extensions

#### 2.1 UEFI Target Profile
**Purpose**: Support UEFI firmware as a target platform alongside Linux/Android.

**Implementation**:
- New `Platform.UEFI` enum value in `core/models.py`
- New compiler backend in `exploit/exploit_compiler.py`:
  - Cross-compile with EDK2 toolchain (`BaseTools/BinWrappers/PosixLike/`)
  - Build as UEFI application (`.efi` PE32+ binary) or DXE driver
  - Use EDK2 headers instead of Linux headers
  - Link against `MdePkg` libraries (UefiLib, BaseMemoryLib, etc.)

- New scaffold template in `exploit/templates/uefi/`:
  - `UefiMain.c` — UEFI application entry point (`EFI_STATUS EFIAPI UefiMain(...)`)
  - `SmmAttack.c` — SMM communication handler exploitation
  - `DxeHook.c` — DXE driver protocol hijacking
  - `VarExploit.c` — UEFI variable service exploitation

**Effort**: High (3-4 weeks). Requires EDK2 build system integration.

#### 2.2 UEFI Vulnerability Analysis
**Purpose**: Analyze UEFI/SMM vulnerabilities using the same LLM-driven analysis pipeline.

**Implementation**:
- New analysis patterns in `analysis/root_cause.py`:
  - UEFI-specific vulnerability types: SMM callout, variable overflow, DXE privilege escalation, secure boot bypass
  - UEFI struct knowledge: `EFI_SYSTEM_TABLE`, `EFI_BOOT_SERVICES`, `EFI_RUNTIME_SERVICES`, `EFI_SMM_COMMUNICATE_HEADER`
  - EDK2 source navigation (similar to kernel source, but EDK2 GitHub repo)

- New module `analysis/uefi_analyzer.py`:
  - Parse UEFI firmware images (`UEFITool` / `uefi-firmware-parser`)
  - Extract DXE drivers, SMM handlers, UEFI variables
  - Identify attack surface: variable services, SMM communication, S3 resume, PEI→DXE handoff
  - LLM-driven analysis of firmware binary capabilities

**Effort**: High (4-6 weeks). UEFI analysis is a specialized domain.

#### 2.3 QEMU/OVMF Verification Backend
**Purpose**: Verify UEFI exploits in an emulated environment.

**Implementation**:
- New verification backend in `infra/uefi_verification.py`:
  - Boot OVMF (Open Virtual Machine Firmware) in QEMU
  - Load exploit as UEFI shell application or DXE driver
  - Monitor via QEMU debug console + GDB
  - Check for SMM entry, variable write success, secure boot state changes
  - Parse UEFI debug output logs for success/failure

- Integration with existing GDB infrastructure:
  - UEFI symbols from `.efi` with debug info
  - Breakpoints on EFI protocol installations, SMM handlers
  - Memory read/write verification at UEFI runtime

**Effort**: Medium (2-3 weeks). OVMF is well-supported in QEMU.

#### 2.4 UEFI Exploit Knowledge Base
**Purpose**: Curate UEFI exploitation techniques for the LLM generator.

**Implementation**:
- New entries in `exploit/exploit_knowledge.py`:
  - SMM callout exploitation (calling non-SMRAM code from SMM)
  - UEFI variable buffer overflow (SetVariable with oversized data)
  - DXE driver protocol hooking (replace protocol interface pointers)
  - S3 boot script table modification
  - Secure Boot bypass via db/dbx manipulation
  - PEI→DXE code injection via HOB manipulation

- New templates in `exploit/templates/uefi/`:
  - Tested SMM communication patterns
  - Variable service exploitation stubs
  - DXE protocol enumeration and hooking

**Effort**: Medium (2 weeks). Requires UEFI security domain expertise.

---

## 3. Autonomous CVE Hunter Mode — IMPLEMENTED

See the new `syzploit hunt` CLI command. Implementation summary:

- **CVE discovery** (`analysis/cve_hunter.py`): Queries NVD, Android Security Bulletins, GitHub, nomi-sec PoC aggregator. LLM ranks candidates by exploitability.
- **Hunt orchestrator** (`orchestrator/hunter.py`): Iterates over ranked CVEs, runs full agent pipeline per-CVE, creates per-CVE work directories, generates summary report.
- **CLI** (`cli/app.py`): `syzploit hunt 5.10.107 --platform android --max-targets 10`
- **Agent tool** (`builtin_tools.py`): `hunt_cves` tool available in agent mode for discovery during runs.

---

## 4. Stub Elimination & Information Flow — IMPLEMENTED

### Changes Made

#### 4.1 CVE-Generic Module Instructions
The `_MODULE_INSTRUCTIONS` in `generator.py` were hardcoded for CVE-2023-20938 (binder UAF). They've been rewritten to be vulnerability-agnostic:

- **Dynamic vuln-type guidance**: `_VULN_TYPE_GUIDANCE` dict provides exploit strategy descriptions for 9 vulnerability types (UAF, double-free, OOB read/write, race condition, integer overflow, type confusion, buffer overflow, uninitialized use)
- **Subsystem-aware fragments**: `_get_subsystem_notes()` detects the kernel subsystem from root cause analysis and returns binder, io_uring, netfilter, pipe, or filesystem-specific instructions only when relevant
- **Slab cache matching table expanded**: spray.c instructions now cover kmalloc-64 through kmalloc-4096 with specific spray objects for each
- **R/W primitive library**: rw_primitive.c instructions now list strategies by slab cache (pipe_buffer, msg_msg, epitem+file, sk_buff, tty_struct)

#### 4.2 Enhanced Root Cause Context
The `rca_ctx` block passed to the code generator now includes ALL fields from `RootCauseAnalysis`:
- `trigger_conditions` (up to 8)
- `affected_subsystem`, `affected_fields`
- `kernel_structs`, `kernel_functions`, `slab_caches`
- `exploitation_details` (from investigation synthesis)
- `key_insights` (from blog analysis)
- `source_snippets` (vulnerable source code, up to 3 files × 2000 chars)

Previously only 5 fields were passed; now 13+ fields flow through.

---

## 5. Proposed New Capabilities

### 5.1 Exploit Reliability Benchmarking
**Purpose**: Run an exploit N times and measure success rate, timing distribution, and failure modes.

**Implementation**:
- New verification mode `verify_exploit --benchmark --runs 100`
- Statistics: success rate, mean/p50/p95/p99 time-to-root, crash rate, KASAN hit rate
- Identifies timing-sensitive exploits that need race tuning
- Agent tool: `benchmark_exploit` with configurable iterations

**Effort**: Low (1 week). Mostly a loop around existing verification.

### 5.2 Kernel Config Analysis
**Purpose**: Check if kernel config enables/disables exploitation-relevant features.

**Implementation**:
- Parse `/proc/config.gz` or `config` from the target
- Check for: SLAB_FREELIST_HARDENED, SLAB_FREELIST_RANDOM, KASAN, KCFI, CFI, 
  STATIC_USERMODEHELPER, RANDOMIZE_BASE, INIT_ON_FREE_DEFAULT_ON, etc.
- Report which mitigations are active and how they affect exploitation
- Agent tool: `analyze_kernel_config`
- Feed into feasibility checks: "SLAB_FREELIST_HARDENED blocks cross-cache attack"

**Effort**: Low (3-5 days).

### 5.3 Crash Stability Analysis
**Purpose**: Determine if a crash/PoC triggers reliably or needs racing.

**Implementation**:
- Run reproducer M times, track crash rate
- Measure timing window for race conditions
- Detect intermittent vs deterministic triggers
- Agent uses this to decide: "trigger is reliable" vs "need tight race loop"
- New tool: `measure_crash_stability`

**Effort**: Low (1 week).

### 5.4 Automated Slab Cache Identification
**Purpose**: Empirically determine which slab cache a freed object lands in.

**Implementation**:
- Use `/proc/slabinfo` before and after triggering the vulnerability
- Monitor allocation deltas to identify the target cache
- Cross-reference with BTF/pahole struct sizes
- Agent tool: `identify_slab_cache`
- Feeds directly into spray module instruction selection

**Effort**: Medium (1-2 weeks).

### 5.5 Cross-Kernel Offset Auto-Discovery
**Purpose**: When exploit offsets from one kernel don't match the target, automatically discover the correct offsets.

**Implementation**:
- Binary search through vmlinux for known patterns (string XREFs, function prologues)
- Use `nm` / `objdump` on vmlinux to find symbol offsets
- Compare kernel configs to predict struct layout changes
- Agent tool: `discover_offsets` — runs if `resolve_kernel_offsets` produces mismatches

**Effort**: Medium (2 weeks).

### 5.6 Exploit Minimization
**Purpose**: Once an exploit works, simplify it for reliability and stealth.

**Implementation**:
- Strip debug printf(), reduce spray count, minimize sleep() calls
- Remove unnecessary code paths
- LLM-driven simplification pass
- Agent tool: `minimize_exploit`

**Effort**: Low (3-5 days).

### 5.7 Multi-Architecture Exploit Porting
**Purpose**: Automatically port an arm64 exploit to x86_64 or vice versa.

**Implementation**:
- Detect architecture-specific constants (pointer sizes, syscall numbers, struct offsets)
- LLM-driven porting with architecture context
- Agent tool: `port_exploit` with target architecture parameter
- Re-verify on the target architecture

**Effort**: Medium (2 weeks).

### 5.8 Template Library Expansion

#### New templates needed:
| Category | Template | Purpose |
|----------|----------|---------|
| `io_uring` | `io_uring_trigger.c/h` | io_uring setup, SQE submission, CQE polling |
| `netfilter` | `nft_trigger.c/h` | Netlink socket setup, nftables rule manipulation |
| `namespace` | `ns_setup.c/h` | User/mount/net namespace creation for unprivileged access |
| `userfaultfd` | `uffd_handler.c/h` | userfaultfd setup for page-fault-based heap control |
| `msg_msg` | `msg_msg_spray.c/h` | SysV message queue spray (Linux only) |
| `sk_buff` | `skb_spray.c/h` | sk_buff data spray via sendmmsg |
| `tty` | `tty_exploit.c/h` | tty_struct exploitation (fake ops table) |
| `pipe_primitive` | `pipe_rw.c/h` | pipe_buffer corruption → arbitrary page R/W |
| `key_payload` | `keyring_spray.c/h` | keyctl add_key for small-slab spray |
| `cross_cache` | `cross_cache.c/h` | Cross-cache page-level reclamation |
| `setxattr` | `setxattr_spray.c/h` | setxattr for controllable-size heap allocation |

**Effort**: Medium (2-3 weeks for all templates). Each needs compilation testing.

---

## 6. Planning & Exploit Generation Improvements — IMPLEMENTED + PROPOSED

### Implemented
- **Dynamic module instructions**: Subsystem-aware, vuln-type-aware guidance
- **Rich root cause context**: All 13+ RCA fields now flow to the generator
- **Subsystem detection**: Auto-detects binder, io_uring, netfilter, pipe, filesystem from root cause and provides specialized guidance fragments

### Proposed Improvements

#### 6.1 Multi-Shot Generation with Self-Critique
**Current**: Generate module → compile → if fail, regenerate with error feedback.
**Proposed**: Generate module → LLM self-review → fix issues → compile → verify.

Add a self-critique step between generation and compilation:
- LLM reviews its own generated code against the plan
- Checks: "Does this actually implement the trigger described in root cause?"
- Checks: "Does the spray target the correct slab cache?"
- Checks: "Does the R/W primitive match the technique in the plan?"
- Fix issues before compilation, reducing compile-fail-regenerate cycles

**Effort**: Low (3-5 days). Add a second LLM call with critique prompt.

#### 6.2 Step-by-Step Generation Mode
**Current**: Generate entire module in one LLM call.
**Proposed**: Break each module into micro-steps, generate and validate each.

Example for `trigger.c`:
1. Generate device open + ioctl setup code → validate compiles
2. Generate kernel state preparation → validate
3. Generate vulnerability trigger sequence → validate
4. Generate error handling + return → validate
5. Assemble into final module

This gives finer-grained error recovery — if step 3 fails, only regenerate step 3 with feedback from steps 1-2.

**Effort**: Medium (1-2 weeks). Significant prompt restructuring.

#### 6.3 Exploit Plan Validation
**Current**: LLM generates exploit plan, pipeline trusts it blindly.
**Proposed**: Validate plan against known constraints before code generation.

Validation checks:
- Slab cache size vs spray technique compatibility
- Platform constraints (no SysV IPC on Android, no userfaultfd after 5.11 without CAP_SYS_PTRACE)
- Architecture constraints (vmemmap base, physmap layout)
- SELinux domain restrictions on file/device access
- Known-broken techniques for specific kernel versions

**Effort**: Medium (1-2 weeks). Data-driven validation rules.

#### 6.4 Dynamic Prompt Weighting
**Current**: All context sections get equal weight in the prompt.
**Proposed**: Boost context sections relevant to the current iteration.

On first attempt: boost reference exploit and root cause analysis.
After compile failure: boost error logs and anti-pattern section.
After verification failure with GDB data: boost GDB traces and struct offsets.
After multiple failures: boost "minimal_seed" strategy, reduce context noise.

The strategy system partially handles this, but a more granular section-level weighting would help.

**Effort**: Medium (1-2 weeks).

#### 6.5 Exploit Plan Refinement from Verification Feedback
**Current**: After verification failure, the exploit plan stays the same; only module code is regenerated.
**Proposed**: LLM reviews verification output and may revise the exploit plan itself.

If verification shows "KASAN: use-after-free in kmalloc-256" but plan says the object is in kmalloc-128:
- Re-plan with correct slab cache
- Re-generate spray with corrected target
- This prevents repeated failures from a wrong plan

New agent tool: `refine_exploit_plan` — takes verification feedback + current plan → revised plan.

**Effort**: Medium (1-2 weeks).

#### 6.6 Parallel Module Generation
**Current**: Modules generated sequentially (trigger → spray → rw_primitive → post_exploit).
**Proposed**: Generate independent modules in parallel.

`trigger.c` and `post_exploit.c` have weak coupling — they could be generated concurrently. `spray.c` depends on trigger but not on post_exploit. Parallelization could cut generation time by 40-60%.

**Effort**: Low (3-5 days). Use `asyncio.gather` or thread pool.
