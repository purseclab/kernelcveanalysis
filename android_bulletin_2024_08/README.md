# Android Security Bulletin August 2024 - Exploit Development

Target: Cuttlefish arm64, kernel 5.10.107-maybe-dirty, Android 13, security patch 2022-08-05

## CVE Summary

### Kernel CVEs
| CVE | Subsystem | Type | Trigger | Status |
|-----|-----------|------|---------|--------|
| CVE-2024-36971 | net/dst_entry | UAF | ICMP Redirect via AF_PACKET on host TAP | READY |
| CVE-2023-4622 | net/af_unix | UAF (race) | unix_stream_sendpage + gc race | PATCHED |
| CVE-2024-26926 | binder | Offset alignment | N/A | NOT AFFECTED (5.10.157+) |

### Framework CVEs (ADB shell-based)
| CVE | Component | Type | Status |
|-----|-----------|------|--------|
| CVE-2024-34740 | BinaryXmlSerializer | Integer overflow + XML injection | READY (needs APK build) |
| CVE-2024-34731 | TranscodingResourcePolicy | Race condition (native C++) | PoC READY |
| CVE-2023-20971 | PermissionManagerService | Logic bug (missing return) | PoC READY |
| CVE-2024-34737 | PiP/ActivityClientController | Resource exhaustion | PoC READY |
| CVE-2024-34743 | SurfaceFlinger | Tapjacking | NOT AFFECTED (Android 14 only) |

## Usage

```bash
# Deploy and run all exploits
./deploy_and_test.sh --instance 19 --cve all

# Run just the kernel ICMP Redirect exploit
./deploy_and_test.sh --instance 19 --cve CVE-2024-36971

# Run all framework PoCs
./deploy_and_test.sh --instance 19 --cve framework

# Run individual framework PoC
./deploy_and_test.sh --instance 19 --cve CVE-2024-34731
./deploy_and_test.sh --instance 19 --cve CVE-2023-20971
./deploy_and_test.sh --instance 19 --cve CVE-2024-34737
```

## CVE-2024-36971: dst_entry UAF via ICMP Redirect

**Architecture**: Host injects ICMP Redirect packets via AF_PACKET on the Cuttlefish TAP interface.

1. **VM setup** (automated via ADB + su 0):
   - Enable `accept_redirects=1` on buried_eth0
   - Add default route via virtual gateway (192.168.97.1)
   - Static ARP entry with dummy MAC (SYNs vanish at L2)

2. **Device binary** creates 64 TCP sockets to 10.0.0.1:9999 (SYN → timeout)

3. **Host script** (`remote_trigger.py`) injects ICMP Redirect (Type 5, Code 1) via AF_PACKET:
   - Source IP: 192.168.97.1 (VM's default gateway)
   - Redirects to: 192.168.97.254 (non-existent)
   - Bypasses host routing entirely — frame goes directly to VM

4. **Kernel processes redirect** → FIB exception → generation counter changes

5. **TCP SYN retransmit** → `dst_negative_advice` → `!rt_is_valid` → `ip_rt_put` → UAF

6. **setxattr spray** attempts cross-cache reclaim of freed ip_dst_cache

Note: `su 0` is used only for network setup (enabling accept_redirects, adding route), not for privilege escalation. The exploit itself is the kernel UAF.

## CVE-2023-4622: AF_UNIX gc race — PATCHED

Confirmed PATCHED via QMP physical memory read of `unix_stream_sendpage`:
- `_raw_spin_lock` at offset +0x3b0 (commit 790c2f9d15b)
- Function size 2020 bytes (patched indicator)
- 80,000+ race attempts: 0 corruptions

## Framework CVE PoCs

All framework PoCs run via ADB shell without `su`. They:
1. Check device patch level to assess vulnerability
2. Attempt to trigger the vulnerable code path
3. Monitor for crash/state-change indicators
4. Report results with clear next-step guidance

### CVE-2024-34731: TranscodingResourcePolicy Race
- Floods concurrent media operations to trigger unsynchronized access
- Monitors for media service crashes via logcat + tombstones
- Full exploitation requires controlled heap spray in mediaserver

### CVE-2023-20971: PermissionManagerService Bypass
- Tests `removePermission` code path via `service call`
- Checks for the telltale "non-dynamic permission" log message
- Full exploitation requires APK with `<permission-tree>` declaration

### CVE-2024-34737: PiP Aspect Ratio Flooding
- Launches PiP-capable activities, floods resize events
- Checks for CountQuotaTracker (patch indicator)
- Full exploitation requires APK with PiP support + tight loop

## Verified Kernel Offsets (5.10.107-maybe-dirty arm64)

Verified via GDB memory dump of init_task (KASLR disabled):
```
init_task       = 0xffffffc012cbc4c0  (comm="swapper" at +0x790)
init_cred       = 0xffffffc012c91418
task_struct.tasks     = 0x4c8
task_struct.pid       = 0x5c8
task_struct.real_cred = 0x778
task_struct.cred      = 0x780
task_struct.comm      = 0x790
cred.uid              = 0x04
```

## QMP PA Mapping (instance 19)

```
Kernel Image at PA 0x40200000 (ARM\x64 magic confirmed)
_text VA = 0xffffffc010000000
Formula: PA = VA - 0xffffffc010000000 + 0x40200000
```

## Target Constraints
- 4 CPUs (`-smp 4,cores=4`) on instance 19
- CONFIG_SYSVIPC not set (no msg_msg spray)
- SELinux enforcing (u:r:shell:s0)
- CFI_CLANG enabled
- INIT_ON_ALLOC_DEFAULT_ON (memory zeroed)
- No user namespaces
- RTM_NEWLINK blocked by SELinux from shell domain
- /proc/kallsyms kptr_restrict active (all addrs = 0)
- KASLR disabled (nokaslr cmdline)
- setxattr spray works from shell domain
- ip_dst_cache is a dedicated SLUB slab (256 bytes, not merged with kmalloc-256)
- /system/xbin/su setuid root — used for network setup only, NOT for escalation
- accept_redirects=0 by default — must be enabled for ICMP Redirect trigger
