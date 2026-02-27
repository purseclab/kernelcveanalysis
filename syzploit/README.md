# syzploit

Agentic kernel vulnerability analysis and exploit synthesis toolkit.

syzploit takes a CVE identifier, syzbot bug URL, crash log, or security blog
post and automatically analyzes the vulnerability, generates a reproducer for a
target kernel version, and synthesizes a privilege-escalation exploit — all
driven by LLM reasoning.

## Quick start

```bash
# Build the Docker image (includes NDK, syzkaller, Ghidra, etc.)
docker build -t syzploit-env .

# Start a container with KVM, host network, and SSH access
./set-env

# Attach to the running container
docker attach syzploit
```

Inside the container, syzploit is installed as an editable package and ready to
use:

```bash
# Copy the example .env and add your API key
cp .env.example .env
# Edit .env — uncomment and set at least one API key:
#   OPENROUTER_API_KEY=sk-or-v1-...
#   (or OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY)

# Run the full pipeline on a CVE
uv run syzploit pipeline CVE-2023-20938 \
  --blog-url "https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/" \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host cuttlefish2 \
  --no-persistent --setup-tunnels --instance 5 \
  --kernel-image /home/jack/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \
  --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \
  --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \
  --platform android --planner auto \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --arch arm64 --debug
```

## Architecture

```
syzploit/src/syzploit/
├── core/               ← Shared foundations (models, config, LLM client)
├── orchestrator/       ← Agent + deterministic pipeline + tool registry
├── analysis/           ← Crash parsing, CVE/blog analysis, root cause, feasibility
├── reproducer/         ← LLM code generation, cross-compilation, SSH verification
├── exploit/            ← Exploit planning, code generation, stitching
├── infra/              ← ADB, SSH, VM control (QEMU / Cuttlefish), GDB
├── data/               ← Bug DB (SQLite), syzbot scraper, file storage
└── cli/                ← Typer CLI commands
```

### How it works

```
           ┌────────────────────────────────┐
           │        CLI  (cli/app.py)       │
           │  agent | pipeline | analyze-*  │
           └──────────┬─────────────────────┘
                      │
           ┌──────────▼─────────────────────┐
           │       ORCHESTRATOR             │
           │                                │
           │  Agent (LLM-driven loop)       │  ← agentic mode
           │    or                          │
           │  Pipeline (deterministic)      │  ← pipeline mode
           │                                │
           │  Tools: analyze, reproduce,    │
           │         exploit, feasibility,  │
           │         query_bug_db, pull     │
           └──┬────┬────┬────┬─────────────┘
              │    │    │    │
    ┌─────────▼┐ ┌▼────┴┐ ┌▼──────────┐ ┌──────────┐
    │ analysis │ │repro- │ │  exploit  │ │  infra   │
    │          │ │ducer  │ │           │ │          │
    │ crash    │ │       │ │ planner   │ │ SSH/ADB  │
    │ CVE/NVD  │ │ gen   │ │ generator │ │ QEMU/CF  │
    │ blog     │ │ compile│ │ stitcher │ │ GDB      │
    │ root     │ │ verify│ │ primitives│ │          │
    │ cause    │ │       │ │           │ │          │
    │ feasib.  │ │       │ │           │ │          │
    └──────────┘ └───────┘ └───────────┘ └──────────┘
```

**Two execution modes:**

| Mode | Command | How it works |
|------|---------|-------------|
| **Agentic** | `syzploit agent` | LLM decides which tool to call next based on current state. Adapts dynamically — retries, skips, or revisits stages as needed. |
| **Deterministic** | `syzploit pipeline` | Fixed 3-stage sequence: analyze → reproduce → exploit. Each stage can be skipped with flags. |

The **Agent** works by:
1. Classifying the input (CVE? blog? crash log? syzbot URL?) — uses regex fast-path for common patterns, LLM fallback for ambiguous inputs
2. Entering a reasoning loop (max 20 iterations)
3. At each step, asking the LLM: *"Given the current state, which tool should I call next?"* — only shows tools relevant to the current pipeline stage
4. Invoking the chosen tool, which mutates the shared `TaskContext`
5. Stopping when the goal is achieved or no further progress is possible

The agent includes several cost-reduction features:
- **Per-task model routing**: uses a cheaper model for routing decisions (e.g. `gpt-4o-mini`) while keeping a strong model for analysis/codegen
- **Context-aware tool filtering**: only presents relevant tools (5-10) instead of all 21, reducing prompt tokens
- **Failed-tool tracking**: tools that fail 2+ times are automatically blocked
- **Compressed prompts**: terse history format + truncated verification feedback

### Core data flow

Every tool reads from and writes to a **TaskContext** — a Pydantic model that
accumulates artefacts as the pipeline progresses:

```
TaskContext
├── input_type       "cve" | "syzbot" | "crash_log" | "blog_post" | "poc"
├── input_value      "CVE-2023-20938"
├── target_kernel    "5.10.160"
├── target_arch      arm64
├── target_platform  android
├── crash_report     CrashReport (parsed stack frames, vuln type, slab info)
├── root_cause       RootCauseAnalysis (LLM summary, function, subsystem)
├── feasibility      FeasibilityReport (5 checks, continuous 0–1 score, verdict)
├── reproducer       ReproducerResult (C source, binary path, success flag)
├── exploit_plan     ExploitPlan (technique, ordered steps, primitives)
└── exploit_result   ExploitResult (C source, binary path, uid verification)
```

## Commands

### `syzploit agent` — Agentic mode (recommended)

Let the LLM decide what to do. Best for end-to-end analysis from a single
input:

```bash
# From a CVE with a blog write-up
uv run syzploit agent CVE-2024-36971 \
  --blog-url "https://example.com/cve-2024-36971-analysis" \
  --kernel 6.1.75 --arch arm64 --platform android \
  --ssh-host cuttlefish2 --instance 3 \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --output-dir ./analysis_CVE-2024-36971

# From a syzbot URL
uv run syzploit agent "https://syzkaller.appspot.com/bug?extid=abc123" \
  --kernel 5.15.100 --output-dir ./syzbot_analysis

# From a raw crash log file
uv run syzploit agent /path/to/kasan_report.txt --kernel 6.1.75
```

### `syzploit pipeline` — Deterministic mode

Fixed 3-stage sequence. Use `--skip-*` flags to run only specific stages:

```bash
# Full pipeline: analyze → reproduce → exploit
uv run syzploit pipeline CVE-2023-20938 \
  --blog-url "https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/" \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host cuttlefish2 --no-persistent --setup-tunnels --instance 5 \
  --kernel-image /home/jack/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \
  --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \
  --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \
  --platform android --planner auto \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --arch arm64 --debug

# Analysis only (no reproducer/exploit generation)
uv run syzploit pipeline CVE-2024-36971 \
  --skip-reproducer --skip-exploit \
  --output-dir ./analysis_only

# Skip analysis, just generate exploit from existing state
uv run syzploit pipeline CVE-2023-20938 \
  --skip-analysis --skip-reproducer \
  --output-dir ./existing_analysis
```

### `syzploit analyze-cve`

Standalone CVE analysis — fetches from NVD/MITRE, searches GitHub for PoCs,
and uses LLM to classify:

```bash
uv run syzploit analyze-cve CVE-2024-36971 \
  --blog-url "https://example.com/writeup" \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --output analysis.json
```

### `syzploit analyze-blog`

Scrape and analyze a security blog post:

```bash
uv run syzploit analyze-blog \
  "https://googleprojectzero.blogspot.com/2024/01/exploiting-null-dereferences-in-kernel.html" \
  --output blog_analysis.json
```

### `syzploit analyze-crash`

Parse a kernel crash log (KASAN, UBSAN, generic oops) and produce a root-cause
analysis:

```bash
uv run syzploit analyze-crash /path/to/crash.log --output crash_analysis.json
```

### `syzploit check-feasibility`

Check whether a vulnerability is present on a target kernel version:

```bash
uv run syzploit check-feasibility /path/to/crash.log \
  --kernel 5.10.160 \
  --vmlinux /path/to/vmlinux \
  --ssh-host cuttlefish2 --ssh-port 22
```

### `syzploit pull` / `syzploit query`

Manage the local syzbot bug database:

```bash
# Pull latest bugs from syzbot
uv run syzploit pull upstream
uv run syzploit pull android-6.1

# Search local database
uv run syzploit query upstream --search "use-after-free binder"
```

## Migration from syzploit_old

The old `pipeline-cve` command maps directly to the new `pipeline` command.
Here is the equivalence:

| Old (`syzploit_old`) | New (`syzploit`) |
|---------------------|------------------|
| `pipeline-cve CVE-XXX` | `pipeline CVE-XXX` |
| `pipeline-cuttlefish BUG_ID` | `pipeline BUG_ID --ssh-host ...` |
| `pipeline BUG_ID` | `pipeline BUG_ID` |
| `analyze CVE-XXX` | `analyze-cve CVE-XXX` |
| `analyze-cve CVE-XXX` | `analyze-cve CVE-XXX` |
| `analyze-blog URL` | `analyze-blog URL` |
| `synthesize BUG_ID` | `pipeline BUG_ID --skip-analysis` |
| `test-cuttlefish BUG_ID` | `pipeline BUG_ID --skip-exploit` |
| `check-feasibility BUG_ID` | `check-feasibility crash.log --kernel ...` |

### Key differences

1. **Unified `pipeline` command** — The old codebase had `pipeline`,
   `pipeline-cve`, and `pipeline-cuttlefish` as separate commands with
   overlapping arguments. Now there is a single `pipeline` command that
   auto-detects input type (CVE, syzbot URL, crash log, blog, PoC).

2. **New `agent` command** — LLM-driven mode that didn't exist before. The
   agent decides which tools to invoke based on current progress.

3. **Configuration via `.env`** — Infrastructure settings (SSH host, instance,
   model) can be set in a `.env` file instead of passing them on every
   invocation. CLI flags override `.env` values.

4. **`--blog-url` accepts CVE IDs** — In `pipeline`, the first argument can be
   a CVE ID, and blog URLs are provided via `--blog-url` flags (repeatable).

### Translating the example command

**Old:**
```bash
uv run syzploit pipeline-cve CVE-2023-20938 \
  --blog-url "https://androidoffsec.withgoogle.com/posts/..." \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host cuttlefish2 --no-persistent --setup-tunnels --instance 5 \
  --kernel-image /home/jack/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \
  --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \
  --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \
  --platform android --planner auto \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --arch arm64 --debug
```

**New (identical flags, just `pipeline` instead of `pipeline-cve`):**
```bash
uv run syzploit pipeline CVE-2023-20938 \
  --blog-url "https://androidoffsec.withgoogle.com/posts/..." \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host cuttlefish2 --no-persistent --setup-tunnels --instance 5 \
  --kernel-image /home/jack/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \
  --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \
  --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \
  --platform android --planner auto \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --arch arm64 --debug
```

Or with the **agentic mode** (LLM decides what to do):
```bash
uv run syzploit agent CVE-2023-20938 \
  --blog-url "https://androidoffsec.withgoogle.com/posts/..." \
  --output-dir ./analysis_CVE-2023-20938 \
  --ssh-host cuttlefish2 --instance 5 --no-persistent --setup-tunnels \
  --kernel-image /home/jack/challenge-4/challenge-4.1/package/kernel/Image \
  --start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./gdb_run.sh 5" \
  --stop-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./stop.sh 5" \
  --exploit-start-cmd "cd /home/jack/challenge-4/challenge-4.1 && ./run.sh 5" \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --arch arm64 --debug
```

## Configuration

syzploit reads configuration from a **`.env` file** in the project root. On
startup the loader checks (in order):

1. `<project-root>/.env` — the main syzploit directory (recommended)
2. `src/syzploit/.env` — inside the package
3. `$CWD/.env` — your current working directory
4. `~/.env` — home directory fallback

All matching files are loaded, but **earlier values win** — so the project-root
`.env` always takes priority.

### Setting up `.env`

```bash
# Start from the included template
cp .env.example .env

# Then edit .env with your values:
```

```bash
# .env — syzploit configuration
# Set at least one API key. syzploit checks them in order and uses
# the first one it finds.
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxx
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=...

# Default LLM model (any LiteLLM identifier)
SYZPLOIT_LLM_MODEL=openrouter/anthropic/claude-sonnet-4.6

# SSH target for Cuttlefish / QEMU
SYZPLOIT_SSH_HOST=cuttlefish2
SYZPLOIT_SSH_PORT=22

# Where syzbot bug data is stored
SYZBOT_REPRO_DATA_DIR=/workspace/syzploit/syzploit_data/

# Debug output
SYZPLOIT_DEBUG=true
```

CLI flags always override `.env` values — for example `--model gpt-4o` will
use GPT-4o even if `SYZPLOIT_LLM_MODEL` is set to something else in `.env`.

### Per-task model routing

Different LLM tasks benefit from different models. For example, code generation
may work best with a coding-specialized model, while analysis tasks benefit
from strong reasoning. syzploit lets you assign a different model to each task
type:

| Task | CLI flag | Env var | Used for |
|------|---------|---------|----------|
| **Default** | `--model` | `SYZPLOIT_LLM_MODEL` | Fallback for all tasks |
| **Decision** | `--decision-model` | `SYZPLOIT_LLM_DECISION_MODEL` | Agent routing, input classification (lightweight JSON) |
| **Analysis** | `--analysis-model` | `SYZPLOIT_LLM_ANALYSIS_MODEL` | Crash analysis, CVE analysis, blog parsing, root cause |
| **Code generation** | `--codegen-model` | `SYZPLOIT_LLM_CODEGEN_MODEL` | Exploit synthesis, reproducer generation, compilation fixes |
| **Planning** | `--planning-model` | `SYZPLOIT_LLM_PLANNING_MODEL` | Exploit strategy planning |

Every per-task model defaults to empty, which means it falls back to `--model`
(or `SYZPLOIT_LLM_MODEL`). You only need to set the ones you want to override.

**Example `.env` with mixed models:**
```bash
SYZPLOIT_LLM_MODEL=gpt-4o                              # default fallback
SYZPLOIT_LLM_DECISION_MODEL=gpt-4o-mini                # cheap routing ($0.15/M input)
SYZPLOIT_LLM_ANALYSIS_MODEL=anthropic/claude-sonnet-4-20250514    # strong reasoning
SYZPLOIT_LLM_CODEGEN_MODEL=deepseek/deepseek-coder     # strong code gen
SYZPLOIT_LLM_PLANNING_MODEL=gpt-4o                     # balanced
```

**Or via CLI flags (override `.env` per-invocation):**
```bash
uv run syzploit agent CVE-2023-20938 \
  --model openrouter/anthropic/claude-sonnet-4.6 \
  --decision-model gpt-4o-mini \
  --codegen-model deepseek/deepseek-coder \
  --analysis-model openrouter/anthropic/claude-sonnet-4.6 \
  --ssh-host cuttlefish2 --instance 5 --debug
```

The `ModelRouter` resolves each task at runtime. You can inspect the resolved
models at startup by enabling `--debug` — the router summary is printed to
stderr.

### Configuration reference

| Setting | CLI flag | Env var | Default |
|---------|---------|---------|---------|
| LLM model | `--model` | `SYZPLOIT_LLM_MODEL` | `gpt-4o` |
| Decision model | `--decision-model` | `SYZPLOIT_LLM_DECISION_MODEL` | *(falls back to model)* |
| Analysis model | `--analysis-model` | `SYZPLOIT_LLM_ANALYSIS_MODEL` | *(falls back to model)* |
| Codegen model | `--codegen-model` | `SYZPLOIT_LLM_CODEGEN_MODEL` | *(falls back to model)* |
| Planning model | `--planning-model` | `SYZPLOIT_LLM_PLANNING_MODEL` | *(falls back to model)* |
| API key | — | `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | — |
| Debug | `--debug` | `SYZPLOIT_DEBUG` | `false` |
| SSH host | `--ssh-host` | `SYZPLOIT_SSH_HOST` | `localhost` |
| SSH port | `--ssh-port` | `SYZPLOIT_SSH_PORT` | `22` |
| Data dir | — | `SYZBOT_REPRO_DATA_DIR` | `./data` |

## Feasibility checking

The feasibility checker (`check-feasibility` command / `analysis.feasibility`
module) answers the question: **"Does this vulnerability exist on my target
kernel?"**

This is critical when you find a bug on one kernel version (e.g. upstream
6.8-rc1) but want to exploit it on a different version (e.g. Android's
5.10.160).

### How it works

The checker runs up to **5 independent checks**, each producing a weighted
signal that shifts a continuous score (0.0–1.0).  Checks are skipped
automatically if the required inputs are not provided.

```
┌──────────────────────────────────────────────────────────┐
│              assess_feasibility(crash)                    │
│                                                          │
│  Check 1: Symbol presence  (fuzzy matching)             │
│    Extracts function names from the crash stack trace    │
│    and verifies they exist on the target kernel.         │
│    Strips .isra / .constprop / +offset for matching.     │
│    Tries: SSH→kallsyms, local kallsyms, System.map, nm  │
│      → present  (+0.15)                                  │
│      → absent   (−0.30)                                  │
│      → partial  (−0.10)                                  │
│                                                          │
│  Check 2: Fix backport detection  (3 strategies)        │
│    1. git merge-base --is-ancestor                       │
│    2. git log --grep (commit hash in message)            │
│    3. "cherry picked from commit <hash>" tag search      │
│    4. Changelog file scan (fallback)                     │
│      → patched   (−0.40, strong negative)                │
│      → unpatched (+0.10)                                 │
│                                                          │
│  Check 3: Source-level diff  (static analysis — NEW)    │
│    git diff between original and target kernel tags      │
│    for the vulnerable files and functions.                │
│    Uses --function-context to isolate per-function diffs. │
│      → identical      (+0.25)                            │
│      → minor_changes  (+0.10)                            │
│      → major_changes  (−0.25)                            │
│      → missing        (−0.35)                            │
│                                                          │
│  Check 4: Live crash test  (dmesg before/after)         │
│    Compile reproducer, push to target, capture dmesg     │
│    diff, match crash signature against expected funcs.    │
│      → triggered       (+0.40, strongest positive)       │
│      → no_crash        (−0.30)                           │
│      → different_crash (−0.15)                           │
│                                                          │
│  Check 5: GDB path verification                         │
│    Breakpoints on crash-stack functions, run repro under  │
│    GDB, parse hit/miss JSON from tracing script.          │
│      → path_confirmed (+0.35)                            │
│      → partial_path   (+0.10)                            │
│      → path_diverged  (−0.35)                            │
│                                                          │
│  ─── Continuous Weighted Scoring ────                    │
│    Start at 0.5 (neutral), shift by each check above.    │
│    Clamp to [0.0, 1.0].                                  │
│      ≥ 0.55 → "likely_feasible"                          │
│      ≤ 0.35 → "likely_patched"                           │
│      else   → "inconclusive"                             │
│    Confidence = average of per-check confidences (0–1).  │
└──────────────────────────────────────────────────────────┘
```

### Verdict outcomes

| Verdict | Score range | Meaning |
|---------|-----------|---------|
| **likely_feasible** | ≥ 0.55 | Vulnerability likely present on target — proceed with exploitation |
| **inconclusive** | 0.35 – 0.55 | Mixed signals — manual review recommended |
| **likely_patched** | ≤ 0.35 | Vulnerability likely patched or code paths changed |

### Source-level diff (static analysis)

The source-diff check is the key **static analysis** improvement for
cross-version feasibility.  It works without needing a running kernel:

1. Takes the `--original-tag` (kernel the bug was found on) and
   `--target-tag` (kernel you want to exploit).
2. Runs `git diff <original>..<target> -- <file>` for each vulnerable file.
3. Uses `git diff --function-context` to check if the *specific* vulnerable
   function body has changed.
4. Computes a similarity ratio (0.0–1.0) weighted 70% function-level,
   30% file-level.

**Why this matters:** Two kernel versions may have the same symbols in
`/proc/kallsyms`, yet the function body could have been subtly changed
(e.g. bounds checking added, locking order modified) in a way that
incidentally fixes the bug without a dedicated fix commit. The source diff
catches these cases.

### Example usage

```bash
# Minimal: symbol check via SSH
uv run syzploit check-feasibility crash.log \
  --kernel 5.10.160 --ssh-host cuttlefish2

# Full static analysis with source diff
uv run syzploit check-feasibility crash.log \
  --kernel 5.10.160 \
  --kernel-tree /path/to/linux \
  --original-tag v6.8-rc1 \
  --target-tag android13-5.10-lts \
  --fix-commits abc123def456,789012abc345 \
  --vmlinux /path/to/vmlinux

# Programmatic usage
from syzploit.analysis.feasibility import assess_feasibility, check_source_diff
from syzploit.analysis.crash_parser import parse_crash_log

crash = parse_crash_log(open("crash.log").read())
report = assess_feasibility(
    crash,
    target_kernel="5.10.160",
    kernel_tree_path="/path/to/linux",
    original_tag="v6.8-rc1",
    target_tag="android13-5.10-lts",
    fix_commits=["abc123def456"],
    ssh_host="cuttlefish2",
    vmlinux_path="/path/to/vmlinux",
)
print(report.summary())
# === Feasibility Report: (unknown) ===
#   Verdict         : likely_feasible
#   Confidence      : 68%
#   Symbol check    : present (12/14 found)
#   Fix backport    : unpatched
#   Source diff      : identical (similarity=100%)
```

## Docker

The project includes a Dockerfile that sets up the complete development
environment:

- **Ubuntu 22.04** with build tools (gcc, clang, make, cmake)
- **Android NDK 25.2** for ARM64 cross-compilation
- **Syzkaller** for reproducer compilation
- **Ghidra 11.4** for binary analysis
- **GDB multiarch** for kernel debugging
- **vmlinux-to-elf** for kernel image extraction

### Building and running

```bash
# Build the image
docker build -t syzploit-env .

# Start the container
./set-env

# Re-attach later
docker attach syzploit

# Or run a one-off command
docker exec syzploit uv run syzploit pipeline CVE-2024-36971 --debug
```

The `set-env` script creates a container with:
- `--network=host` — for SSH access to Cuttlefish VMs
- `--device=/dev/kvm` — for QEMU acceleration
- Bind mounts for the project directory, ingots_tools, and SSH keys

### kexploit integration

If `ingots_tools` is mounted at `/workspace/ingots_tools`, the entrypoint
automatically installs kexploit packages on first launch.

## Project structure

```
syzploit/
├── Dockerfile                  Docker build definition
├── docker-entrypoint.sh        Container entrypoint (kexploit auto-install)
├── set-env                     Container launch script
├── pyproject.toml              Python package definition
├── .dockerignore               Docker build exclusions
└── src/syzploit/
    ├── __init__.py             Package root (version 0.2.0)
    ├── __main__.py             python -m syzploit support
    ├── main.py                 Entry-point → cli.app.main
    ├── core/
    │   ├── models.py           Pydantic models (CrashReport, RootCauseAnalysis, ExploitPlan, …)
    │   ├── config.py           Config class, .env loading, API key resolution
    │   ├── llm.py              LLMClient, ModelRouter (per-task model routing), refusal detection
    │   └── log.py              Rich console, debug helpers
    ├── orchestrator/
    │   ├── agent.py            LLM-driven agentic loop (classify → decide → invoke)
    │   ├── pipeline.py         Deterministic 3-stage pipeline
    │   ├── context.py          TaskContext — shared state accumulator
    │   ├── tools.py            ToolRegistry with decorator registration
    │   └── builtin_tools.py    6 registered tools (analyze, reproduce, exploit, …)
    ├── analysis/
    │   ├── crash_parser.py     KASAN/UBSAN/generic crash log parsing
    │   ├── cve_analyzer.py     NVD + MITRE + GitHub PoC search
    │   ├── blog_analyzer.py    Blog scraping + LLM analysis
    │   ├── root_cause.py       LLM root-cause analysis from CrashReport
    │   ├── exploitability.py   Heuristic + score-based classification
    │   ├── feasibility.py      Symbol check, fix backport, source diff, live test, GDB path
    │   └── dispatcher.py       Input routing (CVE/blog/crash → analyzer)
    ├── reproducer/
    │   ├── generator.py        LLM-driven C reproducer generation
    │   ├── compiler.py         Cross-compilation (arm64/x86_64) + LLM auto-fix
    │   ├── verifier.py         SSH-based execution + dmesg crash detection
    │   └── pipeline.py         End-to-end reproducer pipeline
    ├── exploit/
    │   ├── planner.py          Exploit strategy planning (5 technique patterns)
    │   ├── generator.py        LLM exploit code generation
    │   ├── stitcher.py         Code assembly with template registry
    │   ├── primitives.py       PrimitiveRegistry (heap spray, pipe r/w, …)
    │   └── pipeline.py         Full exploit pipeline (plan → generate → stitch → compile)
    ├── infra/
    │   ├── adb.py              ADB port calculation for Cuttlefish
    │   ├── ssh.py              SSHSession (run, upload, download, dmesg)
    │   ├── vm.py               VMController (QEMU + Cuttlefish backends)
    │   └── gdb.py              GDBController (attach, breakpoints, scripts)
    ├── data/
    │   ├── storage.py          Data dir helpers, file downloads
    │   ├── bug_db.py           SQLite bug database (CRUD)
    │   └── scraper.py          Syzbot bug scraping + filtering
    └── cli/
        └── app.py              Typer CLI (8 commands)
```

## Development

```bash
# Install with dev dependencies
uv sync --extra dev

# Type checking
uv run mypy src/syzploit

# Linting
uv run ruff check src/

# Format
uv run ruff format src/
```

## License

Research project — internal use.
