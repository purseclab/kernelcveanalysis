# Ingots Tools

**Ingots Tools** is a research toolkit designed for Linux and Android kernel exploit analysis, adaptation, and synthesis. It is a monorepo managed by `uv` containing several interconnected Python packages and tools.

## Workspace Overview

The project is organized as a `uv` workspace with the following members:

### 1. `exploit_adaptation` (Tool: `kexploit`)
*   **Purpose:** automatically adapt Proof-of-Concept (PoC) exploits between different Linux kernel versions using LLMs and binary analysis (Ghidra).
*   **Key Features:** Exploit annotation, offset adaptation, and experimental exploit synthesis.
*   **Documentation:** See `exploit_adaptation/GEMINI.md` for detailed instructions.
*   **Usage:** `uv run kexploit [COMMAND]`

### 2. `android_env` (Tool: `aenv`)
*   **Purpose:** Dynamically analyze exploit mitigations in a specific Android environment.
*   **Key Features:**
    *   Dump and analyze SECCOMP filters.
    *   Inspect and diff SELinux policies (reachable services, permissions).
    *   Helper scripts for expanding dynamically linked binaries.
*   **Usage:** `uv run aenv [COMMAND]`
    *   `uv run aenv seccomp <output.json>`: Save allowed syscalls.
    *   `uv run aenv selinux dump <setype>`: Dump SELinux type info.
    *   `uv run aenv selinux diff <type1> <type2>`: Compare SELinux types.

### 3. `libadb`
*   **Purpose:** A Python library providing ADB (Android Debug Bridge) utilities and tools specifically tailored for kernel exploitation research.
*   **Used by:** `android_env` and `scripts`.

### 4. `scripts`
*   **Purpose:** Miscellaneous utility scripts.
*   **Key Script:** `expand_binary.py` (expands dynamically linked binaries for exploit chaining).

### 5. `sandbox_env`
*   **Purpose:** Secure Docker-based sandbox implementation for DeepAgents.
*   **Key Features:** `DockerSandbox` and `DockerSandboxProvider`.

## Setup & Dependencies

The project uses `uv` for dependency management.

1.  **Install uv:** [Installation Guide](https://docs.astral.sh/uv/getting-started/installation/)
2.  **Environment Variables:**
    *   Check `exploit_adaptation/README.md` for `kexploit` specific variables (e.g., `OPENAI_API_KEY`, `GHIDRA_INSTALL_DIR`).
    *   Check `android_env/README.md` for Android-specific setup (SSH tunnels for Cuttlefish/ADB).

## Development

*   **Language:** Python 3.12+ (some modules require 3.13+).
*   **Dependency Management:** `uv sync` to install dependencies for all workspace members.
*   **Type Checking:** `uv run mypy src` (within specific package directories).

## Directory Structure

*   `android_env/`: Android analysis tools.
*   `exploit_adaptation/`: Kernel exploit adaptation (kexploit).
*   `libadb/`: Shared ADB library.
*   `scripts/`: Standalone scripts.
*   `SYNTHESIS_TODO.md`: Roadmap for exploit synthesis features.
