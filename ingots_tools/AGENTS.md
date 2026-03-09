# Ingots Tools

**Ingots Tools** is a research toolkit designed for Linux and Android kernel exploit analysis, adaptation, and synthesis. It is a monorepo managed by `uv` containing several interconnected Python packages and tools.

## Workspace Overview

The project is organized as a `uv` workspace with the following members:

### 1. `kexploit` (Tool: `kexploit`)
*   **Purpose:** Automatically adapt Proof-of-Concept (PoC) exploits between different Linux kernel versions using LLMs and binary analysis (Ghidra).
*   **Key Features:** Exploit annotation, offset adaptation, and experimental exploit synthesis.
*   **Documentation:** See `kexploit/GEMINI.md` for detailed instructions.
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

### 3. `kexploit_agent` (Tool: `kexploit_agent`)
*   **Purpose:** Secure Docker-based sandbox implementation for DeepAgents.
*   **Key Features:**
    *   **Docker Sandboxing:** `DockerSandbox` and `DockerSandboxProvider` for managing isolated environments with restricted capabilities (`cap_drop=['ALL']`) for secure execution.
    *   **Resource Mounting:** Support for mounting host folders (read-only or read-write) to provide context (e.g., kernel source code) or workspace for agents.
    *   **Agent Integration:** Integration with `deepagents` for creating autonomous exploit analysis agents, including automatic system prompt injection of sandbox mount information.
    *   **Automated Image Building:** CLI tool to build the standardized Docker image used for the sandbox environment.
*   **Usage:** `uv run kexploit_agent build_image`

### 4. `kexploit_utils`
*   **Purpose:** Shared utility library for the `ingots_tools` workspace.
*   **Key Features:**
    *   Centralized management of the `KEXPLOIT_DATA_DIR` and its subdirectories (kernels, Ghidra projects, VMs, etc.).
    *   Common file operations (downloading, conditional writing).
    *   Workspace-wide configuration management (`KexploitConfig`).

### 5. `libadb`
*   **Purpose:** A Python library providing ADB (Android Debug Bridge) utilities and tools specifically tailored for kernel exploitation research.
*   **Used by:** `android_env` and `scripts`.

### 6. `scripts`
*   **Purpose:** Miscellaneous utility scripts.
*   **Key Script:** `expand_binary.py` (expands dynamically linked binaries for exploit chaining).

## Setup & Dependencies

The project uses `uv` for dependency management.

1.  **Install uv:** [Installation Guide](https://docs.astral.sh/uv/getting-started/installation/)
2.  **Environment Variables:**
    *   Check `kexploit/README.md` for `kexploit` specific variables (e.g., `OPENAI_API_KEY`, `GHIDRA_INSTALL_DIR`, `KEXPLOIT_DATA_DIR`).
    *   Check `android_env/README.md` for Android-specific setup (SSH tunnels for Cuttlefish/ADB).

## Development

*   **Language:** Python 3.12+ (some modules require 3.13+).
*   **Dependency Management:** `uv sync` to install dependencies for all workspace members.
*   **Type Checking:** `uv run mypy src` (within specific package directories).

## Directory Structure

*   `android_env/`: Android analysis tools.
*   `kexploit/`: Kernel exploit adaptation and synthesis tool.
*   `kexploit_agent/`: Sandbox environment for agents.
*   `kexploit_utils/`: Shared utilities and data management.
*   `libadb/`: Shared ADB library.
*   `scripts/`: Standalone utility scripts.
*   `SYNTHESIS_TODO.md`: Roadmap for exploit synthesis features.