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

### 7. `android_app_mcp` (Tool: `android_app_mcp`)
*   **Purpose:** MCP server for debugging and instrumenting Android apps inside an emulator over ADB.
*   **Key Features:**
    *   Uploads and launches the bundled `frida-server` on startup.
    *   Exposes emulator shell and file operations over MCP.
    *   Supports Frida app enumeration, attach/spawn, script management, and RPC calls.
*   **Usage:** `uv run android_app_mcp serve --adb-host <host> --adb-port <port>`

### 8. `primitives`
*   **Purpose:** Exploit primitive library for Linux kernel research.
*   **Key Features:**
    *   Stores primitives as structured entries under `src/primitive_data/`.
    *   Each primitive includes `metadata.json`, `PRIMITIVE.md`, and `primitive.c`.
    *   Provides reusable primitive data consumed by other tooling in the workspace.

### 9. `object_db`
*   **Purpose:** Shared kernel object database models and extraction utilities.
*   **Key Features:**
    *   Maintains shared object and BTF type models.
    *   Includes CodeQL query integration used by `kexploit`.
    *   Provides database-layer utilities for kernel object analysis workflows.

### 10. `cuttle_server`
*   **Purpose:** FastAPI control plane for launching, tracking, leasing, and stopping Cuttlefish instances.
*   **Key Features:**
    *   SQLite-backed instance state tracking with per-instance runtime directories.
    *   Config-directory driven startup via `uv run cuttle_server <config-dir>`.
    *   TOML-based template definitions for Cuttlefish installations, kernels, initrds, SELinux mode, and APK lists.
    *   Shared bearer-token auth plus `X-User-Id` ownership checks, with configurable admin user support.
    *   Lease expiration, explicit stop handling, stop-by-name support, and runtime directory cleanup after shutdown.
    *   Per-instance `adb_port` reporting so clients can connect over the same host as the HTTP control plane.
    *   Server-side template APK auto-loading during startup via `libadb`, with a per-request opt-out.
*   **Documentation:** See `cuttle_server/cuttle_server/README.md` for API and config details.

### 11. `cuttle_cli`
*   **Purpose:** Typer-based CLI client for `cuttle_server`.
*   **Key Features:**
    *   Reads default connection config from `~/.config/cuttle_cli/config.toml`.
    *   Supports `start`, `list`, `stop`, `templates list`, and `templates show`.
    *   Manages a local pidfile-backed daemon for syncing `adb connect` / `adb disconnect` with the current user's visible instances.
    *   `start` can disable server-side app auto-loading with `--no-load-apps`.
    *   Sends shared auth and user headers for all server requests.

### 12. `cuttle_types`
*   **Purpose:** Shared request/response models used by `cuttle_server` and `cuttle_cli`.
*   **Key Features:**
    *   Pydantic models for instance lifecycle requests and responses.
    *   Shared instance connection fields such as `adb_port`.
    *   Shared startup overrides such as `load_apps`.
    *   Shared template summary/detail views.
    *   Common `InstanceState` enum used across server and client packages.

## Setup & Dependencies

The project uses `uv` for dependency management.

1.  **Install uv:** [Installation Guide](https://docs.astral.sh/uv/getting-started/installation/)
2.  **Environment Variables:**
    *   Check `kexploit/README.md` for `kexploit` specific variables (e.g., `OPENAI_API_KEY`, `GHIDRA_INSTALL_DIR`, `KEXPLOIT_DATA_DIR`).
    *   Check `android_env/README.md` for Android-specific setup (SSH tunnels for Cuttlefish/ADB).
    *   Check `cuttle_server/cuttle_server/README.md` for the Cuttlefish control-plane config directory layout and template format.

## Development

*   **Language:** Python 3.12+ (some modules require 3.13+).
*   **Dependency Management:** `uv sync` to install dependencies for all workspace members.
*   **Type Checking:** Use `uv run mypy <package_name>` from the workspace root while developing to check package-local type errors (for example, `uv run mypy kexploit`).

## Style Guide

*   Prefer typed data models over ad hoc structures.
    *   Use `@dataclass` types for internal structured data and Pydantic models for validated config, persistence, and API request/response objects.
    *   Avoid passing around untyped `dict`s, raw JSON-shaped objects, or positional `tuple`s when the data has a stable schema.
*   Favor explicit field names and type annotations at module boundaries.
    *   New interfaces should make expected shapes obvious from the type signature rather than relying on implicit key conventions.
*   When replacing legacy loose structures, prefer incremental migration toward typed wrappers instead of adding more untyped call paths.

## Directory Structure

*   `android_env/`: Android analysis tools.
*   `android_app_mcp/`: MCP server for Android app debugging and Frida-based instrumentation.
*   `kexploit/`: Kernel exploit adaptation and synthesis tool.
*   `kexploit_agent/`: Sandbox environment for agents.
*   `kexploit_utils/`: Shared utilities and data management.
*   `libadb/`: Shared ADB library.
*   `cuttle_server/`: Cuttlefish control-plane packages (`cuttle_server` and `cuttle_cli`).
*   `object_db/`: Shared kernel object database models and extraction utilities.
*   `primitives/`: Structured exploit primitive library and metadata.
*   `scripts/`: Standalone utility scripts.
*   `SYNTHESIS_TODO.md`: Roadmap for exploit synthesis features.
