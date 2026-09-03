---
name: kartifact
description: Create, write, list, and pull versioned exploit artifact folders through the kartifact CLI.
---

# Kartifact CLI

Use kartifact when an unmanaged agent needs to exchange an artifact folder with
the Ingots artifact database. The artifact type must come from the task or that
type's documentation; kartifact intentionally has no type-discovery command.

## Rules

- Run the CLI from the Ingots Tools workspace with `uv run kartifact`.
- Do not modify `artifactdb.sqlite` or anything under the managed `blobs/`
  directory directly.
- Treat `artifact.id` in `artifact.toml` as the checked-out revision token.
- Do not edit `artifact.parent_id`; it is rendered provenance.
- Use a missing or empty folder for `create` and `pull`.
- Artifact trees may contain only regular files and directories. Do not add
  symlinks, sockets, pipes, or device files.
- Prefer `--json` when consuming output programmatically. It is a global option
  and must precede the command.

## Create a working template

```bash
uv run kartifact create <type> <folder> --name <safe-name>
```

The name may contain letters, digits, `.`, `_`, and `-`. Edit the generated
`artifact.toml` metadata and add the artifact's files before writing it.
Note: Certain artifact types (such as `kernel`) do not support `create` or `write`
and must be ingested via their dedicated import command.

## Android App Artifacts (`android_app`)

To package an Android application:

```bash
uv run kartifact create android_app <folder> --name <safe-name>
```

- **Required File**: The artifact requires one APK file (`app.apk`).
- **Original Filename & Overrides**: You should keep the original APK filename (e.g. `Bluetooth.apk`, `Settings.apk`) and map it in `artifact.toml` via `[file_overrides]`:
  ```toml
  [file_overrides]
  "app.apk" = "Bluetooth.apk"
  ```
- **Keeping Notes**: You are strongly encouraged to keep markdown notes in files like `NOTES.md` inside the artifact folder to record decompilation findings, attack surface analysis, permissions, and vulnerabilities. Notes files are stored directly as files in the artifact and are completely transparent to metadata.

## Android System Artifacts (`android_system`)

To define an Android system composition:

```bash
uv run kartifact create android_system <folder> --name <safe-name>
```

- **Referenced Artifacts**: Specify the name of a kernel artifact and a list of android app artifacts in `[metadata]`:
  ```toml
  [metadata]
  kernel_name = "goldfish-5.10"
  app_names = ["bluetooth-app", "nfc-app"]
  ```
- **Files**: No specific binary files are mandatory; you can keep research notes (such as `NOTES.md`) and configuration files inside the folder as needed. Notes files are stored transparently in the artifact folder without needing metadata specification.
- **Write Verification**: When writing an `android_system` revision, `kartifact` verifies that the referenced `kernel_name` and all referenced `app_names` exist in the database.

## Vulnerability Artifacts (`vulnerability`)

To document and version a vulnerability patch and its details:

```bash
uv run kartifact create vulnerability <folder> --name <safe-name>
```

- **Metadata Fields (`[metadata]`)**:
  - `cve` (optional): CVE identifier (e.g. `"CVE-2023-12345"`).
  - `vuln_target` (required): Target component (e.g. `"kernel"`, a library name like `"libbluetooth"`, or an app package).
  - `vuln_type` (required): Vulnerability classification (e.g. `uaf`, `command_injection`, `js_injection_webview`, `directory_traversal`, `file_write`, `buffer_overflow`, `race_condition`, `double_free`, `integer_overflow`, `type_confusion`, `intent_redirection`, `sql_injection`, `logic_error`, `other`).
  - `description` (required): Summary description of the bug.
  - `affected_versions` (optional list of strings): Versions or version ranges separated by `-` (e.g. `["5.10.107", "5.4.0 - 5.10.107"]`). When `vuln_target = "kernel"`, each version is validated against the Linux kernel version format.
  - `targets` (optional list of strings): Target artifact names (such as kernel or app artifact names). When provided, `kartifact` verifies that all referenced target artifacts exist in the database at write time.
- **Mandatory File**:
  - `patch.diff`: The diff patch fixing or reproducing the vulnerability. Can be mapped to a custom path using `[file_overrides]`.
- **Optional File**:
  - `DETAILS.md`: Extended analysis explaining vulnerability mechanics, exploitation prerequisites, and capabilities granted upon exploitation.

## Exploit Artifacts (`exploit`)

To package a standalone exploit targeting a kernel or Android application:

```bash
uv run kartifact create exploit <folder> --name <safe-name>
```

- **Metadata Fields (`[metadata]`)**:
  - `target` (required): Name of the target artifact (`kernel` artifact for kernel exploits, or `android_app` artifact for userspace exploits).
  - `vulnerability` (required): Name of the referenced `vulnerability` artifact.
  - `exploit_type` (required, accepts `type` alias): Either `"kernel"` or `"userspace"`.
- **Files**:
  - `build.sh`: Script to compile and link exploit binaries.
    - **Mandatory** when `exploit_type = "kernel"`.
    - **Optional** when `exploit_type = "userspace"`.
    - Can be mapped via `[file_overrides]`.
  - Exploit source files (e.g. `exploit.c`, headers, Android project files) and notes (`NOTES.md`) are stored directly in the artifact directory.
- **Write Verification**: `kartifact` verifies that the referenced `vulnerability` artifact and `target` artifact exist in the database.

## Exploit Chain Artifacts (`chain`)

To define and assemble a multi-step exploit chain:

```bash
uv run kartifact create chain <folder> --name <safe-name>
```

- **Metadata Fields (`[metadata]`)**:
  - `target` (required): Name of the target `android_system` artifact.
  - `chain_type` (required, accepts `type` alias): Either `"remote"` or `"local"` (depending on whether an attacker app or remote delivery vector is used).
  - `steps` (required list of tables): Ordered steps in the chain:
    ```toml
    [[metadata.steps]]
    exploit = "bluetooth-app-rce"
    role = "Initial remote code execution in Bluetooth daemon"
    chaining = "Writes exploit payload to shared memory and triggers kernel ioctl"

    [[metadata.steps]]
    exploit = "goldfish-pipe-uaf"
    role = "Local privilege escalation to root via kernel pipe UAF"
    chaining = "Obtains root shell in system context"
    ```
- **Files**: Combined source code, chaining runners, and research notes (`NOTES.md`) stored directly in the folder.
- **Write Verification**: `kartifact` verifies that the referenced `android_system` artifact and all referenced `exploit` artifacts in `steps` exist in the database.

## Import a kernel artifact

To ingest a kernel into the artifact store:

```bash
uv run kartifact import-kernel <path-to-image> --name <safe-name> [--initrd <path-to-initrd>]
uv run kartifact --json import-kernel <path-to-image> --name <safe-name> [--initrd <path-to-initrd>]
```

This command executes `vmlinux-to-elf` on the kernel image, extracts the ELF binary
with symbols, detects the architecture (e.g. `amd64`, `aarch64`, `arm`, `x86`), extracts
the kernel version banner, extracts the `.config` if present (`CONFIG_IKCONFIG`), and
commits the immutable artifact into storage.

Standardized files inside a kernel artifact:
- `image`: The original kernel image (e.g. `bzImage`, `Image`, `zImage`).
- `vmlinux`: The converted ELF file with extracted kernel symbols.
- `config`: The kernel configuration file (if present).
- `initrd`: The initial ramdisk file (if `--initrd` was provided).
- `artifact.toml`: Manifest containing `[artifact]` header and `[metadata]` with
  `architecture`, `version`, `full_version`, `has_config`, and `has_initrd`.

## File Overrides

By default, an artifact's expected files are resolved at the root of the artifact folder
matching the logical file name (e.g. `image`, `vmlinux`, `main.c`). You can override the
relative path for any registered mandatory or optional file using a `[file_overrides]`
(or `[files]`) table in `artifact.toml`:

```toml
[file_overrides]
vmlinux = "build/custom_vmlinux.elf"
```

Overrides must be relative paths inside the artifact tree without path traversal (`..`).
File access methods (`read_bytes`, `get_path`, etc.) and store write verification
automatically use these mapped paths without requiring per-artifact code changes.

## Store a revision


```bash
uv run kartifact --json write <folder>
```

A successful write creates an immutable database revision and rewrites the
working folder's `artifact.toml` with its new `id` and `parent_id`. Keep using
that rewritten folder for later revisions.

If a write reports a stale-head conflict, another revision already advanced the
same type/name. Either pull the newer revision and reapply the work, or choose a
new unused name in `artifact.toml` to create an intentional fork. Never remove
or replace the ID to bypass a conflict.

If kartifact reports `source_update_failed`, the returned artifact ID was
committed even though the working TOML could not be rewritten. Pull that ID into
a new empty folder before continuing.

## List artifacts

```bash
uv run kartifact list <type>
uv run kartifact --json list <type>
uv run kartifact --json list <type> --include-shadowed
```

The default list contains visible name heads. Use `--include-shadowed` when an
older immutable revision is needed.

## Pull an exact revision

```bash
uv run kartifact --json pull <revision-id> <empty-folder>
```

Pull always selects by UUID, copies that revision's files, and renders canonical
database metadata into `artifact.toml`.

