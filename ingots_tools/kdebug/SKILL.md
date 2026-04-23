---
name: android-kdebug
description: Use this skill when debugging Android apps over ADB with the kdebug Frida CLI, or when you need the equivalent plain adb commands for shell, file transfer, install, and log inspection tasks that kdebug does not implement.
---

# Android Kdebug

Use this skill when the task is to debug an Android app on an ADB-visible device with `kdebug`.

## Rules

- Prefer `kdebug` for Frida workflows.
- Prefer `kdebug lldb ...` for native attach workflows.
- Prefer plain `adb` for shell, file transfer, install, and logcat tasks.
- Pass an explicit target device each time with `--device <serial-or-host:port>` unless the user gave a different command form.
- Do not invent Frida session IDs or script IDs. List sessions or scripts first when needed.
- Do not invent LLDB session IDs. List LLDB sessions first when needed.

## Frida workflows

List visible apps:

```bash
kdebug --device <target> frida apps
```

Attach to a running app:

```bash
kdebug --device <target> frida attach <package>
```

Spawn suspended and resume later:

```bash
kdebug --device <target> frida spawn <package>
kdebug --device <target> frida resume <session-id>
```

Inspect active state:

```bash
kdebug --device <target> frida sessions
kdebug --device <target> frida scripts
```

Load a persistent script:

```bash
kdebug --device <target> frida load-script <session-id> --name <name> --file hook.js
kdebug --device <target> frida load-script <session-id> --name <name> --source 'rpc.exports = { ping() { return "ok"; } };'
printf '%s\n' 'send("hello")' | kdebug --device <target> frida load-script <session-id> --name stdin-hook --stdin
```

Run a one-shot script or call RPC exports:

```bash
kdebug --device <target> frida eval <session-id> --file probe.js
kdebug --device <target> frida rpc <script-id> <method> [args...]
kdebug --device <target> frida messages <script-id>
```

Detach and clean up:

```bash
kdebug --device <target> frida unload-script <script-id>
kdebug --device <target> frida detach <session-id>
```

Use `--json` when the output needs to be consumed by another tool.

## LLDB workflows

Attach by package or PID:

```bash
kdebug --device <target> lldb attach-package <package>
kdebug --device <target> lldb attach-pid <pid>
```

Inspect active LLDB sessions:

```bash
kdebug --device <target> lldb sessions
```

Print the host LLDB command to connect:

```bash
kdebug --device <target> lldb connect <session-id>
kdebug --device <target> lldb connect <session-id> --binary <host-binary>
kdebug --device <target> lldb connect <session-id> --binary <host-binary> --sysroot <sysroot>
```

Stop an LLDB session and remove its port forward:

```bash
kdebug --device <target> lldb stop <session-id>
```

Notes:

- v1 is attach-only; it does not start Android apps under LLDB control.
- `kdebug` manages `lldb-server` on the device but does not launch host `lldb` automatically.
- Bundled binaries are expected under `kdebug/assets/lldb-server/<abi>/lldb-server`.
- LLDB attach assumes a root-capable debugging environment.

## Daemon behavior

Frida commands auto-start a local daemon for the selected device. Explicit daemon commands are only for inspection or cleanup:

```bash
kdebug --device <target> daemon status
kdebug --device <target> daemon start
kdebug --device <target> daemon stop
```

The daemon holds live Frida sessions and loaded scripts in memory. If it stops, those sessions are gone and must be recreated.

## Use adb for non-Frida tasks

Run shell commands:

```bash
adb -s <target> shell <command>
adb -s <target> shell su root sh -c '<command>'
```

Copy files:

```bash
adb -s <target> push <local-path> <remote-path>
adb -s <target> pull <remote-path> <local-path>
```

Read or write text files:

```bash
adb -s <target> shell cat <remote-path>
adb -s <target> shell 'printf %s "content" > <remote-path>'
adb -s <target> shell 'cat > <remote-path>' < local-file
```

Install apps:

```bash
adb -s <target> install <app.apk>
adb -s <target> install-multiple <base.apk> <split.apk>
```

Inspect logs:

```bash
adb -s <target> logcat
adb -s <target> logcat --pid <pid>
```
