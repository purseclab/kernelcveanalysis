---
name: cuttle-cli
description: Use this skill to launch and manage Android Cuttlefish instances using the cuttle-cli and cuttle-server.
---

# Cuttle CLI

Use this skill when the task is to operate a running `cuttle_server` environment through `cuttle-cli` cli tool.

## Rules

- Do not use `--server-host`, `--server-port`, `--auth-token`, or `--user-id` to override any configured settings.
- Assume the CLI is already configured. If it fails because configuration or auth is missing, stop and report that instead of inventing overrides.
- Prefer the narrowest action that satisfies the task. Avoid `stop --stop-all` unless the user clearly asked for it.

## Main workflows

### Inspect what is available

Use these first when the template or instance name is unknown:

```bash
cuttle-cli templates list
cuttle-cli templates show <template-name>
cuttle-cli list
cuttle-cli list --all
```

Notes:

- If user specifies a template to use, do not inspect other templates.
- `templates list` prints one template per line with CPU count and SELinux state.
- `templates show <template-name>` prints the runtime root, kernel/initrd paths, SELinux setting, and template app list.
- `list` shows only visible non-terminal instances by default.
- `list --all` also includes stopped, crashed, and expired instances.

### Start an instance

Basic launch:

```bash
cuttle-cli start <template-name>
```

Useful optional flags:

```bash
cuttle-cli start <template-name> --name <instance-name>
cuttle-cli start <template-name> --cpus <count>
cuttle-cli start <template-name> --selinux true
cuttle-cli start <template-name> --selinux false
cuttle-cli start <template-name> --no-load-apps
```

Guidance:

- Use `--name` when the user wants a stable human-readable instance name.
- Use `--cpus` and `--selinux` only when the user asked for those overrides.
- Use `--no-load-apps` when the task should avoid template APK auto-loading.
- Success output includes the effective instance name, instance id, state, and `adb=<host:port>` when available.

### Stop instances

Stop a single instance by effective name:

```bash
cuttle-cli stop <instance-name>
```

Bulk stop modes:

```bash
cuttle-cli stop --stop-all
cuttle-cli stop --stop-all-user <user-id>
```

Guidance:

- Pass exactly one of `<instance-name>`, `--stop-all`, or `--stop-all-user`.
- Prefer stopping a single named instance.
- If an instance was launched without a custom name, its effective stop target is its instance id.

## Daemon behavior

`cuttle-cli start`, `cuttle-cli list`, and `cuttle-cli stop` automatically ensure the managed daemon is running.

Use explicit daemon commands only when the task is about daemon state or ADB sync behavior:

```bash
cuttle-cli daemon status
cuttle-cli daemon start
cuttle-cli daemon stop
cuttle-cli daemon sync
```

Guidance:

- `daemon status` reports `running`, `stale`, or `stopped`.
- `daemon sync` is for one-shot synchronization and fails if the daemon is already running.
- Prefer the normal `start`/`list`/`stop` commands over manual daemon management.

## Agent pattern

1. If the template or target instance is unknown, inspect with `templates list`, `templates show`, or `list`.
2. Run the smallest command that accomplishes the task.
3. Read stdout and return the important fields: template name, instance name, instance id, state, and ADB target when present.
4. If `cuttle-cli` reports missing config/auth or another CLI error, surface that error plainly and stop.
