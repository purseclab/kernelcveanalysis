---
name: verify-android-poc
description: Use when directed to make a verified Android kernel PoC.
---

# Verify an Android PoC

Use `verify-kernel-poc` from:

```text
/home/jack/Documents/college/purdue/research/kernelcveanalysis/kernel_PoCs/common/verify
```

Prefer **app mode** for verification because it reflects real app permissions.
Use shell mode or manual `adb` only to debug exploit logic.

```bash
cd /home/jack/Documents/college/purdue/research/kernelcveanalysis/kernel_PoCs/common/verify

# Preferred verification
uv run verify-kernel-poc --template <template> --from-app /path/to/libpoc.so

# Shell-context debugging
uv run verify-kernel-poc --template <template> /path/to/poc

# Run only, stream stdout, no root checks
uv run verify-kernel-poc --template <template> --run-only /path/to/poc
```

App mode randomly selects one of 2 test apps (identical, different package names).
This is to test PoC does not hardcode specific app paths or UID.
To test a specific app (not prefered, only for debugging), use `--from-app 1` or `--from-app 2`.
`--from-app all` runs the PoC from both apps on 2 seperate VMs.

## Fast development loop

The verifier accepts an existing instance with `--adb <host:port>` instead of
`--template`, which skips guest startup and is much faster while iterating.
Start one guest with `cuttle-cli start <template> --name poc-dev --no-load-apps`,
reuse the printed `adb=` target, and stop it when done. `--keep-instance` also
leaves a verifier-started guest running for follow-up runs.

Use `--adb <host:port>` when investigating a non cuttle-cli target, such as
a physical phone.

Ad hoc `adb`, shell-mode, and manual debugging are encouraged for speed during
development. Final verification should still be app mode on a clean,
disposable guest.

Inspect metadata and the resolved plan when unsure:

```bash
uv run verify-kernel-poc --print-metadata /path/to/poc
uv run verify-kernel-poc --dry-run /path/to/poc
```

## Rules

- App mode is the preferred result. From app context, verify the operations the
  PoC depends on, e.g. syscalls/seccomp, `/dev`, `/proc`, `/sys`, binder,
  netlink, io_uring, filesystems, sockets, and SELinux.
- Shell-mode or manual ADB success is not app-context proof. Debug there, then
  return to app mode.
- A pass requires the randomized root-only flag token, not just `uid=0(root)`.
- Each run changes guest state (adb root/unroot, helper app, root flag, possibly
  SELinux/kernel). Reuse for development as needed, but use a clean disposable
  guest for final verification.
- Report the verifier exit code and output. `0` means verified, `1` root check
  failed, `2` setup/ADB error, `3` unsupported mode.

App mode supports `shared` and `jni` artifacts and shell, listening, and reverse
payloads. It runs as an app UID such as `u:r:untrusted_app`. Two identical
helper apps with different packages/paths are bundled: `--from-app` picks one
at random, `--from-app 1`/`2` select one, and `--from-app all` starts two VMs,
installs both apps on each, and runs both apps on both.

If app mode fails, read the included app logs. If the helper APK mismatch error
appears, run the verifier from `common/verify` with `uv run` so the repository
APKs are used.

## Workflow

1. Inspect metadata and build the matching Android artifact.
2. Try app mode first.
3. If it fails, check whether the PoC has a shell-context guard or hit an app
   permission boundary.
4. Debug with shell mode/manual ADB if needed, then rerun app mode.
5. Confirm the root token, UID, kernel, SELinux state, and cleanup.

## Checklist

- App-mode run completed, or explicitly shown not applicable.
- App-context permissions for syscalls, devices, procfs/sysfs, kernel
  interfaces, filesystems, sockets, and SELinux checked.
- Root token matched, not merely a printed UID.
- Shell-only success not represented as app-mode verified.
