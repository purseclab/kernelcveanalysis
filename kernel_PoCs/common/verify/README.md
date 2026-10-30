# verify-kernel-poc

Verify that a `kernel_PoCs/common` wrapped exploit actually obtains root on an
Android Cuttlefish guest.

The verifier launches a disposable template, runs the PoC as the non-root
Android `shell` user, and checks that the payload can read a randomized
root-only flag file. It also prints kernel identity and SELinux state before
and after the run.

## Install

```bash
cd kernel_PoCs/common/verify
uv sync
uv run verify-kernel-poc --help
```

For a global command:

```bash
uv tool install .
verify-kernel-poc --help
```

## Basic use

```bash
uv run verify-kernel-poc --template challenge7.1.3.a /path/to/exp
```

Reuse an already-running instance:

```bash
uv run verify-kernel-poc --adb localhost:6520 /path/to/exp
```

Keep the instance for debugging:

```bash
uv run verify-kernel-poc --template challenge7.1.3.a --keep-instance /path/to/exp
```

## Embedded metadata

New common-wrapped binaries contain a JSON block between these markers:

```text
__KPOC_METADATA_V1_BEGIN__ ... __KPOC_METADATA_V1_END__
```

Example:

```json
{
  "schema": 1,
  "generator": "kernel_PoCs/common",
  "target": "android",
  "arch": "aarch64",
  "artifact": "executable",
  "run": "exec",
  "entry": "main",
  "linkage": "dynamic",
  "payload": { "kind": "shell" },
  "root_check": { "mode": "shell" }
}
```

Inspect it without launching a guest:

```bash
uv run verify-kernel-poc --print-metadata /path/to/exp
uv run verify-kernel-poc --dry-run /path/to/exp
```

The verifier uses metadata automatically for:

- executable vs shared vs JNI artifact
- local, listening, or reverse shell payload
- reverse-shell IP and port
- listening-shell port

Older binaries or unusual wrappers can be described with CLI overrides.

## CLI overrides

```text
--artifact auto|executable|shared|jni
--payload auto|shell|listening-shell|reverse-shell
--payload-ip IP
--payload-port PORT
--poc-arg VALUE
--run-command '... {poc} ...'

--from-app
--app-apk PATH
--app-package PACKAGE

--root-check auto|flag|command|regex|none
--root-flag-path PATH
--root-check-command '... {flag} ...'
--root-check-regex REGEX
```

Examples:

```bash
# Override a missing metadata block
uv run verify-kernel-poc -t challenge7.1.3.a \
  --artifact executable --payload shell /path/to/exp

# Shared object with an embedded listening shell
uv run verify-kernel-poc -t challenge7.1.3.a /path/to/libexp.so

# JNI or shared library, loaded by the bundled helper app
uv run verify-kernel-poc -t challenge7.1.3.a --from-app /path/to/libexp.so

# JNI with a custom app runner
uv run verify-kernel-poc -t challenge7.1.3.a \
  --run-command 'app_process ... {poc}' /path/to/libexp.so

# Custom root check
uv run verify-kernel-poc -t challenge7.1.3.a \
  --root-check regex --root-check-regex 'uid=0\(root\)' /path/to/exp
```

## Run modes

| Artifact / payload | Behavior |
|---|---|
| executable + shell | Runs the PoC, then feeds root-check commands to its root shell |
| executable + listening shell | Uses `adb forward`, connects, and sends root-check commands |
| executable + reverse shell | Uses `adb reverse` for loopback IPs, otherwise listens on the host |
| shared | Runs `LD_PRELOAD=<poc> /system/bin/sleep 200` by default |
| shared/JNI + `--from-app` | Installs the helper APK and loads the PoC in app context |
| jni | Requires `--from-app` or `--run-command` |

For a shared object that starts a detached worker, use
`--run-command 'LD_PRELOAD={poc} /system/bin/true'` so the initial host exits
promptly while the verifier waits for the payload connection.

For a reverse shell, building the wrapper with `--ip 127.0.0.1` is recommended
because the verifier can then use `adb reverse` reliably regardless of guest
networking.


## App mode

`--from-app` installs the tiny debuggable helper APK from
`src/verify_kernel_poc/assets/kpoc-verify.apk`, copies the PoC into the app
data directory, and starts the helper with an explicit Intent:

```bash
am start -W -n com.purdue.kpoc.verify/.RunActivity ...
```

The Activity starts the PoC from the app process (`u:r:untrusted_app`) and pumps
the child's stdio over a loopback socket. The verifier uses `adb forward` to
connect to that socket and sends the same root-check script as normal.

For a constructor-loaded shared object, the app runs the same command as
regular shared mode:

```sh
LD_PRELOAD=<app-local-poc> /system/bin/sleep 200
```

For a JNI artifact, the app runs:

```sh
CLASSPATH=<installed-helper-apk> app_process /system/bin \
  com.purdue.kpoc.verify.Loader <app-local-poc>
```

```bash
uv run verify-kernel-poc -t challenge7.1.3.a --from-app /path/to/libexp.so
```

App mode only accepts `shared` or `jni` artifacts; executable artifacts fail
with exit code `3`. Shell payloads use the app's loopback stdio pump. Listening
and reverse payloads launch the app with `pump=false`, then use the normal
`adb forward` or `adb reverse` path to connect to the payload's own port. The
verifier also checks that `run-as` reports a real app UID before launching the
Activity.

After the child starts, the root check is exactly the same as normal: the
payload must read the randomized root-only flag. The helper app source and a
reproducible build script live in `app/`. Use `--app-apk` to provide a different
helper APK and `--app-package` if its package name differs.

## Root flag

By default the verifier creates:

```text
/data/local/tmp/kpoc-verify-<random>/flag
```

with mode `0400 root:root`. It verifies that the ADB `shell` user cannot read
the file before running the PoC. After the payload starts, it sends:

```sh
id
cat <flag>
getenforce
exit
```

A pass requires the random token from the flag. Printing `uid=0` alone is not
enough.

Root provisioning first uses `adb root`/`adb unroot` to write the flag. If adb
root is unavailable, it logs the fallback and tries the guest's `su` (`su 0`,
`su root`, or `su -c`) instead.

## Reporting

The human output includes:

```text
template selinux
kernel
uid before / after
selinux before / after
root flag path
root token match
attempt count and duration
guest output
```

A `Permissive` SELinux state is reported as a warning. Use
`--require-selinux enforcing` or `--require-selinux permissive` to make it a
hard check.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | root verified |
| `1` | PoC ran but root check failed |
| `2` | setup, ADB, or Cuttlefish error |
| `3` | unsupported mode or missing required CLI flags |

## Development

```bash
cd kernel_PoCs/common/verify
uv sync
uv run pytest -q
```

Metadata is emitted by `../exploit_metadata.h`, which is included from
`../exploit_entry.h`. The verifier scans the built binary as bytes, so the JSON
must remain ASCII and must not contain NUL bytes.
