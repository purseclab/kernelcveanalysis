# ksandbox

Reusable Docker sandbox package with a small daemon interface over a Unix socket.
The daemon, ripgrep, and fd are static executables mounted read-only from a
shared host cache into every target image at `/opt/ksandbox/bin`, so the sandbox
can use any linux/amd64 Docker image that provides `/bin/sh` without copying the
binaries for each container.

The sandbox supports command execution, single-file byte read/write/edit
operations, directory listing, grep, glob, and host folder mounts under
`/data/<name>`.
Per-container runtime directories contain only the Unix socket. Persistent
sandboxes keep them under `KEXPLOIT_DATA_DIR/ksandbox/runtimes/` and mount them
read-write into containers at `/sandbox_runtime/daemon.sock`.

On first use, ksandbox builds its static tool bundle with Docker and caches it
under `$XDG_CACHE_HOME/ksandbox` (or `~/.cache/ksandbox`). It can also be prepared
or refreshed explicitly:

```bash
uv run ksandbox setup
uv run ksandbox setup --force
```

## CLI

```bash
uv run ksandbox list
uv run ksandbox start <container-id>
uv run ksandbox stop <container-id>
uv run ksandbox delete <container-id>
uv run ksandbox delete <container-id> --force
```

`create()` returns a stopped persistent sandbox. Use `sandbox.start()` to resume
it, including as `with sandbox.start() as running_sandbox:`; leaving the context
stops it but keeps it available for a future start. Use
`provider.create_and_run(...)` for a short-lived sandbox that is deleted on
context exit. The persistent metadata database is stored at
`KEXPLOIT_DATA_DIR/ksandbox/sandboxes.sqlite3`.

Pass the image tag to `create()` or `create_and_run()`. For the maintained
Codex agent sandbox, build it with `uv run kexploit-utils build-all` and use
`DockerTag.CODEX_SANDBOX`.

Set `KSANDBOX_LOG_LEVEL=DEBUG` to enable detailed sandbox and container lifecycle
logs. `KEXPLOIT_AGENT_LOG_LEVEL` is also honored for compatibility.

## Command execution

Commands are argv-first and never receive shell parsing unless it is explicitly
requested. `exec_sync()` returns separate byte streams; `exec()` returns an
interactive process with chunked stdout and stderr reads.

```python
result = sandbox.exec_sync(["python3", "-c", "print('hello')"])
assert result.stdout == b"hello\n"

with sandbox.exec("read line; printf 'got:%s' \"$line\"", shell=True) as process:
    process.stdin_write(b"hello\n")
    process.close_stdin()
    assert process.wait_finish() == 0
    assert process.read_stdout() == b"got:hello"
```

All process methods accept `timeout_secs`. A timed-out interactive operation
raises `TimeoutError` and leaves the process running; call `kill()` explicitly.
`exec_sync()` kills its process group before raising `TimeoutError`.
