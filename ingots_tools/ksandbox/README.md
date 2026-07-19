# ksandbox

Reusable Docker sandbox package with a small daemon interface over a Unix socket.
The daemon, ripgrep, and fd are static executables mounted read-only from a
shared host cache into every target image at `/opt/ksandbox/bin`, so the sandbox
can use any linux/amd64 Docker image that provides `/bin/sh` without copying the
binaries for each container.

The sandbox supports command execution, single-file byte read/write/edit
operations, directory listing, grep, glob, and host folder mounts under
`/data/<name>`.
Per-container runtime directories contain only the Unix socket. They are created
under `/tmp/ksandbox/<uuid>/daemon.sock` and mounted read-write into containers
at `/sandbox_runtime/daemon.sock`.

On first use, ksandbox builds its static tool bundle with Docker and caches it
under `$XDG_CACHE_HOME/ksandbox` (or `~/.cache/ksandbox`). It can also be prepared
or refreshed explicitly:

```bash
uv run ksandbox setup
uv run ksandbox setup --force
```

## CLI

```bash
uv run ksandbox build-image
uv run ksandbox build-image ./my-context -f Dockerfile -t my-sandbox:latest
uv run ksandbox list
uv run ksandbox delete <container-id>
```

Select a prebuilt custom image by constructing
`DockerSandboxProvider(image_tag="my-sandbox:latest")`. The default remains
`ksandbox:latest`.

Set `KSANDBOX_LOG_LEVEL=DEBUG` to enable detailed sandbox and container lifecycle
logs. `KEXPLOIT_AGENT_LOG_LEVEL` is also honored for compatibility.
