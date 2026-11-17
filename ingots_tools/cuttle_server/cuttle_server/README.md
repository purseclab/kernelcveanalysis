# Cuttlefish Server

`cuttle_server` is a FastAPI control plane for launching and managing Cuttlefish instances from a config directory.

## Running

From the workspace root:

```sh
uv run cuttle-server /path/to/config-dir
```

Optional bind overrides:

```sh
uv run cuttle-server /path/to/config-dir --host 0.0.0.0 --port 9000
```

### Docker Image Setup

Before using Docker-backed templates, build the default image from the
`cuttle_server` package directory:

```sh
./setup.sh
```

The script builds `cuttlefish-host:latest`, matching the default
`docker_image` shown below. It uses Google's stable Cuttlefish orchestration
image as its base and refreshes that base when rebuilding.

The image tag and base image can be overridden when needed:

```sh
CUTTLEFISH_DOCKER_IMAGE=my-cuttlefish:latest \
CUTTLEFISH_BASE_IMAGE=registry.example.com/cuttlefish:version \
./setup.sh
```

## Config Layout

The config directory must contain:

```text
config-dir/
  cuttle_server.toml
  templates/
    phone.toml
    tablet.toml
```

### Main Config

`cuttle_server.toml` contains server-level paths, auth, and limits:

```toml
server_host = "127.0.0.1"
server_port = 8000
auth_token = "replace-me"
admin_user_id = "admin"
database_path = "data/cuttlefish.db"
instance_timeout_sec = 600
cvd_start_timeout_sec = 120
reconcile_interval_sec = 30
base_instance_num = 0
max_instances = 10
docker_image = "cuttlefish-host:latest"
snapshot_root = "/var/lib/cuttlefish_snapshots"
```

- Relative paths are resolved relative to the config directory.
- `server_host` and `server_port` control the default FastAPI bind address. CLI `--host` and `--port` still override them for one-off runs.
- Docker-published ADB ports bind to the configured `server_host`; a one-off HTTP `--host` override does not change their binding.
- `auth_token` is the shared bearer token required on every request.
- `admin_user_id` is the only user allowed to reconcile and bypass normal per-user instance visibility.
- Per-instance runtime state is stored under `/tmp/cvd` using short generated directory names to avoid Unix socket path-length failures.
- Set `instance_timeout_sec = 0` to disable automatic expiration globally.
- `cvd_start_timeout_sec` bounds the `cvd start --daemon` subprocess so failed launches do not hang forever.
- `reconcile_interval_sec` controls how often the server's background cleanup task checks for expired instances.
- `base_instance_num` reserves the first `N` Cuttlefish instance numbers for manually launched devices. When set to `N`, the server allocates from `N + 1` through `N + max_instances`.
- `snapshot_root` is where snapshot data is stored (default `/var/lib/cuttlefish_snapshots`). It is deliberately outside the instance runtime root so stopping or expiring an instance never removes its snapshots. The server creates it on startup when any template supports snapshots, so the directory (or its parent) must be writable by the server user. Snapshots are large (about the guest's RAM plus its disk overlays; roughly 6 GB each in practice), so size this volume accordingly.
- `docker_image` is the default prebuilt image for Docker-backed templates. Run `./setup.sh` to build the provided default image; the server itself does not build or pull images automatically.

### Host TAP Capacity

Host-backed Cuttlefish instances use TAP interfaces provisioned by the host's
`cuttlefish-host-resources` service. On Debian-based installations, the number
of interface sets is normally controlled by `num_cvd_accounts` in
`/etc/default/cuttlefish-host-resources`; when unset, the packaged service
commonly defaults to 10. Each usable instance number needs its corresponding
`cvd-etap-NN`, `cvd-mtap-NN`, `cvd-wtap-NN`, and `cvd-wifiap-NN` interfaces.

The highest instance number managed by the server is
`base_instance_num + max_instances`, so `num_cvd_accounts` must be at least that
large. For example, this server configuration allocates instance numbers 5
through 20 and therefore requires at least 20 host interface sets:

```toml
# cuttle_server.toml
base_instance_num = 4
max_instances = 16
```

```sh
# /etc/default/cuttlefish-host-resources
num_cvd_accounts=20
```

If the required TAP interfaces are absent, Cuttlefish can still appear to boot
while logging errors such as `Unable to connect to cvd-mtap-13 tap interface`.
The guest then has no corresponding network interface; on phone images this can
also cause repeated cellular setup attempts and eventual Android system-service
failure.

Changing `num_cvd_accounts` requires reprovisioning the host resources. Drain
all running Cuttlefish instances before restarting
`cuttlefish-host-resources`, because doing so destroys and recreates the shared
TAP and bridge devices.

#### Reprovisioning TAP Interfaces

First coordinate with all server users and stop every managed and manually
launched Cuttlefish instance. `cuttle-cli list` only shows instances visible to
the configured user, so an administrator must also account for instances owned
by other users:

```sh
cuttle-cli list
cuttle-cli stop INSTANCE_NAME
```

After all instances have stopped, prevent new launches while the shared network
resources are being replaced:

```sh
sudo systemctl stop cuttle-server
```

Set `num_cvd_accounts` in `/etc/default/cuttlefish-host-resources` to at least
`base_instance_num + max_instances`, then restart the resource service:

```sh
sudoedit /etc/default/cuttlefish-host-resources
sudo systemctl restart cuttlefish-host-resources.service
sudo systemctl status --no-pager cuttlefish-host-resources.service
```

Verify the number of interfaces created for each TAP type. The following counts
should each equal `num_cvd_accounts`:

```sh
for prefix in cvd-etap cvd-mtap cvd-wtap cvd-wifiap; do
    printf '%s: ' "$prefix"
    ip tuntap show | awk -F: -v prefix="$prefix" \
        '$1 ~ "^" prefix "-" { count++ } END { print count + 0 }'
done
```

Finally, restart the control plane and confirm it is healthy:

```sh
sudo systemctl start cuttle-server
sudo systemctl status --no-pager cuttle-server
```

The first resource restart after increasing `num_cvd_accounts` may log errors
while deleting higher-numbered interfaces that did not previously exist. Check
the final service status and interface counts before restarting the control
plane.

### Template Config

Each `templates/*.toml` file defines one launch template:

```toml
name = "phone"
runtime_root = "/opt/cuttlefish"
command_mode = "cvd"
backend = "host"
cpus = 4
kernel_path = "/srv/kernels/bzImage"
initrd_path = "/srv/kernels/initramfs.img"
selinux = false
apps = [
  "/srv/apps/one.apk",
  "/srv/apps/two.xapk",
  "/srv/apps/three.apkm",
]
snapshot_supported = false
```

- `name` is the template identifier used as `template_name`.
- `runtime_root` is the Cuttlefish installation directory. Relative values are resolved relative to the template file.
- `command_mode` chooses which Cuttlefish command wrapper to use. It defaults to `cvd`, which runs `bin/cvd start` and `bin/cvd stop`. Set it to `legacy` to run `bin/launch_cvd` and `bin/stop_cvd`.
- `backend` selects `host` or `docker` and defaults to `host`.
- A Docker template may set `docker_image` to override the server default. A Docker template must resolve an image from one of those locations.
- `kernel_path` and `initrd_path` are optional. When omitted, the server does not pass the corresponding Cuttlefish launch argument, allowing the image defaults such as `boot.img` to be used.
- Relative `kernel_path`, `initrd_path`, and `apps` entries are resolved relative to the template file.
- `snapshot_supported` (default `false`) allows instances of this template to be launched with snapshot support (`cuttle-cli start --snapshots`) and snapshotted. It requires `backend = "host"`, `command_mode = "legacy"`, and a runtime that ships `bin/snapshot_util_cvd`; the server refuses to load the template otherwise. See [Snapshots](#snapshots).
- `apps` are parsed, validated, persisted, returned by the API, and auto-installed in order during startup unless disabled per request.
- Supported app payloads are `.apk`, `.xapk`, and `.apkm`. Bundle formats are unpacked server-side; embedded APK splits are installed together and bundled OBB files are copied into `/sdcard/Android/obb/...`.

## API

Implemented endpoints:

- `POST /v1/instances`
- `GET /v1/instances`
- `GET /v1/instances/{instance_id}`
- `GET /v1/instances/{instance_id}/logs`
- `POST /v1/instances/{instance_id}/renew`
- `POST /v1/instances/{instance_id}/stop`
- `POST /v1/instances/by-name/{instance_name}/stop`
- `POST /v1/instances/by-name/{instance_name}/restart`
- `POST /v1/instances/by-name/{instance_name}/snapshots`
- `POST /v1/instances/by-name/{instance_name}/restore`
- `GET /v1/snapshots`
- `GET /v1/snapshots/by-name/{snapshot_name}`
- `DELETE /v1/snapshots/by-name/{snapshot_name}`
- `GET /v1/templates`
- `GET /v1/templates/{template_name}`
- `POST /v1/admin/reconcile`

All endpoints require:

```text
Authorization: Bearer <auth_token>
X-User-Id: <user_id>
```

Create request shape:

```json
{
  "template_name": "phone",
  "instance_name": "demo",
  "overrides": {
    "cpus": 6,
    "selinux": false,
    "load_apps": false,
    "unmanaged": true,
    "snapshots_enabled": false
  }
}
```

Notes:

- `X-User-Id` defines the current user for every operation.
- Non-admin users can only list and operate on their own instances.
- If `instance_name` is omitted, the server stores it internally as `null` and exposes the effective name as the `instance_id`.
- Explicit names are unique per user among non-terminal instances.
- Instance views include `adb_port` once the launch succeeds. Clients should connect to `<same-host-as-http-server>:<adb_port>`.
- `overrides.load_apps` defaults to `true`. Set it to `false` to skip template APK installation for that instance.
- `overrides.unmanaged` defaults to `false`. When true, clients persist the endpoint for external ADB forwarding and exclude it from local daemon connect/disconnect management, including after restart.
- `overrides.snapshots_enabled` defaults to `false`. It launches the instance with snapshot support and is rejected for templates without `snapshot_supported`.
- `POST /v1/instances?async_start=true` returns after recording the instance in `starting` state and completes launch in the background.
- `POST /v1/instances/by-name/{instance_name}/restart?async_start=true` stops an active instance, records it in `starting` state, and completes its relaunch in the background.

## Snapshots

A snapshot saves a running instance's memory, device state, and disks so the instance can later be put back exactly as it was: processes, open files and kernel state included.

Setup: set `snapshot_supported = true` on the template (host backend, legacy command mode) and make sure `snapshot_root` is writable. The Cuttlefish runtime must also ship a `crosvm` that can snapshot and restore arm64 guests; see `SNAPSHOT_PROGRESS.md` for the patched build used for the challenge7 runtimes.

Launching: `cuttle-cli start <template> --snapshots` adds `--snapshot_compatible --gpu_mode=guest_swiftshader --vhost_user_vsock=false` to the launch command. These are required: the GPU must be 2D SwiftShader, and vsock must be crosvm's built-in device because the default vhost-user vsock process cannot save its state. Instances launched without `--snapshots` cannot be snapshotted.

Endpoints:

- `POST /v1/instances/by-name/{instance_name}/snapshots` with `{"snapshot_name": "..."}` snapshots an `active` instance that was launched with snapshot support. It runs synchronously (the guest is paused for a few seconds) and returns the snapshot view.
- `POST /v1/instances/by-name/{instance_name}/restore` with `{"snapshot_name": "..."}` restores a snapshot into an instance and returns the instance view. It accepts `?async_start=true` like restart.
- `GET /v1/snapshots?instance=<name-or-id>&template=<template>` lists snapshots; both filters are optional.
- `GET /v1/snapshots/by-name/{snapshot_name}` and `DELETE /v1/snapshots/by-name/{snapshot_name}` show and delete one snapshot. Either accepts a snapshot id in place of the name.

Ownership follows the same rules as instances. A snapshot belongs to the owner of the instance it was taken from (including when the admin takes it), names are unique per owner, non-admin users only see their own snapshots, and the admin sees all of them. A name that several users share is ambiguous for the admin, who must then use the snapshot id. A failed snapshot is kept as a `failed` record with its `failure_reason` until its name is reused or it is deleted. Snapshots that were still being created when the server stopped are marked failed on the next startup.

Restore rules. Cuttlefish bakes the original instance's absolute paths, instance number, network device names and vsock CID into a snapshot, so a snapshot can only be restored into the instance it was taken from (same instance number and runtime directory). `restore` checks that:

- the snapshot is `ready` and belongs to the instance's owner;
- the instance uses the same template and backend and was launched with snapshot support;
- the snapshot's instance number and runtime directory match the instance;
- the Cuttlefish host tools (`run_cvd`, `assemble_cvd`, `snapshot_util_cvd` and `crosvm`) are unchanged since the snapshot was taken, because the saved device state is not stable across versions.

An `active` or `crashed` instance is stopped first (a stop failure is kept as a warning, as in restart). A `stopped` or `expired` instance is brought back under its old name and id, provided its instance number and name are still free. The runtime directory is recreated from the snapshot, the lease is reset, and template apps are not installed again because the restored guest already has them. Restoring does not modify the snapshot, so it can be restored repeatedly. Deleting a snapshot is refused while a restore is reading it.

Runtime directory names must stay short: Cuttlefish creates Unix sockets under them, and socket paths are limited to 108 characters.

## Runtime Behavior

- Each instance gets a unique runtime directory under `/tmp/cvd/<short-instance-id>`.
- Host templates run the configured start and stop commands directly with `cwd=<runtime_dir>` and `HOME=<runtime_dir>`.
- Docker templates mount `runtime_root` read-write at its host path (and `kernel_path`/`initrd_path` read-only at their host paths when they are outside it), so absolute host paths, wrapper scripts, and Cuttlefish's lock files and in-place image rewrites behave exactly as in host mode. They use an anonymous Docker volume at `/var/lib/cuttlefish`, and run one internal Cuttlefish instance numbered `1`. Each container receives a host-global vsock guest CID starting at `10000`, offset by its allocated logical instance number, so concurrent containers do not contend for the same CID. The anonymous volume is removed with the container; server-owned CVD stdout/stderr logs remain in the instance runtime directory.
- Docker templates require a local Docker daemon, `/dev/kvm`, `/dev/net/tun`, and an image containing the host-side runtime dependencies. Available vhost devices are passed through automatically. The image entrypoint provisions one isolated set of Cuttlefish Ethernet, mobile, and Wi-Fi interfaces and starts a per-container operator before launching the instance. Docker instances always run webRTC because it is the host end of the guest display and audio devices; without it the guest never finishes booting. Startup waits for Cuttlefish's `VIRTUAL_DEVICE_BOOT_COMPLETED` marker rather than probing the published ADB port. The entrypoint performs network and operator setup as root, then drops to the uid/gid of the `cuttle_server` process (passed as `CUTTLE_CONTAINER_UID`/`CUTTLE_CONTAINER_GID`) with the container's `kvm` and `cvdnetwork` groups before running Cuttlefish, so files it writes into the shared runtime root are owned by the server user, as in host mode. Paths outside `runtime_root`, `kernel_path`, and `initrd_path` are not available inside the container. Docker's seccomp filter is disabled for these containers because Cuttlefish requires `AF_VSOCK`, which the default profile blocks.
- CVD stdout/stderr are written to `cvd-start.log` and `cvd-stop.log` in the instance runtime directory. The logs endpoint also returns Cuttlefish's `kernel.log`, `launcher.log`, and `logcat`.
- Before removing a failed Docker container and its anonymous volume, the server copies those three internal Cuttlefish logs into the instance runtime directory.
- The server also sets `ANDROID_HOST_OUT=<runtime_root>` and `ANDROID_PRODUCT_OUT=<runtime_root>` so older `cvd start` selector logic can resolve the template installation.
- Host instances publish an ADB TCP port derived from their logical instance number.
- Docker instances always use port `6520` internally. Docker assigns a unique host port bound to the configured `server_host`; clients reuse the same hostname they used for the HTTP API and only vary the returned port.
- Restart preserves the instance id, effective name, resolved launch configuration, logical instance number, and ADB port, and resets the lease using the configured default timeout. Docker explicitly rebinds the previous host port.
- `max_instances` still means the number of instances managed by the server, not the highest raw Cuttlefish instance number.
- When `load_apps` is enabled and the template has apps, the server connects to the instance over server-local ADB, waits for boot completion, installs each `.apk` directly or unpacks and installs `.xapk`/`.apkm` bundles in template order, then disconnects before marking the instance `ACTIVE`.
- The server runs a background task on startup that periodically reconciles and stops expired instances, and it also performs one reconciliation pass immediately during startup.
- If automatic expiration is disabled globally, new instances are created without an `expires_at` deadline until a client explicitly renews them with a timeout.
- After a successful explicit stop or expiration cleanup, the runtime directory is removed.
- If stop or cleanup fails, the instance record is updated with `failure_reason` and the runtime directory is left in place for inspection.
- During restart only, a backend stop failure is retained in `cvd-stop.log` as a warning and startup is still attempted. Runtime-directory cleanup failure remains fatal.
- If startup or app loading fails, the instance is stopped and left in `crashed` state with its failure reason and runtime logs preserved. Explicitly stopping the crashed instance removes its runtime directory.

Current `command_mode = "cvd"` start command shape:

```text
cvd start \
  --base_instance_num=<N> \
  --cpus=<cpus> \
  --start_webrtc=true \
  [--kernel_path=<kernel>] \
  [--initramfs_path=<initrd>] \
  --daemon \
  --report_anonymous_usage_stats=n
```

If SELinux is disabled, the server also adds:

```text
--extra_kernel_cmdline=androidboot.selinux=permissive
```

Its stop command uses:

```text
cvd stop
```

With `command_mode = "legacy"`, the server runs `launch_cvd` with the same launch flags and stops with:

```text
stop_cvd
```

Docker templates use the equivalent container paths, force
`--base_instance_num=1`, set `--vsock_guest_cid` to `10000` plus the allocated
logical instance offset, disable WebRTC, and use `--daemon=false` so the
container lifecycle follows the launcher. Stop uses Docker's hardcoded graceful
timeout and force-removes the container when necessary.

## Current Limitations

- Snapshots are implemented only for the host backend in `legacy` command mode. Restoring a snapshot into a different instance (for example a new Docker container, where every instance has the same paths) is not supported yet.
- A snapshot can only be restored into the instance it was taken from, and only while the Cuttlefish host tools are unchanged.
- Snapshot creation is synchronous and holds the server's instance lock while the guest is paused.
- Authorization is still a single shared bearer token; user identity is a separate header, not a signed credential.
- The admin user can see all instances; stop-by-name is ambiguous for admin if multiple users have the same explicit active name.
- `webrtc_port` is returned as `null`; the first Docker backend version deliberately disables WebRTC.
- Template config is loaded once at startup; there is no hot reload.
- App loading always uses the server-local standard `adb` client/server flow; there is no custom raw-ADB transport in `libadb`.
