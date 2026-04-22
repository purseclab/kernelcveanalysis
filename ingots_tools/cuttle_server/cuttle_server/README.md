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
reconcile_interval_sec = 30
max_instances = 10
```

- Relative paths are resolved relative to the config directory.
- `server_host` and `server_port` control the default FastAPI bind address. CLI `--host` and `--port` still override them for one-off runs.
- `auth_token` is the shared bearer token required on every request.
- `admin_user_id` is the only user allowed to reconcile and bypass normal per-user instance visibility.
- Per-instance runtime state is stored under `/tmp/cvd` using short generated directory names to avoid Unix socket path-length failures.
- Set `instance_timeout_sec = 0` to disable automatic expiration globally.
- `reconcile_interval_sec` controls how often the server's background cleanup task checks for expired instances.

### Template Config

Each `templates/*.toml` file defines one launch template:

```toml
name = "phone"
runtime_root = "/opt/cuttlefish"
cpus = 4
kernel_path = "/srv/kernels/bzImage"
initrd_path = "/srv/kernels/initramfs.img"
selinux = false
apps = [
  "/srv/apps/one.apk",
  "/srv/apps/two.xapk",
  "/srv/apps/three.apkm",
]
```

- `name` is the template identifier used as `template_name`.
- `runtime_root` is the Cuttlefish installation directory. Relative values are resolved relative to the template file.
- The server derives `bin/cvd` from `runtime_root`.
- Relative `kernel_path`, `initrd_path`, and `apps` entries are resolved relative to the template file.
- `apps` are parsed, validated, persisted, returned by the API, and auto-installed in order during startup unless disabled per request.
- Supported app payloads are `.apk`, `.xapk`, and `.apkm`. Bundle formats are unpacked server-side; embedded APK splits are installed together and bundled OBB files are copied into `/sdcard/Android/obb/...`.

## API

Implemented endpoints:

- `POST /v1/instances`
- `GET /v1/instances`
- `GET /v1/instances/{instance_id}`
- `POST /v1/instances/{instance_id}/renew`
- `POST /v1/instances/{instance_id}/stop`
- `POST /v1/instances/by-name/{instance_name}/stop`
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
    "load_apps": false
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

## Runtime Behavior

- Each instance gets a unique runtime directory under `/tmp/cvd/<short-instance-id>`.
- `cvd start` and `cvd stop` run with `cwd=<runtime_dir>` and `HOME=<runtime_dir>`.
- The server also sets `ANDROID_HOST_OUT=<runtime_root>` and `ANDROID_PRODUCT_OUT=<runtime_root>` so older `cvd start` selector logic can resolve the template installation.
- Each instance publishes an ADB TCP port derived from its Cuttlefish instance number. The launcher binds that listener on `0.0.0.0`; clients reuse the same hostname they used for the HTTP API and only vary the returned port.
- When `load_apps` is enabled and the template has apps, the server connects to the instance over server-local ADB, waits for boot completion, installs each `.apk` directly or unpacks and installs `.xapk`/`.apkm` bundles in template order, then disconnects before marking the instance `ACTIVE`.
- The server runs a background task on startup that periodically reconciles and stops expired instances, and it also performs one reconciliation pass immediately during startup.
- If automatic expiration is disabled globally, new instances are created without an `expires_at` deadline until a client explicitly renews them with a timeout.
- After a successful explicit stop or expiration cleanup, the runtime directory is removed.
- If stop or cleanup fails, the instance record is updated with `failure_reason` and the runtime directory is left in place for inspection.
- If app loading fails, instance creation fails, the instance is stopped, and the record is left in `crashed` state with a failure reason.

Current start command shape:

```text
cvd start \
  --base_instance_num=<N> \
  --cpus=<cpus> \
  --start_webrtc=true \
  --kernel_path=<kernel> \
  --initramfs_path=<initrd> \
  --daemon \
  --report_anonymous_usage_stats=n
```

If SELinux is disabled, the server also adds:

```text
--extra_kernel_cmdline=androidboot.selinux=permissive
```

Stop uses:

```text
cvd stop
```

## Current Limitations

- Authorization is still a single shared bearer token; user identity is a separate header, not a signed credential.
- The admin user can see all instances; stop-by-name is ambiguous for admin if multiple users have the same explicit active name.
- `adb_port` is exposed, but `adb_serial` and `webrtc_port` are still returned as `null`.
- Template config is loaded once at startup; there is no hot reload.
- App loading always uses the server-local standard `adb` client/server flow; there is no custom raw-ADB transport in `libadb`.
