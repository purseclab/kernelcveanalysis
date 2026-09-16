# Cuttle CLI

`cuttle_cli` is a Typer-based client for `cuttle_server`.

It can also be used directly as a synchronous Python library. The high-level
client reads the same configuration and exposes the same operations as the CLI:

```python
from cuttle_cli import CuttleClient

client = CuttleClient.from_config()

start_result = client.start(
    "phone",
    name="research-device",
    cpus=6,
    load_apps=False,
)
if not start_result.is_active:
    raise RuntimeError(start_result.instance.failure_reason or "startup failed")

for instance in client.list_instances():
    print(instance.instance_name, client.adb_target(instance))

logs = client.logs("research-device")
print(logs.kernel_log)
restart_result = client.restart("research-device")
if not restart_result.is_active:
    raise RuntimeError(restart_result.instance.failure_reason or "restart failed")
client.stop("research-device")
```

`start`, `restart`, `list_instances`, `stop`, `stop_all`, and `stop_all_user`
ensure the managed ADB daemon is running, matching the corresponding CLI
behavior. Bulk stop methods return a `StopManyResult` containing both successful
stops and typed per-instance failures. Explicit daemon operations are available
as `daemon_start`, `daemon_stop`, `daemon_status`, and `daemon_sync`.

The complete high-level method set is:

- `start(..., unmanaged=False) -> StartResult`
- `restart(instance_name) -> StartResult`
- `list_instances(...) -> list[InstanceView]`
- `logs(instance_id_or_name) -> InstanceLogsView`
- `stop(instance_name) -> InstanceView`
- `stop_all() -> StopManyResult`
- `stop_all_user(user_id) -> StopManyResult`
- `list_templates() -> list[TemplateSummary]`
- `show_template(template_name) -> TemplateView`
- `daemon_start()`, `daemon_stop()`, `daemon_status()`, and `daemon_sync()`

`start()` and `restart()` wait for the instance to leave `starting`, return its
final state and logs, and consider only `StartResult.is_active` successful.
`restart()` preserves the effective name, instance id, resolved launch settings,
ADB target, and managed/unmanaged setting while resetting the lease to the
server default. Transport, server, and managed-daemon failures raise `CliError`.

Default config path (provided by `platformdirs`):

```text
macOS: ~/Library/Application Support/cuttle_cli/config.toml
Linux: ~/.config/cuttle_cli/config.toml
```

State files for the managed daemon live under the platform-specific user state
directory:

```text
macOS: ~/Library/Application Support/cuttle_cli/
Linux: ~/.local/state/cuttle_cli/
```

Supported commands:

- `uv run cuttle-cli start <template-name>`
- `uv run cuttle-cli start <template-name> --unmanaged`
- `uv run cuttle-cli restart <instance-name>`
- `uv run cuttle-cli list`
- `uv run cuttle-cli list --all`
- `uv run cuttle-cli logs <instance-id-or-name>`
- `uv run cuttle-cli stop <instance-name>`
- `uv run cuttle-cli stop --stop-all`
- `uv run cuttle-cli stop --stop-all-user <user-id>`
- `uv run cuttle-cli templates list`
- `uv run cuttle-cli templates show <template-name>`
- `uv run cuttle-cli daemon start`
- `uv run cuttle-cli daemon stop`
- `uv run cuttle-cli daemon status`
- `uv run cuttle-cli daemon sync`

The CLI auto-starts the managed daemon for `start`, `restart`, `list`, and `stop`.
The daemon keeps the local shared ADB server in sync with the current user's
visible instances by issuing `adb connect` and `adb disconnect` against
`<server_host>:<adb_port>`. After a successful restart, the client also issues a
fresh `adb connect` for the unchanged target.

`start` also supports `--load-apps/--no-load-apps` to control whether the server should auto-install the template APK list during instance startup.
Pass `--unmanaged` when the instance's ADB endpoint will be managed externally,
such as when forwarding it into a Docker container. Unmanaged endpoints are
persisted across restart and are never connected or disconnected by the local
managed daemon; the flag defaults to false.
`start` prints new CVD launch log output while the instance is starting.
`list` shows only non-terminal instances by default; pass `--all` or `-a` to include stopped, crashed, and expired instances.
`logs` prints the latest CVD start/stop output plus Cuttlefish `kernel.log`,
`launcher.log`, and `logcat` for a visible instance by id or name. These
diagnostic logs are also printed automatically when `start` fails.
`restart` accepts the effective name of an active instance, performs a clean
launch with the same persisted settings and ADB port, and resets its lease. A
failure from the old runtime's stop command is displayed as a warning but does
not prevent startup from being attempted.
`stop` can target one instance by effective name, `--stop-all` visible non-terminal instances, or `--stop-all-user <user-id>` for a specific visible owner.
`templates list` and `templates show` include each template's CVD command mode
and host/Docker backend. `templates show` also reports the resolved Docker image.

Minimal config shape:

```toml
server_host = "example.com"
server_port = 8000
auth_token = "replace-me"
user_id = "alice"
```
