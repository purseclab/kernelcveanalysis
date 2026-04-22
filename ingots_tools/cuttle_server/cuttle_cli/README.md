# Cuttle CLI

`cuttle_cli` is a Typer-based client for `cuttle_server`.

Default config path:

```text
~/.config/cuttle_cli/config.toml
```

State files for the managed daemon live under:

```text
~/.local/state/cuttle_cli/
```

Supported commands:

- `uv run cuttle_cli start <template-name>`
- `uv run cuttle_cli list`
- `uv run cuttle_cli list --all`
- `uv run cuttle_cli stop <instance-name>`
- `uv run cuttle_cli templates list`
- `uv run cuttle_cli templates show <template-name>`
- `uv run cuttle_cli daemon start`
- `uv run cuttle_cli daemon stop`
- `uv run cuttle_cli daemon status`
- `uv run cuttle_cli daemon sync`

The CLI auto-starts the managed daemon for `start`, `list`, and `stop`. The daemon keeps the local shared ADB server in sync with the current user's visible instances by issuing `adb connect` and `adb disconnect` against `<server_host>:<adb_port>`.

`start` also supports `--load-apps/--no-load-apps` to control whether the server should auto-install the template APK list during instance startup.
`list` shows only non-terminal instances by default; pass `--all` or `-a` to include stopped, crashed, and expired instances.

Minimal config shape:

```toml
server_host = "example.com"
server_port = 8000
auth_token = "replace-me"
user_id = "alice"
```
