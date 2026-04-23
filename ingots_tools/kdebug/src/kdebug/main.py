from __future__ import annotations

import json
from shlex import quote
import sys
from dataclasses import dataclass
from pathlib import Path

import typer
from typing_extensions import Annotated

from .client import KdebugDaemonClient
from .daemon import (
    CliError,
    ensure_daemon_running,
    normalize_target,
    run_daemon_forever,
    start_daemon,
    status_view,
    stop_daemon,
)
from .frida_core import FRIDA_SERVER_HOST_PATH
from .lldb_core import LLDB_SERVER_ASSET_ROOT

app = typer.Typer(add_completion=False, no_args_is_help=True)
daemon_app = typer.Typer(add_completion=False, no_args_is_help=True)
frida_app = typer.Typer(add_completion=False, no_args_is_help=True)
lldb_app = typer.Typer(add_completion=False, no_args_is_help=True, help="Native LLDB attach workflows over ADB.")
app.add_typer(daemon_app, name="daemon")
app.add_typer(frida_app, name="frida")
app.add_typer(lldb_app, name="lldb")


@dataclass
class AppState:
    target: str | None
    output_json: bool
    frida_server_path: Path
    lldb_server_root: Path


@app.callback()
def main_callback(
    ctx: typer.Context,
    device: Annotated[
        str | None,
        typer.Option("--device", help="ADB serial or host:port for the target device."),
    ] = None,
    adb_host: Annotated[
        str | None,
        typer.Option("--adb-host", help="ADB host for the target device."),
    ] = None,
    adb_port: Annotated[
        int | None,
        typer.Option("--adb-port", help="ADB port for the target device."),
    ] = None,
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON output."),
    ] = False,
    frida_server_path: Annotated[
        Path,
        typer.Option(
            "--frida-server-path",
            exists=False,
            dir_okay=False,
            readable=True,
            help="Path to the host frida-server binary.",
        ),
    ] = FRIDA_SERVER_HOST_PATH,
    lldb_server_root: Annotated[
        Path,
        typer.Option(
            "--lldb-server-root",
            exists=False,
            file_okay=False,
            readable=True,
            help="Root directory containing lldb-server binaries organized by ABI.",
        ),
    ] = LLDB_SERVER_ASSET_ROOT,
) -> None:
    if ctx.resilient_parsing or any(arg in {"--help", "-h"} for arg in sys.argv[1:]):
        return
    try:
        target = normalize_target(device=device, adb_host=adb_host, adb_port=adb_port)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    ctx.obj = AppState(
        target=target,
        output_json=output_json,
        frida_server_path=frida_server_path,
        lldb_server_root=lldb_server_root,
    )


@daemon_app.command("start")
def daemon_start(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    try:
        start_daemon(state.target, state.frida_server_path, state.lldb_server_root)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    _emit(ctx, {"status": "running", "target": state.target}, f"daemon running for {state.target}")


@daemon_app.command("stop")
def daemon_stop(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    try:
        stopped = stop_daemon(state.target, state.frida_server_path, state.lldb_server_root)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    message = f"daemon stopped for {state.target}" if stopped else f"daemon already stopped for {state.target}"
    _emit(ctx, {"status": "stopped" if stopped else "already_stopped", "target": state.target}, message)


@daemon_app.command("status")
def daemon_status(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    try:
        view = status_view(state.target, state.frida_server_path, state.lldb_server_root).model_dump(mode="json")
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if state.output_json:
        typer.echo(json.dumps(view, indent=2))
        return
    status = view["status"]
    if status == "running":
        typer.echo(f"running pid={view['pid']} target={view['target']} socket={view['socket_path']}")
        return
    if status == "stale":
        typer.echo(f"stale pid={view['pid']} target={view['target']} socket={view['socket_path']}")
        return
    typer.echo("stopped")


@daemon_app.command("run-internal", hidden=True)
def daemon_run_internal(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    run_daemon_forever(state.target, state.frida_server_path, state.lldb_server_root)


@frida_app.command("apps")
def frida_apps(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    client = _client_from_ctx(ctx)
    result = client.list_apps()
    if state.output_json:
        typer.echo(json.dumps(result, indent=2))
        return
    apps = result.get("apps", [])
    if not apps:
        typer.echo("No Frida-visible apps.")
        return
    for app_view in apps:
        pid = app_view["pid"] if app_view["pid"] is not None else "-"
        typer.echo(f"{app_view['identifier']}\t{app_view['name']}\tpid={pid}")


@frida_app.command("attach")
def frida_attach(ctx: typer.Context, package_name: str) -> None:
    result = _client_from_ctx(ctx).attach(package_name)
    _emit(ctx, result, _render_session(result))


@frida_app.command("spawn")
def frida_spawn(ctx: typer.Context, package_name: str) -> None:
    result = _client_from_ctx(ctx).spawn(package_name)
    _emit(ctx, result, _render_session(result))


@frida_app.command("resume")
def frida_resume(ctx: typer.Context, session_id: str) -> None:
    result = _client_from_ctx(ctx).resume(session_id)
    _emit(ctx, result, f"{result['status']} {result['session_id']}")


@frida_app.command("detach")
def frida_detach(ctx: typer.Context, session_id: str) -> None:
    result = _client_from_ctx(ctx).detach(session_id)
    _emit(ctx, result, f"{result['status']} {result['session_id']}")


@frida_app.command("sessions")
def frida_sessions(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    result = _client_from_ctx(ctx).list_sessions()
    if state.output_json:
        typer.echo(json.dumps(result, indent=2))
        return
    sessions = result.get("sessions", [])
    if not sessions:
        typer.echo("No active sessions.")
        return
    for session in sessions:
        typer.echo(
            f"{session['session_id']}\t{session['package_name']}\tpid={session['pid']}\tpaused={session['paused']}"
        )


@frida_app.command("scripts")
def frida_scripts(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    result = _client_from_ctx(ctx).list_scripts()
    if state.output_json:
        typer.echo(json.dumps(result, indent=2))
        return
    scripts = result.get("scripts", [])
    if not scripts:
        typer.echo("No loaded scripts.")
        return
    for script in scripts:
        typer.echo(
            f"{script['script_id']}\t{script['session_id']}\t{script['name']}\tbuffered={script['buffered_messages']}"
        )


@frida_app.command("load-script")
def frida_load_script(
    ctx: typer.Context,
    session_id: str,
    name: Annotated[str, typer.Option("--name", help="Human-readable script name.")],
    source: Annotated[str | None, typer.Option("--source", help="Inline Frida script source.")] = None,
    file: Annotated[Path | None, typer.Option("--file", help="Path to a Frida script file.")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read the script source from stdin.")] = False,
) -> None:
    script_source = _resolve_script_source(source=source, file=file, stdin=stdin)
    result = _client_from_ctx(ctx).load_script(session_id, name, script_source)
    _emit(ctx, result, f"loaded {result['script_id']} session={result['session_id']} name={result['name']}")


@frida_app.command("unload-script")
def frida_unload_script(ctx: typer.Context, script_id: str) -> None:
    result = _client_from_ctx(ctx).unload_script(script_id)
    _emit(ctx, result, f"{result['status']} {result['script_id']}")


@frida_app.command("eval")
def frida_eval(
    ctx: typer.Context,
    session_id: str,
    source: Annotated[str | None, typer.Option("--source", help="Inline Frida script source.")] = None,
    file: Annotated[Path | None, typer.Option("--file", help="Path to a Frida script file.")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read the script source from stdin.")] = False,
) -> None:
    script_source = _resolve_script_source(source=source, file=file, stdin=stdin)
    result = _client_from_ctx(ctx).eval(session_id, script_source)
    _emit(ctx, result, json.dumps(result, indent=2))


@frida_app.command("rpc")
def frida_rpc(ctx: typer.Context, script_id: str, method: str, args: list[str]) -> None:
    result = _client_from_ctx(ctx).rpc_call(script_id, method, args)
    _emit(ctx, result, json.dumps(result, indent=2))


@frida_app.command("messages")
def frida_messages(
    ctx: typer.Context,
    script_id: str,
    clear: Annotated[bool, typer.Option("--clear/--no-clear", help="Clear buffered messages after reading them.")] = True,
) -> None:
    result = _client_from_ctx(ctx).get_messages(script_id, clear=clear)
    _emit(ctx, result, json.dumps(result, indent=2))


@lldb_app.command("attach-package")
def lldb_attach_package(ctx: typer.Context, package_name: str) -> None:
    result = _client_from_ctx(ctx).lldb_attach_package(package_name)
    result["commands"] = _lldb_shell_commands(result)
    _emit(ctx, result, _render_lldb_attach(result))


@lldb_app.command("attach-pid")
def lldb_attach_pid(ctx: typer.Context, pid: int) -> None:
    result = _client_from_ctx(ctx).lldb_attach_pid(pid)
    result["commands"] = _lldb_shell_commands(result)
    _emit(ctx, result, _render_lldb_attach(result))


@lldb_app.command("sessions")
def lldb_sessions(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx, require_target=True)
    result = _client_from_ctx(ctx).lldb_list_sessions()
    if state.output_json:
        typer.echo(json.dumps(result, indent=2))
        return
    sessions = result.get("sessions", [])
    if not sessions:
        typer.echo("No active LLDB sessions.")
        return
    for session in sessions:
        typer.echo(
            f"{session['session_id']}\t{session['package_name']}\tpid={session['pid']}\t"
            f"local={session['local_port']}\tserver_pid={session['server_pid']}\tabi={session['abi']}"
        )


@lldb_app.command("stop")
def lldb_stop(ctx: typer.Context, session_id: str) -> None:
    result = _client_from_ctx(ctx).lldb_stop_session(session_id)
    _emit(ctx, result, f"{result['status']} {result['session_id']}")


@lldb_app.command("connect")
def lldb_connect(
    ctx: typer.Context,
    session_id: str,
    binary: Annotated[
        Path | None,
        typer.Option("--binary", exists=False, dir_okay=False, help="Host binary path for symbols."),
    ] = None,
    sysroot: Annotated[
        Path | None,
        typer.Option("--sysroot", exists=False, file_okay=False, help="Optional host sysroot for shared libraries."),
    ] = None,
) -> None:
    result = _client_from_ctx(ctx).lldb_get_connect_info(session_id)
    result["commands"] = _lldb_shell_commands(result, binary=binary, sysroot=sysroot)
    _emit(ctx, result, _render_lldb_connect(result))


def _state_from_ctx(ctx: typer.Context, *, require_target: bool) -> AppState:
    state = ctx.obj
    if not isinstance(state, AppState):
        raise typer.Exit(code=1)
    if require_target and not state.target:
        typer.echo("pass --device or --adb-host/--adb-port to select a target device", err=True)
        raise typer.Exit(code=1)
    return state


def _client_from_ctx(ctx: typer.Context) -> KdebugDaemonClient:
    state = _state_from_ctx(ctx, require_target=True)
    try:
        ensure_daemon_running(state.target, state.frida_server_path, state.lldb_server_root)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    return KdebugDaemonClient(state.target, state.frida_server_path, state.lldb_server_root)


def _resolve_script_source(*, source: str | None, file: Path | None, stdin: bool) -> str:
    selected = sum(bool(value) for value in (source, file, stdin))
    if selected != 1:
        raise typer.BadParameter("choose exactly one of --source, --file, or --stdin")
    if source is not None:
        return source
    if file is not None:
        return file.read_text(encoding="utf-8")
    return sys.stdin.read()


def _emit(ctx: typer.Context, data: dict[str, object], human_text: str) -> None:
    state = _state_from_ctx(ctx, require_target=False)
    if state.output_json:
        typer.echo(json.dumps(data, indent=2))
        return
    typer.echo(human_text)


def _render_session(data: dict[str, object]) -> str:
    return (
        f"session {data['session_id']} package={data['package_name']} "
        f"pid={data['pid']} paused={data['paused']}"
    )


def _lldb_shell_commands(
    info: dict[str, object],
    *,
    binary: Path | None = None,
    sysroot: Path | None = None,
) -> list[str]:
    commands: list[str] = []
    connect_port = int(info.get("connect_port", info["local_port"]))
    if sysroot is not None:
        commands.append(f"-o {quote(f'settings set target.sysroot {sysroot}')}")
    if binary is not None:
        commands.append(f"-o {quote(f'target create {binary}')}")
    commands.append(f"-o {quote(f'gdb-remote 127.0.0.1:{connect_port}')}")
    return [f"lldb {' '.join(commands)}"]


def _render_lldb_attach(data: dict[str, object]) -> str:
    commands = data.get("commands", [])
    shell_command = commands[0] if isinstance(commands, list) and commands else ""
    return (
        f"session {data['session_id']} package={data['package_name']} pid={data['pid']} "
        f"local=127.0.0.1:{data['local_port']} abi={data['abi']}\n"
        f"run:\n{shell_command}"
    )


def _render_lldb_connect(data: dict[str, object]) -> str:
    commands = data.get("commands", [])
    shell_command = commands[0] if isinstance(commands, list) and commands else ""
    return (
        f"session {data['session_id']} local=127.0.0.1:{data['connect_port']}\n"
        f"run:\n{shell_command}"
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
