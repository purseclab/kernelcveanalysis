from __future__ import annotations

from dataclasses import dataclass
import sys
import time

import typer
from cuttle_types import (
    CreateInstanceRequest,
    InstanceLogsView,
    InstanceState,
    InstanceView,
    LaunchOverrides,
    TemplateSummary,
)
from typing_extensions import Annotated

from .client import CliError, CuttleApiClient
from .config import CliConfigError, CliSettings, load_cli_settings
from .daemon import (
    ensure_managed_daemon_running,
    get_daemon_status,
    render_daemon_identity,
    run_daemon_forever,
    start_managed_daemon,
    stop_managed_daemon,
    sync_managed_daemon_once,
)

app = typer.Typer(add_completion=False, no_args_is_help=True)
templates_app = typer.Typer(add_completion=False, no_args_is_help=True)
daemon_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(templates_app, name="templates")
app.add_typer(daemon_app, name="daemon")

VISIBLE_INSTANCE_STATES = frozenset(
    {InstanceState.STARTING, InstanceState.ACTIVE, InstanceState.STOPPING}
)


@dataclass
class AppState:
    client: CuttleApiClient
    settings: CliSettings


@app.callback()
def main_callback(
    ctx: typer.Context,
    server_host: Annotated[
        str | None, typer.Option("--server-host", help="Override configured server host.")
    ] = None,
    server_port: Annotated[
        int | None, typer.Option("--server-port", help="Override configured server port.")
    ] = None,
    auth_token: Annotated[
        str | None, typer.Option("--auth-token", help="Override configured auth token.")
    ] = None,
    user_id: Annotated[
        str | None, typer.Option("--user-id", help="Override configured user id.")
    ] = None,
) -> None:
    if ctx.resilient_parsing or any(arg in {"--help", "-h"} for arg in sys.argv[1:]):
        return
    try:
        settings = load_cli_settings(
            server_host=server_host,
            server_port=server_port,
            auth_token=auth_token,
            user_id=user_id,
        )
    except CliConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    ctx.obj = AppState(client=CuttleApiClient.from_settings(settings), settings=settings)


@app.command()
def start(
    ctx: typer.Context,
    template_name: Annotated[str, typer.Argument(help="Template name to launch.")],
    name: Annotated[
        str | None,
        typer.Option("--name", help="Optional user-facing instance name."),
    ] = None,
    cpus: Annotated[
        int | None,
        typer.Option("--cpus", help="Optional CPU count override."),
    ] = None,
    selinux: Annotated[
        bool | None,
        typer.Option(
            "--selinux",
            help="Optional SELinux override. Pass true or false.",
        ),
    ] = None,
    load_apps: Annotated[
        bool | None,
        typer.Option(
            "--load-apps/--no-load-apps",
            help="Whether to auto-install template apps during startup.",
        ),
    ] = None,
) -> None:
    state = _state_from_ctx(ctx)
    _ensure_daemon_running_or_exit(state.settings)
    client = state.client
    try:
        response = client.start_instance(
            CreateInstanceRequest(
                template_name=template_name,
                instance_name=name,
                overrides=LaunchOverrides(
                    cpus=cpus,
                    selinux=selinux,
                    load_apps=load_apps,
                ),
            ),
            async_start=True,
        )
        instance = response.instance
        printed_log_chars = 0
        while instance.state == InstanceState.STARTING:
            logs = client.get_instance_logs(instance.instance_id)
            printed_log_chars = _echo_new_log_text(
                logs.start_log,
                printed_log_chars,
            )
            instance = client.get_instance(instance.instance_id)
            if instance.state == InstanceState.STARTING:
                time.sleep(1)
        logs = client.get_instance_logs(instance.instance_id)
        _echo_new_log_text(logs.start_log, printed_log_chars)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    if instance.state == InstanceState.CRASHED:
        detail = instance.failure_reason or "startup failed"
        typer.echo(f"failed to start {instance.instance_name}: {detail}", err=True)
        raise typer.Exit(code=1)

    adb_target = client.adb_target(instance) or "-"
    typer.echo(
        f"started {instance.instance_name} ({instance.instance_id}) "
        f"template={instance.template_name} state={instance.state.value} "
        f"adb={adb_target}"
    )


@app.command(name="logs")
def show_logs(
    ctx: typer.Context,
    instance: Annotated[str, typer.Argument(help="Instance id or name.")],
) -> None:
    client = _client_from_ctx(ctx)
    try:
        logs = _get_logs_by_id_or_name(client, instance)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    _echo_logs_view(logs)


@app.command(name="list")
def list_instances(
    ctx: typer.Context,
    all_instances: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Show all instances, including stopped, crashed, and expired ones.",
        ),
    ] = False,
) -> None:
    state = _state_from_ctx(ctx)
    _ensure_daemon_running_or_exit(state.settings)
    client = state.client
    try:
        response = client.list_instances()
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    instances = (
        response.instances
        if all_instances
        else [
            instance
            for instance in response.instances
            if _is_default_list_state(instance)
        ]
    )

    if not instances:
        typer.echo("No instances.")
        return

    headers = (
        "instance_name",
        "instance_id",
        "state",
        "template",
        "owner",
        "adb_target",
    )
    rows = [
        (
            instance.instance_name,
            instance.instance_id,
            instance.state.value,
            instance.template_name,
            instance.owner_id,
            client.adb_target(instance) or "-",
        )
        for instance in instances
    ]
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    typer.echo(_format_columns(headers, widths))
    for row in rows:
        typer.echo(_format_columns(row, widths))


@app.command()
def stop(
    ctx: typer.Context,
    instance_name: Annotated[
        str | None,
        typer.Argument(
            help="Effective instance name to stop. Unnamed instances use their instance id."
        ),
    ] = None,
    stop_all: Annotated[
        bool,
        typer.Option(
            "--stop-all",
            help="Stop all visible non-terminal instances you have permission to stop.",
        ),
    ] = False,
    stop_all_user: Annotated[
        str | None,
        typer.Option(
            "--stop-all-user",
            help="Stop all visible non-terminal instances owned by the given user.",
        ),
    ] = None,
) -> None:
    state = _state_from_ctx(ctx)
    _ensure_daemon_running_or_exit(state.settings)
    client = state.client
    if sum(bool(value) for value in (instance_name, stop_all, stop_all_user)) != 1:
        typer.echo(
            "specify exactly one of INSTANCE_NAME, --stop-all, or --stop-all-user",
            err=True,
        )
        raise typer.Exit(code=1)

    if instance_name is not None:
        try:
            instance = client.stop_instance_by_name(instance_name)
        except CliError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc

        typer.echo(
            f"stopped {instance.instance_name} ({instance.instance_id}) "
            f"state={instance.state.value}"
        )
        return

    try:
        visible_instances = client.list_instances().instances
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    instances_to_stop = [
        instance
        for instance in visible_instances
        if _is_default_list_state(instance)
        and (stop_all or instance.owner_id == stop_all_user)
    ]
    if not instances_to_stop:
        typer.echo("No matching running instances.")
        return

    failure = False
    for instance in instances_to_stop:
        try:
            stopped = client.stop_instance(instance.instance_id)
        except CliError as exc:
            typer.echo(
                f"failed to stop {instance.instance_name} ({instance.instance_id}): {exc}",
                err=True,
            )
            failure = True
            continue

        typer.echo(
            f"stopped {stopped.instance_name} ({stopped.instance_id}) "
            f"owner={stopped.owner_id} state={stopped.state.value}"
        )

    if failure:
        raise typer.Exit(code=1)


def _format_columns(values: tuple[str, ...], widths: list[int]) -> str:
    padded = [value.ljust(width) for value, width in zip(values[:-1], widths[:-1])]
    padded.append(values[-1])
    return "  ".join(padded)


def _is_default_list_state(instance: InstanceView) -> bool:
    return instance.state in VISIBLE_INSTANCE_STATES


@daemon_app.command("start")
def start_daemon(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx)
    try:
        start_managed_daemon(state.settings)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("daemon started")


@daemon_app.command("stop")
def stop_daemon() -> None:
    try:
        stopped = stop_managed_daemon()
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("daemon stopped" if stopped else "daemon was not running")


@daemon_app.command("status")
def daemon_status() -> None:
    status = get_daemon_status()
    if status.running and status.metadata is not None:
        typer.echo(f"running\tpid={status.metadata.pid}\t{render_daemon_identity(status.metadata)}")
        return
    if status.stale and status.metadata is not None:
        typer.echo(f"stale\tpid={status.metadata.pid}\t{render_daemon_identity(status.metadata)}")
        return
    typer.echo("stopped")


@daemon_app.command("sync")
def sync_daemon(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx)
    status = get_daemon_status()
    if status.running:
        typer.echo("daemon is already running; stop it before manual sync", err=True)
        raise typer.Exit(code=1)
    try:
        endpoints = sync_managed_daemon_once(state.settings)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"synced {len(endpoints)} endpoints")


@daemon_app.command("run-internal", hidden=True)
def run_internal_daemon(ctx: typer.Context) -> None:
    state = _state_from_ctx(ctx)
    try:
        run_daemon_forever(state.settings)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@templates_app.command(name="list")
def list_templates(ctx: typer.Context) -> None:
    client = _client_from_ctx(ctx)
    try:
        response = client.list_templates()
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    if not response.templates:
        typer.echo("No templates.")
        return

    for template in response.templates:
        _echo_template_summary(template)


@templates_app.command(name="show")
def show_template(
    ctx: typer.Context,
    template_name: Annotated[str, typer.Argument(help="Template name to inspect.")],
) -> None:
    client = _client_from_ctx(ctx)
    try:
        template = client.get_template(template_name)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"name: {template.template_name}")
    typer.echo(f"runtime_root: {template.runtime_root}")
    typer.echo(f"command_mode: {template.command_mode.value}")
    typer.echo(f"cpus: {template.cpus}")
    typer.echo(f"kernel_path: {template.kernel_path or '<default>'}")
    typer.echo(f"initrd_path: {template.initrd_path or '<default>'}")
    typer.echo(f"selinux: {template.selinux}")
    if template.apps:
        typer.echo("apps:")
        for app_path in template.apps:
            typer.echo(f"  {app_path}")
    else:
        typer.echo("apps: []")


def _echo_template_summary(template: TemplateSummary) -> None:
    typer.echo(
        f"{template.template_name}\tcpus={template.cpus}\tselinux={template.selinux}"
        f"\tcommand_mode={template.command_mode.value}"
    )


def _echo_new_log_text(log_text: str, offset: int) -> int:
    if len(log_text) <= offset:
        return offset
    typer.echo(log_text[offset:], nl=False)
    return len(log_text)


def _get_logs_by_id_or_name(client: CuttleApiClient, identifier: str) -> InstanceLogsView:
    first_error: CliError | None = None
    try:
        return client.get_instance_logs(identifier)
    except CliError as exc:
        first_error = exc

    response = client.list_instances()
    matches = [
        instance
        for instance in response.instances
        if instance.instance_id == identifier or instance.instance_name == identifier
    ]
    if len(matches) == 1:
        return client.get_instance_logs(matches[0].instance_id)
    if len(matches) > 1:
        raise CliError(f"multiple visible instances match {identifier!r}")
    assert first_error is not None
    raise first_error


def _echo_logs_view(logs: InstanceLogsView) -> None:
    typer.echo(
        f"instance={logs.instance_name} ({logs.instance_id}) state={logs.state.value}"
    )
    if logs.failure_reason:
        typer.echo(f"failure_reason: {logs.failure_reason}")
    if logs.launch_command:
        typer.echo(f"launch_command: {' '.join(logs.launch_command)}")
    if logs.start_log:
        typer.echo("== cvd start ==")
        typer.echo(logs.start_log, nl=not logs.start_log.endswith("\n"))
    if logs.stop_log:
        typer.echo("== cvd stop ==")
        typer.echo(logs.stop_log, nl=not logs.stop_log.endswith("\n"))
    if not logs.start_log and not logs.stop_log:
        typer.echo("No logs.")


def _client_from_ctx(ctx: typer.Context) -> CuttleApiClient:
    return _state_from_ctx(ctx).client


def _state_from_ctx(ctx: typer.Context) -> AppState:
    state = ctx.obj
    if not isinstance(state, AppState):
        raise RuntimeError("CLI client has not been initialized")
    return state


def _ensure_daemon_running_or_exit(settings: CliSettings) -> None:
    try:
        ensure_managed_daemon_running(settings)
    except CliError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


def main() -> None:
    app()


if __name__ == "__main__":
    main()
