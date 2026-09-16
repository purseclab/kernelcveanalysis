from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Never

import typer
from cuttle_types import InstanceLogsView, TemplateSummary
from typing_extensions import Annotated

from .client import CliError, CuttleClient, StopManyResult
from .config import CliConfigError
from .daemon import render_daemon_identity

app = typer.Typer(add_completion=False, no_args_is_help=True)
templates_app = typer.Typer(add_completion=False, no_args_is_help=True)
daemon_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(templates_app, name="templates")
app.add_typer(daemon_app, name="daemon")


@dataclass
class AppState:
    client: CuttleClient


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
        client = CuttleClient.from_config(
            server_host=server_host,
            server_port=server_port,
            auth_token=auth_token,
            user_id=user_id,
        )
    except CliConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    ctx.obj = AppState(client=client)


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
    unmanaged: Annotated[
        bool,
        typer.Option(
            "--unmanaged",
            help="Do not manage this instance's ADB connection with the local daemon.",
        ),
    ] = False,
) -> None:
    client = _client_from_ctx(ctx)
    try:
        result = client._start_with_progress(
            template_name,
            name=name,
            cpus=cpus,
            selinux=selinux,
            load_apps=load_apps,
            unmanaged=unmanaged,
            on_log_chunk=_echo_log_chunk,
        )
    except CliError as exc:
        _exit_with_error(exc)

    if not result.is_active:
        _echo_cuttlefish_diagnostic_logs(result.logs)
        detail = result.instance.failure_reason or "startup failed"
        typer.echo(
            f"failed to start {result.instance.instance_name}: {detail}",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(
        f"started {result.instance.instance_name} ({result.instance.instance_id}) "
        f"template={result.instance.template_name} state={result.instance.state.value} "
        f"adb={result.adb_target or '-'}"
    )


@app.command()
def restart(
    ctx: typer.Context,
    instance_name: Annotated[
        str,
        typer.Argument(
            help=(
                "Effective instance name to restart. Unnamed instances use their "
                "instance id."
            )
        ),
    ],
) -> None:
    try:
        result = _client_from_ctx(ctx)._restart_with_progress(
            instance_name,
            on_log_chunk=_echo_log_chunk,
        )
    except CliError as exc:
        _exit_with_error(exc)

    _echo_restart_stop_warning(result.logs)
    if not result.is_active:
        _echo_cuttlefish_diagnostic_logs(result.logs)
        detail = result.instance.failure_reason or "startup failed"
        typer.echo(
            f"failed to restart {result.instance.instance_name}: {detail}",
            err=True,
        )
        raise typer.Exit(code=1)

    typer.echo(
        f"restarted {result.instance.instance_name} ({result.instance.instance_id}) "
        f"template={result.instance.template_name} state={result.instance.state.value} "
        f"adb={result.adb_target or '-'}"
    )


@app.command(name="logs")
def show_logs(
    ctx: typer.Context,
    instance: Annotated[str, typer.Argument(help="Instance id or name.")],
) -> None:
    try:
        logs = _client_from_ctx(ctx).logs(instance)
    except CliError as exc:
        _exit_with_error(exc)
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
    client = _client_from_ctx(ctx)
    try:
        instances = client.list_instances(include_terminal=all_instances)
    except CliError as exc:
        _exit_with_error(exc)

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
    if sum(bool(value) for value in (instance_name, stop_all, stop_all_user)) != 1:
        typer.echo(
            "specify exactly one of INSTANCE_NAME, --stop-all, or --stop-all-user",
            err=True,
        )
        raise typer.Exit(code=1)

    client = _client_from_ctx(ctx)
    if instance_name is not None:
        try:
            instance = client.stop(instance_name)
        except CliError as exc:
            _exit_with_error(exc)
        typer.echo(
            f"stopped {instance.instance_name} ({instance.instance_id}) "
            f"state={instance.state.value}"
        )
        return

    try:
        result = (
            client.stop_all()
            if stop_all
            else client.stop_all_user(_required_user_id(stop_all_user))
        )
    except CliError as exc:
        _exit_with_error(exc)
    _render_stop_many(result)


@daemon_app.command("start")
def start_daemon(ctx: typer.Context) -> None:
    try:
        _client_from_ctx(ctx).daemon_start()
    except CliError as exc:
        _exit_with_error(exc)
    typer.echo("daemon started")


@daemon_app.command("stop")
def stop_daemon(ctx: typer.Context) -> None:
    try:
        stopped = _client_from_ctx(ctx).daemon_stop()
    except CliError as exc:
        _exit_with_error(exc)
    typer.echo("daemon stopped" if stopped else "daemon was not running")


@daemon_app.command("status")
def daemon_status(ctx: typer.Context) -> None:
    status = _client_from_ctx(ctx).daemon_status()
    if status.running and status.metadata is not None:
        typer.echo(
            f"running\tpid={status.metadata.pid}\t{render_daemon_identity(status.metadata)}"
        )
        return
    if status.stale and status.metadata is not None:
        typer.echo(
            f"stale\tpid={status.metadata.pid}\t{render_daemon_identity(status.metadata)}"
        )
        return
    typer.echo("stopped")


@daemon_app.command("sync")
def sync_daemon(ctx: typer.Context) -> None:
    try:
        endpoints = _client_from_ctx(ctx).daemon_sync()
    except CliError as exc:
        _exit_with_error(exc)
    typer.echo(f"synced {len(endpoints)} endpoints")


@daemon_app.command("run-internal", hidden=True)
def run_internal_daemon(ctx: typer.Context) -> None:
    try:
        _client_from_ctx(ctx)._run_daemon_forever()
    except CliError as exc:
        _exit_with_error(exc)


@templates_app.command(name="list")
def list_templates(ctx: typer.Context) -> None:
    try:
        templates = _client_from_ctx(ctx).list_templates()
    except CliError as exc:
        _exit_with_error(exc)

    if not templates:
        typer.echo("No templates.")
        return
    for template in templates:
        _echo_template_summary(template)


@templates_app.command(name="show")
def show_template(
    ctx: typer.Context,
    template_name: Annotated[str, typer.Argument(help="Template name to inspect.")],
) -> None:
    try:
        template = _client_from_ctx(ctx).show_template(template_name)
    except CliError as exc:
        _exit_with_error(exc)

    typer.echo(f"name: {template.template_name}")
    typer.echo(f"backend: {template.backend.value}")
    typer.echo(f"docker_image: {template.docker_image or '<none>'}")
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


def _render_stop_many(result: StopManyResult) -> None:
    if not result.stopped and not result.failures:
        typer.echo("No matching running instances.")
        return
    for instance in result.stopped:
        typer.echo(
            f"stopped {instance.instance_name} ({instance.instance_id}) "
            f"owner={instance.owner_id} state={instance.state.value}"
        )
    for failure in result.failures:
        typer.echo(
            f"failed to stop {failure.instance.instance_name} "
            f"({failure.instance.instance_id}): {failure.error_message}",
            err=True,
        )
    if not result.is_successful:
        raise typer.Exit(code=1)


def _format_columns(values: tuple[str, ...], widths: list[int]) -> str:
    padded = [value.ljust(width) for value, width in zip(values[:-1], widths[:-1])]
    padded.append(values[-1])
    return "  ".join(padded)


def _echo_template_summary(template: TemplateSummary) -> None:
    typer.echo(
        f"{template.template_name}\tcpus={template.cpus}\tselinux={template.selinux}"
        f"\tcommand_mode={template.command_mode.value}"
        f"\tbackend={template.backend.value}"
    )


def _echo_log_chunk(log_chunk: str) -> None:
    typer.echo(log_chunk, nl=False)


def _echo_restart_stop_warning(logs: InstanceLogsView) -> None:
    if not logs.stop_log.startswith("restart stop warning:"):
        return
    typer.echo("== restart stop warning ==", err=True)
    typer.echo(
        logs.stop_log,
        nl=not logs.stop_log.endswith("\n"),
        err=True,
    )


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
    _echo_cuttlefish_diagnostic_logs(logs)
    if not any(
        (
            logs.start_log,
            logs.stop_log,
            logs.kernel_log,
            logs.launcher_log,
            logs.logcat,
        )
    ):
        typer.echo("No logs.")


def _echo_cuttlefish_diagnostic_logs(logs: InstanceLogsView) -> None:
    for heading, contents in (
        ("kernel.log", logs.kernel_log),
        ("launcher.log", logs.launcher_log),
        ("logcat", logs.logcat),
    ):
        if not contents:
            continue
        typer.echo(f"== {heading} ==")
        typer.echo(contents, nl=not contents.endswith("\n"))


def _client_from_ctx(ctx: typer.Context) -> CuttleClient:
    state = ctx.obj
    if not isinstance(state, AppState):
        raise RuntimeError("CLI client has not been initialized")
    return state.client


def _required_user_id(user_id: str | None) -> str:
    if user_id is None:
        raise RuntimeError("stop-all-user mode requires a user id")
    return user_id


def _exit_with_error(error: CliError) -> Never:
    typer.echo(str(error), err=True)
    raise typer.Exit(code=1) from error


def main() -> None:
    app()


if __name__ == "__main__":
    main()
