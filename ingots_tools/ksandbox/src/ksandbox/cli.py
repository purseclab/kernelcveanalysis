from __future__ import annotations

import typer

from .docker_sandbox import DockerSandboxProvider
from .logging_utils import configure_logging
from .tool_bundle import ensure_tool_bundle

app = typer.Typer()


@app.command("setup", help="Build and cache the static in-container tools")
def setup(
    force: bool = typer.Option(False, "--force", help="Rebuild an existing bundle."),
) -> None:
    path = ensure_tool_bundle(force=force)
    typer.echo(str(path))


@app.command("list", help="List ksandbox containers")
def list_sandboxes(
    status: str | None = typer.Option(None, help="Optional Docker status filter."),
) -> None:
    provider = DockerSandboxProvider.get()
    for sandbox in provider.list(status=status):
        typer.echo(
            f"{sandbox.id}\t{sandbox.status}\t{sandbox.state}\t{sandbox.name}\t{sandbox.image}"
        )


@app.command("start", help="Start a stopped ksandbox container")
def start_sandbox(sandbox_id: str) -> None:
    DockerSandboxProvider.get()._start_from_cli(sandbox_id)


@app.command("stop", help="Stop a running ksandbox container")
def stop_sandbox(sandbox_id: str) -> None:
    DockerSandboxProvider.get()._stop_from_cli(sandbox_id)


@app.command("delete", help="Delete a ksandbox container")
def delete_sandbox(
    sandbox_id: str,
    force: bool = typer.Option(False, "--force", help="Allow deletion of a running sandbox."),
) -> None:
    DockerSandboxProvider.get().delete(sandbox_id, force=force)


def main() -> None:
    configure_logging(default_level="INFO")
    app()
