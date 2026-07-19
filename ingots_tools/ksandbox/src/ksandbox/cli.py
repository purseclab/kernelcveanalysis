from __future__ import annotations

import typer
from pathlib import Path

from .docker_sandbox import DockerSandboxProvider
from .logging_utils import configure_logging, get_logger
from .tool_bundle import ensure_tool_bundle

app = typer.Typer()
logger = get_logger(__name__)


@app.command("setup", help="Build and cache the static in-container tools")
def setup(
    force: bool = typer.Option(False, "--force", help="Rebuild an existing bundle."),
) -> None:
    configure_logging(default_level="INFO")
    path = ensure_tool_bundle(force=force)
    typer.echo(str(path))


@app.command("build-image", help="Build a Docker image for use by ksandbox")
def build_image(
    context: Path | None = typer.Argument(
        None, help="Docker build context; defaults to the ksandbox package."
    ),
    dockerfile: str | None = typer.Option(
        None, "--dockerfile", "-f", help="Dockerfile path relative to the context."
    ),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Resulting image tag."),
) -> None:
    configure_logging(default_level="INFO")
    provider = DockerSandboxProvider.get()
    logger.info("Building sandbox image")
    provider.build_image(context, dockerfile=dockerfile, tag=tag)


@app.command("list", help="List ksandbox containers")
def list_sandboxes(
    status: str | None = typer.Option(None, help="Optional Docker status filter."),
) -> None:
    configure_logging(default_level="INFO")
    provider = DockerSandboxProvider.get()
    for container in provider.list(status=status):
        typer.echo(
            f"{container.id}\t{container.status}\t{container.name}\t{container.image}"
        )


@app.command("delete", help="Delete a ksandbox container")
def delete_sandbox(
    sandbox_id: str,
    force: bool = typer.Option(True, "--force/--no-force"),
) -> None:
    configure_logging(default_level="INFO")
    DockerSandboxProvider.get().delete(sandbox_id, force=force)


def main() -> None:
    app()
