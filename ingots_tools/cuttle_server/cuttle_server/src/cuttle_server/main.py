from __future__ import annotations

from pathlib import Path

import typer
import uvicorn
from typing_extensions import Annotated

from .api import create_app
from .config import ConfigError, load_settings

app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
)


@app.command(name=None)
def serve(
    config_dir: Annotated[
        Path,
        typer.Argument(
            help="Directory containing cuttle_server.toml and the templates/ folder."
        ),
    ],
    host: Annotated[
        str | None,
        typer.Option("--host", help="Override the configured FastAPI bind host."),
    ] = None,
    port: Annotated[
        int | None,
        typer.Option("--port", help="Override the configured FastAPI bind port."),
    ] = None,
) -> None:
    try:
        settings = load_settings(config_dir)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    uvicorn.run(
        create_app(settings),
        host=host or settings.server_host,
        port=port or settings.server_port,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
