from typing_extensions import Annotated

import typer
from libadb import AdbClient

from .server import create_server

app = typer.Typer()


@app.command(help="Run the Android app MCP server over stdio.")
def serve(
    adb_host: Annotated[str, typer.Option("--adb-host", help="ADB host for the target emulator.")] = "0.0.0.0",
    adb_port: Annotated[int, typer.Option("--adb-port", help="ADB port for the target emulator.")] = 6532,
):
    adb = AdbClient(f"{adb_host}:{adb_port}")
    adb.upload_tools()
    server = create_server(adb)
    server.run(transport="stdio")


def main():
    app()


if __name__ == "__main__":
    main()
