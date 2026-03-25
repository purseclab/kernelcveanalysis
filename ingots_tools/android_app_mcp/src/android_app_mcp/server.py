from pathlib import Path

from libadb import AdbClient, AdbCommandError
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .adb_tools import read_text_file, write_text_file


def create_server(adb: AdbClient) -> FastMCP:
    server = FastMCP(
        name="android_app_mcp",
        instructions="Debug Android emulator apps through ADB-backed shell, file, and install tools.",
    )

    @server.tool(description="Run a shell command inside the Android emulator.")
    def run_shell(command: str, root: bool = False) -> dict[str, str]:
        try:
            return {"output": adb.shell_text(command, root=root)}
        except AdbCommandError as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Read a UTF-8 text file from the Android emulator.")
    def read_file(path: str, root: bool = False) -> dict[str, str]:
        try:
            content = read_text_file(adb, path, root=root)
        except (AdbCommandError, ValueError) as exc:
            raise ToolError(str(exc)) from exc
        return {"path": path, "content": content}

    @server.tool(description="Write a UTF-8 text file into the Android emulator.")
    def write_file(
        path: str,
        content: str,
        root: bool = False,
        create_parents: bool = False,
    ) -> dict[str, int | str]:
        try:
            bytes_written = write_text_file(
                adb,
                path,
                content,
                root=root,
                create_parents=create_parents,
            )
        except AdbCommandError as exc:
            raise ToolError(str(exc)) from exc
        return {"path": path, "bytes_written": bytes_written}

    @server.tool(description="Install an APK from the host into the Android emulator.")
    def install_app(apk_path: str) -> dict[str, str]:
        apk = Path(apk_path)
        if not apk.exists():
            raise ToolError(f"APK does not exist: {apk_path}")
        if not apk.is_file():
            raise ToolError(f"APK path is not a file: {apk_path}")

        try:
            adb.install_app(apk)
        except Exception as exc:
            raise ToolError(f"Failed to install APK `{apk_path}`: {exc}") from exc
        return {"apk_path": apk_path, "status": "installed"}

    return server
