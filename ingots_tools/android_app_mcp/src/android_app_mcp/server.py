from pathlib import Path

from libadb import AdbClient, AdbCommandError
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .adb_tools import read_text_file, write_text_file
from .frida_support import FridaManager


def create_server(adb: AdbClient, frida: FridaManager) -> FastMCP:
    server = FastMCP(
        name="android_app_mcp",
        instructions="Debug Android emulator apps through ADB-backed shell, file, install, and Frida instrumentation tools.",
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

    @server.tool(description="List Frida-visible Android apps.")
    def frida_list_apps() -> dict[str, list[dict[str, object | None]]]:
        try:
            return {"apps": frida.list_apps()}
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Attach Frida to a running Android app by package name.")
    def frida_attach(package_name: str) -> dict[str, object]:
        try:
            return frida.attach(package_name)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Spawn an Android app suspended and attach Frida immediately.")
    def frida_spawn(package_name: str) -> dict[str, object]:
        try:
            return frida.spawn(package_name)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Resume a previously spawned Frida session.")
    def frida_resume(session_id: str) -> dict[str, str]:
        try:
            return frida.resume(session_id)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Detach a Frida session and unload its scripts.")
    def frida_detach(session_id: str) -> dict[str, str]:
        try:
            return frida.detach(session_id)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Load a persistent Frida script into an attached session.")
    def frida_load_script(session_id: str, name: str, source: str) -> dict[str, str]:
        try:
            return frida.load_script(session_id, name, source)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Unload a persistent Frida script.")
    def frida_unload_script(script_id: str) -> dict[str, str]:
        try:
            return frida.unload_script(script_id)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Evaluate a one-shot Frida script in an attached session.")
    def frida_eval(session_id: str, source: str) -> dict[str, object]:
        try:
            return frida.eval(session_id, source)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Call an RPC export on a persistent Frida script.")
    def frida_rpc_call(
        script_id: str,
        method: str,
        args: list[object] | None = None,
    ) -> dict[str, object]:
        try:
            return frida.rpc_call(script_id, method, args=args)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(description="Fetch buffered Frida messages for a script.")
    def frida_get_messages(script_id: str, clear: bool = True) -> dict[str, object]:
        try:
            return frida.get_messages(script_id, clear=clear)
        except Exception as exc:
            raise ToolError(str(exc)) from exc

    return server
