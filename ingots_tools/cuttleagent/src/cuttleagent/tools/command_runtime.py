from typing import Protocol

from langchain.tools import BaseTool, tool


class CommandRuntime(Protocol):
    def exec(self, command: list[str]) -> str | None: ...


def create_runtime_tool(
    runtime: CommandRuntime, name: str, description: str
) -> BaseTool:
    @tool(name, description=description)
    def run_command(command: list[str]) -> str:
        try:
            result = runtime.exec(command)
            if result is None:
                raise Exception("Result was None")
            return result
        except Exception as e:
            return f"Error: {str(e)}"

    return run_command
