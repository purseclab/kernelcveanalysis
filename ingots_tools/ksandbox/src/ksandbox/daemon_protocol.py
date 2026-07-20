from __future__ import annotations

import base64
import socket
from typing import Annotated, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

SOCKET_NAME = "daemon.sock"


class ProtocolMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthRequest(ProtocolMessage):
    type: Literal["health"] = "health"


class SpawnRequest(ProtocolMessage):
    type: Literal["spawn"] = "spawn"
    argv: list[str] | None = None
    command: str | None = None
    shell: bool = False
    cwd: str | None = None
    env: dict[str, str] | None = None

    @model_validator(mode="after")
    def validate_command_spec(self) -> Self:
        if self.shell:
            if self.command is None or self.argv is not None:
                raise ValueError("shell spawn requires command and forbids argv")
        elif self.command is not None or not self.argv:
            raise ValueError("direct spawn requires a non-empty argv and forbids command")
        return self


class StdinRequest(ProtocolMessage):
    type: Literal["stdin"] = "stdin"
    request_id: str
    data_b64: str


class CloseStdinRequest(ProtocolMessage):
    type: Literal["close_stdin"] = "close_stdin"
    request_id: str


class KillRequest(ProtocolMessage):
    type: Literal["kill"] = "kill"
    request_id: str
    signal: int = 9


class ReadFileRequest(ProtocolMessage):
    type: Literal["read_file"] = "read_file"
    path: str


class WriteFileRequest(ProtocolMessage):
    type: Literal["write_file"] = "write_file"
    path: str
    content_b64: str
    overwrite: bool = False


class EditFileRequest(ProtocolMessage):
    type: Literal["edit_file"] = "edit_file"
    path: str
    old_b64: str
    new_b64: str
    replace_all: bool = False


class ListDirectoryRequest(ProtocolMessage):
    type: Literal["list_directory"] = "list_directory"
    path: str


class GrepRequest(ProtocolMessage):
    type: Literal["grep"] = "grep"
    pattern: str
    path: str | None = None
    glob: str | None = None
    timeout_secs: int | None = None


class GlobRequest(ProtocolMessage):
    type: Literal["glob"] = "glob"
    pattern: str
    path: str = "/"
    timeout_secs: int | None = None


class HealthResponse(ProtocolMessage):
    type: Literal["health"] = "health"
    status: Literal["ok"] = "ok"


class SpawnedEvent(ProtocolMessage):
    type: Literal["spawned"] = "spawned"


class OutputEvent(ProtocolMessage):
    type: Literal["stdout", "stderr"]
    data_b64: str


class ExitEvent(ProtocolMessage):
    type: Literal["exit"] = "exit"
    exit_code: int


class ErrorEvent(ProtocolMessage):
    type: Literal["error"] = "error"
    message: str


class StdinResponse(ProtocolMessage):
    type: Literal["stdin_result"] = "stdin_result"
    request_id: str
    error: str | None = None


class CloseStdinResponse(ProtocolMessage):
    type: Literal["close_stdin_result"] = "close_stdin_result"
    request_id: str
    error: str | None = None


class KillResponse(ProtocolMessage):
    type: Literal["kill_result"] = "kill_result"
    request_id: str
    delivered: bool


FileOperationError = Literal[
    "file_not_found",
    "permission_denied",
    "is_directory",
    "invalid_path",
    "already_exists",
    "unknown_error",
]

EditFileError = Literal[
    "file_not_found",
    "permission_denied",
    "is_directory",
    "invalid_path",
    "string_not_found",
    "multiple_occurrences",
    "unknown_error",
]


class ReadFileResponse(ProtocolMessage):
    type: Literal["read_file_result"] = "read_file_result"
    path: str
    content_b64: str | None = None
    error: FileOperationError | None = None


class WriteFileResponse(ProtocolMessage):
    type: Literal["write_file_result"] = "write_file_result"
    path: str
    error: FileOperationError | None = None


class EditFileResponse(ProtocolMessage):
    type: Literal["edit_file_result"] = "edit_file_result"
    path: str
    occurrences: int = 0
    error: EditFileError | None = None


class DirectoryEntry(ProtocolMessage):
    path: str
    is_dir: bool


class ListDirectoryResponse(ProtocolMessage):
    type: Literal["list_directory_result"] = "list_directory_result"
    entries: list[DirectoryEntry] = []
    error: FileOperationError | None = None


class GrepMatchEntry(ProtocolMessage):
    path: str
    line: int
    text: str


class GrepResponse(ProtocolMessage):
    type: Literal["grep_result"] = "grep_result"
    matches: list[GrepMatchEntry] = []
    timed_out: bool = False
    error: str | None = None


class GlobResponse(ProtocolMessage):
    type: Literal["glob_result"] = "glob_result"
    entries: list[DirectoryEntry] = []
    timed_out: bool = False
    error: str | None = None


DaemonRequest = Annotated[
    HealthRequest
    | SpawnRequest
    | StdinRequest
    | CloseStdinRequest
    | KillRequest
    | ReadFileRequest
    | WriteFileRequest
    | EditFileRequest
    | ListDirectoryRequest
    | GrepRequest
    | GlobRequest,
    Field(discriminator="type"),
]
DaemonResponse = Annotated[
    HealthResponse
    | SpawnedEvent
    | OutputEvent
    | ExitEvent
    | ErrorEvent
    | StdinResponse
    | CloseStdinResponse
    | KillResponse
    | ReadFileResponse
    | WriteFileResponse
    | EditFileResponse
    | ListDirectoryResponse
    | GrepResponse
    | GlobResponse,
    Field(discriminator="type"),
]

REQUEST_ADAPTER: TypeAdapter[DaemonRequest] = TypeAdapter(DaemonRequest)
RESPONSE_ADAPTER: TypeAdapter[DaemonResponse] = TypeAdapter(DaemonResponse)

MessageT = TypeVar("MessageT")


def encode_chunk(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_chunk(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def send_message(sock: socket.socket, payload: ProtocolMessage) -> None:
    message = payload.model_dump_json(exclude_none=True).encode("utf-8") + b"\n"
    sock.sendall(message)


def read_message(reader, adapter: TypeAdapter[MessageT]) -> MessageT | None:
    line = reader.readline()
    if not line:
        return None
    return adapter.validate_json(line)
