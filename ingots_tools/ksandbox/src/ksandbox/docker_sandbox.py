from __future__ import annotations

import os
import shutil
import socket
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Self, Sequence

import docker  # type: ignore

from .daemon_protocol import (
    RESPONSE_ADAPTER,
    SOCKET_NAME,
    EditFileError,
    EditFileRequest,
    EditFileResponse,
    ErrorEvent,
    ExitEvent,
    FileOperationError,
    GlobRequest,
    GlobResponse,
    GrepRequest,
    GrepResponse,
    HealthRequest,
    HealthResponse,
    ListDirectoryRequest,
    ListDirectoryResponse,
    OutputEvent,
    ReadFileRequest,
    ReadFileResponse,
    SpawnedEvent,
    SpawnRequest,
    WriteFileRequest,
    WriteFileResponse,
    decode_chunk,
    encode_chunk,
    read_message,
    send_message,
)
from .logging_utils import get_logger
from .tool_bundle import ensure_tool_bundle

RUNTIME_DIR_IN_CONTAINER = "/sandbox_runtime"
TOOLS_DIR_IN_CONTAINER = "/opt/ksandbox/bin"
HOST_RUNTIME_ROOT = Path(tempfile.gettempdir()) / "ksandbox"
DEFAULT_TIMEOUT_SECS = 60
HEALTHCHECK_TIMEOUT_SECS = 10.0
IMAGE_TAG = "ksandbox:latest"
DAEMON_IN_CONTAINER = f"{TOOLS_DIR_IN_CONTAINER}/ksandbox-daemon"

logger = get_logger(__name__)


@dataclass
class MountInfo:
    src_folder: Path
    name: str
    description: str
    writable: bool

    @classmethod
    def new_temp_workdir(
        cls, name: str, description: str, template: Optional[Path] = None
    ) -> Self:
        workdir_root = HOST_RUNTIME_ROOT / "workdirs"
        workdir_root.mkdir(parents=True, exist_ok=True)
        workdir_path = workdir_root / str(uuid.uuid4())
        if template is None:
            os.mkdir(workdir_path)
            logger.info("Created sandbox workdir mount '%s' at %s", name, workdir_path)
        else:
            shutil.copytree(template, workdir_path)
            logger.info(
                "Created sandbox workdir mount '%s' at %s from template %s",
                name,
                workdir_path,
                template,
            )

        return cls(
            src_folder=workdir_path,
            name=name,
            description=description,
            writable=True,
        )

    def dst_path(self) -> str:
        return path_for_mount_name(self.name)


def path_for_mount_name(name: str) -> str:
    return f"/data/{name}"


@dataclass
class DockerMetadata:
    id: str
    status: str
    image: str
    created: str
    name: str


@dataclass
class CommandResult:
    output: bytes
    exit_code: int | None
    timed_out: bool = False
    timeout_secs: int | None = None
    transport_error: str | None = None


@dataclass
class FileInfo:
    path: str
    is_dir: bool


@dataclass
class ReadFileResult:
    path: str
    content: bytes | None = None
    error: FileOperationError | None = None


@dataclass
class WriteFileResult:
    path: str
    error: FileOperationError | None = None


@dataclass
class EditResult:
    path: str
    occurrences: int = 0
    error: EditFileError | None = None


@dataclass
class ListResult:
    entries: list[FileInfo]
    error: FileOperationError | None = None


@dataclass
class GrepMatch:
    path: str
    line: int
    text: str


@dataclass
class GrepResult:
    matches: list[GrepMatch]
    timed_out: bool = False
    error: str | None = None


@dataclass
class GlobResult:
    entries: list[FileInfo]
    timed_out: bool = False
    error: str | None = None


def _summarize_mounts(mounts: list[MountInfo]) -> list[dict[str, str | bool]]:
    return [
        {
            "src": str(mount.src_folder),
            "dst": mount.dst_path(),
            "writable": mount.writable,
            "description": mount.description,
        }
        for mount in mounts
    ]


class SandboxDaemonClient:
    def __init__(
        self,
        socket_path: Path,
        *,
        default_timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    ) -> None:
        self.socket_path = socket_path
        self.default_timeout_secs = default_timeout_secs

    def _connect(self) -> socket.socket:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.connect(str(self.socket_path))
        return conn

    def _round_trip(self, request, response_type):
        with self._connect() as conn:
            reader = conn.makefile("rb")
            send_message(conn, request)
            response = read_message(reader, RESPONSE_ADAPTER)

        if response is None:
            raise RuntimeError("invalid response from sandbox daemon")
        if isinstance(response, ErrorEvent):
            raise RuntimeError(response.message)
        if not isinstance(response, response_type):
            raise RuntimeError("invalid response from sandbox daemon")
        return response

    def healthcheck(self) -> None:
        response = self._round_trip(HealthRequest(), HealthResponse)
        if response.status != "ok":
            raise RuntimeError(f"sandbox daemon unhealthy: {response}")

    def execute(self, command: str, *, timeout_secs: int | None = None) -> CommandResult:
        timeout = self.default_timeout_secs if timeout_secs is None else timeout_secs
        output_chunks: list[bytes] = []
        exit_code: int | None = None
        timed_out = False
        command_id: str | None = None

        try:
            with self._connect() as conn:
                reader = conn.makefile("rb")
                send_message(conn, SpawnRequest(command=command, timeout_secs=timeout))

                while True:
                    event = read_message(reader, RESPONSE_ADAPTER)
                    if event is None:
                        raise RuntimeError("sandbox daemon closed before exit event")
                    if isinstance(event, SpawnedEvent):
                        command_id = event.id
                        continue
                    if isinstance(event, OutputEvent):
                        output_chunks.append(decode_chunk(event.data_b64))
                        continue
                    if isinstance(event, ExitEvent):
                        exit_code = event.exit_code
                        timed_out = event.timed_out
                        timeout_secs = event.timeout_secs
                        break
                    if isinstance(event, ErrorEvent):
                        raise RuntimeError(event.message)
                    raise RuntimeError(f"unexpected sandbox daemon event: {event}")
        except Exception as exc:
            logger.exception("Sandbox command transport failed")
            return CommandResult(output=b"", exit_code=1, transport_error=str(exc))

        if command_id is None:
            return CommandResult(
                output=b"",
                exit_code=1,
                transport_error="missing command id",
            )

        return CommandResult(
            output=b"".join(output_chunks),
            exit_code=exit_code,
            timed_out=timed_out,
            timeout_secs=timeout_secs,
        )

    def read(self, path: str) -> ReadFileResult:
        response = self._round_trip(ReadFileRequest(path=path), ReadFileResponse)
        content = None if response.content_b64 is None else decode_chunk(response.content_b64)
        return ReadFileResult(path=response.path, content=content, error=response.error)

    def write(
        self, path: str, content: bytes, *, overwrite: bool = False
    ) -> WriteFileResult:
        response = self._round_trip(
            WriteFileRequest(
                path=path,
                content_b64=encode_chunk(content),
                overwrite=overwrite,
            ),
            WriteFileResponse,
        )
        return WriteFileResult(path=response.path, error=response.error)

    def edit(
        self,
        path: str,
        old: bytes,
        new: bytes,
        *,
        replace_all: bool = False,
    ) -> EditResult:
        response = self._round_trip(
            EditFileRequest(
                path=path,
                old_b64=encode_chunk(old),
                new_b64=encode_chunk(new),
                replace_all=replace_all,
            ),
            EditFileResponse,
        )
        return EditResult(
            path=response.path,
            occurrences=response.occurrences,
            error=response.error,
        )

    def list(self, path: str) -> ListResult:
        response = self._round_trip(
            ListDirectoryRequest(path=path), ListDirectoryResponse
        )
        return ListResult(
            entries=[
                FileInfo(path=entry.path, is_dir=entry.is_dir)
                for entry in response.entries
            ],
            error=response.error,
        )

    def grep(
        self,
        pattern: str,
        path: str | None = None,
        glob: str | None = None,
    ) -> GrepResult:
        response = self._round_trip(
            GrepRequest(
                pattern=pattern,
                path=path,
                glob=glob,
                timeout_secs=self.default_timeout_secs,
            ),
            GrepResponse,
        )
        return GrepResult(
            matches=[
                GrepMatch(path=match.path, line=match.line, text=match.text)
                for match in response.matches
            ],
            timed_out=response.timed_out,
            error=response.error,
        )

    def glob(self, pattern: str, path: str = "/") -> GlobResult:
        response = self._round_trip(
            GlobRequest(
                pattern=pattern,
                path=path,
                timeout_secs=self.default_timeout_secs,
            ),
            GlobResponse,
        )
        return GlobResult(
            entries=[
                FileInfo(path=entry.path, is_dir=entry.is_dir)
                for entry in response.entries
            ],
            timed_out=response.timed_out,
            error=response.error,
        )


class DockerSandbox:
    mounts: list[MountInfo]

    def __init__(
        self,
        container: docker.models.containers.Container,
        mounts: list[MountInfo],
        runtime_dir: Path,
        daemon_client: SandboxDaemonClient,
    ):
        self.container = container
        self.mounts = mounts
        self.runtime_dir = runtime_dir
        self.daemon_client = daemon_client

    @property
    def id(self) -> str:
        return self.container.id

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.container.remove(force=True)
        except docker.errors.NotFound:
            pass
        finally:
            shutil.rmtree(self.runtime_dir, ignore_errors=True)

    def execute(self, command: str, *, timeout_secs: int | None = None) -> CommandResult:
        return self.daemon_client.execute(command, timeout_secs=timeout_secs)

    def read(self, path: str) -> ReadFileResult:
        return self.daemon_client.read(path)

    def write(
        self, path: str, content: bytes, *, overwrite: bool = False
    ) -> WriteFileResult:
        return self.daemon_client.write(path, content, overwrite=overwrite)

    def edit(
        self,
        path: str,
        old: bytes,
        new: bytes,
        *,
        replace_all: bool = False,
    ) -> EditResult:
        return self.daemon_client.edit(path, old, new, replace_all=replace_all)

    def list(self, path: str) -> ListResult:
        return self.daemon_client.list(path)

    def grep(
        self,
        pattern: str,
        path: str | None = None,
        glob: str | None = None,
    ) -> GrepResult:
        return self.daemon_client.grep(pattern, path, glob)

    def glob(self, pattern: str, path: str = "/") -> GlobResult:
        return self.daemon_client.glob(pattern, path)


_PROVIDER = None


class DockerSandboxProvider:
    def __init__(
        self,
        *,
        image_tag: str = IMAGE_TAG,
        default_timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    ) -> None:
        self.client = docker.from_env()
        self.image_tag = image_tag
        self.default_timeout_secs = default_timeout_secs

    @classmethod
    def get(cls) -> Self:
        global _PROVIDER
        if _PROVIDER is None:
            _PROVIDER = cls()
        return _PROVIDER

    def build_image(
        self,
        context: str | Path | None = None,
        *,
        dockerfile: str | Path | None = None,
        tag: str | None = None,
    ) -> None:
        docker_build_dir = (
            Path(context).resolve()
            if context is not None
            else Path(__file__).resolve().parents[2]
        )
        dockerfile_name = str(dockerfile) if dockerfile is not None else "Dockerfile"
        self.client.images.build(
            path=str(docker_build_dir),
            dockerfile=dockerfile_name,
            rm=True,
            tag=tag or self.image_tag,
        )

    def list(self, *, status: str | None = None) -> list[DockerMetadata]:
        filters = {"label": "created_by=ksandbox"}
        if status:
            filters["status"] = status
        containers = self.client.containers.list(all=True, filters=filters)
        return [
            DockerMetadata(
                id=c.id,
                status=c.status,
                image=str(c.image.tags),
                created=c.attrs.get("Created", ""),
                name=c.name,
            )
            for c in containers
            if not (c.id is None or c.image is None or c.name is None)
        ]

    def _new_runtime_dir(self) -> Path:
        HOST_RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
        runtime_dir = HOST_RUNTIME_ROOT / str(uuid.uuid4())
        runtime_dir.mkdir(parents=True, exist_ok=False)
        return runtime_dir

    def _wait_for_daemon(self, socket_path: Path) -> None:
        deadline = time.monotonic() + HEALTHCHECK_TIMEOUT_SECS
        client = SandboxDaemonClient(
            socket_path,
            default_timeout_secs=self.default_timeout_secs,
        )
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if socket_path.exists():
                try:
                    client.healthcheck()
                    return
                except Exception as exc:
                    last_error = exc
            time.sleep(0.1)
        raise RuntimeError(f"sandbox daemon failed to start: {last_error}")

    def create_instance(
        self, mounts: Optional[Sequence[MountInfo]] = None, *, name: Optional[str] = None
    ) -> DockerSandbox:
        mounts = list(mounts or [])
        image = self.client.images.get(self.image_tag)
        architecture = image.attrs.get("Architecture")
        operating_system = image.attrs.get("Os")
        if architecture not in {None, "amd64", "x86_64"} or operating_system not in {
            None,
            "linux",
        }:
            raise RuntimeError(
                f"ksandbox supports only linux/amd64 images; "
                f"{self.image_tag!r} is {operating_system or 'unknown'}/{architecture or 'unknown'}"
            )
        tool_bundle_dir = ensure_tool_bundle(client=self.client)
        runtime_dir = self._new_runtime_dir()
        volumes = {
            str(mount.src_folder.absolute()): {
                "bind": mount.dst_path(),
                "mode": "rw" if mount.writable else "ro",
            }
            for mount in mounts
        }
        volumes[str(runtime_dir)] = {"bind": RUNTIME_DIR_IN_CONTAINER, "mode": "rw"}
        volumes[str(tool_bundle_dir.resolve())] = {
            "bind": TOOLS_DIR_IN_CONTAINER,
            "mode": "ro",
        }

        container = None
        try:
            container = self.client.containers.run(
                image,
                command=[],
                detach=True,
                entrypoint=[
                    DAEMON_IN_CONTAINER,
                    "--runtime-dir",
                    RUNTIME_DIR_IN_CONTAINER,
                ],
                name=name,
                labels={
                    "created_by": "ksandbox",
                    "sandbox_runtime_dir": str(runtime_dir),
                },
                user=f"{os.getuid()}:{os.getgid()}",
                cap_drop=["ALL"],
                security_opt=[],
                volumes=volumes,
                working_dir="/",
            )
            socket_path = runtime_dir / SOCKET_NAME
            self._wait_for_daemon(socket_path)
        except Exception:
            if container is not None:
                container.remove(force=True)
            shutil.rmtree(runtime_dir, ignore_errors=True)
            raise

        daemon_client = SandboxDaemonClient(
            socket_path,
            default_timeout_secs=self.default_timeout_secs,
        )
        return DockerSandbox(container, mounts, runtime_dir, daemon_client)

    def delete(self, sandbox_id: str, *, force: bool = True) -> None:
        runtime_dir: Path | None = None
        try:
            container = self.client.containers.get(sandbox_id)
            runtime_dir_label = container.labels.get("sandbox_runtime_dir")
            if runtime_dir_label:
                runtime_dir = Path(runtime_dir_label)
            container.remove(force=force)
        except docker.errors.NotFound:
            pass
        finally:
            if runtime_dir is not None:
                shutil.rmtree(runtime_dir, ignore_errors=True)
