from __future__ import annotations

import os
import shutil
import socket
import threading
import hashlib
import sqlite3
import stat
import tempfile
import time
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Self, Sequence

import docker  # type: ignore
from kexploit_utils import ksandbox_dir # type: ignore[attr-defined]

from .daemon_protocol import (
    RESPONSE_ADAPTER,
    SOCKET_NAME,
    CloseStdinRequest,
    CloseStdinResponse,
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
    KillRequest,
    KillResponse,
    ListDirectoryRequest,
    ListDirectoryResponse,
    OutputEvent,
    ReadFileRequest,
    ReadFileResponse,
    SpawnedEvent,
    SpawnRequest,
    StdinRequest,
    StdinResponse,
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
DAEMON_IN_CONTAINER = f"{TOOLS_DIR_IN_CONTAINER}/ksandbox-daemon"

logger = get_logger(__name__)


def _persistent_runtime_root() -> Path:
    return ksandbox_dir() / "runtimes"


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


@dataclass(frozen=True)
class ExecResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


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


def _hash_mount_tree(src_folder: Path) -> bytes:
    """Return a stable hash of a mount tree without following symlinks."""
    root = src_folder.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"sandbox mount source must be a directory: {src_folder}")

    entries: list[tuple[bytes, Path]] = [(b".", root)]
    for path in root.rglob("*"):
        entries.append((os.fsencode(str(path.relative_to(root))), path))

    digest = hashlib.sha256(b"ksandbox-mount-v1\0")
    for relative_path, path in sorted(entries, key=lambda entry: entry[0]):
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            file_type, content = b"regular", path.read_bytes()
        elif stat.S_ISDIR(mode):
            file_type, content = b"directory", b""
        elif stat.S_ISLNK(mode):
            file_type, content = b"symlink", os.fsencode(os.readlink(path))
        elif stat.S_ISFIFO(mode):
            file_type, content = b"fifo", b""
        elif stat.S_ISCHR(mode):
            file_type, content = b"char-device", b""
        elif stat.S_ISBLK(mode):
            file_type, content = b"block-device", b""
        elif stat.S_ISSOCK(mode):
            file_type, content = b"socket", b""
        else:
            file_type, content = b"unknown", b""

        digest.update(len(file_type).to_bytes(8, "big"))
        digest.update(file_type)
        digest.update(len(relative_path).to_bytes(8, "big"))
        digest.update(relative_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.digest()


@dataclass(frozen=True)
class _StoredSandbox:
    id: str
    state: str
    runtime_dir: Path
    image: str
    created: str
    name: str
    mounts: list[MountInfo]
    mount_hashes: list[bytes]


class _SandboxStore:
    def __init__(self, database_path: Path | None = None) -> None:
        self.database_path = database_path or (
            ksandbox_dir() / "sandboxes.sqlite3"
        )
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sandboxes (
                    docker_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL CHECK (state IN ('stopped', 'running')),
                    runtime_dir TEXT NOT NULL,
                    image TEXT NOT NULL,
                    created TEXT NOT NULL,
                    name TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sandbox_mounts (
                    docker_id TEXT NOT NULL REFERENCES sandboxes(docker_id) ON DELETE CASCADE,
                    position INTEGER NOT NULL,
                    src_folder TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    writable INTEGER NOT NULL,
                    tree_hash BLOB NOT NULL,
                    PRIMARY KEY (docker_id, position)
                );
                """
            )

    @staticmethod
    def _from_rows(
        sandbox_row: sqlite3.Row, mount_rows: list[sqlite3.Row]
    ) -> _StoredSandbox:
        return _StoredSandbox(
            id=sandbox_row["docker_id"],
            state=sandbox_row["state"],
            runtime_dir=Path(sandbox_row["runtime_dir"]),
            image=sandbox_row["image"],
            created=sandbox_row["created"],
            name=sandbox_row["name"],
            mounts=[
                MountInfo(
                    src_folder=Path(row["src_folder"]),
                    name=row["name"],
                    description=row["description"],
                    writable=bool(row["writable"]),
                )
                for row in mount_rows
            ],
            mount_hashes=[bytes(row["tree_hash"]) for row in mount_rows],
        )

    def get(self, sandbox_id: str) -> _StoredSandbox | None:
        with self._connection() as connection:
            sandbox_row = connection.execute(
                "SELECT * FROM sandboxes WHERE docker_id = ?", (sandbox_id,)
            ).fetchone()
            if sandbox_row is None:
                return None
            mount_rows = connection.execute(
                "SELECT * FROM sandbox_mounts WHERE docker_id = ? ORDER BY position",
                (sandbox_id,),
            ).fetchall()
        return self._from_rows(sandbox_row, mount_rows)

    def list(self) -> list[_StoredSandbox]:
        with self._connection() as connection:
            sandbox_rows = connection.execute(
                "SELECT * FROM sandboxes ORDER BY created, docker_id"
            ).fetchall()
            mount_rows = connection.execute(
                "SELECT * FROM sandbox_mounts ORDER BY docker_id, position"
            ).fetchall()
        mounts_by_id: dict[str, list[sqlite3.Row]] = {}
        for row in mount_rows:
            mounts_by_id.setdefault(row["docker_id"], []).append(row)
        return [
            self._from_rows(row, mounts_by_id.get(row["docker_id"], []))
            for row in sandbox_rows
        ]

    def create(self, sandbox: _StoredSandbox) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO sandboxes (docker_id, state, runtime_dir, image, created, name)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sandbox.id,
                    sandbox.state,
                    str(sandbox.runtime_dir),
                    sandbox.image,
                    sandbox.created,
                    sandbox.name,
                ),
            )
            connection.executemany(
                """
                INSERT INTO sandbox_mounts
                (docker_id, position, src_folder, name, description, writable, tree_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        sandbox.id,
                        position,
                        str(mount.src_folder),
                        mount.name,
                        mount.description,
                        mount.writable,
                        sandbox.mount_hashes[position],
                    )
                    for position, mount in enumerate(sandbox.mounts)
                ],
            )

    def claim_start(self, sandbox_id: str) -> bool:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE sandboxes SET state = 'running' "
                "WHERE docker_id = ? AND state = 'stopped'",
                (sandbox_id,),
            )
            return result.rowcount == 1

    def release_start(self, sandbox_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE sandboxes SET state = 'stopped' "
                "WHERE docker_id = ? AND state = 'running'",
                (sandbox_id,),
            )

    def stop(self, sandbox_id: str, hashes: Sequence[bytes] | None) -> bool:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "UPDATE sandboxes SET state = 'stopped' "
                "WHERE docker_id = ? AND state = 'running'",
                (sandbox_id,),
            )
            if result.rowcount != 1:
                return False
            if hashes is not None:
                connection.executemany(
                    "UPDATE sandbox_mounts SET tree_hash = ? "
                    "WHERE docker_id = ? AND position = ?",
                    [
                        (tree_hash, sandbox_id, position)
                        for position, tree_hash in enumerate(hashes)
                    ],
                )
            return True

    def delete(self, sandbox_id: str, *, force: bool) -> bool:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if force:
                result = connection.execute(
                    "DELETE FROM sandboxes WHERE docker_id = ?", (sandbox_id,)
                )
            else:
                result = connection.execute(
                    "DELETE FROM sandboxes WHERE docker_id = ? AND state = 'stopped'",
                    (sandbox_id,),
                )
            return result.rowcount == 1


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

    def exec(
        self,
        argv: Sequence[str] | str,
        *,
        shell: bool = False,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_secs: float | None = None,
    ) -> "SandboxProcess":
        request = _spawn_request(argv, shell=shell, cwd=cwd, env=env)
        process = SandboxProcess(
            self._connect(), default_timeout_secs=self.default_timeout_secs
        )
        try:
            process._send(request)
            process._wait_started(timeout_secs)
            return process
        except Exception:
            process.close()
            raise

    def exec_sync(
        self,
        argv: Sequence[str] | str,
        *,
        shell: bool = False,
        input: bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_secs: float | None = None,
    ) -> ExecResult:
        process = self.exec(
            argv, shell=shell, cwd=cwd, env=env, timeout_secs=timeout_secs
        )
        try:
            if input:
                process.stdin_write(input, timeout_secs=timeout_secs)
            process.close_stdin(timeout_secs=timeout_secs)
            exit_code = process.wait_finish(timeout_secs=timeout_secs)
            return ExecResult(
                stdout=process._drain_stdout(),
                stderr=process._drain_stderr(),
                exit_code=exit_code,
            )
        except TimeoutError:
            try:
                process.kill(timeout_secs=timeout_secs)
                process.wait_finish(timeout_secs=timeout_secs)
            except (RuntimeError, TimeoutError):
                pass
            raise
        finally:
            process.close()

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


def _spawn_request(
    argv: Sequence[str] | str,
    *,
    shell: bool,
    cwd: str | None,
    env: dict[str, str] | None,
) -> SpawnRequest:
    if shell:
        if not isinstance(argv, str):
            raise TypeError("shell execution requires a string command")
        return SpawnRequest(command=argv, shell=True, cwd=cwd, env=env)
    if isinstance(argv, str):
        raise TypeError("direct execution requires a sequence of argument strings")
    values = list(argv)
    if not values or not all(isinstance(value, str) for value in values):
        raise ValueError("direct execution requires a non-empty sequence of strings")
    return SpawnRequest(argv=values, cwd=cwd, env=env)


class SandboxProcess:
    """A single interactive command connected to the sandbox daemon."""

    def __init__(self, conn: socket.socket, *, default_timeout_secs: float) -> None:
        self._conn = conn
        self._default_timeout_secs = default_timeout_secs
        self._send_lock = threading.Lock()
        self._condition = threading.Condition()
        self._stdout: deque[bytes] = deque()
        self._stderr: deque[bytes] = deque()
        self._started = False
        self._exit_code: int | None = None
        self._transport_error: Exception | None = None
        self._control_results: dict[
            str, StdinResponse | CloseStdinResponse | KillResponse
        ] = {}
        self._closed = False
        self._reader = conn.makefile("rb")
        self._reader_thread = threading.Thread(
            target=self._read_events,
            name="ksandbox-process-reader",
            daemon=True,
        )
        self._reader_thread.start()

    def _timeout(self, timeout_secs: float | None) -> float:
        return self._default_timeout_secs if timeout_secs is None else timeout_secs

    def _send(self, request) -> None:
        with self._send_lock:
            if self._closed:
                raise RuntimeError("sandbox process transport is closed")
            send_message(self._conn, request)

    def _read_events(self) -> None:
        try:
            while True:
                event = read_message(self._reader, RESPONSE_ADAPTER)
                if event is None:
                    raise RuntimeError("sandbox daemon closed process transport")
                process_exited = False
                with self._condition:
                    if isinstance(event, SpawnedEvent):
                        self._started = True
                    elif isinstance(event, OutputEvent):
                        target = self._stdout if event.type == "stdout" else self._stderr
                        target.append(decode_chunk(event.data_b64))
                    elif isinstance(event, ExitEvent):
                        self._exit_code = event.exit_code
                        process_exited = True
                    elif isinstance(
                        event, (StdinResponse, CloseStdinResponse, KillResponse)
                    ):
                        self._control_results[event.request_id] = event
                    elif isinstance(event, ErrorEvent):
                        self._transport_error = RuntimeError(event.message)
                    else:
                        self._transport_error = RuntimeError(
                            f"unexpected sandbox process event: {event}"
                        )
                    self._condition.notify_all()
                if process_exited:
                    return
        except Exception as exc:
            with self._condition:
                if self._exit_code is None and self._transport_error is None:
                    self._transport_error = exc
                self._condition.notify_all()

    def _wait_for(self, predicate, timeout_secs: float | None) -> None:
        deadline = time.monotonic() + self._timeout(timeout_secs)
        with self._condition:
            while not predicate():
                if self._transport_error is not None:
                    raise self._transport_error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sandbox process operation timed out")
                self._condition.wait(remaining)
            if self._transport_error is not None:
                raise self._transport_error

    def _wait_started(self, timeout_secs: float | None) -> None:
        self._wait_for(lambda: self._started, timeout_secs)

    def _control(
        self,
        request,
        request_id: str,
        timeout_secs: float | None,
        *,
        allow_exit: bool = False,
    ):
        self._send(request)
        self._wait_for(
            lambda: request_id in self._control_results
            or (allow_exit and self._exit_code is not None),
            timeout_secs,
        )
        with self._condition:
            return self._control_results.pop(request_id, None)

    def stdin_write(self, data: bytes, *, timeout_secs: float | None = None) -> None:
        request_id = uuid.uuid4().hex
        response = self._control(
            StdinRequest(
                request_id=request_id,
                data_b64=encode_chunk(data),
            ),
            request_id,
            timeout_secs,
            allow_exit=True,
        )
        if response is None:
            raise RuntimeError("sandbox process exited before stdin was written")
        assert isinstance(response, StdinResponse)
        if response.error is not None:
            raise RuntimeError(response.error)

    def close_stdin(self, *, timeout_secs: float | None = None) -> None:
        request_id = uuid.uuid4().hex
        response = self._control(
            CloseStdinRequest(request_id=request_id),
            request_id,
            timeout_secs,
            allow_exit=True,
        )
        if response is None:
            return
        assert isinstance(response, CloseStdinResponse)
        if response.error is not None:
            raise RuntimeError(response.error)

    def _read_stream(self, stream: deque[bytes], timeout_secs: float | None) -> bytes:
        self._wait_for(lambda: bool(stream) or self._exit_code is not None, timeout_secs)
        with self._condition:
            return stream.popleft() if stream else b""

    def read_stdout(self, *, timeout_secs: float | None = None) -> bytes:
        return self._read_stream(self._stdout, timeout_secs)

    def read_stderr(self, *, timeout_secs: float | None = None) -> bytes:
        return self._read_stream(self._stderr, timeout_secs)

    def _drain_stdout(self) -> bytes:
        with self._condition:
            data = b"".join(self._stdout)
            self._stdout.clear()
            return data

    def _drain_stderr(self) -> bytes:
        with self._condition:
            data = b"".join(self._stderr)
            self._stderr.clear()
            return data

    def kill(self, *, timeout_secs: float | None = None) -> bool:
        with self._condition:
            if self._exit_code is not None:
                return False
        request_id = uuid.uuid4().hex
        response = self._control(
            KillRequest(request_id=request_id),
            request_id,
            timeout_secs,
            allow_exit=True,
        )
        if response is None:
            return False
        assert isinstance(response, KillResponse)
        return response.delivered

    def wait_finish(self, *, timeout_secs: float | None = None) -> int:
        self._wait_for(lambda: self._exit_code is not None, timeout_secs)
        assert self._exit_code is not None
        exit_code = self._exit_code
        self.close()
        return exit_code

    wait = wait_finish

    def close(self) -> None:
        with self._send_lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._conn.close()
        self._reader.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class DockerSandbox:
    """A persistent sandbox whose Docker container may be stopped and resumed."""

    def __init__(
        self,
        provider: "DockerSandboxProvider",
        stored: _StoredSandbox,
        container: docker.models.containers.Container | None = None,
    ) -> None:
        self._provider = provider
        self._stored = stored
        self.container = container
        self.mounts = stored.mounts
        self.runtime_dir = stored.runtime_dir
        self.daemon_client = SandboxDaemonClient(
            self.runtime_dir / SOCKET_NAME,
            default_timeout_secs=provider.default_timeout_secs,
        )
        self.running = False
        self.state = stored.state
        self.image = stored.image
        self.created = stored.created
        self.name = stored.name
        self.status = stored.state
        if container is not None:
            container_status = getattr(container, "status", None)
            if isinstance(container_status, str):
                self.status = container_status

    @property
    def id(self) -> str:
        return self._stored.id

    @property
    def daemon_socket_path(self) -> Path:
        """Host path to this sandbox's public daemon socket."""
        return self.runtime_dir / SOCKET_NAME

    def _container(self) -> docker.models.containers.Container:
        if self.container is None:
            self.container = self._provider.client.containers.get(self.id)
        return self.container

    def _validate_mount_hashes(self) -> None:
        current_hashes = [_hash_mount_tree(mount.src_folder) for mount in self.mounts]
        if current_hashes != self._stored.mount_hashes:
            raise RuntimeError(
                f"sandbox {self.id} mount contents changed while it was stopped"
            )

    def start(self) -> Self:
        if self.running:
            raise RuntimeError(f"sandbox {self.id} is already running on this handle")
        self._validate_mount_hashes()
        if not self._provider._store.claim_start(self.id):
            raise RuntimeError(f"sandbox {self.id} is already running")

        container = self._container()
        try:
            container.start()
            self._provider._wait_for_daemon(self.runtime_dir / SOCKET_NAME)
        except Exception:
            try:
                container.stop()
            except Exception:
                logger.exception("Failed to stop sandbox after unsuccessful start")
            self._provider._store.release_start(self.id)
            raise

        self.running = True
        self.state = "running"
        self.status = "running"
        return self

    def __enter__(self) -> Self:
        if not self.running:
            raise RuntimeError("use 'with sandbox.start()' to run a sandbox")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def _stop(self, *, allow_unowned: bool) -> None:
        if not self.running and not allow_unowned:
            raise RuntimeError(
                f"sandbox {self.id} was not started by this DockerSandbox instance"
            )

        self._container().stop()
        hash_error: Exception | None = None
        hashes: list[bytes] | None = None
        try:
            hashes = [_hash_mount_tree(mount.src_folder) for mount in self.mounts]
        except Exception as exc:
            hash_error = exc

        if not self._provider._store.stop(self.id, hashes):
            raise RuntimeError(f"sandbox {self.id} is not marked as running")
        updated = self._provider._store.get(self.id)
        if updated is None:
            raise RuntimeError(f"sandbox {self.id} was deleted while stopping")
        self._stored = updated
        self.mounts = updated.mounts
        self.running = False
        self.state = "stopped"
        self.status = "exited"
        if hash_error is not None:
            raise RuntimeError(
                f"sandbox {self.id} stopped, but its mount hash could not be refreshed"
            ) from hash_error

    def stop(self) -> None:
        self._stop(allow_unowned=False)

    def exec(
        self,
        argv: Sequence[str] | str,
        *,
        shell: bool = False,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_secs: float | None = None,
    ) -> SandboxProcess:
        return self.daemon_client.exec(
            argv, shell=shell, cwd=cwd, env=env, timeout_secs=timeout_secs
        )

    def exec_sync(
        self,
        argv: Sequence[str] | str,
        *,
        shell: bool = False,
        input: bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_secs: float | None = None,
    ) -> ExecResult:
        return self.daemon_client.exec_sync(
            argv,
            shell=shell,
            input=input,
            cwd=cwd,
            env=env,
            timeout_secs=timeout_secs,
        )

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
        default_timeout_secs: int = DEFAULT_TIMEOUT_SECS,
        database_path: Path | None = None,
    ) -> None:
        self.client = docker.from_env()
        self.default_timeout_secs = default_timeout_secs
        self._store = _SandboxStore(database_path)

    @classmethod
    def get(cls) -> Self:
        global _PROVIDER
        if _PROVIDER is None:
            _PROVIDER = cls()
        return _PROVIDER

    def _sandbox_from_stored(self, stored: _StoredSandbox) -> DockerSandbox:
        container = None
        try:
            container = self.client.containers.get(stored.id)
        except docker.errors.NotFound:
            pass
        sandbox = DockerSandbox(self, stored, container)
        if container is None:
            sandbox.status = "missing"
        return sandbox

    def get_sandbox(self, sandbox_id: str) -> DockerSandbox:
        stored = self._store.get(sandbox_id)
        if stored is None:
            raise RuntimeError(f"unknown ksandbox instance: {sandbox_id}")
        return self._sandbox_from_stored(stored)

    def list(self, *, status: str | None = None) -> list[DockerSandbox]:
        sandboxes = [self._sandbox_from_stored(stored) for stored in self._store.list()]
        if status is not None:
            sandboxes = [sandbox for sandbox in sandboxes if sandbox.status == status]
        return sandboxes

    def _new_runtime_dir(self) -> Path:
        runtime_root = _persistent_runtime_root()
        runtime_root.mkdir(parents=True, exist_ok=True)
        runtime_dir = runtime_root / str(uuid.uuid4())
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

    def create(
        self, image_tag: str, mounts: Optional[Sequence[MountInfo]] = None, *, name: Optional[str] = None
    ) -> DockerSandbox:
        requested_mounts = list(mounts or [])
        if len({mount.name for mount in requested_mounts}) != len(requested_mounts):
            raise ValueError("sandbox mount names must be unique")
        mounts = [
            MountInfo(
                src_folder=mount.src_folder.resolve(strict=True),
                name=mount.name,
                description=mount.description,
                writable=mount.writable,
            )
            for mount in requested_mounts
        ]
        if len({mount.src_folder for mount in mounts}) != len(mounts):
            raise ValueError("a source directory may only be mounted once")
        mount_hashes = [_hash_mount_tree(mount.src_folder) for mount in mounts]
        image = self.client.images.get(image_tag)
        architecture = image.attrs.get("Architecture")
        operating_system = image.attrs.get("Os")
        if architecture not in {None, "amd64", "x86_64"} or operating_system not in {
            None,
            "linux",
        }:
            raise RuntimeError(
                f"ksandbox supports only linux/amd64 images; "
                f"{image_tag!r} is {operating_system or 'unknown'}/{architecture or 'unknown'}"
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
            container = self.client.containers.create(
                image,
                command=[],
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
            attrs = container.attrs if isinstance(container.attrs, dict) else {}
            container_name = container.name if isinstance(container.name, str) else (name or "")
            stored = _StoredSandbox(
                id=container.id,
                state="stopped",
                runtime_dir=runtime_dir,
                image=image_tag,
                created=attrs.get("Created", ""),
                name=container_name,
                mounts=mounts,
                mount_hashes=mount_hashes,
            )
            self._store.create(stored)
        except Exception:
            if container is not None:
                container.remove(force=True)
            shutil.rmtree(runtime_dir, ignore_errors=True)
            raise

        return DockerSandbox(self, stored, container)

    @contextmanager
    def create_and_run(
        self, image_tag: str, mounts: Optional[Sequence[MountInfo]] = None, *, name: Optional[str] = None
    ) -> Iterator[DockerSandbox]:
        sandbox = self.create(image_tag, mounts, name=name)
        try:
            sandbox.start()
            yield sandbox
        finally:
            try:
                if sandbox.running:
                    sandbox.stop()
            finally:
                self.delete(sandbox.id, force=True)

    def _start_from_cli(self, sandbox_id: str) -> DockerSandbox:
        sandbox = self.get_sandbox(sandbox_id)
        return sandbox.start()

    def _stop_from_cli(self, sandbox_id: str) -> None:
        self.get_sandbox(sandbox_id)._stop(allow_unowned=True)

    def delete(self, sandbox_id: str, *, force: bool = False) -> None:
        stored = self._store.get(sandbox_id)
        if stored is None:
            raise RuntimeError(f"unknown ksandbox instance: {sandbox_id}")
        if stored.state == "running" and not force:
            raise RuntimeError(f"sandbox {sandbox_id} is running; pass force=True to delete it")
        try:
            self.client.containers.get(sandbox_id).remove(force=force)
        except docker.errors.NotFound:
            pass
        if self._store.delete(sandbox_id, force=force):
            shutil.rmtree(stored.runtime_dir, ignore_errors=True)
