from __future__ import annotations

import fcntl
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cuttle_types import InstanceState, InstanceView
from pydantic import BaseModel, Field

from .config import CliSettings, default_state_dir
from .transport import CliError, CuttleApiClient

DAEMON_POLL_INTERVAL_SEC = 5.0
DAEMON_START_TIMEOUT_SEC = 10.0
DAEMON_STOP_TIMEOUT_SEC = 15.0
DAEMON_KILL_TIMEOUT_SEC = 2.0
ADB_COMMAND_TIMEOUT_SEC = 10.0
AUTH_TOKEN_ENV_VAR = "CUTTLE_CLI_AUTH_TOKEN"
DAEMON_MODULE = "cuttle_cli.main"


class DaemonMetadata(BaseModel):
    pid: int
    server_host: str
    server_port: int
    user_id: str
    auth_token_sha256: str = Field(min_length=64, max_length=64)


class OwnedEndpointsState(BaseModel):
    endpoints: list[str] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DaemonPaths:
    state_dir: Path
    pidfile: Path
    metadata: Path
    endpoints: Path
    log: Path
    lock: Path


@dataclass(frozen=True, slots=True)
class DaemonStatus:
    running: bool
    stale: bool
    metadata: DaemonMetadata | None


def daemon_paths() -> DaemonPaths:
    state_dir = default_state_dir()
    return DaemonPaths(
        state_dir=state_dir,
        pidfile=state_dir / "daemon.pid",
        metadata=state_dir / "daemon.json",
        endpoints=state_dir / "owned_endpoints.json",
        log=state_dir / "daemon.log",
        lock=state_dir / "daemon.lock",
    )


@contextmanager
def _state_lock() -> Iterator[None]:
    """Serialize daemon start/stop across CLI processes."""
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    with paths.lock.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def ensure_managed_daemon_running(settings: CliSettings) -> None:
    start_managed_daemon(settings)


def start_managed_daemon(settings: CliSettings) -> None:
    with _state_lock():
        _start_locked(settings)


def _start_locked(settings: CliSettings) -> None:
    status = get_daemon_status()
    if status.running:
        if status.metadata is not None and _same_identity(settings, status.metadata):
            return
        raise CliError("a cuttle_cli daemon is already running for a different server/user identity")

    _cleanup_stale_files()

    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    # Pass the token via the environment so it does not show up in `ps`.
    env = {**os.environ, AUTH_TOKEN_ENV_VAR: settings.auth_token}
    with paths.log.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                DAEMON_MODULE,
                "--server-host",
                settings.server_host,
                "--server-port",
                str(settings.server_port),
                "--user-id",
                settings.user_id,
                "daemon",
                "run-internal",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            env=env,
            start_new_session=True,
        )

    _wait_for_daemon_start(process, settings)


def stop_managed_daemon() -> bool:
    with _state_lock():
        return _stop_locked()


def _stop_locked() -> bool:
    status = get_daemon_status()
    if not status.running:
        _disconnect_owned_endpoints(None, _load_owned_endpoints(), persist=False)
        _cleanup_stale_files()
        return False

    metadata = status.metadata
    assert metadata is not None
    os.kill(metadata.pid, signal.SIGTERM)
    if not _wait_for_exit(metadata.pid, DAEMON_STOP_TIMEOUT_SEC):
        # The daemon is wedged (e.g. a hung adb call); escalate.
        try:
            os.kill(metadata.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if not _wait_for_exit(metadata.pid, DAEMON_KILL_TIMEOUT_SEC):
            raise CliError(f"daemon pid {metadata.pid} did not exit after SIGTERM/SIGKILL")

    _disconnect_owned_endpoints(None, _load_owned_endpoints(), persist=False)
    _cleanup_stale_files()
    return True


def _wait_for_exit(pid: int, timeout_sec: float) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if not _pid_is_running(pid):
            return True
        time.sleep(0.1)
    return not _pid_is_running(pid)


def get_daemon_status() -> DaemonStatus:
    metadata = _load_metadata()
    if metadata is None:
        return DaemonStatus(running=False, stale=False, metadata=None)

    if _pid_is_running(metadata.pid):
        return DaemonStatus(running=True, stale=False, metadata=metadata)
    return DaemonStatus(running=False, stale=True, metadata=metadata)


def run_daemon_forever(settings: CliSettings) -> None:
    stop_event = threading.Event()
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    metadata = _metadata_from_settings(settings)
    _write_metadata(metadata)
    _write_pidfile(metadata.pid)

    def request_stop(_: int, __: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        while not stop_event.is_set():
            try:
                sync_managed_daemon_once(settings)
            except (CliError, OSError, ValueError):
                # A transient server/adb failure must not kill the daemon.
                traceback.print_exc()
            # Wakes immediately on SIGTERM instead of sleeping out the interval.
            stop_event.wait(DAEMON_POLL_INTERVAL_SEC)
    finally:
        _disconnect_owned_endpoints(None, _load_owned_endpoints(), persist=False)
        # Only remove state if a successor daemon has not taken it over.
        current = _load_metadata()
        if current is None or current.pid == os.getpid():
            _cleanup_stale_files()


def sync_managed_daemon_once(settings: CliSettings) -> list[str]:
    client = CuttleApiClient.from_settings(settings)
    return sync_managed_daemon_once_with_client(client)


def sync_managed_daemon_once_with_client(client: CuttleApiClient) -> list[str]:
    instances = client.list_instances().instances
    desired_endpoints = sorted(_desired_endpoints(instances, client))
    unmanaged_endpoints = _unmanaged_endpoints(instances, client)
    current_endpoints = _load_owned_endpoints()

    desired_set = set(desired_endpoints)
    current_set = set(current_endpoints)

    for endpoint in sorted(current_set - desired_set):
        if endpoint in unmanaged_endpoints:
            current_set.remove(endpoint)
            continue
        if _run_adb_command("disconnect", endpoint):
            current_set.remove(endpoint)

    for endpoint in sorted(desired_set - current_set):
        if _run_adb_command("connect", endpoint):
            current_set.add(endpoint)

    updated_endpoints = sorted(current_set)
    _write_owned_endpoints(updated_endpoints)
    return updated_endpoints


def refresh_adb_connection(endpoint: str) -> None:
    result = _run_adb_command_result("connect", endpoint)
    if result.returncode == 0:
        return
    detail = result.stderr.strip() or result.stdout.strip()
    if not detail:
        detail = f"adb exited with status {result.returncode}"
    raise CliError(f"failed to refresh ADB connection to {endpoint}: {detail}")


def render_daemon_identity(metadata: DaemonMetadata) -> str:
    return f"{metadata.user_id}@{metadata.server_host}:{metadata.server_port}"


def _desired_endpoints(
    instances: list[InstanceView],
    client: CuttleApiClient,
) -> set[str]:
    desired: set[str] = set()
    for instance in instances:
        if instance.unmanaged:
            continue
        if instance.state not in {
            InstanceState.STARTING,
            InstanceState.ACTIVE,
            InstanceState.STOPPING,
        }:
            continue
        target = client.adb_target(instance)
        if target is not None:
            desired.add(target)
    return desired


def _unmanaged_endpoints(
    instances: list[InstanceView],
    client: CuttleApiClient,
) -> set[str]:
    return {
        target
        for instance in instances
        if instance.unmanaged
        if (target := client.adb_target(instance)) is not None
    }


def _metadata_from_settings(settings: CliSettings) -> DaemonMetadata:
    return DaemonMetadata(
        pid=os.getpid(),
        server_host=settings.server_host,
        server_port=settings.server_port,
        user_id=settings.user_id,
        auth_token_sha256=_hash_auth_token(settings.auth_token),
    )


def _same_identity(settings: CliSettings, metadata: DaemonMetadata) -> bool:
    return (
        metadata.server_host == settings.server_host
        and metadata.server_port == settings.server_port
        and metadata.user_id == settings.user_id
        and metadata.auth_token_sha256 == _hash_auth_token(settings.auth_token)
    )


def _hash_auth_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _wait_for_daemon_start(process: subprocess.Popen[bytes], settings: CliSettings) -> None:
    deadline = time.monotonic() + DAEMON_START_TIMEOUT_SEC
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CliError(f"daemon exited early with status {process.returncode}")
        status = get_daemon_status()
        if status.running and status.metadata is not None and _same_identity(settings, status.metadata):
            return
        time.sleep(0.1)
    raise CliError(
        f"daemon did not create pidfile/metadata within {DAEMON_START_TIMEOUT_SEC:.0f}s"
    )


def _disconnect_owned_endpoints(
    client: CuttleApiClient | None,
    endpoints: list[str],
    *,
    persist: bool,
) -> None:
    del client
    remaining = set(endpoints)
    for endpoint in sorted(list(remaining)):
        if _run_adb_command("disconnect", endpoint):
            remaining.remove(endpoint)
    if persist:
        _write_owned_endpoints(sorted(remaining))


def _run_adb_command(action: str, endpoint: str) -> bool:
    return _run_adb_command_result(action, endpoint).returncode == 0


def _run_adb_command_result(
    action: str, endpoint: str
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["adb", action, endpoint],
            check=False,
            capture_output=True,
            text=True,
            timeout=ADB_COMMAND_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=["adb", action, endpoint],
            returncode=124,
            stdout="",
            stderr=f"adb {action} timed out after {ADB_COMMAND_TIMEOUT_SEC:.0f}s",
        )


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return _pid_looks_like_daemon(pid)
    return _pid_looks_like_daemon(pid)


def _pid_looks_like_daemon(pid: int) -> bool:
    """Reject zombies and reused pids; unreadable /proc entries count as alive."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        # State is the first field after the ")" closing the command name.
        if stat.rsplit(")", 1)[1].split()[0] == "Z":
            return False
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, IndexError):
        return True
    return DAEMON_MODULE.encode() in cmdline or not cmdline


def _load_metadata() -> DaemonMetadata | None:
    paths = daemon_paths()
    if not paths.metadata.is_file():
        return None
    try:
        return DaemonMetadata.model_validate_json(
            paths.metadata.read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        # Corrupt or half-written metadata: treat as no daemon.
        return None


def _write_metadata(metadata: DaemonMetadata) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(paths.metadata, metadata.model_dump_json(indent=2))


def _write_pidfile(pid: int) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(paths.pidfile, f"{pid}\n")


def _load_owned_endpoints() -> list[str]:
    paths = daemon_paths()
    if not paths.endpoints.is_file():
        return []
    try:
        state = OwnedEndpointsState.model_validate_json(
            paths.endpoints.read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return []
    return state.endpoints


def _atomic_write_text(path: Path, text: str) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def _write_owned_endpoints(endpoints: list[str]) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(
        paths.endpoints,
        OwnedEndpointsState(endpoints=endpoints).model_dump_json(indent=2),
    )


def _cleanup_stale_files() -> None:
    paths = daemon_paths()
    for path in (paths.pidfile, paths.metadata, paths.endpoints):
        path.unlink(missing_ok=True)
