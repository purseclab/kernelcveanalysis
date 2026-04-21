from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cuttle_types import InstanceState, InstanceView
from pydantic import BaseModel, Field

from .client import CliError, CuttleApiClient
from .config import CliSettings, default_state_dir

DAEMON_POLL_INTERVAL_SEC = 5.0


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
    )


def ensure_managed_daemon_running(settings: CliSettings) -> None:
    status = get_daemon_status()
    if status.running:
        if status.metadata is not None and _same_identity(settings, status.metadata):
            return
        raise CliError("a cuttle_cli daemon is already running for a different server/user identity")

    if status.stale:
        _cleanup_stale_files()

    start_managed_daemon(settings)


def start_managed_daemon(settings: CliSettings) -> None:
    status = get_daemon_status()
    if status.running:
        if status.metadata is not None and _same_identity(settings, status.metadata):
            return
        raise CliError("a cuttle_cli daemon is already running for a different server/user identity")

    if status.stale:
        _cleanup_stale_files()

    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    with paths.log.open("a", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "cuttle_cli.main",
                "--server-host",
                settings.server_host,
                "--server-port",
                str(settings.server_port),
                "--auth-token",
                settings.auth_token,
                "--user-id",
                settings.user_id,
                "daemon",
                "run-internal",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            start_new_session=True,
        )

    _wait_for_daemon_start(process, settings)


def stop_managed_daemon() -> bool:
    status = get_daemon_status()
    if not status.running:
        _disconnect_owned_endpoints(None, _load_owned_endpoints(), persist=False)
        _cleanup_stale_files()
        return False

    metadata = status.metadata
    assert metadata is not None
    os.kill(metadata.pid, signal.SIGTERM)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not _pid_is_running(metadata.pid):
            break
        time.sleep(0.1)
    else:
        raise CliError(f"daemon pid {metadata.pid} did not exit after SIGTERM")

    _disconnect_owned_endpoints(None, _load_owned_endpoints(), persist=False)
    _cleanup_stale_files()
    return True


def get_daemon_status() -> DaemonStatus:
    metadata = _load_metadata()
    if metadata is None:
        return DaemonStatus(running=False, stale=False, metadata=None)

    if _pid_is_running(metadata.pid):
        return DaemonStatus(running=True, stale=False, metadata=metadata)
    return DaemonStatus(running=False, stale=True, metadata=metadata)


def run_daemon_forever(settings: CliSettings) -> None:
    stop_requested = False
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    metadata = _metadata_from_settings(settings)
    _write_metadata(metadata)
    _write_pidfile(metadata.pid)

    def request_stop(_: int, __) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        while True:
            sync_managed_daemon_once(settings)
            if stop_requested:
                break
            time.sleep(DAEMON_POLL_INTERVAL_SEC)
    finally:
        _disconnect_owned_endpoints(
            CuttleApiClient.from_settings(settings),
            _load_owned_endpoints(),
            persist=False,
        )
        _cleanup_stale_files()


def sync_managed_daemon_once(settings: CliSettings) -> list[str]:
    client = CuttleApiClient.from_settings(settings)
    return sync_managed_daemon_once_with_client(client)


def sync_managed_daemon_once_with_client(client: CuttleApiClient) -> list[str]:
    desired_endpoints = sorted(_desired_endpoints(client.list_instances().instances, client))
    current_endpoints = _load_owned_endpoints()

    desired_set = set(desired_endpoints)
    current_set = set(current_endpoints)

    for endpoint in sorted(current_set - desired_set):
        if _run_adb_command("disconnect", endpoint):
            current_set.remove(endpoint)

    for endpoint in sorted(desired_set - current_set):
        if _run_adb_command("connect", endpoint):
            current_set.add(endpoint)

    updated_endpoints = sorted(current_set)
    _write_owned_endpoints(updated_endpoints)
    return updated_endpoints


def render_daemon_identity(metadata: DaemonMetadata) -> str:
    return f"{metadata.user_id}@{metadata.server_host}:{metadata.server_port}"


def _desired_endpoints(
    instances: list[InstanceView],
    client: CuttleApiClient,
) -> set[str]:
    desired: set[str] = set()
    for instance in instances:
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
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if process.poll() is not None:
            raise CliError(f"daemon exited early with status {process.returncode}")
        status = get_daemon_status()
        if status.running and status.metadata is not None and _same_identity(settings, status.metadata):
            return
        time.sleep(0.1)
    raise CliError("daemon did not create pidfile/metadata before timeout")


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
    result = subprocess.run(
        ["adb", action, endpoint],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _load_metadata() -> DaemonMetadata | None:
    paths = daemon_paths()
    if not paths.metadata.is_file():
        return None
    return DaemonMetadata.model_validate_json(paths.metadata.read_text(encoding="utf-8"))


def _write_metadata(metadata: DaemonMetadata) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.metadata.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")


def _write_pidfile(pid: int) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.pidfile.write_text(f"{pid}\n", encoding="utf-8")


def _load_owned_endpoints() -> list[str]:
    paths = daemon_paths()
    if not paths.endpoints.is_file():
        return []
    state = OwnedEndpointsState.model_validate_json(
        paths.endpoints.read_text(encoding="utf-8")
    )
    return state.endpoints


def _write_owned_endpoints(endpoints: list[str]) -> None:
    paths = daemon_paths()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.endpoints.write_text(
        OwnedEndpointsState(endpoints=endpoints).model_dump_json(indent=2),
        encoding="utf-8",
    )


def _cleanup_stale_files() -> None:
    paths = daemon_paths()
    for path in (paths.pidfile, paths.metadata, paths.endpoints):
        if path.exists():
            path.unlink()
