from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cuttle_types import (
    CreateInstanceRequest,
    InstanceLogsView,
    InstanceState,
    InstanceView,
    LaunchOverrides,
    TemplateSummary,
    TemplateView,
)

from .config import CliSettings, load_cli_settings
from .daemon import (
    DaemonStatus,
    ensure_managed_daemon_running,
    get_daemon_status,
    refresh_adb_connection,
    run_daemon_forever,
    start_managed_daemon,
    stop_managed_daemon,
    sync_managed_daemon_once,
)
from .transport import CliError, CuttleApiClient

VISIBLE_INSTANCE_STATES = frozenset(
    {InstanceState.STARTING, InstanceState.ACTIVE, InstanceState.STOPPING}
)


@dataclass(frozen=True, slots=True)
class StartResult:
    instance: InstanceView
    logs: InstanceLogsView
    adb_target: str | None

    @property
    def is_active(self) -> bool:
        return self.instance.state == InstanceState.ACTIVE


@dataclass(frozen=True, slots=True)
class StopFailure:
    instance: InstanceView
    error_message: str


@dataclass(frozen=True, slots=True)
class StopManyResult:
    stopped: tuple[InstanceView, ...]
    failures: tuple[StopFailure, ...]

    @property
    def is_successful(self) -> bool:
        return not self.failures


@dataclass(frozen=True, slots=True)
class CuttleClient:
    settings: CliSettings = field(repr=False)
    _api: CuttleApiClient = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_api", CuttleApiClient.from_settings(self.settings))

    @classmethod
    def from_settings(cls, settings: CliSettings) -> "CuttleClient":
        return cls(settings=settings)

    @classmethod
    def from_config(
        cls,
        *,
        server_host: str | None = None,
        server_port: int | None = None,
        auth_token: str | None = None,
        user_id: str | None = None,
        config_path: Path | None = None,
    ) -> "CuttleClient":
        settings = load_cli_settings(
            server_host=server_host,
            server_port=server_port,
            auth_token=auth_token,
            user_id=user_id,
            config_path=config_path,
        )
        return cls.from_settings(settings)

    def start(
        self,
        template_name: str,
        *,
        name: str | None = None,
        cpus: int | None = None,
        selinux: bool | None = None,
        load_apps: bool | None = None,
        unmanaged: bool = False,
    ) -> StartResult:
        return self._start(
            template_name,
            name=name,
            cpus=cpus,
            selinux=selinux,
            load_apps=load_apps,
            unmanaged=unmanaged,
            on_log_chunk=None,
        )

    def _start_with_progress(
        self,
        template_name: str,
        *,
        name: str | None = None,
        cpus: int | None = None,
        selinux: bool | None = None,
        load_apps: bool | None = None,
        unmanaged: bool = False,
        on_log_chunk: Callable[[str], None],
    ) -> StartResult:
        return self._start(
            template_name,
            name=name,
            cpus=cpus,
            selinux=selinux,
            load_apps=load_apps,
            unmanaged=unmanaged,
            on_log_chunk=on_log_chunk,
        )

    def _start(
        self,
        template_name: str,
        *,
        name: str | None,
        cpus: int | None,
        selinux: bool | None,
        load_apps: bool | None,
        unmanaged: bool,
        on_log_chunk: Callable[[str], None] | None,
    ) -> StartResult:
        ensure_managed_daemon_running(self.settings)
        response = self._api.start_instance(
            CreateInstanceRequest(
                template_name=template_name,
                instance_name=name,
                overrides=LaunchOverrides(
                    cpus=cpus,
                    selinux=selinux,
                    load_apps=load_apps,
                    unmanaged=unmanaged,
                ),
            ),
            async_start=True,
        )
        return self._wait_for_start(response.instance, on_log_chunk=on_log_chunk)

    def restart(self, instance_name: str) -> StartResult:
        return self._restart(instance_name, on_log_chunk=None)

    def _restart_with_progress(
        self,
        instance_name: str,
        *,
        on_log_chunk: Callable[[str], None],
    ) -> StartResult:
        return self._restart(instance_name, on_log_chunk=on_log_chunk)

    def _restart(
        self,
        instance_name: str,
        *,
        on_log_chunk: Callable[[str], None] | None,
    ) -> StartResult:
        ensure_managed_daemon_running(self.settings)
        instance = self._api.restart_instance_by_name(
            instance_name,
            async_start=True,
        )
        result = self._wait_for_start(instance, on_log_chunk=on_log_chunk)
        if result.is_active and not result.instance.unmanaged:
            if result.adb_target is None:
                raise CliError(
                    f"restarted instance {result.instance.instance_name} "
                    "does not expose an ADB target"
                )
            try:
                refresh_adb_connection(result.adb_target)
            except CliError as exc:
                stop_warning = result.logs.stop_log.strip()
                warning_detail = (
                    f"; previous stop warning: {stop_warning}"
                    if stop_warning.startswith("restart stop warning:")
                    else ""
                )
                raise CliError(
                    f"restarted instance {result.instance.instance_name} is active at "
                    f"{result.adb_target}, but {exc}{warning_detail}"
                ) from exc
        return result

    def _wait_for_start(
        self,
        instance: InstanceView,
        *,
        on_log_chunk: Callable[[str], None] | None,
    ) -> StartResult:
        emitted_log_chars = 0
        while instance.state == InstanceState.STARTING:
            logs = self._api.get_instance_logs(instance.instance_id)
            emitted_log_chars = self._emit_new_log_text(
                logs.start_log,
                emitted_log_chars,
                on_log_chunk,
            )
            instance = self._api.get_instance(instance.instance_id)
            if instance.state == InstanceState.STARTING:
                time.sleep(1)

        logs = self._api.get_instance_logs(instance.instance_id)
        self._emit_new_log_text(logs.start_log, emitted_log_chars, on_log_chunk)
        return StartResult(
            instance=instance,
            logs=logs,
            adb_target=self._api.adb_target(instance),
        )

    def list_instances(self, *, include_terminal: bool = False) -> list[InstanceView]:
        ensure_managed_daemon_running(self.settings)
        instances = self._api.list_instances().instances
        if include_terminal:
            return list(instances)
        return [instance for instance in instances if self._is_visible(instance)]

    def logs(self, instance_id_or_name: str) -> InstanceLogsView:
        first_error: CliError | None = None
        try:
            return self._api.get_instance_logs(instance_id_or_name)
        except CliError as exc:
            first_error = exc

        matches = [
            instance
            for instance in self._api.list_instances().instances
            if instance.instance_id == instance_id_or_name
            or instance.instance_name == instance_id_or_name
        ]
        if len(matches) == 1:
            return self._api.get_instance_logs(matches[0].instance_id)
        if len(matches) > 1:
            raise CliError(f"multiple visible instances match {instance_id_or_name!r}")
        assert first_error is not None
        raise first_error

    def stop(self, instance_name: str) -> InstanceView:
        ensure_managed_daemon_running(self.settings)
        return self._api.stop_instance_by_name(instance_name)

    def stop_all(self) -> StopManyResult:
        ensure_managed_daemon_running(self.settings)
        instances = [
            instance
            for instance in self._api.list_instances().instances
            if self._is_visible(instance)
        ]
        return self._stop_many(instances)

    def stop_all_user(self, user_id: str) -> StopManyResult:
        ensure_managed_daemon_running(self.settings)
        instances = [
            instance
            for instance in self._api.list_instances().instances
            if self._is_visible(instance) and instance.owner_id == user_id
        ]
        return self._stop_many(instances)

    def list_templates(self) -> list[TemplateSummary]:
        return list(self._api.list_templates().templates)

    def show_template(self, template_name: str) -> TemplateView:
        return self._api.get_template(template_name)

    def adb_target(self, instance: InstanceView) -> str | None:
        return self._api.adb_target(instance)

    def daemon_start(self) -> None:
        start_managed_daemon(self.settings)

    def daemon_stop(self) -> bool:
        return stop_managed_daemon()

    def daemon_status(self) -> DaemonStatus:
        return get_daemon_status()

    def daemon_sync(self) -> list[str]:
        if get_daemon_status().running:
            raise CliError("daemon is already running; stop it before manual sync")
        return sync_managed_daemon_once(self.settings)

    def _run_daemon_forever(self) -> None:
        run_daemon_forever(self.settings)

    def _stop_many(self, instances: list[InstanceView]) -> StopManyResult:
        stopped_instances: list[InstanceView] = []
        failures: list[StopFailure] = []
        for instance in instances:
            try:
                stopped_instances.append(self._api.stop_instance(instance.instance_id))
            except CliError as exc:
                failures.append(StopFailure(instance=instance, error_message=str(exc)))
        return StopManyResult(
            stopped=tuple(stopped_instances),
            failures=tuple(failures),
        )

    @staticmethod
    def _emit_new_log_text(
        log_text: str,
        offset: int,
        on_log_chunk: Callable[[str], None] | None,
    ) -> int:
        if len(log_text) <= offset:
            return offset
        if on_log_chunk is not None:
            on_log_chunk(log_text[offset:])
        return len(log_text)

    @staticmethod
    def _is_visible(instance: InstanceView) -> bool:
        return instance.state in VISIBLE_INSTANCE_STATES


__all__ = [
    "CliError",
    "CuttleApiClient",
    "CuttleClient",
    "StartResult",
    "StopFailure",
    "StopManyResult",
]
