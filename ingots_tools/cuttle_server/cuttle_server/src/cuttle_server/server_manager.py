from __future__ import annotations

import shutil
import threading
import uuid
from datetime import timedelta

from cuttle_types import (
    CreateInstanceRequest,
    CreateInstanceResponse,
    InstanceListResponse,
    InstanceState,
    InstanceView,
    RenewLeaseRequest,
    TemplateListResponse,
    TemplateView,
)

from .app_loader import CuttlefishAppLoader
from .config import CuttlefishSettings
from .cvd_cli import CuttlefishCli
from .db import InstanceDb
from .models import (
    ACTIVE_STATES,
    InstanceRecord,
    ResolvedLaunchConfig,
    TERMINAL_STATES,
    instance_view_from_record,
    template_summary_from_template,
    template_view_from_template,
    utc_now,
)


class InstanceError(Exception):
    pass


class NotFoundError(InstanceError):
    pass


class AuthorizationError(InstanceError):
    pass


class CapacityError(InstanceError):
    pass


class CuttlefishServerManager:
    """Manages starting and stopping instances and writing to the db."""

    def __init__(
        self,
        settings: CuttlefishSettings,
        db: InstanceDb,
        cli: CuttlefishCli,
        app_loader: CuttlefishAppLoader | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.cli = cli
        self.app_loader = app_loader or CuttlefishAppLoader()
        self.lock = threading.RLock()

    def initialize(self) -> None:
        self.settings.instance_runtime_root.mkdir(parents=True, exist_ok=True)
        self.db.initialize()

    def create_instance(
        self,
        user_id: str,
        request: CreateInstanceRequest,
    ) -> CreateInstanceResponse:
        with self.lock:
            self.reconcile_expired_instances()
            config = self._resolve_config(request)
            expires_at = utc_now() + timedelta(
                seconds=self.settings.instance_timeout_sec
            )
            if request.instance_name is not None and self.db.has_active_instance_name(
                user_id, request.instance_name
            ):
                raise InstanceError(
                    f"instance name already in use for user {user_id}: {request.instance_name}"
                )
            instance_num = self._allocate_instance_number()
            instance_id = str(uuid.uuid4())
            record = InstanceRecord(
                instance_id=instance_id,
                owner_id=user_id,
                instance_name=request.instance_name,
                state=InstanceState.STARTING,
                instance_num=instance_num,
                config=config,
                runtime_dir=self.settings.instance_runtime_root / instance_id,
                launch_command=[],
                adb_port=None,
                adb_serial=None,
                webrtc_port=None,
                expires_at=expires_at,
                failure_reason=None,
            )
            self.db.upsert(record)

        try:
            launch_result = self.cli.start_instance(record)
        except Exception as exc:
            record.state = InstanceState.CRASHED
            record.failure_reason = str(exc)
            self.db.upsert(record)
            raise InstanceError(f"failed to start instance: {exc}") from exc

        record.launch_command = launch_result.launch_command
        record.adb_port = launch_result.adb_port
        record.adb_serial = launch_result.adb_serial
        record.webrtc_port = launch_result.webrtc_port
        self.db.upsert(record)

        if record.config.load_apps and record.config.apps:
            try:
                self.app_loader.load_apps(record)
            except Exception as exc:
                self._fail_startup(record, f"failed to load apps: {exc}")
                raise InstanceError(f"failed to load apps: {exc}") from exc

        record.state = InstanceState.ACTIVE
        record.failure_reason = None
        self.db.upsert(record)

        return CreateInstanceResponse(instance=instance_view_from_record(record))

    def get_instance(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
    ) -> InstanceView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            if record.is_expired(
                now=utc_now(), timeout_sec=self.settings.instance_timeout_sec
            ):
                self._expire_instance(record)
                record = self._get_visible_instance_record(
                    user_id, is_admin, instance_id
                )
            return instance_view_from_record(record)

    def renew_lease(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
        request: RenewLeaseRequest,
    ) -> InstanceView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            timeout_sec = request.timeout_sec or self.settings.instance_timeout_sec
            record.expires_at = utc_now() + timedelta(seconds=timeout_sec)
            self.db.upsert(record)
            return instance_view_from_record(record)

    def stop_instance(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
    ) -> InstanceView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            if record.state in {InstanceState.STOPPED, InstanceState.EXPIRED}:
                return instance_view_from_record(record)

            record.state = InstanceState.STOPPING
            self.db.upsert(record)

            try:
                self.cli.stop_instance(record)
                record.state = InstanceState.STOPPED
                record.failure_reason = None
            except Exception as exc:
                record.state = InstanceState.CRASHED
                record.failure_reason = str(exc)
                self.db.upsert(record)
                raise InstanceError(f"failed to stop instance: {exc}") from exc

            self._cleanup_runtime_dir(record, state=InstanceState.STOPPED)
            self.db.upsert(record)
            return instance_view_from_record(record)

    def stop_instance_by_name(
        self,
        user_id: str,
        is_admin: bool,
        instance_name: str,
    ) -> InstanceView:
        record = self._get_record_by_name(user_id, is_admin, instance_name)
        return self.stop_instance(user_id, is_admin, record.instance_id)

    def list_instances(self, user_id: str, is_admin: bool) -> InstanceListResponse:
        owner_id = None if is_admin else user_id
        return InstanceListResponse(
            instances=[
                instance_view_from_record(record)
                for record in self.db.list_instances(owner_id)
            ]
        )

    def list_templates(self) -> TemplateListResponse:
        return TemplateListResponse(
            templates=[
                template_summary_from_template(template)
                for template in sorted(
                    self.settings.templates.values(), key=lambda template: template.name
                )
            ]
        )

    def get_template(self, template_name: str) -> TemplateView:
        template = self.settings.templates.get(template_name)
        if template is None:
            raise NotFoundError(f"template {template_name} does not exist")
        return template_view_from_template(template)

    def reconcile_expired_instances(self) -> None:
        with self.lock:
            for record in self.db.list_instances():
                if record.state in TERMINAL_STATES:
                    continue
                if record.is_expired(
                    now=utc_now(), timeout_sec=self.settings.instance_timeout_sec
                ):
                    self._expire_instance(record)

    def _expire_instance(self, record: InstanceRecord) -> None:
        try:
            self.cli.stop_instance(record)
            record.state = InstanceState.EXPIRED
            record.failure_reason = None
        except Exception as exc:
            record.state = InstanceState.CRASHED
            record.failure_reason = f"expire cleanup failed: {exc}"
            self.db.upsert(record)
            return

        self._cleanup_runtime_dir(record, state=InstanceState.EXPIRED)
        self.db.upsert(record)

    def _cleanup_runtime_dir(self, record: InstanceRecord, *, state: InstanceState) -> None:
        try:
            if record.runtime_dir.exists():
                shutil.rmtree(record.runtime_dir)
        except Exception as exc:
            record.state = state
            record.failure_reason = f"runtime dir cleanup failed: {exc}"
            return
        record.state = state

    def _fail_startup(self, record: InstanceRecord, failure_reason: str) -> None:
        record.state = InstanceState.CRASHED
        record.failure_reason = failure_reason
        try:
            self.cli.stop_instance(record)
        except Exception as stop_exc:
            record.failure_reason = f"{failure_reason}; cleanup stop failed: {stop_exc}"
            self.db.upsert(record)
            return

        self._cleanup_runtime_dir(record, state=InstanceState.CRASHED)
        self.db.upsert(record)

    def _get_instance_record(self, instance_id: str) -> InstanceRecord:
        record = self.db.get(instance_id)
        if not record:
            raise NotFoundError(f"instance {instance_id} does not exist")
        return record

    def _get_visible_instance_record(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
    ) -> InstanceRecord:
        record = self._get_instance_record(instance_id)
        self._ensure_visible(record, user_id, is_admin)
        return record

    def _ensure_visible(
        self, record: InstanceRecord, user_id: str, is_admin: bool
    ) -> None:
        if not is_admin and record.owner_id != user_id:
            raise AuthorizationError(
                f"instance {record.instance_id} does not belong to user {user_id}"
            )

    def _get_record_by_name(
        self,
        user_id: str,
        is_admin: bool,
        instance_name: str,
    ) -> InstanceRecord:
        explicit_matches = self.db.list_instances_by_name(
            instance_name,
            owner_id=None if is_admin else user_id,
        )
        explicit_record = (
            self._select_admin_named_match(explicit_matches)
            if is_admin
            else self._select_user_named_match(explicit_matches)
        )
        if explicit_record is not None:
            return explicit_record

        fallback_record = self.db.get(instance_name)
        if fallback_record is not None:
            self._ensure_visible(fallback_record, user_id, is_admin)
            return fallback_record

        raise NotFoundError(f"instance {instance_name} does not exist")

    def _select_user_named_match(
        self, explicit_matches: list[InstanceRecord]
    ) -> InstanceRecord | None:
        for record in explicit_matches:
            if record.state not in TERMINAL_STATES:
                return record
        return explicit_matches[0] if explicit_matches else None

    def _select_admin_named_match(
        self, explicit_matches: list[InstanceRecord]
    ) -> InstanceRecord | None:
        active_matches = [
            record for record in explicit_matches if record.state in ACTIVE_STATES
        ]
        if len(active_matches) > 1:
            raise InstanceError("instance name is ambiguous for admin; use instance_id")
        if len(active_matches) == 1:
            return active_matches[0]
        if len(explicit_matches) > 1:
            raise InstanceError("instance name is ambiguous for admin; use instance_id")
        return explicit_matches[0] if explicit_matches else None

    def _allocate_instance_number(self) -> int:
        active_numbers = self.db.list_active_instance_numbers()
        for instance_num in range(1, self.settings.max_instances + 1):
            if instance_num not in active_numbers:
                return instance_num
        raise CapacityError(
            f"no instance slots available; max is {self.settings.max_instances}"
        )

    def _resolve_config(self, request: CreateInstanceRequest) -> ResolvedLaunchConfig:
        template = self.settings.templates.get(request.template_name)
        if template is None:
            raise InstanceError(f"unknown template: {request.template_name}")

        return ResolvedLaunchConfig(
            template_name=template.name,
            cpus=request.overrides.cpus or template.cpus,
            selinux=(
                request.overrides.selinux
                if request.overrides.selinux is not None
                else template.selinux
            ),
            runtime_root=template.runtime_root,
            kernel_path=template.kernel_path,
            initrd_path=template.initrd_path,
            apps=list(template.apps),
            load_apps=(
                request.overrides.load_apps
                if request.overrides.load_apps is not None
                else True
            ),
            launch_binary=template.launch_binary,
            stop_binary=template.stop_binary,
        )
