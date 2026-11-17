from __future__ import annotations

import logging
import os
import shutil
import threading
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Mapping
from uuid import UUID

from cuttle_types import (
    CreateInstanceRequest,
    CreateInstanceResponse,
    CreateSnapshotRequest,
    CuttlefishBackendKind,
    InstanceListResponse,
    InstanceLogsView,
    InstanceState,
    InstanceView,
    RenewLeaseRequest,
    RestoreSnapshotRequest,
    SnapshotListResponse,
    SnapshotState,
    SnapshotView,
    TemplateListResponse,
    TemplateView,
)

from .app_loader import AppLoader, CuttlefishAppLoader
from .backends import CuttlefishBackend
from .config import CuttlefishSettings
from .db import InstanceDb
from .models import (
    ACTIVE_STATES,
    InstanceRecord,
    LIVE_SNAPSHOT_STATES,
    ResolvedLaunchConfig,
    SnapshotRecord,
    TERMINAL_STATES,
    instance_view_from_record,
    snapshot_view_from_record,
    template_summary_from_template,
    template_view_from_template,
    utc_now,
)

LOGGER = logging.getLogger(__name__)
RESTART_STOP_WARNING_PREFIX = "restart stop warning: "
# Instances in these states can be the target of a snapshot restore. A running
# (or crashed) instance is stopped first; a stopped or expired one is revived.
RESTORABLE_INSTANCE_STATES = frozenset(
    {
        InstanceState.ACTIVE,
        InstanceState.CRASHED,
        InstanceState.STOPPED,
        InstanceState.EXPIRED,
    }
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
        backends: Mapping[CuttlefishBackendKind, CuttlefishBackend],
        app_loader: AppLoader | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.backends = dict(backends)
        self.app_loader = app_loader or CuttlefishAppLoader()
        self.lock = threading.RLock()
        # Snapshots that an in-flight restore is reading. They must not be
        # deleted until the restoring instance has finished starting.
        self._restoring_snapshot_ids: set[str] = set()

        missing_backends = {
            template.backend
            for template in settings.templates.values()
            if template.backend not in self.backends
        }
        if missing_backends:
            names = ", ".join(sorted(backend.value for backend in missing_backends))
            raise ValueError(f"missing configured Cuttlefish backends: {names}")

    def initialize(self) -> None:
        self.settings.instance_runtime_root.mkdir(parents=True, exist_ok=True)
        if any(
            template.snapshot_supported
            for template in self.settings.templates.values()
        ):
            try:
                self.settings.snapshot_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise RuntimeError(
                    f"cannot create snapshot_root {self.settings.snapshot_root}: "
                    f"{exc}. Create it and make it writable by the server user."
                ) from exc
        self.db.initialize()
        self._fail_interrupted_snapshots()

    def create_instance(
        self,
        user_id: str,
        request: CreateInstanceRequest,
        *,
        start_async: bool = False,
    ) -> CreateInstanceResponse:
        with self.lock:
            self.reconcile_expired_instances()
            config = self._resolve_config(request)
            expires_at = self._resolve_expiration_deadline(
                self.settings.instance_timeout_sec
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
                runtime_dir=(
                    self.settings.instance_runtime_root
                    / self._runtime_dir_name(instance_id)
                ),
                launch_command=[],
                adb_port=None,
                adb_serial=None,
                webrtc_port=None,
                backend_runtime_id=None,
                expires_at=expires_at,
                failure_reason=None,
            )
            record.launch_command = self._build_launch_command(record)
            self.db.upsert(record)

        if start_async:
            thread = threading.Thread(
                target=self._complete_instance_start_in_background,
                args=(record,),
                daemon=True,
            )
            thread.start()
            return CreateInstanceResponse(instance=instance_view_from_record(record))

        self._complete_instance_start(record)
        return CreateInstanceResponse(instance=instance_view_from_record(record))

    def _complete_instance_start(
        self,
        record: InstanceRecord,
        *,
        restore_snapshot: SnapshotRecord | None = None,
    ) -> None:
        try:
            self._start_and_activate(record, restore_snapshot)
        finally:
            if restore_snapshot is not None:
                with self.lock:
                    self._restoring_snapshot_ids.discard(restore_snapshot.snapshot_id)

    def _start_and_activate(
        self,
        record: InstanceRecord,
        restore_snapshot: SnapshotRecord | None,
    ) -> None:
        backend = self._backend_for(record)
        try:
            launch_result = backend.start_instance(
                record,
                snapshot_dir=(
                    restore_snapshot.snapshot_dir if restore_snapshot else None
                ),
            )
        except Exception as exc:
            record.state = InstanceState.CRASHED
            record.failure_reason = str(exc)
            self.db.upsert(record)
            raise InstanceError(f"failed to start instance: {exc}") from exc

        record.launch_command = launch_result.launch_command
        record.adb_port = launch_result.adb_port
        record.adb_serial = launch_result.adb_serial
        record.webrtc_port = launch_result.webrtc_port
        record.backend_runtime_id = launch_result.backend_runtime_id
        self.db.upsert(record)

        # A restored instance already has its apps installed.
        if restore_snapshot is None and record.config.load_apps and record.config.apps:
            try:
                self.app_loader.load_apps(record)
            except Exception as exc:
                self._fail_startup(record, f"failed to load apps: {exc}")
                raise InstanceError(f"failed to load apps: {exc}") from exc

        record.state = InstanceState.ACTIVE
        record.failure_reason = None
        self.db.upsert(record)

    def _complete_instance_start_in_background(
        self,
        record: InstanceRecord,
        restore_snapshot: SnapshotRecord | None = None,
    ) -> None:
        try:
            self._complete_instance_start(record, restore_snapshot=restore_snapshot)
        except InstanceError:
            return

    def get_instance(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
    ) -> InstanceView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            if record.is_expired(now=utc_now()):
                self._expire_instance(record)
                record = self._get_visible_instance_record(
                    user_id, is_admin, instance_id
                )
            return instance_view_from_record(record)

    def get_instance_logs(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
    ) -> InstanceLogsView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            logs = self._backend_for(record).read_logs(record)
            return InstanceLogsView(
                instance_id=record.instance_id,
                instance_name=record.effective_instance_name,
                state=record.state,
                launch_command=record.launch_command,
                failure_reason=record.failure_reason,
                start_log=logs.start_log,
                stop_log=logs.stop_log,
                kernel_log=logs.kernel_log,
                launcher_log=logs.launcher_log,
                logcat=logs.logcat,
            )

    def renew_lease(
        self,
        user_id: str,
        is_admin: bool,
        instance_id: str,
        request: RenewLeaseRequest,
    ) -> InstanceView:
        with self.lock:
            record = self._get_visible_instance_record(user_id, is_admin, instance_id)
            timeout_sec = (
                request.timeout_sec
                if request.timeout_sec is not None
                else self.settings.instance_timeout_sec
            )
            record.expires_at = self._resolve_expiration_deadline(timeout_sec)
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
                self._backend_for(record).stop_instance(record)
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

    def restart_instance_by_name(
        self,
        user_id: str,
        is_admin: bool,
        instance_name: str,
        *,
        start_async: bool = False,
    ) -> InstanceView:
        with self.lock:
            record = self._get_record_by_name(user_id, is_admin, instance_name)
            if record.state != InstanceState.ACTIVE:
                raise InstanceError(
                    f"instance {record.effective_instance_name} is not active"
                )
            if record.adb_port is None:
                raise InstanceError(
                    f"instance {record.effective_instance_name} has no ADB port"
                )

            self._reset_for_relaunch(record, stop_first=True)

        if start_async:
            thread = threading.Thread(
                target=self._complete_instance_start_in_background,
                args=(record,),
                daemon=True,
            )
            thread.start()
            return instance_view_from_record(record)

        self._complete_instance_start(record)
        return instance_view_from_record(record)

    def _reset_for_relaunch(
        self,
        record: InstanceRecord,
        *,
        stop_first: bool,
        snapshot_dir: Path | None = None,
    ) -> None:
        """Clear `record` so it can be launched again in the same slot.

        Stops the instance first when `stop_first` is set (a stop failure is kept
        as a warning), removes its runtime directory, and leaves the record in
        STARTING with a fresh lease. The caller holds `self.lock` and then calls
        `_complete_instance_start`.
        """
        stop_warning: str | None = None
        if stop_first:
            record.state = InstanceState.STOPPING
            self.db.upsert(record)
            try:
                self._backend_for(record).stop_instance(record)
            except Exception as exc:
                stop_warning = f"{RESTART_STOP_WARNING_PREFIX}{exc}"

        try:
            if record.runtime_dir.exists():
                shutil.rmtree(record.runtime_dir)
        except Exception as exc:
            detail = f"restart runtime dir cleanup failed: {exc}"
            if stop_warning is not None:
                detail = f"{stop_warning}; {detail}"
            record.state = InstanceState.CRASHED
            record.failure_reason = detail
            self.db.upsert(record)
            raise InstanceError(detail) from exc

        record.state = InstanceState.STARTING
        record.launch_command = self._build_launch_command(
            record, snapshot_dir=snapshot_dir
        )
        record.adb_serial = None
        record.webrtc_port = None
        record.backend_runtime_id = None
        record.expires_at = self._resolve_expiration_deadline(
            self.settings.instance_timeout_sec
        )
        record.failure_reason = None
        self.db.upsert(record)

        if stop_warning is not None:
            self._write_restart_stop_warning(record, stop_warning)

    def list_instances(self, user_id: str, is_admin: bool) -> InstanceListResponse:
        owner_id = None if is_admin else user_id
        return InstanceListResponse(
            instances=[
                instance_view_from_record(record)
                for record in self.db.list_instances(owner_id)
            ]
        )

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def create_snapshot(
        self,
        user_id: str,
        is_admin: bool,
        instance_name: str,
        request: CreateSnapshotRequest,
    ) -> SnapshotView:
        with self.lock:
            instance = self._get_record_by_name(user_id, is_admin, instance_name)
            if instance.state != InstanceState.ACTIVE:
                raise InstanceError(
                    f"instance {instance.effective_instance_name} is not active"
                )
            if not instance.config.snapshot_compatible:
                raise InstanceError(
                    f"instance {instance.effective_instance_name} was not started "
                    "with snapshot support; start it with --snapshots"
                )

            # Snapshots belong to the instance's owner, so an admin snapshotting
            # someone else's instance produces a snapshot that user can see.
            owner_id = instance.owner_id
            for existing in self.db.list_snapshots_by_name(
                request.snapshot_name, owner_id=owner_id
            ):
                if existing.state in LIVE_SNAPSHOT_STATES:
                    raise InstanceError(
                        f"snapshot name already in use for user {owner_id}: "
                        f"{request.snapshot_name}"
                    )
                self._remove_snapshot(existing)

            backend = self._backend_for(instance)
            try:
                fingerprint = backend.host_tools_fingerprint(instance)
            except Exception as exc:
                raise InstanceError(
                    f"cannot snapshot instance {instance.effective_instance_name}: {exc}"
                ) from exc

            snapshot_id = str(uuid.uuid4())
            record = SnapshotRecord(
                snapshot_id=snapshot_id,
                snapshot_name=request.snapshot_name,
                owner_id=owner_id,
                state=SnapshotState.CREATING,
                source_instance_id=instance.instance_id,
                source_instance_name=instance.effective_instance_name,
                template_name=instance.config.template_name,
                backend=instance.config.backend,
                instance_num=instance.instance_num,
                runtime_dir=instance.runtime_dir,
                snapshot_dir=(
                    self.settings.snapshot_root / self._runtime_dir_name(snapshot_id)
                ),
                host_tools_fingerprint=fingerprint,
                created_at=utc_now(),
            )
            self.db.upsert_snapshot(record)

            try:
                backend.take_snapshot(instance, record.snapshot_dir)
            except Exception as exc:
                self._remove_snapshot_dir(record.snapshot_dir)
                record.state = SnapshotState.FAILED
                record.failure_reason = str(exc)
                self.db.upsert_snapshot(record)
                raise InstanceError(
                    f"failed to snapshot instance {instance.effective_instance_name}: "
                    f"{exc}"
                ) from exc

            record.size_bytes = _disk_usage_bytes(record.snapshot_dir)
            record.state = SnapshotState.READY
            self.db.upsert_snapshot(record)
            return snapshot_view_from_record(record)

    def list_snapshots(
        self,
        user_id: str,
        is_admin: bool,
        *,
        instance: str | None = None,
        template_name: str | None = None,
    ) -> SnapshotListResponse:
        records = self.db.list_snapshots(None if is_admin else user_id)
        if instance is not None:
            records = [
                record
                for record in records
                if instance in (record.source_instance_id, record.source_instance_name)
            ]
        if template_name is not None:
            records = [
                record for record in records if record.template_name == template_name
            ]
        return SnapshotListResponse(
            snapshots=[snapshot_view_from_record(record) for record in records]
        )

    def get_snapshot_by_name(
        self, user_id: str, is_admin: bool, snapshot_name: str
    ) -> SnapshotView:
        record = self._get_snapshot_by_name(user_id, is_admin, snapshot_name)
        return snapshot_view_from_record(record)

    def delete_snapshot_by_name(
        self, user_id: str, is_admin: bool, snapshot_name: str
    ) -> SnapshotView:
        with self.lock:
            record = self._get_snapshot_by_name(user_id, is_admin, snapshot_name)
            if record.state == SnapshotState.CREATING:
                raise InstanceError(
                    f"snapshot {record.snapshot_name} is still being created"
                )
            if record.snapshot_id in self._restoring_snapshot_ids:
                raise InstanceError(
                    f"snapshot {record.snapshot_name} is being restored"
                )
            self._remove_snapshot(record)
            return snapshot_view_from_record(record)

    def restore_snapshot(
        self,
        user_id: str,
        is_admin: bool,
        instance_name: str,
        request: RestoreSnapshotRequest,
        *,
        start_async: bool = False,
    ) -> InstanceView:
        """Restore a snapshot into an instance.

        A running instance is stopped first; a stopped or expired one is revived.
        Cuttlefish only restores a snapshot into the instance number and runtime
        directory it was taken in, so the instance must match the snapshot.
        """
        with self.lock:
            record = self._get_record_by_name(user_id, is_admin, instance_name)
            snapshot = self._get_snapshot_for_instance(
                user_id, is_admin, record, request.snapshot_name
            )
            self._check_restore_compatible(record, snapshot)

            self._reset_for_relaunch(
                record,
                stop_first=record.state
                in {InstanceState.ACTIVE, InstanceState.CRASHED},
                snapshot_dir=snapshot.snapshot_dir,
            )
            self._restoring_snapshot_ids.add(snapshot.snapshot_id)

        if start_async:
            thread = threading.Thread(
                target=self._complete_instance_start_in_background,
                args=(record, snapshot),
                daemon=True,
            )
            thread.start()
            return instance_view_from_record(record)

        self._complete_instance_start(record, restore_snapshot=snapshot)
        return instance_view_from_record(record)

    def _check_restore_compatible(
        self, instance: InstanceRecord, snapshot: SnapshotRecord
    ) -> None:
        name = instance.effective_instance_name
        if snapshot.state != SnapshotState.READY:
            raise InstanceError(
                f"snapshot {snapshot.snapshot_name} is not ready "
                f"(state: {snapshot.state.value})"
            )
        if instance.state not in RESTORABLE_INSTANCE_STATES:
            raise InstanceError(
                f"instance {name} is {instance.state.value}; wait for it to finish "
                "starting or stopping before restoring"
            )
        if snapshot.owner_id != instance.owner_id:
            raise InstanceError(
                f"snapshot {snapshot.snapshot_name} belongs to {snapshot.owner_id}, "
                f"not to the owner of instance {name}"
            )
        if (
            instance.config.template_name != snapshot.template_name
            or instance.config.backend != snapshot.backend
        ):
            raise InstanceError(
                f"snapshot {snapshot.snapshot_name} was taken from template "
                f"{snapshot.template_name} ({snapshot.backend.value} backend), but "
                f"instance {name} uses {instance.config.template_name} "
                f"({instance.config.backend.value} backend)"
            )
        if not instance.config.snapshot_compatible:
            raise InstanceError(
                f"instance {name} was not started with snapshot support"
            )
        if (
            instance.instance_num != snapshot.instance_num
            or instance.runtime_dir != snapshot.runtime_dir
        ):
            raise InstanceError(
                f"snapshot {snapshot.snapshot_name} was taken from instance "
                f"{snapshot.source_instance_name} (instance number "
                f"{snapshot.instance_num}). Cuttlefish can only restore a snapshot "
                "into the instance number and runtime directory it was taken in, "
                f"which instance {name} does not match"
            )
        try:
            fingerprint = self._backend_for(instance).host_tools_fingerprint(instance)
        except Exception as exc:
            raise InstanceError(f"cannot check snapshot compatibility: {exc}") from exc
        if fingerprint != snapshot.host_tools_fingerprint:
            raise InstanceError(
                f"the Cuttlefish host tools changed since snapshot "
                f"{snapshot.snapshot_name} was taken, so it can no longer be restored"
            )
        if instance.is_terminal:
            # A stopped or expired instance gives up its slot, which another
            # instance may have taken in the meantime.
            if instance.instance_num in self.db.list_active_instance_numbers():
                raise InstanceError(
                    f"instance number {instance.instance_num} is in use by another "
                    f"instance, so {name} cannot be restored right now"
                )
            if instance.instance_name is not None and self.db.has_active_instance_name(
                instance.owner_id, instance.instance_name
            ):
                raise InstanceError(
                    f"instance name already in use for user {instance.owner_id}: "
                    f"{instance.instance_name}"
                )

    def _get_snapshot_by_name(
        self, user_id: str, is_admin: bool, snapshot_name: str
    ) -> SnapshotRecord:
        matches = self.db.list_snapshots_by_name(
            snapshot_name,
            owner_id=None if is_admin else user_id,
        )
        live = [match for match in matches if match.state in LIVE_SNAPSHOT_STATES]
        if is_admin and (len(live) > 1 or (not live and len(matches) > 1)):
            raise InstanceError("snapshot name is ambiguous for admin; use snapshot_id")
        if live:
            return live[0]
        if matches:
            return matches[0]

        fallback = self.db.get_snapshot(snapshot_name)
        if fallback is not None:
            self._ensure_snapshot_visible(fallback, user_id, is_admin)
            return fallback
        raise NotFoundError(f"snapshot {snapshot_name} does not exist")

    def _get_snapshot_for_instance(
        self,
        user_id: str,
        is_admin: bool,
        instance: InstanceRecord,
        snapshot_name: str,
    ) -> SnapshotRecord:
        """Find `snapshot_name` among the snapshots of the instance's owner.

        Restricting to the owner keeps an admin's lookup unambiguous when several
        users reuse the same snapshot name.
        """
        matches = [
            match
            for match in self.db.list_snapshots_by_name(
                snapshot_name, owner_id=instance.owner_id
            )
            if match.state in LIVE_SNAPSHOT_STATES
        ]
        if matches:
            return matches[0]
        return self._get_snapshot_by_name(user_id, is_admin, snapshot_name)

    @staticmethod
    def _ensure_snapshot_visible(
        record: SnapshotRecord, user_id: str, is_admin: bool
    ) -> None:
        if not is_admin and record.owner_id != user_id:
            raise AuthorizationError(
                f"snapshot {record.snapshot_id} does not belong to user {user_id}"
            )

    def _remove_snapshot(self, record: SnapshotRecord) -> None:
        self._remove_snapshot_dir(record.snapshot_dir)
        self.db.delete_snapshot(record.snapshot_id)

    def _remove_snapshot_dir(self, snapshot_dir: Path) -> None:
        # The path comes from the database; never delete outside the snapshot root.
        if not snapshot_dir.is_relative_to(self.settings.snapshot_root):
            raise InstanceError(
                f"refusing to remove {snapshot_dir}: outside the snapshot root "
                f"{self.settings.snapshot_root}"
            )
        try:
            if snapshot_dir.exists():
                shutil.rmtree(snapshot_dir)
        except OSError as exc:
            raise InstanceError(
                f"failed to remove snapshot data {snapshot_dir}: {exc}"
            ) from exc

    def _fail_interrupted_snapshots(self) -> None:
        """Mark snapshots that were being created when the server stopped as failed."""
        for record in self.db.list_snapshots():
            if record.state != SnapshotState.CREATING:
                continue
            try:
                self._remove_snapshot_dir(record.snapshot_dir)
            except InstanceError:
                LOGGER.exception(
                    "failed to remove partial snapshot data %s", record.snapshot_dir
                )
            record.state = SnapshotState.FAILED
            record.failure_reason = "interrupted by a server restart"
            self.db.upsert_snapshot(record)

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
            records = self.db.list_instances()
            self._reconcile_backends(records)
            for record in self.db.list_instances():
                if record.state in TERMINAL_STATES:
                    continue
                if record.is_expired(now=utc_now()):
                    self._expire_instance(record)

    def _expire_instance(self, record: InstanceRecord) -> None:
        try:
            self._backend_for(record).stop_instance(record)
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

    @staticmethod
    def _write_restart_stop_warning(record: InstanceRecord, warning: str) -> None:
        try:
            record.runtime_dir.mkdir(parents=True, exist_ok=True)
            (record.runtime_dir / "cvd-stop.log").write_text(
                f"{warning}\n",
                encoding="utf-8",
            )
        except OSError:
            LOGGER.exception(
                "failed to persist restart stop warning for instance %s",
                record.instance_id,
            )

    def _fail_startup(self, record: InstanceRecord, failure_reason: str) -> None:
        record.state = InstanceState.CRASHED
        record.failure_reason = failure_reason
        try:
            self._backend_for(record).stop_instance(record)
        except Exception as stop_exc:
            record.failure_reason = f"{failure_reason}; cleanup stop failed: {stop_exc}"
            self.db.upsert(record)
            return

        self.db.upsert(record)

    def _build_launch_command(
        self, record: InstanceRecord, *, snapshot_dir: Path | None = None
    ) -> list[str]:
        return list(
            self._backend_for(record).build_start_command(
                record, snapshot_dir=snapshot_dir
            )
        )

    def _backend_for(self, record: InstanceRecord) -> CuttlefishBackend:
        try:
            return self.backends[record.config.backend]
        except KeyError as exc:
            raise InstanceError(
                f"backend {record.config.backend.value!r} is unavailable"
            ) from exc

    def _reconcile_backends(self, records: list[InstanceRecord]) -> None:
        required_backend_kinds = {
            template.backend for template in self.settings.templates.values()
        }
        required_backend_kinds.update(record.config.backend for record in records)
        for backend_kind in required_backend_kinds:
            backend = self.backends.get(backend_kind)
            if backend is None:
                continue
            for failure in backend.reconcile(records):
                record = self.db.get(failure.instance_id)
                if record is None or record.state not in ACTIVE_STATES:
                    continue
                record.state = InstanceState.CRASHED
                record.failure_reason = failure.reason
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
        first_instance_num = self.settings.base_instance_num + 1
        last_instance_num = self.settings.base_instance_num + self.settings.max_instances
        for instance_num in range(first_instance_num, last_instance_num + 1):
            if instance_num not in active_numbers:
                return instance_num
        raise CapacityError(
            "no instance slots available; "
            f"managed range is {first_instance_num}-{last_instance_num}"
        )

    @staticmethod
    def _runtime_dir_name(instance_id: str) -> str:
        try:
            return UUID(instance_id).hex
        except ValueError:
            return instance_id.replace("-", "")

    @staticmethod
    def _resolve_expiration_deadline(timeout_sec: int | None = None) -> datetime | None:
        if timeout_sec is None:
            return None
        return utc_now() + timedelta(seconds=timeout_sec)

    def _resolve_config(self, request: CreateInstanceRequest) -> ResolvedLaunchConfig:
        template = self.settings.templates.get(request.template_name)
        if template is None:
            raise InstanceError(f"unknown template: {request.template_name}")
        if request.overrides.snapshots_enabled and not template.snapshot_supported:
            raise InstanceError(
                f"template {template.name} does not support snapshots"
            )

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
            unmanaged=request.overrides.unmanaged,
            command_mode=template.command_mode,
            backend=template.backend,
            docker_image=template.docker_image,
            cvd_binary=template.cvd_binary,
            snapshot_compatible=request.overrides.snapshots_enabled,
        )


def _disk_usage_bytes(path: Path) -> int:
    """Disk space used by the files under `path`; sparse files count as allocated."""
    total = 0
    for directory, _, file_names in os.walk(path):
        for file_name in file_names:
            try:
                total += os.lstat(os.path.join(directory, file_name)).st_blocks * 512
            except OSError:
                continue
    return total
