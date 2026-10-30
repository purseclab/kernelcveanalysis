from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cuttle_cli import CliError, CuttleClient

from .adb import Adb
from .models import MetadataError, VerifyError


@dataclass(slots=True)
class Guest:
    client: CuttleClient
    template: str
    instance_name: str
    instance_id: str
    adb_target: str
    adb: Adb
    template_selinux: str | None
    created: bool
    warnings: list[str] = field(default_factory=list)

    def stop(self) -> None:
        if not self.created:
            return
        target = self.instance_id or self.instance_name
        try:
            self.client.stop(target)
        except CliError as exc:
            raise VerifyError(
                f"failed to stop Cuttlefish instance {self.instance_name}: {exc}"
            ) from exc


def start_guest(
    template: str,
    *,
    name: str,
    cpus: int | None = None,
    selinux: bool | None = None,
) -> Guest:
    try:
        client = CuttleClient.from_config()
    except Exception as exc:
        raise MetadataError(f"failed to load cuttle-cli configuration: {exc}") from exc

    template_selinux: str | None = None
    try:
        view = client.show_template(template)
        template_selinux = "enabled" if view.selinux else "disabled"
    except Exception as exc:
        template_selinux = None
        template_warning = f"could not inspect template {template}: {exc}"
    else:
        template_warning = ""

    try:
        result = client.start(
            template,
            name=name,
            cpus=cpus,
            selinux=selinux,
            load_apps=False,
            unmanaged=False,
        )
    except CliError as exc:
        raise VerifyError(f"failed to start template {template}: {exc}") from exc

    if not result.is_active or not result.adb_target:
        reason = result.instance.failure_reason or "startup failed"
        raise VerifyError(
            f"failed to start {result.instance.instance_name}: {reason}"
        )

    adb = Adb(result.adb_target)
    try:
        adb.connect()
        adb.wait_for_device()
        adb.wait_for_boot_completed()
    except Exception as exc:
        try:
            client.stop(result.instance.instance_id)
        except Exception:
            pass
        raise VerifyError(
            f"guest {result.instance.instance_name} did not become usable over ADB: {exc}"
        ) from exc

    guest = Guest(
        client=client,
        template=template,
        instance_name=result.instance.instance_name,
        instance_id=result.instance.instance_id,
        adb_target=result.adb_target,
        adb=adb,
        template_selinux=template_selinux,
        created=True,
    )
    if template_warning:
        guest.warnings.append(template_warning)
    return guest


def attach_guest(adb_target: str) -> Guest:
    adb = Adb(adb_target)
    try:
        adb.connect()
        adb.wait_for_device()
        adb.wait_for_boot_completed()
    except Exception as exc:
        raise VerifyError(f"could not attach to {adb_target}: {exc}") from exc
    return Guest(
        client=None,  # type: ignore[arg-type]
        template="",
        instance_name=adb_target,
        instance_id="",
        adb_target=adb_target,
        adb=adb,
        template_selinux=None,
        created=False,
    )


def guest_info_dict(guest: Guest) -> dict[str, Any]:
    return {
        "instance_name": guest.instance_name,
        "instance_id": guest.instance_id,
        "adb_target": guest.adb_target,
        "template_selinux": guest.template_selinux,
        "created": guest.created,
    }
