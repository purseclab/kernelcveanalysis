from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from libadb import AdbClient

from .models import InstanceRecord

ADB_CONNECT_TIMEOUT_SEC = 60.0
ADB_BOOT_TIMEOUT_SEC = 180.0
ADB_CONNECT_RETRY_INTERVAL_SEC = 1.0


@dataclass(frozen=True, slots=True)
class CuttlefishAppLoader:
    connect_timeout_sec: float = ADB_CONNECT_TIMEOUT_SEC
    boot_timeout_sec: float = ADB_BOOT_TIMEOUT_SEC
    connect_retry_interval_sec: float = ADB_CONNECT_RETRY_INTERVAL_SEC

    def load_apps(self, record: InstanceRecord) -> None:
        if not record.config.load_apps or not record.config.apps:
            return
        if record.adb_port is None:
            raise RuntimeError("instance does not have an adb port")

        adb = AdbClient(f"127.0.0.1:{record.adb_port}")
        connected = False
        try:
            self._connect_until_ready(adb)
            connected = True
            adb.wait_for_device(timeout_sec=self.connect_timeout_sec)
            adb.wait_for_boot_completed(timeout_sec=self.boot_timeout_sec)
            for app_path in record.config.apps:
                adb.install_app(app_path)
        finally:
            if connected:
                try:
                    adb.disconnect()
                except subprocess.CalledProcessError:
                    pass

    def _connect_until_ready(self, adb: AdbClient) -> None:
        deadline = time.monotonic() + self.connect_timeout_sec
        while True:
            try:
                adb.connect()
                return
            except subprocess.CalledProcessError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"timed out connecting adb to {adb.remote_addr}"
                    ) from exc
                time.sleep(self.connect_retry_interval_sec)
