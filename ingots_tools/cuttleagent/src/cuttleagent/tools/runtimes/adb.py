import os
import shutil
from logging import getLogger
from pathlib import Path

from ..command_runtime import CommandRuntime

logger = getLogger(__name__)


class AdbRuntime(CommandRuntime):
    def __init__(
        self,
        serial: str | None = None,
    ) -> None:
        self.adb_path = self.resolve_adb_path()
        self.serial = serial

        # todo search if serial is None fo rthe default device

    def exec(self, command: list[str]) -> str | None:
        # todo
        pass

    @staticmethod
    def resolve_adb_path() -> Path:
        candidates: list[Path] = []

        if env_path := os.environ.get("ADB_PATH"):
            candidates.append(Path(env_path))

        if which_path := shutil.which("adb"):
            candidates.append(Path(which_path))

        for env_var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
            if sdk_root := os.environ.get(env_var):
                candidates.append(Path(sdk_root) / "platform-tools" / "adb")

        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()

        raise FileNotFoundError(
            "Could not find adb. Set ADB_PATH or install Android platform-tools."
        )
