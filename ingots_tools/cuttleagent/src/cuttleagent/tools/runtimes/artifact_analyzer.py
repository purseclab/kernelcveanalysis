from logging import getLogger
from pathlib import Path
from secrets import token_hex

import docker
import docker.errors

from ..command_runtime import CommandRuntime

logger = getLogger(__name__)


class ArtifactAnalyzerRuntime(CommandRuntime):
    INPUT_MOUNT: str = "/work/apps"
    OUTPUT_MOUNT: str = "/work/findings"

    def __init__(self, image_tag: str, dockerfile_path: Path):
        self.docker = docker.from_env()
        try:
            self.image = self.docker.images.get(image_tag)
        except docker.errors.ImageNotFound:
            self.image, _ = self.docker.images.build(
                path=str(dockerfile_path.parent),
                dockerfile=str(dockerfile_path.name),
                tag=image_tag,
            )
        self.container = None

    def start(self, input_dir: Path, output_dir: Path) -> None:
        if self.container is not None:
            return None
        self.container = self.docker.containers.run(
            image=self.image,
            command=["sleep", "infinity"],
            detach=True,
            volumes={
                str(input_dir): {"bind": self.INPUT_MOUNT, "mode": "ro"},
                str(output_dir): {"bind": self.OUTPUT_MOUNT, "mode": "rw"},
            },
            name=f"cuttleagent-analysis-{token_hex(4)}",
            remove=True,
        )

    def list_input_dir(self) -> list[Path]:
        if self.container is None:
            return []
        exit_code, output = self.container.exec_run(
            f"find {self.INPUT_MOUNT} -maxdepth 1 -mindepth 1"
        )

        if exit_code != 0:
            raise RuntimeError(output.decode())
        return [Path(line) for line in output.decode().splitlines()]

    def exec(self, command: list[str]) -> str | None:
        if self.container is None:
            logger.warning("Tried to exec non-existent container.")
            return None
        result = self.container.exec_run(command)
        return result.output.decode()

    def stop(self) -> None:
        if self.container is None:
            logger.warning("Tried to stop non-existent container.")
            return None
        self.container.stop()

    def remove(self) -> None:
        if self.container is None:
            logger.warning("Tried to remove non-existent container.")
            return None
        self.container.remove()
