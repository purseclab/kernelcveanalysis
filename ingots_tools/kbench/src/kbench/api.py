from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
from pathlib import Path
from types import TracebackType
from typing import Self

from pydantic import BaseModel, Field, SerializeAsAny, computed_field

from cuttle_cli import CuttleClient
from ksandbox import DockerSandboxProvider, DockerSandbox, MountInfo
from kexploit_agent import BaseAgent, HarnessType, AgentGroup, ModelConfig

logger = logging.getLogger(__name__)

GUEST_ADB_HOST = "cuttlefish"
GUEST_ADB_PORT = 6000

# score contains additional properties which can be serialized using basemodel
class Score(BaseModel, ABC):
    @computed_field  # type: ignore[prop-decorator]
    @property
    @abstractmethod
    def score(self) -> float:
        """Overall score from 0 to 1"""
        ...

class Challenge(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of challenge."""
        ...

    @property
    @abstractmethod
    def tag(self) -> str:
        """Docker image tag for challenge env."""
        ...

    @property
    @abstractmethod
    def cuttlefish_template(self) -> str:
        """Name of cuttlefish template to launch for challenge."""
        ...

    @property
    @abstractmethod
    def internet_enabled(self) -> bool:
        """Whether the challenge sandbox may access the Internet."""
        ...

    @property
    @abstractmethod
    def model_config(self) -> ModelConfig:
        """Model used for eval."""
        ...

    @property
    @abstractmethod
    def harness(self) -> HarnessType:
        """Harness used for eval."""
        ...

    @abstractmethod
    def system_prompt(self, adb_host: str) -> str:
        """System prompt used for agent."""
        ...

    @property
    @abstractmethod
    def mount_path(self) -> str:
        """Location in container to mount solution folder."""
        ...

    @abstractmethod
    def run(self, instance: 'ChallengeInstance') -> Score:
        ...

@dataclass
class ChallengeInstance:
    solution: Path
    agent: BaseAgent
    sandbox: 'AdbSandbox'

@dataclass
class BenchmarkRun:
    name: str
    # how manny instances to run in parallel, none for no cap
    num_instances: int | None
    challenges: list[Challenge]
    output_folder: Path

class ChallengeResult(BaseModel):
    score: SerializeAsAny[Score]
    runtime: float

class BenchmarkResult(BaseModel):
    overall_score: float
    total_runtime: float

    # map from challenge to scores
    scores: dict[str, SerializeAsAny[Score]]
    results: dict[str, ChallengeResult] = Field(default_factory=dict)


@dataclass
class GlobalRunState:
    sandbox_provider: DockerSandboxProvider
    cuttle_client: CuttleClient
    run_group: AgentGroup
    grader_group: AgentGroup
    solutions_folder: Path

class AdbSandbox:
    state: GlobalRunState
    docker_tag: str
    cuttle_template: str
    mounts: list[MountInfo]
    name: str | None
    internet_enabled: bool
    extra_hosts: dict[str, str]

    adb_host: str | None
    adb_port: int | None
    cuttle_cli_device_id: str | None
    sandbox: DockerSandbox | None
    _started: bool
    _stopped: bool

    # TODO: maybe name cuttlefish and docker instances
    def __init__(
        self,
        state: GlobalRunState,
        docker_tag: str,
        cuttle_template: str,
        mounts: list[MountInfo],
        name: str | None = None,
        internet_enabled: bool = False,
        extra_hosts: dict[str, str] | None = None,
    ):
        self.state = state
        self.docker_tag = docker_tag
        self.cuttle_template = cuttle_template
        self.mounts = mounts
        self.name = name
        self.internet_enabled = internet_enabled
        self.extra_hosts = dict(extra_hosts or {})

        self.adb_host = None
        self.adb_port = None
        self.cuttle_cli_device_id = None
        self.sandbox = None
        self._started = False
        self._stopped = False

    def start(self) -> Self:
        if self._started:
            return self
        if self._stopped:
            raise RuntimeError("cannot restart a stopped AdbSandbox")

        prefix = f"Challenge '{self.name}': " if self.name else ""
        logger.info("%sstarting emulator (template: %s)...", prefix, self.cuttle_template)
        # setup cuttlefish vm
        cuttle_result = self.state.cuttle_client.start(
            self.cuttle_template,
            unmanaged=True,
        )
        assert cuttle_result.adb_target is not None

        self.adb_host, port_str = cuttle_result.adb_target.split(":")
        self.adb_port = int(port_str)
        self.cuttle_cli_device_id = cuttle_result.instance.instance_id

        try:
            logger.info("%sstarting sandbox (tag: %s)...", prefix, self.docker_tag)
            extra_hosts = dict(self.extra_hosts)
            extra_hosts[GUEST_ADB_HOST] = "127.0.0.1"
            # setup sandbox
            self.sandbox = self.state.sandbox_provider.create(
                self.docker_tag,
                mounts=self.mounts,
                allow_internet=self.internet_enabled,
                extra_hosts=extra_hosts,
            )
            _ = self.sandbox.start()
            self.sandbox.forward_port(
                target_host=self.adb_host,
                host_port=self.adb_port,
                guest_addr="127.0.0.1",
                guest_port=GUEST_ADB_PORT,
            )
            self._run_adb(["connect", self.container_adb_host])
        except Exception:
            _ = self.state.cuttle_client.stop(self.cuttle_cli_device_id)
            raise

        self._started = True
        return self

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    def stop(self) -> None:
        if self._stopped or not self._started:
            return
        self._stopped = True
        try:
            if self.sandbox is not None and self.sandbox.running:
                self.sandbox.stop()
        finally:
            if self.cuttle_cli_device_id is not None:
                _ = self.state.cuttle_client.stop(self.cuttle_cli_device_id)

    def _run_adb(self, args: list[str]):
        # FIXME: check return results
        assert self.sandbox is not None
        _ = self.sandbox.exec_sync(["adb"] + args)

    def restart_cuttlefish(self):
        assert self.cuttle_cli_device_id is not None
        self._run_adb(["disconnect", self.container_adb_host])
        # FIXME: check return results
        _ = self.state.cuttle_client.restart(self.cuttle_cli_device_id)
        self._run_adb(["connect", self.container_adb_host])

    @property
    def container_adb_host(self) -> str:
        return f"{GUEST_ADB_HOST}:{GUEST_ADB_PORT}"
