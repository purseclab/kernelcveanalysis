from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from pydantic import BaseModel

from cuttle_cli import CuttleClient
from ksandbox import DockerSandboxProvider, DockerSandbox, MountInfo
from kexploit_agent import BaseAgent, HarnessType, AgentGroup, ModelConfig

GUEST_ADB_HOST = "cuttlefish"
GUEST_ADB_PORT = 6000

# score contains additional properties which can be serialized using basemodel
class Score(BaseModel, ABC):
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
    score: Score
    runtime: float

class BenchmarkResult(BaseModel):
    overall_score: float
    total_runtime: float

    # map from challenge to scores
    scores: dict[str, Score]
    results: dict[str, ChallengeResult] = {}


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
    ):
        self.state = state
        self.docker_tag = docker_tag
        self.cuttle_template = cuttle_template
        self.mounts = mounts

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
            # setup sandbox
            self.sandbox = self.state.sandbox_provider.create(
                self.docker_tag,
                mounts=self.mounts,
                allow_internet=False,
                extra_hosts={GUEST_ADB_HOST: "127.0.0.1"},
            )
            _ = self.sandbox.start()
            self.sandbox.forward_port(
                target_host=self.adb_host,
                host_port=self.adb_port,
                guest_addr=GUEST_ADB_HOST,
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
