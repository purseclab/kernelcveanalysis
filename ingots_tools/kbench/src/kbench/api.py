import logging
import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Self
from uuid import uuid4

from cuttle_cli import CuttleClient
from pydantic import BaseModel, Field, SerializeAsAny, computed_field

from kexploit_agent import AgentGroup, BaseAgent, HarnessType, ModelConfig
from ksandbox import DockerSandbox, DockerSandboxProvider, MountInfo

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
    def run(self, instance: "ChallengeInstance") -> Score: ...


@dataclass
class ChallengeInstance:
    solution: Path
    agent: BaseAgent
    sandbox: "AdbSandbox"


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

    _resource_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )
    _active_agents: set[BaseAgent] = field(default_factory=set, init=False, repr=False)
    _active_sandboxes: set["AdbSandbox"] = field(
        default_factory=set,
        init=False,
        repr=False,
    )

    def register_sandbox(self, sandbox: "AdbSandbox") -> None:
        with self._resource_lock:
            self._active_sandboxes.add(sandbox)

    def unregister_sandbox(self, sandbox: "AdbSandbox") -> None:
        with self._resource_lock:
            self._active_sandboxes.discard(sandbox)

    def register_agent(self, agent: BaseAgent) -> None:
        with self._resource_lock:
            self._active_agents.add(agent)

    def unregister_agent(self, agent: BaseAgent) -> None:
        with self._resource_lock:
            self._active_agents.discard(agent)

    @contextmanager
    def manage_agent(self, agent: BaseAgent) -> Iterator[BaseAgent]:
        self.register_agent(agent)
        try:
            yield agent
        finally:
            try:
                agent.close()
            finally:
                self.unregister_agent(agent)

    def cleanup_active_resources(self) -> None:
        """Best-effort cleanup used when a benchmark worker is interrupted."""
        with self._resource_lock:
            agents = tuple(self._active_agents)
            sandboxes = tuple(self._active_sandboxes)

        # Closing an agent first terminates provider subprocesses that may otherwise
        # keep a worker blocked while its Docker sandbox is being stopped.
        for agent in agents:
            try:
                agent.close()
            except Exception:
                logger.exception("failed to close benchmark agent during cleanup")
            else:
                self.unregister_agent(agent)

        for sandbox in sandboxes:
            try:
                sandbox.stop()
            except Exception:
                logger.exception("failed to stop benchmark sandbox during cleanup")


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
    cuttle_cli_instance_name: str
    sandbox: DockerSandbox | None
    _started: bool
    _starting: bool
    _stopped: bool
    _cleanup_requested: bool
    _lifecycle_lock: threading.RLock

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
        self.cuttle_cli_instance_name = f"kbench-{uuid4().hex}"
        self.sandbox = None
        self._started = False
        self._starting = False
        self._stopped = False
        self._cleanup_requested = False
        self._lifecycle_lock = threading.RLock()

    @property
    def load_template_apps(self) -> bool:
        """Whether cuttle_server should install the template's configured apps."""
        return True

    def _after_adb_connect(self) -> None:
        """Hook for benchmark-specific provisioning after ADB is connected."""

    def start(self) -> Self:
        with self._lifecycle_lock:
            if self._started:
                return self
            if self._stopped or self._starting:
                raise RuntimeError("cannot restart a stopped or starting AdbSandbox")
            self._starting = True
        self.state.register_sandbox(self)

        prefix = f"Challenge '{self.name}': " if self.name else ""
        logger.info(
            "%sstarting emulator (template: %s)...", prefix, self.cuttle_template
        )
        try:
            cuttle_result = self.state.cuttle_client.start(
                self.cuttle_template,
                name=self.cuttle_cli_instance_name,
                load_apps=self.load_template_apps,
                unmanaged=True,
            )
            if cuttle_result.adb_target is None:
                raise RuntimeError("Cuttlefish server did not return an ADB target")
            with self._lifecycle_lock:
                self.adb_host, port_str = cuttle_result.adb_target.split(":")
                self.adb_port = int(port_str)
                self.cuttle_cli_device_id = cuttle_result.instance.instance_id
                if self._cleanup_requested:
                    raise RuntimeError(
                        "sandbox cleanup requested during Cuttlefish startup"
                    )

                logger.info("%sstarting sandbox (tag: %s)...", prefix, self.docker_tag)
                extra_hosts = dict(self.extra_hosts)
                extra_hosts[GUEST_ADB_HOST] = "127.0.0.1"
                self.sandbox = self.state.sandbox_provider.create(
                    self.docker_tag,
                    mounts=self.mounts,
                    allow_internet=self.internet_enabled,
                    extra_hosts=extra_hosts,
                )
                self.sandbox.start()
                self.sandbox.forward_port(
                    target_host=self.adb_host,
                    host_port=self.adb_port,
                    guest_addr="127.0.0.1",
                    guest_port=GUEST_ADB_PORT,
                )
            self._run_adb(["connect", self.container_adb_host])
            self._after_adb_connect()

            with self._lifecycle_lock:
                if self._cleanup_requested:
                    raise RuntimeError("sandbox cleanup requested during startup")
                self._started = True
                self._starting = False
        except BaseException:
            with self._lifecycle_lock:
                self._starting = False
            try:
                self.stop()
            except Exception:
                logger.exception(
                    "%sfailed to clean up sandbox after startup error", prefix
                )
            raise

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
        errors: list[Exception] = []
        unregister = False
        with self._lifecycle_lock:
            if self._stopped:
                return
            self._cleanup_requested = True
            if self.sandbox is not None and self.sandbox.running:
                try:
                    self.sandbox.stop()
                except Exception as error:  # noqa: BLE001 - continue with Cuttlefish cleanup
                    errors.append(error)
            try:
                self._stop_cuttlefish()
            except Exception as error:  # noqa: BLE001 - report both cleanup failures
                errors.append(error)

            if not errors and not self._starting:
                self._started = False
                self._stopped = True
                unregister = True

        if unregister:
            self.state.unregister_sandbox(self)
        if len(errors) == 1:
            raise errors[0]
        if errors:
            raise ExceptionGroup("failed to stop benchmark sandbox", errors)

    def _stop_cuttlefish(self) -> None:
        target = self.cuttle_cli_device_id or self.cuttle_cli_instance_name
        try:
            self.state.cuttle_client.stop(target)
        except Exception as stop_error:
            try:
                still_visible = any(
                    instance.instance_id == self.cuttle_cli_device_id
                    or instance.instance_name == self.cuttle_cli_instance_name
                    for instance in self.state.cuttle_client.list_instances()
                )
            except Exception as verification_error:
                raise stop_error from verification_error
            if still_visible:
                raise
            logger.info(
                "Cuttlefish stop reported an error after the instance disappeared: %s",
                str(stop_error).splitlines()[0],
            )

    def _run_adb(self, args: list[str]) -> None:
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
