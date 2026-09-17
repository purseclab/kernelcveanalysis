from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from kbench.api import GlobalRunState
from kbench.runner import run_challenge, run_challenges

from kbench import AdbSandbox, Challenge, ChallengeInstance, ChallengeResult, Score
from kexploit_agent import AgentGroup, BaseAgent, HarnessType, Model, ModelConfig


class StubScore(Score):
    passed: bool

    @property
    def score(self) -> float:
        return 1.0 if self.passed else 0.0


class StubChallenge(Challenge):
    def __init__(self) -> None:
        self.prompt_adb_host: str | None = None
        self.received_instance: ChallengeInstance | None = None
        self.created_agent = MagicMock()

    @property
    def name(self) -> str:
        return "stub"

    @property
    def tag(self) -> str:
        return "android-bench:stub"

    @property
    def cuttlefish_template(self) -> str:
        return "challenge6"

    @property
    def internet_enabled(self) -> bool:
        return True

    @property
    def model_config(self) -> ModelConfig:
        return ModelConfig(model=Model.DEEPSEEK_V4_1_FLASH)

    @property
    def harness(self) -> HarnessType:
        return HarnessType.PI

    def system_prompt(self, adb_host: str) -> str:
        self.prompt_adb_host = adb_host
        return f"Use {adb_host}"

    @property
    def mount_path(self) -> str:
        return "/data/solution"

    def run(self, instance: ChallengeInstance) -> Score:
        self.received_instance = instance
        return StubScore(passed=True)


def test_run_challenge_uses_container_hosts_for_adb_and_inference(
    tmp_path: Path,
) -> None:
    state = MagicMock(spec=GlobalRunState)
    state.solutions_folder = tmp_path
    state.run_group = MagicMock()
    challenge = StubChallenge()
    docker_sandbox = MagicMock()
    adb_sandbox = MagicMock()
    adb_sandbox.__enter__.return_value = adb_sandbox
    adb_sandbox.container_adb_host = "cuttlefish:6000"
    adb_sandbox.sandbox = docker_sandbox

    with (
        patch("kbench.runner.AdbSandbox", return_value=adb_sandbox) as sandbox_cls,
        patch.object(
            HarnessType,
            "create_agent",
            return_value=challenge.created_agent,
        ) as create_agent,
    ):
        result = run_challenge(state, challenge)

    assert result.score.score == 1.0
    assert challenge.prompt_adb_host == "cuttlefish:6000"
    sandbox_cls.assert_called_once_with(
        state,
        "android-bench:stub",
        "challenge6",
        sandbox_cls.call_args.args[3],
        name="stub",
        internet_enabled=True,
        extra_hosts={"openrouter.ai": "127.0.0.1"},
    )
    create_agent.assert_called_once_with(
        "stub_agent",
        challenge.model_config,
        "Use cuttlefish:6000",
        docker_sandbox,
        agent_group=state.run_group,
    )
    assert challenge.received_instance is not None


def test_run_challenges_cleans_resources_before_joining_interrupted_workers(
    tmp_path: Path,
) -> None:
    state = GlobalRunState(
        sandbox_provider=MagicMock(),
        cuttle_client=MagicMock(),
        run_group=AgentGroup("run"),
        grader_group=AgentGroup("graders"),
        solutions_folder=tmp_path,
    )
    registered = threading.Event()
    released = threading.Event()
    agent = MagicMock(spec=BaseAgent)
    agent.close.side_effect = released.set
    sandbox = MagicMock(spec=AdbSandbox)
    challenge = StubChallenge()

    def blocked_runner(
        worker_state: GlobalRunState,
        worker_challenge: Challenge,
    ) -> ChallengeResult:
        worker_state.register_agent(agent)
        worker_state.register_sandbox(sandbox)
        registered.set()
        assert released.wait(timeout=2)
        return ChallengeResult(score=StubScore(passed=True), runtime=0.1)

    def interrupting_as_completed(
        futures: dict[object, object],
    ) -> list[object]:
        assert futures
        assert registered.wait(timeout=2)
        raise KeyboardInterrupt

    with (
        patch("kbench.runner.as_completed", side_effect=interrupting_as_completed),
        pytest.raises(KeyboardInterrupt),
    ):
        run_challenges(
            state,
            [challenge],
            run_name="interrupt test",
            num_instances=1,
            challenge_runner=blocked_runner,
        )

    agent.close.assert_called()
    sandbox.stop.assert_called()
