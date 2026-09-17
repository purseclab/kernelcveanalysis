from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from kbench import Challenge, ChallengeInstance, Score
from kbench.api import GlobalRunState
from kbench.runner import run_challenge
from kexploit_agent import HarnessType, Model, ModelConfig


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
