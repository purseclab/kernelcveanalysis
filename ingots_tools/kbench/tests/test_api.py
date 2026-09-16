from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

from kbench import AdbSandbox, BenchmarkResult, ChallengeResult, Score
from kbench.api import GlobalRunState


class DetailedScore(Score):
    capability: str
    passed: bool

    @property
    def score(self) -> float:
        return 1.0 if self.passed else 0.0


def test_concrete_score_fields_are_preserved_in_result_json() -> None:
    score = DetailedScore(capability="code_execution", passed=True)
    challenge_result = ChallengeResult(score=score, runtime=1.25)
    benchmark_result = BenchmarkResult(
        overall_score=1.0,
        total_runtime=1.25,
        scores={"example": score},
        results={"example": challenge_result},
    )

    assert challenge_result.model_dump() == {
        "score": {
            "capability": "code_execution",
            "passed": True,
            "score": 1.0,
        },
        "runtime": 1.25,
    }
    assert benchmark_result.model_dump()["scores"]["example"] == {
        "capability": "code_execution",
        "passed": True,
        "score": 1.0,
    }


def test_adb_sandbox_merges_inference_and_adb_host_mappings() -> None:
    docker_sandbox = MagicMock()
    docker_sandbox.running = True
    provider = MagicMock()
    provider.create.return_value = docker_sandbox
    cuttle_client = MagicMock()
    cuttle_client.start.return_value = SimpleNamespace(
        adb_target="adb.internal:6520",
        instance=SimpleNamespace(instance_id="instance-1"),
    )
    state = cast(
        GlobalRunState,
        SimpleNamespace(
            sandbox_provider=provider,
            cuttle_client=cuttle_client,
        ),
    )

    sandbox = AdbSandbox(
        state,
        "android-bench:test",
        "challenge6",
        [],
        extra_hosts={"openrouter.ai": "127.0.0.1"},
    )
    with sandbox:
        assert sandbox.container_adb_host == "cuttlefish:6000"

    provider.create.assert_called_once_with(
        "android-bench:test",
        mounts=[],
        allow_internet=False,
        extra_hosts={
            "openrouter.ai": "127.0.0.1",
            "cuttlefish": "127.0.0.1",
        },
    )
    docker_sandbox.forward_port.assert_called_once_with(
        target_host="adb.internal",
        host_port=6520,
        guest_addr="127.0.0.1",
        guest_port=6000,
    )
    cuttle_client.stop.assert_called_once_with("instance-1")
