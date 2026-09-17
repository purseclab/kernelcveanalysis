import logging
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed

from cuttle_cli import CuttleClient
from tqdm import tqdm  # type: ignore[import-untyped]

from kexploit_agent import AgentGroup
from ksandbox import DockerSandboxProvider, MountInfo

from .api import (
    AdbSandbox,
    BenchmarkResult,
    BenchmarkRun,
    Challenge,
    ChallengeInstance,
    ChallengeResult,
    GlobalRunState,
)

logger = logging.getLogger(__name__)


def run_challenge(state: GlobalRunState, challenge: Challenge) -> ChallengeResult:
    logger.info("Challenge '%s': starting setup...", challenge.name)
    solution = state.solutions_folder / challenge.name
    solution.mkdir(parents=True, exist_ok=True)
    model_config = challenge.model_config

    solution_mount = MountInfo(
        src_folder=solution,
        name="solution",
        description="folder to place challenge solution",
        writable=True,
    )

    start_time = time.perf_counter()
    with AdbSandbox(
        state,
        challenge.tag,
        challenge.cuttlefish_template,
        [solution_mount],
        name=challenge.name,
        internet_enabled=challenge.internet_enabled,
        extra_hosts={
            model_config.resolved_api_host: model_config.resolved_guest_addr,
        },
    ) as sandbox:
        docker_sandbox = sandbox.sandbox
        assert docker_sandbox is not None

        system_prompt = challenge.system_prompt(sandbox.container_adb_host)
        agent = challenge.harness.create_agent(
            f"{challenge.name}_agent",
            model_config,
            system_prompt,
            docker_sandbox,
            agent_group=state.run_group,
        )

        logger.info("Challenge '%s': running...", challenge.name)
        with state.manage_agent(agent):
            score = challenge.run(
                ChallengeInstance(
                    solution=solution,
                    agent=agent,
                    sandbox=sandbox,
                )
            )

    runtime = time.perf_counter() - start_time
    challenge_result = ChallengeResult(score=score, runtime=runtime)

    challenge_results_file = solution / "results.json"
    challenge_results_file.write_text(challenge_result.model_dump_json(indent=2))

    return challenge_result


def run_challenges(
    state: GlobalRunState,
    challenges: list[Challenge],
    *,
    run_name: str,
    num_instances: int | None,
    challenge_runner: Callable[
        [GlobalRunState, Challenge], ChallengeResult
    ] = run_challenge,
) -> dict[str, ChallengeResult]:
    """Run challenge workers and clean their live resources before joining on failure."""
    challenge_results: dict[str, ChallengeResult] = {}
    max_workers = (
        num_instances if num_instances is not None and num_instances > 0 else None
    )
    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures: dict[Future[ChallengeResult], Challenge] = {}
    try:
        futures = {
            executor.submit(challenge_runner, state, challenge): challenge
            for challenge in challenges
        }
        with tqdm(total=len(challenges), desc=f"Running {run_name}") as pbar:
            for future in as_completed(futures):
                challenge = futures[future]
                result = future.result()
                challenge_results[challenge.name] = result
                pbar.update(1)
                logger.info(
                    "Challenge '%s' finished in %.2fs with score: %.4f",
                    challenge.name,
                    result.runtime,
                    result.score.score,
                )
    except BaseException:
        for future in futures:
            future.cancel()
        # ThreadPoolExecutor.__exit__ waits for running workers before unwinding
        # their context managers. Clean their registered resources first so a
        # provider process or sandbox command cannot keep that wait stuck.
        state.cleanup_active_resources()
        executor.shutdown(wait=True, cancel_futures=True)
        # A sandbox may have completed startup concurrently with the first pass.
        state.cleanup_active_resources()
        raise
    else:
        executor.shutdown(wait=True)

    return challenge_results


def run_benchmark(run: BenchmarkRun) -> BenchmarkResult:
    run.output_folder.mkdir(exist_ok=True, parents=True)

    state = GlobalRunState(
        sandbox_provider=DockerSandboxProvider.get(),
        # TODO: use diff user id once cuttle client supports multiple daemons at a time with diff user id
        cuttle_client=CuttleClient.from_config(),
        run_group=AgentGroup(f"{run.name}"),
        grader_group=AgentGroup(f"{run.name} graders"),
        solutions_folder=run.output_folder,
    )

    total_start_time = time.perf_counter()
    challenge_results = run_challenges(
        state,
        run.challenges,
        run_name=run.name,
        num_instances=run.num_instances,
    )
    scores = {
        challenge_name: result.score
        for challenge_name, result in challenge_results.items()
    }

    total_runtime = time.perf_counter() - total_start_time
    overall_score = (
        sum(res.score.score for res in challenge_results.values())
        / len(challenge_results)
        if challenge_results
        else 0.0
    )

    benchmark_result = BenchmarkResult(
        overall_score=overall_score,
        total_runtime=total_runtime,
        scores=scores,
        results=challenge_results,
    )

    results_path = run.output_folder / "results.json"
    results_path.write_text(benchmark_result.model_dump_json(indent=2))
    logger.info(
        "Benchmark '%s' finished in %.2fs with average score: %.4f",
        run.name,
        total_runtime,
        overall_score,
    )

    return benchmark_result


run = run_benchmark
