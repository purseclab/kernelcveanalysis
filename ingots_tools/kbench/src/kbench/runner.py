from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time

from cuttle_cli import CuttleClient
from kexploit_agent import AgentGroup
from ksandbox import DockerSandboxProvider, MountInfo
from tqdm import tqdm  # type: ignore[import-untyped]

from .api import (
    AdbSandbox,
    BenchmarkResult,
    BenchmarkRun,
    Challenge,
    ChallengeInstance,
    ChallengeResult,
    GlobalRunState,
    Score,
)

logger = logging.getLogger(__name__)

def run_challenge(state: GlobalRunState, challenge: Challenge) -> ChallengeResult:
    solution = state.solutions_folder / challenge.name
    solution.mkdir(parents=True, exist_ok=True)

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
    ) as sandbox:
        adb_host = sandbox.adb_host
        assert adb_host is not None
        docker_sandbox = sandbox.sandbox
        assert docker_sandbox is not None

        system_prompt = challenge.system_prompt(adb_host)
        agent = challenge.harness.create_agent(
            f"{challenge.name}_agent",
            challenge.model_config,
            system_prompt,
            docker_sandbox,
            agent_group=state.run_group,
        )

        score = challenge.run(ChallengeInstance(
            solution=solution,
            agent=agent,
            sandbox=sandbox,
        ))

    runtime = time.perf_counter() - start_time
    challenge_result = ChallengeResult(score=score, runtime=runtime)

    challenge_results_file = solution / "results.json"
    challenge_results_file.write_text(challenge_result.model_dump_json(indent=2))

    return challenge_result

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

    scores: dict[str, Score] = {}
    challenge_results: dict[str, ChallengeResult] = {}
    total_start_time = time.perf_counter()

    max_workers = (
        run.num_instances
        if run.num_instances is not None and run.num_instances > 0
        else None
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_challenge, state, challenge): challenge
            for challenge in run.challenges
        }
        with tqdm(total=len(run.challenges), desc=f"Running {run.name}") as pbar:
            for future in as_completed(futures):
                challenge = futures[future]
                result = future.result()
                scores[challenge.name] = result.score
                challenge_results[challenge.name] = result
                pbar.update(1)
                logger.info(
                    "Challenge '%s' finished in %.2fs with score: %.4f",
                    challenge.name,
                    result.runtime,
                    result.score.score,
                )

    total_runtime = time.perf_counter() - total_start_time
    overall_score = (
        sum(res.score.score for res in challenge_results.values()) / len(challenge_results)
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
