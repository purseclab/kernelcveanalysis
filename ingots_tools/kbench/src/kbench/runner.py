from concurrent.futures import ThreadPoolExecutor

from cuttle_cli import CuttleClient
from kexploit_agent import AgentGroup
from ksandbox import DockerSandboxProvider, MountInfo

from .api import AdbSandbox, BenchmarkRun, Challenge, ChallengeInstance, GlobalRunState, Score

def run_challenge(state: GlobalRunState, challenge: Challenge) -> Score:
    solution = state.solutions_folder / challenge.name
    solution.mkdir(parents=True)

    solution_mount = MountInfo(
        src_folder=solution,
        name="solution",
        description="folder to place challenge solution",
        writable=True,
    )

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

        return challenge.run(ChallengeInstance(
            solution=solution,
            agent=agent,
            sandbox=sandbox,
        ))

def run_benchmark(run: BenchmarkRun):
    run.output_folder.mkdir(exist_ok=True, parents=True)

    state = GlobalRunState(
        sandbox_provider=DockerSandboxProvider.get(),
        # TODO: use diff user id once cuttle client supports multiple daemons at a time with diff user id
        cuttle_client=CuttleClient.from_config(),
        run_group=AgentGroup(f"{run.name}"),
        grader_group=AgentGroup(f"{run.name} graders"),
        solutions_folder=run.output_folder,
    )

    def _run_challenge(challenge: Challenge) -> Score:
        return run_challenge(state, challenge)

    with ThreadPoolExecutor(max_workers=run.num_instances) as executor:
        results = executor.map(_run_challenge, run.challenges)
