from typing import Annotated, cast
from dataclasses import replace
from pathlib import Path
import random
import sqlite3
import subprocess

from dotenv import load_dotenv
import typer

from .dataset import load_git_commits
from .git import GitDb, GitRepo, parse_time, save_commits_to_db, load_commits_from_db, _path_for_db_name
from .filter import WhitespaceFilter, CommitFilter, RunFilterArgs, run_filter,  FilterPipeline, MergeCommitFilter, ConfigFilter, KernelConfig, IfdefFilter, ClassifierFilter, CountFilter
from .filter.source_pruning import source_pruning_tail
from .filter.pruning_audit import PruningAudit
from .filter.source_roles import SourceInputAssumptionPolicy
from .filter.output_paths import repository_input_roots, validate_output_paths
from .visualization import show_commit_sunburst
from .update import update_to_db
from .extract import extract_to_db
from .policy_cli import policy_app
from .policy_cli import policy_profile_inputs, setools_runtime, validate_policy_outputs
from .filter.policy_analysis import PolicyFilter
from .filter.policy_context import PolicyBuildContext
from .filter.policy_profile import AnalysisScope, PolicyTargetProfile, SELinuxPolicyEvaluator

app = typer.Typer()
filter_app = typer.Typer()
app.add_typer(filter_app, name="filter")
app.add_typer(policy_app, name="policy")


@app.callback()
def load_environment() -> None:
    """Load environment variables from `.env` in the invocation directory."""

    _ = load_dotenv(Path.cwd() / ".env", override=False)


@app.command("extract", help="Create or extend a continuous raw commit range, preserving existing commits.")
def extract_commits(
    repo: Annotated[Path, typer.Option(exists=True, file_okay=False, help="Path to Linux Git checkout (uses current HEAD; no pull).")],
    db: Annotated[Path, typer.Option(dir_okay=False, help="SQLite database to create or extend.")],
    start: Annotated[str | None, typer.Option(help="Inclusive UTC start date (mm-dd-yyyy); omitted means all history.")] = None,
    end: Annotated[str | None, typer.Option(help="Exclusive UTC end date (mm-dd-yyyy); omitted means through HEAD.")] = None,
    start_at_stored_end: Annotated[bool, typer.Option(help="Use the stored range's end as the start, extending forward.")] = False,
    end_at_stored_start: Annotated[bool, typer.Option(help="Use the stored range's start as the end, extending backward.")] = False,
) -> None:
    try:
        start_date = parse_time(start) if start is not None else None
        end_date = parse_time(end) if end is not None else None
        result = extract_to_db(
            GitRepo(repo), GitDb(db), start_date, end_date,
            start_at_stored_end=start_at_stored_end,
            end_at_stored_start=end_at_stored_start,
        )
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.CalledProcessError) as error:
        typer.echo(f"Extraction failed: {error}", err=True)
        raise typer.Exit(1) from error

    typer.echo(f"Added {result.added_commits} commits; {result.total_commits} total in `{db}`.")
    first = result.start_date.isoformat() if result.start_date is not None else "all history"
    last = result.end_date.isoformat() if result.end_date is not None else "HEAD"
    typer.echo(f"Coverage: [{first}, {last}).")


@app.command("update", help="Pull Linux and append missing raw commits without re-extracting stored patches.")
def update_commits(
    repo: Annotated[Path, typer.Option(exists=True, file_okay=False, help="Path to Linux Git checkout.")],
    db: Annotated[Path, typer.Option(exists=True, dir_okay=False, help="Existing unfiltered SQLite commit database.")],
    start: Annotated[
        str | None,
        typer.Option(help="Original extraction start date (mm-dd-yyyy); required only for databases without an update checkpoint."),
    ] = None,
    pull: Annotated[
        bool,
        typer.Option("--pull/--no-pull", help="Fast-forward the checkout from its configured upstream before updating."),
    ] = True,
) -> None:
    try:
        start_date = parse_time(start) if start is not None else None
        result = update_to_db(GitRepo(repo), GitDb(db), start_date, pull=pull)
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.CalledProcessError) as error:
        typer.echo(f"Update failed: {error}", err=True)
        raise typer.Exit(1) from error

    typer.echo(
        f"Added {result.added_commits} commits; {result.total_commits} total in `{db}`."
    )
    typer.echo(f"Synchronized through {result.tip_commit}.")


@app.command("gen-dataset", help="Generate dataset of kernel commits, along with other train / test splits.")
def gen_dataset(
    seed: Annotated[int, typer.Option(help="Seed for randomly partitioning train and test sets.")] = 67,
):
    lpe_commits = load_git_commits(dedup=True)

    # all lpe commits
    # all commits are already stored separately
    save_commits_to_db("lpe_commits", lpe_commits)

@app.command("visualize", help="Visualize database of commits for testing.")
def visualize(
    db_name: Annotated[str, typer.Argument(help="Name of commit database to visualize (default is lpe commits).")] = "lpe_commits",
):
    commits = load_commits_from_db(db_name)
    result = show_commit_sunburst(commits)
    print(f"Visualization saved to `{result}`")

@filter_app.callback()
def options(
    ctx: typer.Context,
    repo: Annotated[Path, typer.Option(help="Path to linux git repo.")],
    db: Annotated[str, typer.Option(help="Name of sqlite database to extract commits from.")],
    dest: Annotated[str, typer.Option(help="Destination database name to save filtered commits to.")],
    start: Annotated[str | None, typer.Option(help="Start date for filtering commits. (mm-dd-yyyy format)")] = None,
    end: Annotated[str | None, typer.Option(help="End date for filtering commits. (mm-dd-yyyy format)")] = None,
):
    ctx.obj = RunFilterArgs(
        repo=GitRepo(repo),
        db=GitDb.load_name(db),
        destination_db_name=dest,
        start_date=None if start is None else parse_time(start),
        end_date=None if end is None else parse_time(end),
    )

def get_run_args(ctx: typer.Context) -> RunFilterArgs:
    return cast(RunFilterArgs, ctx.obj)

def run(ctx: typer.Context, filter: CommitFilter):
    run_filter(get_run_args(ctx), filter)

@filter_app.command("config", help="Filter source changes; configuration exclusions require complete build-input evidence.")
def filter(
    ctx: typer.Context,
    config: Annotated[Path | None, typer.Option(help="Kernel config file to filter with.")] = None,
    config_observations: Annotated[
        bool, typer.Option(help="Collect advisory Kbuild modes with full-history scans. Does not authorize exclusions. Requires --config."),
    ] = False,
    workers: Annotated[
        int,
        typer.Option(min=1, help="Processes for --config-observations only; ignored otherwise."),
    ] = 4,
    source_pruning: Annotated[
        bool, typer.Option("--source-pruning/--no-source-pruning", help="Enable experimental Tree-sitter rename and unreferenced-definition filters."),
    ] = False,
    constant_branches: Annotated[
        bool, typer.Option(help="Also fold numeric preprocessor branches with complete source comparison. Adds source scanning cost. Requires --source-pruning."),
    ] = False,
    source_pruning_lossy: Annotated[bool, typer.Option(help="Also assume incomplete preprocessing discovery, ignore observable rename metadata, and allow code-address changes from source reordering; observed macro hazards still retain. Requires --source-pruning and --source-pruning-report.")] = False,
    source_pruning_report: Annotated[Path | None, typer.Option(help="JSONL source-pruning decisions, including lossy risk labels.")] = None,
    whitespace_line_numbers_lossy: Annotated[
        bool, typer.Option(help="Ignore physical line-number changes for otherwise equivalent tokens, gaps and byte columns. Can remove runtime-relevant changes. Requires --whitespace-report."),
    ] = False,
    whitespace_report: Annotated[Path | None, typer.Option(help="JSONL whitespace decisions, required with --whitespace-line-numbers-lossy.")] = None,
    unresolved_inputs_lossy: Annotated[
        bool, typer.Option(help="Assume unsupported raw-input expressions cannot observe affected source changes. Can remove runtime-relevant commits; observed raw consumers and failed scans still retain. Requires --input-role-report."),
    ] = False,
    input_role_report: Annotated[Path | None, typer.Option(help="Mandatory JSONL evidence for --unresolved-inputs-lossy assumptions.")] = None,
    policy_profile: Annotated[Path | None, typer.Option(exists=True, dir_okay=False, help="Pinned SELinux/credential profile for compiler-backed policy filtering.")] = None,
    policy_build_context: Annotated[Path | None, typer.Option(exists=True, dir_okay=False, help="Prepared compiler context JSON for policy analysis.")] = None,
    policy_report: Annotated[Path | None, typer.Option(help="JSONL policy decisions, required with --policy-profile.")] = None,
    policy_cache: Annotated[Path | None, typer.Option(help="Persistent compiler and binary-policy cache.")] = None,
    policy_direct_app: Annotated[bool, typer.Option(help="Explicitly restrict policy scope to synchronous direct app context.")] = False,
    setools_python: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    setools_module_path: Annotated[list[Path] | None, typer.Option(exists=True, file_okay=False)] = None,
):
    if config_observations and config is None:
        raise typer.BadParameter("--config-observations requires --config")
    kernel_config: KernelConfig | None = None
    if config is not None:
        kernel_config = KernelConfig(config.read_text())
        filter = FilterPipeline(
            [
                MergeCommitFilter(),
                ConfigFilter(kernel_config, workers=workers, collect_observations=config_observations),
                IfdefFilter(kernel_config),
                WhitespaceFilter(),
            ]
        )
    else:
        filter = FilterPipeline(
            [
                MergeCommitFilter(),
                WhitespaceFilter(),
            ]
        )

    if (constant_branches or source_pruning_lossy or source_pruning_report is not None) and not source_pruning:
        raise typer.BadParameter("Source-pruning options require --source-pruning")
    if source_pruning_lossy and source_pruning_report is None:
        raise typer.BadParameter("--source-pruning-lossy requires --source-pruning-report to record risky removals")
    if whitespace_line_numbers_lossy and whitespace_report is None:
        raise typer.BadParameter("--whitespace-line-numbers-lossy requires --whitespace-report to record risky removals")
    if unresolved_inputs_lossy and input_role_report is None:
        raise typer.BadParameter("--unresolved-inputs-lossy requires --input-role-report to record risky removals")
    if input_role_report is not None and not unresolved_inputs_lossy:
        raise typer.BadParameter("--input-role-report requires --unresolved-inputs-lossy")
    if policy_profile is None:
        if (policy_build_context is not None or policy_report is not None or policy_direct_app or policy_cache is not None
                or setools_python is not None or setools_module_path):
            raise typer.BadParameter("Policy options require --policy-profile")
    elif policy_build_context is None or policy_report is None:
        raise typer.BadParameter("--policy-profile requires --policy-build-context and --policy-report")
    source_audit: PruningAudit | None = None
    whitespace_audit: PruningAudit | None = None
    input_role_audit: PruningAudit | None = None
    reports = tuple(path for path in (source_pruning_report, whitespace_report, input_role_report) if path is not None)
    args = get_run_args(ctx)
    protected = (args.db.db, _path_for_db_name(args.destination_db_name)) + tuple(
        value for value in (config, policy_profile, policy_build_context, setools_python) if value is not None
    ) + tuple(setools_module_path or ())
    outputs = reports + tuple(path for path in (policy_report, policy_cache) if path is not None)
    if reports:
        try:
            if policy_build_context is not None:
                build = PolicyBuildContext.load(policy_build_context)
                target = PolicyTargetProfile.load(policy_profile) if policy_profile is not None else None
                validate_policy_outputs(outputs, build,
                                        protected + (policy_profile_inputs(target) if target else ()))
            # Validate every writable report/cache together before any open.
            validate_output_paths(outputs, protected=protected,
                                  protected_roots=repository_input_roots(args.repo.repo))
            if source_pruning_report is not None:
                source_audit = PruningAudit.create(source_pruning_report, args.repo.repo,
                                                  protected + tuple(path for path in outputs if path != source_pruning_report))
            if whitespace_report is not None:
                whitespace_audit = PruningAudit.create(whitespace_report, args.repo.repo,
                                                      protected + tuple(path for path in outputs if path != whitespace_report))
            if input_role_report is not None:
                input_role_audit = PruningAudit.create(input_role_report, args.repo.repo,
                                                      protected + tuple(path for path in outputs if path != input_role_report))
        except (OSError, ValueError) as error:
            raise typer.BadParameter(str(error)) from error
    if unresolved_inputs_lossy:
        assert input_role_audit is not None
        ctx.obj = replace(args, input_role_policy=SourceInputAssumptionPolicy(input_role_audit))
    if source_pruning:
        filter.filters[-1:] = source_pruning_tail(
            kernel_config, source_audit, lossy=source_pruning_lossy,
            constant_branches=constant_branches,
            whitespace_line_numbers_lossy=whitespace_line_numbers_lossy,
            whitespace_audit=whitespace_audit,
        )
    else:
        filter.filters[-1] = WhitespaceFilter(
            line_numbers_lossy=whitespace_line_numbers_lossy, on_pruned=whitespace_audit,
        )
    if policy_profile is None:
        run(ctx, filter)
        return
    assert policy_build_context is not None and policy_report is not None
    try:
        import hashlib

        target = PolicyTargetProfile.load(policy_profile)
        build = PolicyBuildContext.load(policy_build_context)
        if config is not None and hashlib.sha256(config.read_bytes()).hexdigest() != build.config_sha256:
            raise ValueError("Config-stage and compiler policy configurations must match")
        if policy_direct_app:
            target = target.model_copy(update={"scope": AnalysisScope.DIRECT_APP})
        validate_policy_outputs(outputs, build, protected + policy_profile_inputs(target))
        validate_output_paths(outputs, protected=protected,
                              protected_roots=repository_input_roots(args.repo.repo))
        evaluator = SELinuxPolicyEvaluator(target.policy_file, enforcing=target.selinux_enforcing,
                                           cache_path=policy_cache, runtime=setools_runtime(setools_python, setools_module_path))
        policy_report.parent.mkdir(parents=True, exist_ok=True)
        with policy_report.open("w") as report:
            stage = PolicyFilter(target, build, evaluator, cache_path=policy_cache,
                                 on_decision=lambda decision: print(decision.model_dump_json(), file=report))
            filter.filters.append(stage)
            run(ctx, filter)
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        typer.echo(f"Policy filtering failed: {error}", err=True)
        raise typer.Exit(1) from error

@filter_app.command("rank", help="Ranks filtered commits with OpenRouter GPT-6 Luna Decisions.")
def rank(
    ctx: typer.Context,
    all_commits: Annotated[
        bool,
        typer.Option("--all", help="Rank every commit instead of sampling 100."),
    ] = False,
):
    filters: list[CommitFilter] = []
    if not all_commits:
        filters.append(CountFilter(100, seed=67))
    filters.append(ClassifierFilter())

    run(ctx, FilterPipeline(filters))

def main():
    app()
