from typing import Annotated, cast
from pathlib import Path
import random

from dotenv import load_dotenv
import typer

from .dataset import load_git_commits
from .git import GitDb, GitRepo, extract_to_db, parse_time, save_commits_to_db, load_commits_from_db
from .filter import WhitespaceFilter, CommitFilter, RunFilterArgs, run_filter,  FilterPipeline, MergeCommitFilter, ConfigFilter, KernelConfig, IfdefFilter, JevFilter, CountFilter
from .visualization import show_commit_sunburst

app = typer.Typer()
filter_app = typer.Typer()
app.add_typer(filter_app, name="filter")


@app.callback()
def load_environment() -> None:
    """Load environment variables from `.env` in the invocation directory."""

    _ = load_dotenv(Path.cwd() / ".env", override=False)


@app.command("extract", help="Extract commits from linux repo into sqlite database.")
def extract_commits(
    repo: Annotated[Path, typer.Option(help="Path to linux git repo.")],
    db: Annotated[Path, typer.Option(help="Path to sqlite database to extract commits to.")],
    start: Annotated[str | None, typer.Option(help="Start date for extracting commits. (mm-dd-yyyy format)")] = None,
    end: Annotated[str | None, typer.Option(help="End date for extracting commits. (mm-dd-yyyy format)")] = None,
):
    start_date = parse_time(start) if start is not None else None
    end_date = parse_time(end) if end is not None else None
    processed = extract_to_db(GitRepo(repo), GitDb(db), start_date, end_date)
    print(f"stored {processed} commits to database `{str(db)}`.")

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

@filter_app.command("config", help="Filter commits for promising lpe commits based of code present for a given config.")
def filter(
    ctx: typer.Context,
    config: Annotated[Path | None, typer.Option(help="Kernel config file to filter with.")] = None,
):
    if config is not None:
        kernel_config = KernelConfig(config.read_text())
        filter = FilterPipeline(
            [
                MergeCommitFilter(),
                ConfigFilter(kernel_config),
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

    run(ctx, filter)

@filter_app.command("rank", help="Runs jev ranking on filtered commits.")
def rank(
    ctx: typer.Context,
):
    filter = FilterPipeline([
        CountFilter(100, seed=67),
        JevFilter(),
    ])

    run(ctx, filter)

def main():
    app()
