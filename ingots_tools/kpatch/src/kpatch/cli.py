from typing import Annotated
from pathlib import Path
import random

import typer

from .dataset import load_git_commits
from .git import GitDb, GitRepo, extract_to_db, parse_time, save_commits_to_db, load_commits_from_db
from .filter import FileFilter, filter_commit_time_range
from .visualization import show_commit_sunburst

app = typer.Typer()

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

@app.command("filter", help="Filter commits for promising lpe commits.")
def filter(
    repo: Annotated[Path, typer.Option(help="Path to linux git repo.")],
    db: Annotated[Path, typer.Option(help="Path to sqlite database to extract commits to.")],
    dest: Annotated[str, typer.Option(help="Destination database name to save filtered commits to.")],
    start: Annotated[str, typer.Option(help="Start date for filtering commits. (mm-dd-yyyy format)")],
    end: Annotated[str, typer.Option(help="End date for filtering commits. (mm-dd-yyyy format)")],
    config: Annotated[Path | None, typer.Option(help="Kernel config file to filter with.")] = None,
):
    start_date = parse_time(start)
    end_date = parse_time(end)
    filter_commit_time_range(GitRepo(repo), GitDb(db), dest, config, start_date, end_date)

@app.command("test", help="Temporary function for testing.")
def run():
    # time between 7.1 and 7.2
    start = parse_time("06-14-2026")
    end = parse_time("08-16-2026")

    db = GitDb(Path("db/all_commits.sqlite"))
    commits = db.commits_between(start, end)

    # permissive arm filter
    # TODO: decide about kconfig, if it should be included
    filter = FileFilter(
        ["arch/arm", "arch/arm64", "block", "crypto", "drivers", "fs", "include", "init", "io_uring", "ipc", "kernel", "lib", "mm", "net", "rust", "security", "sound", "virt"],
        [".c", ".h", ".S"],
    )

    dataset_commits = load_git_commits()
    # _dataset_filtered = filter.filter_commits(dataset_commits)
    # print("Dataset report:")
    # print(filter.render_report())
    for commit in random.sample(dataset_commits, k=10):
        # if commit not in dataset_filtered:
        #     print("warning: dataset lpe commit missed by filter")
        print(commit)
        print("\n\n\n\n\n")

    print(f"Original commits: {len(commits)}")
    commits_filtered = filter.filter_commits(commits)
    print(f"Filtered commits: {len(commits_filtered)}")
    print(filter.render_report())
    _ = show_commit_sunburst(commits)
    # analyze_dataset()
    # git_scan()

def main():
    app()
