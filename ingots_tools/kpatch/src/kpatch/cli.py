from typing import Annotated
from pathlib import Path

import typer

from .dataset import load_git_commits
from .git import GitDb, GitRepo, extract_to_db, parse_time
from .filter import FileFilter

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

@app.command("test", help="Temporary function for testing.")
def run():
    # time between 7.1 and 7.2
    start = parse_time("06-14-2026")
    end = parse_time("08-16-2026")

    db = GitDb(Path("commit.db"))
    commits = db.commits_between(start, end)

    # permissive arm filter
    # TODO: decide about kconfig, if it should be included
    filter = FileFilter(
        ["arch/arm", "arch/arm64", "block", "crypto", "drivers", "fs", "include", "init", "io_uring", "ipc", "kernel", "lib", "mm", "net", "rust", "security", "sound", "virt"],
        [".c", ".h", ".S"],
    )

    dataset_commits = load_git_commits()
    _dataset_filtered = filter.filter_commits(dataset_commits)
    print("Dataset report:")
    print(filter.render_report())
    # for commit in dataset_commits:
    #     if commit not in dataset_filtered:
    #         print("warning: dataset lpe commit missed by filter")
    #         print(commit.diff_str)
    #         print("\n\n\n\n\n")

    print(f"Original commits: {len(commits)}")
    commits_filtered = filter.filter_commits(commits)
    print(f"Filtered commits: {len(commits_filtered)}")
    print(filter.render_report())
    # analyze_dataset()
    # git_scan()

def main():
    app()
