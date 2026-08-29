from typing import Annotated
from pathlib import Path

import typer

from .dataset import load_git_commits
from .git import GitDb, GitRepo, extract_to_db, parse_time
from .filter import filter_commits, FileFilter

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
    filter = FileFilter(
        ["arch/arm", "arch/arm64", "block", "crypto", "drivers", "fs", "include", "init", "io_uring", "ipc", "kernel", "lib", "mm", "net", "rust", "security", "sound", "virt"],
        [".c", ".h"],
    )

    dataset_commits = load_git_commits()
    dataset_filtered = filter_commits(filter, dataset_commits)
    for commit in dataset_commits:
        if commit not in dataset_filtered:
            print("warn")
    assert len(dataset_commits) == len(dataset_filtered)

    print(f"Original commits: {len(commits)}")
    commits_filtered = filter_commits(filter, commits)
    print(f"Filtered commits: {len(commits_filtered)}")
    # analyze_dataset()
    # git_scan()

def main():
    app()
