from typing import Annotated
from pathlib import Path

import typer

from .dataset import analyze_dataset
from .git import GitRepo, parse_time

app = typer.Typer()

@app.command("extract", help="Extract commits from linux repo into sqlite database.")
def extract_commits(
    repo: Annotated[Path, typer.Option(help="Path to linux git repo.")],
    db: Annotated[Path, typer.Option(help="Path to sqlite database to extract commits to.")],
    start: Annotated[str, typer.Option(help="Start date for extracting commits. (mm-dd-yyyy format)")],
    end: Annotated[str, typer.Option(help="Start date for extracting commits. (mm-dd-yyyy format)")],
):
    start_date = parse_time(start)
    end_date = parse_time(end)
    commits = GitRepo(repo).commits_between(start_date, end_date)

@app.command("test", help="Temporary function for testing.")
def run():
    analyze_dataset()
    # git_scan()

def main():
    app()
