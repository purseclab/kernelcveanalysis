from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import subprocess

GIT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
LOG_RECORD_START = "\x1e"
LOG_MESSAGE_END = "\x1f"
LOG_FIELD_SEPARATOR = "\x00"
GIT_LOG_FORMAT = "%x1e%H%x00%an <%ae>%x00%aI%x00%cI%x00%P%x00%B%x1f"


@dataclass(slots=True, frozen=True)
class GitCommit:
    """A commit and the patch emitted for it by ``git log --patch``."""

    commit_id: str
    author: str
    author_date: datetime
    committer_date: datetime
    parents: tuple[str, ...]
    message: str
    diff: str


class GitRepo:
    repo: Path

    def __init__(self, repo: Path):
        self.repo = repo

    def _run_git(self, args: list[str]) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo)] + args,
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    @staticmethod
    def _format_git_time(value: datetime) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Git date boundaries must be timezone-aware")
        return value.strftime(GIT_TIME_FORMAT)

    def commits_between(self, start: datetime, end: datetime) -> list[GitCommit]:
        """Return commits in ``[start, end)`` with their messages and diffs."""

        output = self._run_git([
            "log",
            "--full-history",
            f"--since-as-filter={self._format_git_time(start)}",
            f"--before={self._format_git_time(end)}",
            "--no-merges",
            f"--format={GIT_LOG_FORMAT}",
            "--patch",
            "--no-color",
            "--no-ext-diff",
            "--full-index",
            "--binary",
        ])

        commits: list[GitCommit] = []
        for record in output.split(LOG_RECORD_START)[1:]:
            try:
                metadata, diff = record.split(LOG_MESSAGE_END, 1)
            except ValueError as error:
                raise ValueError("Unable to split git log message from diff") from error

            fields = metadata.split(LOG_FIELD_SEPARATOR, 5)
            if len(fields) != 6:
                raise ValueError("Unexpected git log record format")

            commit_id, author, author_date, committer_date, parents, message = fields
            commits.append(
                GitCommit(
                    commit_id=commit_id,
                    author=author,
                    author_date=datetime.fromisoformat(author_date),
                    committer_date=datetime.fromisoformat(committer_date),
                    parents=tuple(parents.split()),
                    message=message,
                    diff=diff.lstrip("\n"),
                )
            )

        return commits


def parse_time(time: str) -> datetime:
    return datetime.strptime(time, "%m-%d-%Y").replace(
        tzinfo=UTC,
    )


def git_scan():
    repo = GitRepo(Path("./linux"))
    print(repo.commits_between(parse_time("01-01-2024"), parse_time("01-02-2024"))[0])
