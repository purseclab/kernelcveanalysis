import re
from re import Pattern

from .git import GitCommit
from .diff import DiffFileType


# this performs the trivial filtering on commits, before any classifiers or model calls

class FileFilter:
    """Filters systems we are interested in."""
    # TODO: way to exclude directory trees
    # TODO: maybe will need to recognize versions,
    # and change excluded paths or smthn if file structure changes

    # this is list of paths in linux repo root, of subsystems we care about
    paths: list[str]

    # this is list of file extensions we care about
    extensions: list[str]

    regex: Pattern[str]

    def __init__(self, paths: list[str], extensions: list[str]):
        self.paths = paths
        self.extensions = extensions
        self.regex = self.build_regex()

    def build_regex(self) -> Pattern[str]:
        """Build a regex for files below one of the configured paths.

        Paths are treated as directory prefixes, and extensions may be given
        either with or without their leading dot. Both the directory prefix
        and extension are escaped, so values such as ``drivers/net+`` and
        ``.c++`` are matched literally.
        """

        prefixes = []
        for path in self.paths:
            normalized_path = path.removeprefix("./").rstrip("/")
            prefixes.append(
                f"{re.escape(normalized_path)}/" if normalized_path else ""
            )

        extensions = []
        for extension in self.extensions:
            normalized_extension = (
                extension if extension.startswith(".") else f".{extension}"
            )
            if normalized_extension == ".":
                raise ValueError("file extensions must not be empty")
            extensions.append(re.escape(normalized_extension))

        if not prefixes:
            prefixes.append(r"(?!)")
        if not extensions:
            extensions.append(r"(?!)")

        prefix_regex = "(?:" + "|".join(prefixes) + ")"
        extension_regex = "(?:" + "|".join(extensions) + ")"
        return re.compile(
            rf"\A{prefix_regex}(?:[^/]+/)*[^/]+{extension_regex}\Z"
        )

    def matches_file(self, file: str) -> bool:
        return self.regex.fullmatch(file) is not None


def filter_commit(filter: FileFilter, commit: GitCommit) -> bool:
    """Return false if commit should be pruned before pipeline."""

    for file_change in commit.diff.files:
        # for now, we filter out big changes creating new files
        # these can sometimes be accidentel lpe fixes when refactoring,
        # but they are large and difficult to determine cheaply if lpe fixing commit
        # and all the llm bug scanners people run to geenerate commits,
        # will not be making these sort of commits
        #
        # TODO: regression tests might make new file?
        if file_change.kind != DiffFileType.DEFAULT:
            return False

    # only keep changes we care about, prune if none we care about
    commit.diff.files = [file_change for file_change in commit.diff.files if filter.matches_file(file_change.file)]
    return len(commit.diff.files) == 0

def filter_commits(filter: FileFilter, commits: list[GitCommit]) -> list[GitCommit]:
    return [commit for commit in commits if filter_commit(filter, commit)]
