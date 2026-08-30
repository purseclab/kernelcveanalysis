from dataclasses import dataclass

from .git import GitCommit
from .diff import DiffFile, DiffFileType


# this performs the trivial filtering on commits, before any classifiers or model calls


@dataclass(slots=True)
class FilterStats:
    paths: dict[str, int]
    extensions: dict[str, int]


class FileFilter:
    """Filters systems we are interested in."""
    # TODO: way to exclude directory trees
    # TODO: maybe will need to recognize versions,
    # and change excluded paths or smthn if file structure changes

    # this is list of paths in linux repo root, of subsystems we care about
    paths: list[str]

    # this is list of file extensions we care about
    extensions: list[str]

    _stats: FilterStats

    def __init__(self, paths: list[str], extensions: list[str]):
        self.paths = paths
        self.extensions = extensions
        for extension in extensions:
            self._normalize_extension(extension)
        self._stats = FilterStats(
            paths={path: 0 for path in paths},
            extensions={extension: 0 for extension in extensions},
        )

    def matches_file(self, file: str) -> bool:
        return any(
            self._matches_path(file, path) and self._matches_extension(file, extension)
            for path in self.paths
            for extension in self.extensions
        )

    @staticmethod
    def _matches_path(file: str, path: str) -> bool:
        normalized_path = path.removeprefix("./").rstrip("/")
        return not normalized_path or file.startswith(f"{normalized_path}/")

    @staticmethod
    def _normalize_extension(extension: str) -> str:
        normalized_extension = (
            extension if extension.startswith(".") else f".{extension}"
        )
        if normalized_extension == ".":
            raise ValueError("file extensions must not be empty")
        return normalized_extension

    @classmethod
    def _matches_extension(cls, file: str, extension: str) -> bool:
        normalized_extension = cls._normalize_extension(extension)
        filename = file.rsplit("/", 1)[-1]
        return filename != normalized_extension and filename.endswith(normalized_extension)

    def _record_matches(self, files: list[DiffFile]) -> None:
        for path in self._stats.paths:
            if any(self._matches_path(file.file, path) for file in files):
                self._stats.paths[path] += 1

        for extension in self._stats.extensions:
            if any(self._matches_extension(file.file, extension) for file in files):
                self._stats.extensions[extension] += 1

    def stats(self) -> FilterStats:
        return FilterStats(
            paths=self._stats.paths.copy(),
            extensions=self._stats.extensions.copy(),
        )

    def render_report(self) -> str:
        stats = self.stats()
        lines = ["Filter report:", "Paths:"]
        lines.extend(f"  {path}: {count} commits" for path, count in stats.paths.items())
        lines.append("Extensions:")
        lines.extend(
            f"  {extension}: {count} commits"
            for extension, count in stats.extensions.items()
        )
        return "\n".join(lines)

    def filter_commit(self, commit: GitCommit) -> bool:
        """Return whether the commit contains an included file change."""

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

        matching_files = [
            file_change
            for file_change in commit.diff.files
            if self.matches_file(file_change.file)
        ]
        if not matching_files:
            return False

        self._record_matches(matching_files)
        commit.diff.files = matching_files
        return True

    def filter_commits(self, commits: list[GitCommit]) -> list[GitCommit]:
        self._stats = FilterStats(
            paths={path: 0 for path in self.paths},
            extensions={extension: 0 for extension in self.extensions},
        )
        return [commit for commit in commits if self.filter_commit(commit)]
