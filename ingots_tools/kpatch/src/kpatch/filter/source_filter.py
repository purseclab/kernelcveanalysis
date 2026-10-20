from collections import defaultdict
from collections.abc import Iterable, Iterator
import posixpath
import re
import subprocess

from ..diff import Diff
from ..git import GitRepo


_SOURCE_EXTENSIONS = (".c", ".h", ".S")
_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*(?P<open>[<"])(?P<path>[^>"]+)[>"]'
)
_GLOBAL_TARGET_CACHE_SIZE = 4096


def _iter_git_output(
    repo: GitRepo,
    args: list[str],
    delimiter: bytes,
    success_codes: tuple[int, ...],
) -> Iterator[bytes]:
    """Read bounded chunks instead of retaining a tree-wide command output."""

    command = ["git", "-C", str(repo.repo), *args]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    pending = b""
    try:
        while chunk := process.stdout.read(64 * 1024):
            records = (pending + chunk).split(delimiter)
            pending = records.pop()
            yield from records
        if pending:
            yield pending

        returncode = process.wait()
        if returncode not in success_codes:
            raise subprocess.CalledProcessError(returncode, command)
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


class SourceIncludeIndex:
    """A shared, conservative reverse index of C preprocessor includes.

    The index stores possible edges only. Callers still read the source at the
    commit being evaluated to confirm that an edge exists and is active there.
    """

    def __init__(self, srcarch: str, tracked_paths: Iterable[str] = ()):
        self.srcarch = srcarch
        # Store a canonical string per path so edges do not retain a fresh copy
        # of both source and target for every include in the repository.
        self._tracked_paths: dict[str, str] = {}
        self._global_targets: dict[tuple[str, str], str | None] = {}
        self._includers: dict[str, set[str]] = defaultdict(set)
        self._targets: dict[str, set[str]] = defaultdict(set)
        self._sorted_includers: dict[str, tuple[str, ...]] = {}
        self.add_paths(tracked_paths)

    @classmethod
    def from_repository(
        cls,
        repo: GitRepo,
        commit: str,
        srcarch: str,
        extra_paths: Iterable[str] = (),
    ) -> "SourceIncludeIndex":
        tracked_paths = (
            raw_path.decode("utf-8", errors="replace")
            for raw_path in _iter_git_output(
                repo,
                ["ls-tree", "-r", "-z", "--name-only", commit],
                b"\0",
                (0,),
            )
            if raw_path
        )
        out = cls(srcarch, tracked_paths)
        out.add_paths(extra_paths)

        prefix = f"{commit}:".encode()
        for raw_row in _iter_git_output(
            repo,
            [
                "grep",
                "-n",
                "-I",
                "-E",
                r'^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]',
                commit,
                "--",
                "*.c",
                "*.h",
                "*.S",
            ],
            b"\n",
            (0, 1),
        ):
            if not raw_row.startswith(prefix):
                continue
            source, separator, line = raw_row[len(prefix) :].partition(b":")
            if not separator:
                continue
            _, separator, line = line.partition(b":")
            if separator:
                out.add_line(
                    source.decode("utf-8", errors="replace"),
                    line.decode("utf-8", errors="replace"),
                )
        return out

    def add_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            if path.endswith(_SOURCE_EXTENSIONS) and path not in self._tracked_paths:
                self._tracked_paths[path] = path
                # A new path can resolve a miss or supersede a fallback target.
                self._global_targets.clear()

    def _resolve_global(self, requested: str) -> str | None:
        key = (self.srcarch, requested)
        if key in self._global_targets:
            return self._global_targets[key]

        target = None
        for candidate in (
            f"arch/{self.srcarch}/include/{requested}",
            f"include/{requested}",
            f"arch/{self.srcarch}/include/uapi/{requested}",
            f"include/uapi/{requested}",
            requested,
        ):
            normalized = posixpath.normpath(candidate).lstrip("/")
            target = self._tracked_paths.get(normalized)
            if target is not None:
                break

        if len(self._global_targets) >= _GLOBAL_TARGET_CACHE_SIZE:
            self._global_targets.clear()
        self._global_targets[key] = target
        return target

    def _resolve(self, source: str, opener: str, requested: str) -> str | None:
        if not requested or "$" in requested:
            return None

        if opener == '"':
            local = posixpath.join(posixpath.dirname(source), requested)
            target = self._tracked_paths.get(posixpath.normpath(local).lstrip("/"))
            if target is not None:
                return target
        return self._resolve_global(requested)

    def target_from_line(self, source: str, line: str) -> str | None:
        match = _INCLUDE_RE.match(line)
        if match is None:
            return None
        return self._resolve(source, match.group("open"), match.group("path"))

    def _add_edge(self, source: str, target: str) -> None:
        includers = self._includers[target]
        if source not in includers:
            includers.add(source)
            self._targets[source].add(target)
            self._sorted_includers.pop(target, None)

    def add_line(self, source: str, line: str) -> None:
        target = self.target_from_line(source, line)
        if target is not None:
            self._add_edge(self._tracked_paths.get(source, source), target)

    def _alias_source(self, first: str, second: str) -> None:
        """Keep include candidates reachable across a pure source rename."""

        first = self._tracked_paths.get(first, first)
        second = self._tracked_paths.get(second, second)
        targets = self._targets.get(first, set()) | self._targets.get(second, set())
        for target in targets:
            self._add_edge(first, target)
            self._add_edge(second, target)

    def add_diff(self, diff: Diff) -> None:
        for diff_file in diff.files:
            for path in (diff_file.file, diff_file.old_file):
                if path is not None:
                    self.add_paths((path,))

            if (
                diff_file.old_file is not None
                and diff_file.old_file != diff_file.file
            ):
                self._alias_source(diff_file.old_file, diff_file.file)

            old_source = diff_file.old_file or diff_file.file
            for chunk in diff_file.chunks:
                for line in chunk.lines:
                    if line.startswith("+"):
                        self.add_line(diff_file.file, line[1:])
                    elif line.startswith("-"):
                        self.add_line(old_source, line[1:])

    def includers(self, target: str) -> tuple[str, ...]:
        cached = self._sorted_includers.get(target)
        if cached is not None:
            return cached
        sources = self._includers.get(target)
        if not sources:
            return ()
        result = tuple(
            sorted(
                sources,
                key=lambda path: (not path.endswith((".c", ".S")), path),
            )
        )
        self._sorted_includers[target] = result
        return result

    def transitive_targets(self, sources: Iterable[str]) -> frozenset[str]:
        """Return sources and every file they may include, transitively."""

        targets = set(sources)
        pending = list(targets)
        while pending:
            source = pending.pop()
            for target in self._targets.get(source, ()):
                if target not in targets:
                    targets.add(target)
                    pending.append(target)
        return frozenset(targets)

    def dependent_targets(self, sources: Iterable[str]) -> frozenset[str]:
        """Return files whose include reachability may change with sources."""

        direct_targets = {
            target
            for source in sources
            for target in self._targets.get(source, ())
        }
        return self.transitive_targets(direct_targets)
