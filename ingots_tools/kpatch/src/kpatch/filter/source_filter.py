from collections import defaultdict
from collections.abc import Iterable
import posixpath
import re
import subprocess

from ..diff import Diff
from ..git import GitRepo


_SOURCE_EXTENSIONS = (".c", ".h", ".S")
_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*(?P<open>[<"])(?P<path>[^>"]+)[>"]'
)


class SourceIncludeIndex:
    """A shared, conservative reverse index of C preprocessor includes.

    The index stores possible edges only. Callers still read the source at the
    commit being evaluated to confirm that an edge exists and is active there.
    """

    def __init__(self, srcarch: str, tracked_paths: Iterable[str] = ()):
        self.srcarch = srcarch
        self._tracked_paths = {
            path for path in tracked_paths if path.endswith(_SOURCE_EXTENSIONS)
        }
        self._includers: dict[str, set[str]] = defaultdict(set)
        self._targets: dict[str, set[str]] = defaultdict(set)

    @classmethod
    def from_repository(
        cls,
        repo: GitRepo,
        commit: str,
        srcarch: str,
        extra_paths: Iterable[str] = (),
    ) -> "SourceIncludeIndex":
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(repo.repo),
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                commit,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
        tracked_paths = {
            path
            for raw_path in tree.split(b"\0")
            if raw_path
            if (path := raw_path.decode("utf-8", errors="replace")).endswith(
                _SOURCE_EXTENSIONS
            )
        }
        tracked_paths.update(
            path for path in extra_paths if path.endswith(_SOURCE_EXTENSIONS)
        )
        out = cls(srcarch, tracked_paths)

        grep = subprocess.run(
            [
                "git",
                "-C",
                str(repo.repo),
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
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if grep.returncode not in (0, 1):
            raise subprocess.CalledProcessError(grep.returncode, grep.args)

        prefix = f"{commit}:"
        for raw_row in grep.stdout.decode("utf-8", errors="replace").splitlines():
            if not raw_row.startswith(prefix):
                continue
            source, separator, line = raw_row[len(prefix) :].partition(":")
            if not separator:
                continue
            _, separator, line = line.partition(":")
            if separator:
                out.add_line(source, line)
        return out

    def add_paths(self, paths: Iterable[str]) -> None:
        self._tracked_paths.update(
            path for path in paths if path.endswith(_SOURCE_EXTENSIONS)
        )

    def _resolve(self, source: str, opener: str, requested: str) -> str | None:
        if not requested or "$" in requested:
            return None

        candidates: list[str] = []
        if opener == '"':
            candidates.append(posixpath.join(posixpath.dirname(source), requested))

        candidates.extend(
            (
                f"arch/{self.srcarch}/include/{requested}",
                f"include/{requested}",
                f"arch/{self.srcarch}/include/uapi/{requested}",
                f"include/uapi/{requested}",
                requested,
            )
        )
        for candidate in candidates:
            normalized = posixpath.normpath(candidate).lstrip("/")
            if normalized in self._tracked_paths:
                return normalized
        return None

    def target_from_line(self, source: str, line: str) -> str | None:
        match = _INCLUDE_RE.match(line)
        if match is None:
            return None
        return self._resolve(source, match.group("open"), match.group("path"))

    def add_line(self, source: str, line: str) -> None:
        target = self.target_from_line(source, line)
        if target is not None:
            self._includers[target].add(source)
            self._targets[source].add(target)

    def _alias_source(self, first: str, second: str) -> None:
        """Keep include candidates reachable across a pure source rename."""

        targets = self._targets.get(first, set()) | self._targets.get(second, set())
        for target in targets:
            self._includers[target].update((first, second))
            self._targets[first].add(target)
            self._targets[second].add(target)

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
        return tuple(
            sorted(
                self._includers.get(target, ()),
                key=lambda path: (not path.endswith((".c", ".S")), path),
            )
        )

    def transitive_targets(self, sources: Iterable[str]) -> frozenset[str]:
        """Return sources and every file they may include, transitively."""

        pending = list(sources)
        targets: set[str] = set()
        while pending:
            source = pending.pop()
            if source in targets:
                continue
            targets.add(source)
            pending.extend(self._targets.get(source, set()) - targets)
        return frozenset(targets)

    def dependent_targets(self, sources: Iterable[str]) -> frozenset[str]:
        """Return files whose include reachability may change with sources."""

        direct_targets = {
            target
            for source in sources
            for target in self._targets.get(source, ())
        }
        return self.transitive_targets(direct_targets)
