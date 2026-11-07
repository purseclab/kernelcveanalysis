from collections import defaultdict
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import posixpath
import re
import subprocess
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from ..diff import Diff
from ..git import GitRepo
from .git_output import GitGrepRow, iter_git_grep_rows, iter_git_records
from .whitespace.c_lexer import preprocessor_directive_text


_SOURCE_EXTENSIONS = (".c", ".h", ".S")
_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*(?P<open>[<"])(?P<path>[^>"\n]+)[>"]\s*$'
)
_INPUT_DIRECTIVE_RE = re.compile(r'^\s*#\s*(include|include_next|import|embed)\b')
_GNU_SPLICE_RE = re.compile(r'\\[^\S\r\n]+(?:\r\n|\n)')
_GLOBAL_TARGET_CACHE_SIZE = 4096


@dataclass(frozen=True, slots=True)
class IncludeFacts:
    targets: frozenset[str] = frozenset()
    unknown: bool = False


class _SourceIncludeSnapshot(BaseModel):
    """Canonical vocabulary; only its tracked prefix participates in lookup."""

    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[2] = 2
    srcarch: str
    paths: list[str]
    tracked_path_count: int
    adjacency: list[list[int]]
    uncertain_sources: list[int]
    opaque_sources: list[int]
    nonfile_sources: list[int]

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        path_count = len(self.paths)
        if not 0 <= self.tracked_path_count <= path_count:
            raise ValueError("tracked_path_count is outside the path vocabulary")
        if len(set(self.paths)) != path_count:
            raise ValueError("snapshot path vocabulary contains duplicates")
        if len(self.adjacency) != path_count:
            raise ValueError("snapshot adjacency must have one row per path")
        for indices in (self.uncertain_sources, self.opaque_sources, self.nonfile_sources):
            if len(set(indices)) != len(indices) or any(index < 0 or index >= path_count for index in indices):
                raise ValueError("uncertain source ID is outside the path vocabulary")
        if not set(self.opaque_sources).issubset(self.uncertain_sources):
            raise ValueError("opaque sources must also be uncertain")
        if not set(self.nonfile_sources).issubset(self.opaque_sources):
            raise ValueError("nonfile sources must also be opaque")
        for target_ids in self.adjacency:
            if any(target_id < 0 or target_id >= self.tracked_path_count for target_id in target_ids):
                raise ValueError("snapshot target ID is outside the tracked vocabulary")
            if len(set(target_ids)) != len(target_ids):
                raise ValueError("snapshot adjacency contains duplicate target IDs")
        return self


def _iter_git_grep(repo: GitRepo, args: list[str]) -> Generator[GitGrepRow, None, None]:
    """Use PCRE's fast literal alternation when available, with a Git fallback."""

    try:
        yield from iter_git_grep_rows(repo, args)
    except subprocess.CalledProcessError as error:
        if "-P" not in args or error.returncode not in (128, 129):
            raise
        yield from iter_git_grep_rows(repo, ["-E" if arg == "-P" else arg for arg in args])


def _covering_literals(names: Iterable[str]) -> list[str]:
    """Drop redundant substring patterns; callers still check exact words."""

    selected: list[str] = []
    for name in sorted(names, key=lambda name: (len(name), name)):
        if not any(part in name for part in selected):
            selected.append(name)
    return selected


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
        self._uncertain_sources: set[str] = set()
        self._opaque_sources: set[str] = set()
        self._nonfile_sources: set[str] = set()
        self._sorted_uncertain_sources: tuple[str, ...] | None = None
        self._resolution_uncertain = False
        self.generation = 0
        self.add_paths(tracked_paths)

    @classmethod
    def from_repository(
        cls,
        repo: GitRepo,
        commit: str,
        srcarch: str,
        extra_paths: Iterable[str] = (),
        *,
        reference_names: frozenset[str] = frozenset(),
        reference_hit: Callable[[str, int, bytes], None] | None = None,
        prefer_pcre: bool = False,
    ) -> "SourceIncludeIndex":
        out = cls(srcarch)
        with closing(iter_git_records(repo, ["ls-tree", "-r", "-z", commit], b"\0", (0,))) as entries:
            for entry in entries:
                metadata, separator, raw_path = entry.partition(b"\t")
                if not separator or not raw_path:
                    raise ValueError("Invalid Git tree entry")
                mode = metadata.split(b" ", 1)[0]
                if mode == b"160000":
                    # An enabled submodule may contain unknown project-header
                    # consumers, but its directory is not an includable file.
                    path = raw_path.decode("utf-8")
                    out._mark_uncertain(path, opaque=True)
                    out._nonfile_sources.add(path)
                    continue
                path = raw_path.decode("utf-8")
                out.add_paths((path,))
                if mode not in {b"100644", b"100755"}:
                    out._mark_uncertain(path, opaque=True)
        out.add_paths(extra_paths)

        prefix = f"{commit}:".encode()
        # Marker discovery returns paths only: streaming every matching source
        # line would duplicate the reference bootstrap's much smaller row set.
        candidates: set[str] = set(out._opaque_sources)
        with closing(iter_git_records(
            repo, ["grep", "-l", "-z", "-a", "-F", "-e", "#", "-e", "%", "-e", "?", "-e", "\\", commit, "--"],
            b"\0", (0, 1),
        )) as marker_paths:
            for raw_path in marker_paths:
                if not raw_path.startswith(prefix) or len(raw_path) == len(prefix):
                    raise ValueError("Unexpected Git grep path prefix")
                candidates.add(raw_path[len(prefix):].decode("utf-8"))
        pattern = r'^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]'
        patterns = ["-e", pattern]
        matcher = "-P" if prefer_pcre else "-E"
        if reference_names:
            # Minimal covering substrings avoid overlapping alternatives.
            # Exact raw words are checked by the callback.
            literals = _covering_literals(reference_names)
            patterns.extend(("-e", "(" + "|".join(re.escape(name) for name in literals) + ")"))
            # Reference bootstrap establishes global absence, so inspect every
            # tracked path; compilers can accept NUL with warnings, so Git's
            # binary classification cannot establish absence either.
        arguments = [
            "grep", *(["--threads=16"] if prefer_pcre else []),
            "-n", "-z", "-a", matcher, *patterns, commit, "--",
        ]
        with closing(_iter_git_grep(repo, arguments)) as rows:
            for row in rows:
                if not row.path.startswith(prefix) or len(row.path) == len(prefix):
                    raise ValueError("Unexpected Git grep path prefix")
                path = row.path[len(prefix):].decode("utf-8")
                line = row.contents
                if any(marker in line for marker in (b"#", b"%", b"?", b"\\")):
                    candidates.add(path)
                    # A matching line can be inside a comment. Exact-buffer
                    # analysis verifies this positive hint before using it.
                    out.add_line(path, line.decode("utf-8", errors="replace"))
                if reference_hit is not None:
                    reference_hit(path, row.line, line)
        # A marker is not proof of a complete include inventory. Keep every
        # candidate uncertain and defer full normalization to reader-cached,
        # exact-revision analysis of enabled inputs and their dynamic closure.
        for path in candidates:
            out._mark_uncertain(path)
        return out

    def _snapshot(self) -> _SourceIncludeSnapshot:
        paths = list(self._tracked_paths)
        tracked_path_count = len(paths)
        path_ids = {path: index for index, path in enumerate(paths)}
        for source in self._targets:
            if source not in path_ids:
                path_ids[source] = len(paths)
                paths.append(source)

        adjacency: list[list[int]] = [[] for _ in paths]
        for source, targets in self._targets.items():
            adjacency[path_ids[source]] = sorted(path_ids[target] for target in targets)
        return _SourceIncludeSnapshot(
            srcarch=self.srcarch,
            paths=paths,
            tracked_path_count=tracked_path_count,
            adjacency=adjacency,
            uncertain_sources=sorted(path_ids[source] for source in self.uncertain_sources),
            opaque_sources=sorted(path_ids[source] for source in self._opaque_sources),
            nonfile_sources=sorted(path_ids[source] for source in self._nonfile_sources),
        )

    def write_snapshot(self, path: Path) -> None:
        """Persist the global index once, without serializing repeated paths."""

        path.write_text(self._snapshot().model_dump_json(), encoding="utf-8")

    @classmethod
    def read_snapshot(cls, path: Path) -> Self:
        """Restore validated edges and lookup vocabulary without invoking Git."""

        snapshot = _SourceIncludeSnapshot.model_validate_json(path.read_bytes())
        out = cls(snapshot.srcarch)
        paths = snapshot.paths
        out._tracked_paths = {
            paths[path_id]: paths[path_id]
            for path_id in range(snapshot.tracked_path_count)
        }
        for source_id, target_ids in enumerate(snapshot.adjacency):
            for target_id in target_ids:
                out._add_edge(paths[source_id], paths[target_id])
        for source_id in snapshot.uncertain_sources:
            out._mark_uncertain(paths[source_id], opaque=source_id in snapshot.opaque_sources)
        out._nonfile_sources = {paths[source_id] for source_id in snapshot.nonfile_sources}
        return out

    def add_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            if path not in self._tracked_paths:
                self._tracked_paths[path] = path
                # A new path can resolve a miss or supersede a fallback target.
                self._global_targets.clear()
                self.generation += 1
                if self._targets and not self._resolution_uncertain:
                    self._resolution_uncertain = True
                    self._sorted_uncertain_sources = None

    def _mark_uncertain(self, source: str, *, opaque: bool = False) -> None:
        self.add_paths((source,))
        if source not in self._uncertain_sources:
            self._uncertain_sources.add(source)
            self._sorted_uncertain_sources = None
            self.generation += 1
        if opaque and source not in self._opaque_sources:
            self._opaque_sources.add(source)
            self.generation += 1

    @property
    def uncertain_sources(self) -> tuple[str, ...]:
        if self._sorted_uncertain_sources is None:
            candidates = self._uncertain_sources | self._targets.keys() if self._resolution_uncertain else self._uncertain_sources
            self._sorted_uncertain_sources = tuple(sorted(
                candidates, key=lambda path: (not path.endswith((".c", ".S", ".s")), path)
            ))
        return self._sorted_uncertain_sources

    def has_path(self, path: str) -> bool:
        return path in self._tracked_paths and path not in self._nonfile_sources

    def has_input(self, path: str) -> bool:
        """Tracked inputs also include opaque submodule commit references."""

        return path in self._tracked_paths

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
        match = _INCLUDE_RE.fullmatch(line)
        if match is None:
            return None
        return self._resolve(source, match.group("open"), match.group("path"))

    def analyze_source(
        self,
        source: str,
        contents: bytes,
        active_lines: Callable[[str], set[int]] | None = None,
    ) -> IncludeFacts:
        """Analyze one complete input; unknown is never an empty-edge proof."""

        if len(contents) > 2 * 1024 * 1024:
            return IncludeFacts(unknown=True)
        decoded = contents.decode("utf-8", errors="replace")
        unknown = (source in self._opaque_sources or b"\0" in contents
                   or "\ufffd" in decoded or "\ufeff" in decoded
                   or any(character in decoded for character in ("\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"))
                   or _GNU_SPLICE_RE.search(decoded) is not None)
        decoded = decoded.replace("\r\n", "\n").replace("\r", "\n")
        unknown |= "\v" in decoded or "\f" in decoded or _GNU_SPLICE_RE.search(decoded) is not None
        text = preprocessor_directive_text(decoded, strict_multiline=True)
        if text is None:
            return IncludeFacts(unknown=True)
        # These C whitespace characters are not directive line boundaries.
        text = text.replace("\v", " ").replace("\f", " ").replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"(?m)^(\s*)%:", r"\1#", text)
        if re.search(r'\b(?:__has_include|__has_include_next|__has_embed|_Pragma)\b', text):
            unknown = True
        active = active_lines(text) if active_lines is not None else None
        targets: set[str] = set()
        for number, line in enumerate(text.split("\n"), 1):
            if active is not None and number not in active:
                continue
            if re.match(r'^\s*#\s*(define|undef)\b', line):
                # A definition can alter conditional meaning in this file or
                # a later included input. No compiler macro environment is
                # available to establish that such changes preserve absence.
                unknown = True
            if re.match(r'^\s*#\s*pragma\b', line):
                unknown = True
            if not _INPUT_DIRECTIVE_RE.match(line):
                continue
            target = self.target_from_line(source, line)
            if target is None:
                unknown = True
            else:
                targets.add(target)
        return IncludeFacts(frozenset(targets), unknown)

    def _add_edge(self, source: str, target: str) -> None:
        includers = self._includers[target]
        if source not in includers:
            includers.add(source)
            self._targets[source].add(target)
            self._sorted_includers.pop(target, None)
            self.generation += 1

    def add_line(self, source: str, line: str) -> None:
        target = self.target_from_line(source, line)
        if target is not None:
            self._add_edge(self._tracked_paths.get(source, source), target)
        elif _INPUT_DIRECTIVE_RE.match(line):
            self._mark_uncertain(source)

    def _alias_source(self, first: str, second: str) -> None:
        """Keep include candidates reachable across a pure source rename."""

        first = self._tracked_paths.get(first, first)
        second = self._tracked_paths.get(second, second)
        targets = self._targets.get(first, set()) | self._targets.get(second, set())
        for target in targets:
            self._add_edge(first, target)
            self._add_edge(second, target)
        if first in self._uncertain_sources or second in self._uncertain_sources:
            opaque = first in self._opaque_sources or second in self._opaque_sources
            self._mark_uncertain(first, opaque=opaque)
            self._mark_uncertain(second, opaque=opaque)

    def add_diff(self, diff: Diff) -> None:
        for diff_file in diff.files:
            for path in (diff_file.file, diff_file.old_file):
                if path is not None:
                    self.add_paths((path,))
                    # A compact history hunk omits comment/splice context and
                    # may omit an unchanged directive whose meaning changed.
                    # Read exact blobs before using historical edge absence.
                    opaque = any(mode is not None and mode not in {"100644", "100755"}
                                 for mode in (diff_file.old_mode, diff_file.new_mode))
                    self._mark_uncertain(path, opaque=opaque)
                    modes = {mode for mode in (diff_file.old_mode, diff_file.new_mode) if mode is not None}
                    was_nonfile = path in self._nonfile_sources
                    if modes == {"160000"}:
                        self._nonfile_sources.add(path)
                    elif modes:
                        # A path that can also be a regular file remains a
                        # possible include target across these revisions.
                        self._nonfile_sources.discard(path)
                    if was_nonfile != (path in self._nonfile_sources):
                        self.generation += 1

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
