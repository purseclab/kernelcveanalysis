"""Bounded, revision-specific reverse references, populated only on demand.

Raw spelling searches deliberately count strings, callbacks and macro arguments
as potential uses. Child snapshots update changed files rather than rescanning
the repository. No worktree checkout or persistent database mutation is needed.
"""

from collections import OrderedDict
from collections.abc import Callable, Iterable
from contextlib import closing
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re
import sqlite3
import subprocess
from time import perf_counter

from pydantic import TypeAdapter

from .source_filter import SourceIncludeIndex, _covering_literals, _iter_git_grep, _iter_git_output
from .syntax import IDENTIFIER
from ..diff import Diff
from ..git import GitRepo


@dataclass(frozen=True, slots=True)
class ReferenceSite:
    path: str
    line: int


_SITES_ADAPTER: TypeAdapter[tuple[ReferenceSite, ...] | None] = TypeAdapter(tuple[ReferenceSite, ...] | None)
_REFERENCE_WORD = re.compile(rb"[A-Za-z_0-9]+")


class _LiveReference(Exception):
    """A caller proved a use; an unfinished scan cannot establish absence."""


@dataclass(frozen=True, slots=True)
class ReferenceIndexStats:
    repository_scans: int
    incremental_updates: int
    cache_hits: int
    scan_seconds: float


@dataclass(slots=True)
class _ReferenceSnapshot:
    revision: str
    paths: dict[str, frozenset[str] | None]


class ReferenceIndex:
    """A lazy inverted index with explicit limits on queries and occurrences."""

    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes], cache_path: Path | None = None) -> None:
        self.repo = repo
        self.read_file = read_file
        self._entries: OrderedDict[tuple[str, str], tuple[ReferenceSite, ...] | None] = OrderedDict()
        self.repository_scans = 0
        self.incremental_updates = 0
        self.cache_hits = 0
        self.scan_seconds = 0.0
        self._anchor: str | None = None
        self._anchor_paths: dict[str, frozenset[str] | None] = {}
        self._snapshots: OrderedDict[bytes, _ReferenceSnapshot] = OrderedDict()
        self._deltas: OrderedDict[tuple[str | None, str], tuple[str, ...]] = OrderedDict()
        self._pool: frozenset[str] = frozenset()
        self.source_includes: SourceIncludeIndex | None = None
        self._include_revision: str | None = None
        self._include_seen: set[str] = set()
        self._scope: tuple[str, ...] | None = None
        self._scope_tag = ""
        self._is_live: Callable[[str, ReferenceSite], bool] | None = None
        self._query_revision: str | None = None
        self._query_names: frozenset[str] = frozenset()
        self._observed: set[str] = set()
        self._dead_observed: set[str] = set()
        self._bootstrap_revision: str | None = None
        self._bootstrap_names: frozenset[str] = frozenset()
        self._bootstrap_sites: dict[str, list[ReferenceSite]] = {}
        self._database: sqlite3.Connection | None = None
        if getattr(repo, "repo", None) is not None:
            if cache_path is None:
                path = Path(repo._run_git(["rev-parse", "--git-path", "kpatch-references-v4.sqlite"]).decode().strip())
                cache_path = path if path.is_absolute() else repo.repo / path
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._database = sqlite3.connect(cache_path, timeout=30)
            self._database.execute("PRAGMA journal_mode=WAL")
            self._database.execute("CREATE TABLE IF NOT EXISTS queries (revision TEXT, name TEXT, sites BLOB NOT NULL, PRIMARY KEY(revision,name))")
            self._database.execute("CREATE TABLE IF NOT EXISTS snapshots (version BLOB PRIMARY KEY, revision TEXT NOT NULL)")

    def close(self) -> None:
        if self._database is not None:
            self._database.commit()
            self._database.close()
            self._database = None
        self.source_includes = None
        self._include_seen.clear()

    def __enter__(self) -> "ReferenceIndex":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def stats(self) -> ReferenceIndexStats:
        return ReferenceIndexStats(self.repository_scans, self.incremental_updates, self.cache_hits, self.scan_seconds)

    def observe_patch(self, patch: str) -> None:
        """Cheap candidate planning during the existing history metadata pass."""

        all_added: str | None = None
        for block in patch.split("diff --git ")[1:]:
            lines = block.splitlines()
            old = "\n".join(line[1:] for line in lines if line.startswith("-") and not line.startswith("---"))
            new = "\n".join(line[1:] for line in lines if line.startswith("+") and not line.startswith("+++"))
            if max(len(old), len(new)) > 128 * 1024:
                continue
            path = lines[0].rsplit(" b/", 1)[-1]
            if path.endswith(".h") and path.startswith(("include/linux/", "include/net/", "include/crypto/")):
                declaration = r"\bstatic\s+inline\b[^;={}]*?\b([a-z_][a-z_0-9]{11,})\s*\("
                introduced = set(re.findall(declaration, new)) - set(re.findall(declaration, old))
                if introduced:
                    if all_added is None:
                        all_added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
                    introduced = {name for name in introduced if len(re.findall(r"\b" + re.escape(name) + r"\b", all_added)) == len(re.findall(r"\b" + re.escape(name) + r"\b", new))}
                if introduced:
                    for text in (old, new):
                        introduced.update(re.findall(r"(?m)^\s*#\s*define\s+([a-z_][a-z_0-9]{11,})\b", text))
                    self._dead_observed.update(introduced)
                    # Planning affects scan cost, never eligibility. Other
                    # candidates still use the lazy reference lookup.
                    self._dead_observed = set(sorted(self._dead_observed)[:8])
            if path.startswith(("drivers/", "arch/", "include/dt-bindings/")):
                continue
            if re.sub(rb"\s+", b"", IDENTIFIER.sub(b"@", old.encode())) != re.sub(rb"\s+", b"", IDENTIFIER.sub(b"@", new.encode())):
                continue
            names: set[str] = set()
            for pattern in (
                r"\bstatic\b[^;={}]*?\b([A-Za-z_]\w*)\s*\(",
                r"^\s*#\s*define\s+([A-Za-z_]\w*)",
                r"^\s*([A-Z][A-Z_0-9]+)\s*(?:=[^;{}]*)?,\s*$",
            ):
                before = set(re.findall(pattern, old, re.MULTILINE))
                after = set(re.findall(pattern, new, re.MULTILINE))
                if before and after:
                    names.update(before ^ after)
            self._observed.update(name for name in names if len(name) >= 8 and name.islower())
            if len(self._observed) > 256:
                self._observed = set(sorted(self._observed)[:256])

    def begin_bootstrap(self, revision: str) -> frozenset[str]:
        self._bootstrap_revision = revision
        planned = set(sorted(self._observed)[:16])
        for name in sorted(self._dead_observed):
            batch = planned | spelling_guards(name)
            if len(_covering_literals(batch)) <= 16:
                planned = batch
        self._bootstrap_names = frozenset(sorted(planned)[:256])
        self._scope_tag = ""
        self._bootstrap_sites = {name: [] for name in self._bootstrap_names if not self._load(revision, name)}
        return frozenset(self._bootstrap_sites)

    def bootstrap_hit(self, path: str, line: int, contents: bytes) -> None:
        for name in {match.group().decode() for match in _REFERENCE_WORD.finditer(contents)} & self._bootstrap_sites.keys():
            if len(self._bootstrap_sites[name]) <= 512:
                self._bootstrap_sites[name].append(ReferenceSite(path, line))

    def finish_bootstrap(self) -> None:
        assert self._bootstrap_revision is not None
        for name, sites in self._bootstrap_sites.items():
            self._persist(self._bootstrap_revision, name, tuple(sites) if len(sites) <= 512 else None)
        self._bootstrap_sites.clear()
        if self._database is not None:
            self._database.commit()

    def has_bootstrap(self, names: frozenset[str]) -> bool:
        return self._bootstrap_revision is not None and names <= self._bootstrap_names

    def bind_includes(self, index: SourceIncludeIndex, revision: str) -> None:
        self.source_includes = index
        self._include_revision = revision
        self._include_seen = {revision}

    def _augment_includes(self, revision: str) -> bool:
        index = self.source_includes
        if index is None or self._include_revision is None:
            return False
        if revision in self._include_seen:
            return True
        paths = [path.decode() for path in _iter_git_output(
            self.repo, ["diff", "--name-only", "-z", "--diff-filter=ACMRTUXB", self._include_revision, revision, "--", "*.c", "*.h", "*.S"], b"\0", (0,),
        ) if path]
        index.add_paths(paths)
        source: str | None = None
        arguments = ["diff", "--no-ext-diff", "--no-renames", "--unified=0", "--diff-filter=ACMRTUXB", "-G", r"^[[:space:]]*#[[:space:]]*include", self._include_revision, revision, "--", "*.c", "*.h", "*.S"]
        for row in _iter_git_output(self.repo, arguments, b"\n", (0,)):
            if row.startswith(b"+++ "):
                if not row.startswith(b"+++ b/"):
                    return False
                source = row[6:].decode()
            elif source is not None and row.startswith(b"+"):
                index.add_line(source, row[1:].decode("utf-8", errors="strict"))
        self._include_revision = revision
        self._include_seen.add(revision)
        if len(self._include_seen) > 256:
            self._include_seen = {revision}
        return True

    def scope_for(self, roots: Iterable[str], revision: str, *, max_paths: int | None = None) -> frozenset[str] | None:
        """Possible consumers and their headers, using the build stage's graph."""

        index = self.source_includes
        if index is None:
            return None
        roots = tuple(roots)
        # Adding historical edges only enlarges this set. A scope already over
        # budget will require a global search regardless of the include delta.
        initial = self._scope_paths(roots)
        if max_paths is not None and len(initial) > max_paths:
            return None
        if sum(len(path) + 1 for path in initial) > 512 * 1024:
            return None
        if not self._augment_includes(revision):
            return None
        sources = set(roots)
        if any(path.endswith(".h") and not index.includers(path) for path in sources):
            return None
        paths = self._scope_paths(roots)
        if max_paths is not None and len(paths) > max_paths:
            return None
        if sum(len(path) + 1 for path in paths) > 512 * 1024:
            return None
        # Compiler flags and forced includes can mention a private symbol too.
        return paths | frozenset({"*Makefile*", "*Kbuild*", "*.mk", "*.lds*"})

    def _scope_paths(self, roots: Iterable[str]) -> frozenset[str]:
        assert self.source_includes is not None
        index = self.source_includes
        sources = set(roots)
        pending = list(sources)
        while pending:
            for source in index.includers(pending.pop()):
                if source not in sources:
                    sources.add(source)
                    pending.append(source)
        return index.transitive_targets(sources)

    def _cache_name(self, name: str) -> str:
        return "v4:" + name + self._scope_tag

    def _remember(self, revision: str, name: str, sites: tuple[ReferenceSite, ...] | None) -> None:
        self._entries[revision, self._cache_name(name)] = sites
        self._entries.move_to_end((revision, self._cache_name(name)))
        if len(self._entries) > 128:
            self._entries.popitem(last=False)
        self._persist(revision, name, sites)

    def _persist(self, revision: str, name: str, sites: tuple[ReferenceSite, ...] | None) -> None:
        if self._database is not None:
            self._database.execute("INSERT OR REPLACE INTO queries VALUES (?,?,?)", (revision, self._cache_name(name), _SITES_ADAPTER.dump_json(sites)))

    def _load(self, revision: str, name: str) -> bool:
        key = (revision, self._cache_name(name))
        if key in self._entries:
            return True
        if self._database is None:
            return False
        row = self._database.execute("SELECT sites FROM queries WHERE revision=? AND name=?", key).fetchone()
        if row is None:
            return False
        sites = _SITES_ADAPTER.validate_json(row[0])
        self._entries[key] = sites
        if len(self._entries) > 128:
            self._entries.popitem(last=False)
        return True

    @staticmethod
    def _sites(path: str, source: bytes, names: frozenset[str]) -> dict[str, list[ReferenceSite]]:
        result: dict[str, list[ReferenceSite]] = {name: [] for name in names}
        for line_number, line in enumerate(source.split(b"\n"), 1):
            for name in {match.group().decode() for match in _REFERENCE_WORD.finditer(line)} & names:
                result[name].append(ReferenceSite(path, line_number))
        return result

    def lookup(
        self,
        revision: str,
        names: frozenset[str],
        *,
        parent: str | None = None,
        changed_paths: frozenset[str] = frozenset(),
        scope: frozenset[str] | None = None,
        is_live: Callable[[str, ReferenceSite], bool] | None = None,
    ) -> dict[str, tuple[ReferenceSite, ...] | None]:
        if len(names) > 256:
            return {name: None for name in names}
        self._scope = tuple(sorted(scope)) if scope is not None else None
        self._scope_tag = "\0" + sha256("\0".join(self._scope).encode()).hexdigest() if self._scope is not None else ""
        self._is_live, self._query_revision = is_live, revision
        self._query_names = names
        try:
            return self._lookup(revision, names, parent, changed_paths)
        except _LiveReference:
            # Deliberately do not persist absence/unknown for an interrupted
            # search. A different configuration may need the complete facts.
            return {name: None for name in names}
        finally:
            self._is_live = None
            self._query_names = frozenset()
            if self._database is not None:
                self._database.commit()

    def _lookup(self, revision: str, names: frozenset[str], parent: str | None, changed_paths: frozenset[str]) -> dict[str, tuple[ReferenceSite, ...] | None]:
        missing: set[str] = set()
        for name in names:
            if self._load(revision, name):
                self._entries.move_to_end((revision, self._cache_name(name)))
                self.cache_hits += 1
            elif parent is not None and self._load(parent, name):
                self._update(revision, parent, name, changed_paths)
            else:
                missing.add(name)
        if missing:
            self._query(revision, frozenset(missing))
        if self._database is not None:
            self._database.commit()
        return {name: self._entries.get((revision, self._cache_name(name))) for name in names}

    def plan_diffs(self, diffs: Iterable[Diff]) -> None:
        """Batch names from bounded lookahead after earlier pruning stages."""

        names: set[str] = set()
        functions: set[str] = set()
        for diff in diffs:
            for file in diff.files:
                if not file.file.endswith((".c", ".h")):
                    continue
                lines = [line for chunk in file.chunks for line in chunk.lines]
                if file.file.endswith(".h"):
                    changed = "\n".join(line[1:] for line in lines if line.startswith(("-", "+")))
                    functions.update(re.findall(r"\bstatic\b[^;={}]*?\b([A-Za-z_]\w*)\s*\(", changed))
                    for chunk in file.chunks:
                        if chunk.section and "static " in chunk.section:
                            functions.update(re.findall(r"\b([A-Za-z_]\w*)\s*\(", chunk.section))
                old = "\n".join(line[1:] for line in lines if line.startswith("-")).encode()
                new = "\n".join(line[1:] for line in lines if line.startswith("+")).encode()
                if max(len(old), len(new)) > 128 * 1024:
                    continue
                if re.sub(rb"\s+", b"", IDENTIFIER.sub(b"@", old)) != re.sub(rb"\s+", b"", IDENTIFIER.sub(b"@", new)):
                    continue
                changes = [(a, b) for a, b in zip(IDENTIFIER.findall(old), IDENTIFIER.findall(new)) if a != b]
                names.update(token.decode() for pair in changes for token in pair)
        planned = frozenset(sorted(name for name in names if len(name) >= 8)[:128])
        functions = set(sorted(name for name in functions if len(name) >= 12 and name.islower())[:64])
        self._pool = frozenset(sorted(planned | frozenset(guard for name in functions for guard in spelling_guards(name)))[:256])

    def _ensure_anchor(self, names: frozenset[str]) -> None:
        assert self._anchor is not None
        prefetch = frozenset(sorted(self._pool - names)[:max(0, 256 - len(names))])
        wanted = names | prefetch
        for name in tuple(self._anchor_paths):
            if len(self._anchor_paths) + len(wanted - self._anchor_paths.keys()) <= 256:
                break
            if name not in wanted:
                del self._anchor_paths[name]
        missing = set(wanted - self._anchor_paths.keys())
        for name in tuple(missing):
            if self._load(self._anchor, name):
                sites = self._entries[self._anchor, self._cache_name(name)]
                self._anchor_paths[name] = None if sites is None else frozenset(site.path for site in sites)
                missing.remove(name)
        if not missing:
            return
        for name, sites in self._scan(self._anchor, frozenset(missing)).items():
            self._anchor_paths[name] = None if sites is None else frozenset(site.path for site in sites)
            self._persist(self._anchor, name, sites)
            if name in names:
                self._remember(self._anchor, name, sites)

    def _select_anchor(self, revision: str) -> None:
        try:
            makefile = self.read_file(revision, "Makefile")
        except (FileNotFoundError, subprocess.CalledProcessError):
            version = b"unknown"
        else:
            version = b".".join(re.findall(rb"^(?:VERSION|PATCHLEVEL)\s*=\s*(\d+)", makefile, re.MULTILINE))
        if version not in self._snapshots:
            row = self._database.execute("SELECT revision FROM snapshots WHERE version=?", (version,)).fetchone() if self._database is not None else None
            anchor = row[0] if row is not None else revision
            self._snapshots[version] = _ReferenceSnapshot(anchor, {})
            if self._database is not None:
                self._database.execute("INSERT OR IGNORE INTO snapshots VALUES (?,?)", (version, anchor))
            if len(self._snapshots) > 4:
                self._snapshots.popitem(last=False)
        self._snapshots.move_to_end(version)
        snapshot = self._snapshots[version]
        self._anchor, self._anchor_paths = snapshot.revision, snapshot.paths

    def changed_paths(self, parent: str, revision: str) -> frozenset[str]:
        """Actual repository deltas, even if the input patch omitted a file."""
        return frozenset(self._delta_paths(parent, revision))

    def _delta_paths(self, parent: str, revision: str) -> tuple[str, ...]:
        key = (parent, revision)
        if key not in self._deltas:
            paths = tuple(path.decode() for path in _iter_git_output(
                self.repo, ["diff", "--no-renames", "--name-only", "-z", "--diff-filter=ACDMRTUXB", parent, revision], b"\0", (0,),
            ) if path and (path.endswith((b".c", b".h", b".S", b".s", b".rs", b".mk")) or b"Makefile" in path or b"Kbuild" in path or b".lds" in path))
            self._deltas[key] = paths
            while len(self._deltas) > 1 and (len(self._deltas) > 32 or sum(map(len, self._deltas.values())) > 32768):
                self._deltas.popitem(last=False)
        self._deltas.move_to_end(key)
        return self._deltas[key]

    def _query(self, revision: str, names: frozenset[str]) -> None:
        bootstrapped = self._scope is None and self.has_bootstrap(names)
        if self._scope is not None or (not self._pool and not bootstrapped):
            result = {} if self._scope == () else self._scan(revision, names, self._scope or ())
            for name in names:
                self._remember(revision, name, result.get(name, ()))
            return
        if bootstrapped:
            assert self._bootstrap_revision is not None
            self._anchor = self._bootstrap_revision
            snapshot = self._snapshots.setdefault(b"bootstrap", _ReferenceSnapshot(self._anchor, {}))
            self._anchor_paths = snapshot.paths
        else:
            self._select_anchor(revision)
        self._ensure_anchor(names)
        if revision == self._anchor:
            missing = frozenset(name for name in names if (revision, self._cache_name(name)) not in self._entries)
            if not missing:
                return
            names = missing
        searchable = frozenset(name for name in names if self._anchor_paths[name] is not None)
        paths = set(self._delta_paths(self._anchor or revision, revision))
        for name in searchable:
            paths.update(self._anchor_paths[name] or ())
        result = self._scan(revision, searchable, tuple(sorted(paths))) if searchable and paths else {}
        result.update((name, None) for name in names - searchable)
        for name in names:
            self._remember(revision, name, result.get(name, ()))

    def _update(self, revision: str, parent: str, name: str, paths: frozenset[str]) -> None:
        previous = self._entries[parent, self._cache_name(name)]
        if previous is None:
            self._remember(revision, name, None)
            return
        sites = [site for site in previous if site.path not in paths]
        try:
            for path in paths:
                try:
                    source = self.read_file(revision, path)
                except FileNotFoundError:
                    continue
                sites.extend(self._sites(path, source, frozenset({name}))[name])
        except (OSError, ValueError):
            self._remember(revision, name, None)
            return
        self.incremental_updates += 1
        self._remember(revision, name, tuple(sites) if len(sites) <= 512 else None)

    def _scan(self, revision: str, names: frozenset[str], paths: tuple[str, ...] = ()) -> dict[str, tuple[ReferenceSite, ...] | None]:
        arguments = ["grep", "--threads=8", "-n", "-z", "-I", "-F"]
        for name in _covering_literals(names):
            arguments.extend(("-e", name))
        arguments.append(revision)
        arguments.append("--")
        arguments.extend(paths or ("*.c", "*.h", "*.S", "*.s", "*.rs", "*Makefile*", "*Kbuild*", "*.mk", "*.lds*"))
        prefix = f"{revision}:".encode()
        results: dict[str, list[ReferenceSite]] = {name: [] for name in names}
        self.repository_scans += 1
        started = perf_counter()
        try:
            with closing(_iter_git_grep(self.repo, arguments)) as rows:
                for row in rows:
                    fields = row.split(b"\0", 2)
                    if len(fields) != 3 or not fields[0].startswith(prefix):
                        continue
                    path = fields[0][len(prefix):].decode("utf-8", errors="strict")
                    line = int(fields[1])
                    site = ReferenceSite(path, line)
                    matched = {match.group().decode() for match in _REFERENCE_WORD.finditer(fields[2])} & names
                    for name in matched:
                        if self._is_live is not None and name in self._query_names and revision == self._query_revision and self._is_live(name, site):
                            raise _LiveReference
                        if len(results[name]) <= 512:
                            results[name].append(site)
        finally:
            self.scan_seconds += perf_counter() - started
        return {name: tuple(sites) if len(sites) <= 512 else None for name, sites in results.items()}


def spelling_guards(name: str) -> frozenset[str]:
    """Also treat common prefix/suffix token-paste spellings as potential uses."""

    guards = {name}
    for position in range(1, len(name)):
        prefix, suffix = name[:position], name[position:]
        guards.update(part for part in (prefix, suffix) if len(part) >= (len(name) + 1) // 2)
    return frozenset(guards)
