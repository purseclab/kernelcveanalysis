"""Conservative literal include closure for source-only absence checks.

This recognizes a closed textual subset, not the compiler include resolver.
Opaque directives, missing/generated inputs and expansion operators retain a
candidate. An advisory include graph never certifies absence of macro effects.
"""

from collections import OrderedDict
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, replace
import posixpath
import re

from .git_output import iter_git_records
from .syntax import has_opaque_tokens, macro_definitions, node_text, parse_source
from .whitespace.c_lexer import preprocessor_directive_text
from ..git import GitRepo


@dataclass(frozen=True, slots=True)
class MacroEnvironment:
    closed: bool
    reason: str
    files: tuple[str, ...] = ()
    macros: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _IncludeSite:
    source: str
    opener: str
    requested: str


_INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"\n]+)[>"]\s*$')
_INCLUDE_DIRECTIVE = re.compile(r'^\s*#\s*(?:include|include_next|import)\b')


class MacroEnvironmentGuard:
    def __init__(self, repo: GitRepo, read_file: Callable[[str, str], bytes], srcarch: str = "") -> None:
        self.repo = repo
        self.read_file, self.srcarch = read_file, srcarch
        self._cache: OrderedDict[tuple[str, str], MacroEnvironment] = OrderedDict()
        self._include_cache: OrderedDict[str, tuple[_IncludeSite, ...] | None] = OrderedDict()

    def _includes(self, revision: str) -> tuple[_IncludeSite, ...] | None:
        if revision in self._include_cache:
            self._include_cache.move_to_end(revision)
            return self._include_cache[revision]
        result = self._scan_includes(revision)
        self._include_cache[revision] = result
        if len(self._include_cache) > 4:
            self._include_cache.popitem(last=False)
        return result

    def _scan_includes(self, revision: str) -> tuple[_IncludeSite, ...] | None:
        # A symlink or submodule can introduce aliases/inputs outside the literal
        # tracked-file model. Do not infer absence through those environments.
        with closing(iter_git_records(self.repo, ['ls-tree', '-r', '-z', revision], b'\0', (0,))) as entries:
            for count, entry in enumerate(entries):
                if count > 200000 or entry.split(b' ', 1)[0] not in {b'100644', b'100755'}:
                    return None
        prefix = (revision + ':').encode()
        arguments = ['grep', '-l', '-z', '-F', '-e', '#', '-e', '%:', '-e', '??=', revision, '--']
        records: list[_IncludeSite] = []
        total = 0
        # Read whole candidate files before stripping comments/splices. A '#' can
        # follow a block comment on the same line, or terminate a multiline one.
        with closing(iter_git_records(self.repo, arguments, b'\0', (0, 1))) as paths:
            for count, raw_path in enumerate(paths):
                if count >= 128 or not raw_path.startswith(prefix):
                    return None
                path = raw_path[len(prefix):].decode()
                source = self.read_file(revision, path)
                total += len(source)
                if total > 2 * 1024 * 1024 or b'\0' in source or b'??=' in source:
                    return None
                text = preprocessor_directive_text(source.decode())
                if text is None:
                    return None
                for line in text.splitlines():
                    if line.lstrip().startswith('%:'):
                        return None
                    if not _INCLUDE_DIRECTIVE.match(line):
                        continue
                    match = _INCLUDE.fullmatch(line)
                    if match is None:
                        return None
                    records.append(_IncludeSite(path, match[1], match[2]))
        return tuple(records)

    def _include(self, revision: str, source: str, opener: str, requested: str) -> tuple[str, bytes] | None:
        candidates: list[str] = []
        if opener == '"':
            candidates.append(posixpath.normpath(posixpath.join(posixpath.dirname(source), requested)))
        candidates.extend((f"arch/{self.srcarch}/include/{requested}", "include/" + requested,
                           f"arch/{self.srcarch}/include/uapi/{requested}", "include/uapi/" + requested,
                           requested))
        found: list[tuple[str, bytes]] = []
        for path in dict.fromkeys(candidates):
            if path.startswith("../") or path.startswith("/"):
                return None
            try:
                contents = self.read_file(revision, path)
            except FileNotFoundError:
                continue
            found.append((path, contents))
        # Ambiguous search-order bindings require a real compiler context.
        return found[0] if len(found) == 1 else None

    def inspect(self, revision: str, root: str) -> MacroEnvironment:
        key = revision, root
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        result = self._inspect(revision, root)
        inspected_files = set(result.files)
        inspected_macros = set(result.macros)
        if result.closed:
            records = self._includes(revision)
            if records is None:
                result = MacroEnvironment(False, 'incomplete_reverse_include_environment')
            else:
                pending, seen = [root], {root}
                while pending and result.closed:
                    target = pending.pop()
                    for site in records:
                        path, opener, requested = site.source, site.opener, site.requested
                        if path in seen or posixpath.basename(requested) != posixpath.basename(target):
                            continue
                        resolved = self._include(revision, path, opener, requested)
                        if resolved is None:
                            result = MacroEnvironment(False, 'unresolved_reverse_include')
                            break
                        if resolved[0] != target:
                            continue
                        seen.add(path)
                        if len(seen) > 128:
                            result = MacroEnvironment(False, 'reverse_include_budget')
                            break
                        result = self._inspect(revision, path)
                        inspected_files.update(result.files)
                        inspected_macros.update(result.macros)
                        if not result.closed:
                            break
                        pending.append(path)
        result = replace(result, files=tuple(sorted(inspected_files)), macros=frozenset(inspected_macros))
        self._cache[key] = result
        if len(self._cache) > 128:
            self._cache.popitem(last=False)
        return result

    def _inspect(self, revision: str, root: str) -> MacroEnvironment:
        pending = [(root, self.read_file(revision, root))]
        visited: set[str] = set()
        macros: set[str] = set()
        total_bytes = 0
        def result(closed: bool, reason: str) -> MacroEnvironment:
            return MacroEnvironment(closed, reason, tuple(sorted(visited)), frozenset(macros))

        while pending:
            path, source = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            total_bytes += len(source)
            if len(visited) > 128 or total_bytes > 2 * 1024 * 1024:
                return result(False, "macro_environment_budget")
            # Raw reference searches cannot see identifiers joined by phase-two
            # splicing. Test before normalization removes that evidence.
            if re.search(rb"\\[^\S\r\n]*(?:\r\n|\n|\r)", source):
                return result(False, "unmodeled_preprocessing_spelling")
            try:
                text = preprocessor_directive_text(source.decode())
            except UnicodeError:
                return result(False, "unreadable_macro_environment")
            if text is None:
                return result(False, "opaque_macro_environment")
            for definition in macro_definitions(parse_source(text.encode())):
                name = definition.child_by_field_name("name")
                if name is None:
                    return result(False, "unclassified_macro_definition")
                macros.add(node_text(name).decode())
            if has_opaque_tokens(parse_source(source), implicit_names=False):
                return result(False, "opaque_macro_environment")
            if re.search(r"(?m)^\s*%:", text):
                return result(False, "unmodeled_preprocessing_spelling")
            for line in text.splitlines():
                if not _INCLUDE_DIRECTIVE.match(line):
                    continue
                match = _INCLUDE.fullmatch(line)
                if match is None:
                    return result(False, "computed_or_nonstandard_include")
                target = self._include(revision, path, match[1], match[2])
                if target is None:
                    return result(False, "unresolved_or_ambiguous_include")
                pending.append(target)
        return result(True, "literal_text_environment")
