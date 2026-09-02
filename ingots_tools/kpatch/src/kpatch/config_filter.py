from enum import StrEnum, Enum
from dataclasses import dataclass
from typing import Self
import posixpath
import re

from .git import GitRepo
from .diff import Diff, DiffFileType

class ConfigValue(StrEnum):
    ENABLED = "y"
    MODULE = "m"
    DISABLED = "n"

class KernelConfig:
    _unset_re = re.compile(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set\s*$")
    _key_re = re.compile(r"^CONFIG_[A-Za-z0-9_]+$")

    values: dict[str, ConfigValue]
    raw_values: dict[str, str]

    def __init__(self, config: str):
        self.values = {}
        self.raw_values = {}

        for raw_line in config.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            unset_match = self._unset_re.fullmatch(line)
            if unset_match is not None:
                key = unset_match.group(1)
                self.values[key] = ConfigValue.DISABLED
                self.raw_values[key] = ""
                continue

            if line.startswith("#"):
                continue

            key, separator, raw_value = line.partition("=")
            key = key.strip()
            raw_value = raw_value.strip()
            if not separator or self._key_re.fullmatch(key) is None:
                continue

            try:
                value = ConfigValue(raw_value)
            except ValueError:
                # Integer and string symbols are defined for Make conditionals,
                # but do not have a tristate value of their own.
                value = ConfigValue.ENABLED

            self.values[key] = value
            self.raw_values[key] = (
                "" if value is ConfigValue.DISABLED else raw_value
            )

    def get(self, key: str) -> ConfigValue:
        return self.values.get(key, ConfigValue.DISABLED)

    def get_raw(self, key: str) -> str:
        return self.raw_values.get(key, "")


CODE_FILES = [".c", ".S"]
HEADER_FILES = [".h"]


class KbuildMakefile:
    """A small, non-executing parser for the declarative Kbuild subset.

    Files named ``Kbuild`` and per-directory kernel ``Makefile`` files use the
    same syntax.  The distinction only matters when choosing which file to
    read, so this parser deliberately has no file-kind flag.
    """

    _assignment_re = re.compile(
        r"^(?P<name>[^\s:=+?]+)\s*(?P<operator>:=|\+=|\?=|=)\s*(?P<value>.*)$"
    )
    _variable_re = re.compile(r"\$\(([^()]+)\)|\$\{([^{}]+)\}")

    @dataclass(slots=True)
    class _Conditional:
        parent_active: bool
        branch_taken: bool
        active: bool

    def __init__(self, contents: str, config: KernelConfig, folder: str):
        self._config: KernelConfig = config
        self.folder: str = folder
        self._variables: dict[str, str] = {}
        self._simple_variables: set[str] = set()
        self._included: dict[str, ConfigValue] = {}

        self._parse(contents)
        self._collect_goals()

    @staticmethod
    def _logical_lines(contents: str) -> list[str]:
        lines: list[str] = []
        pending = ""

        for physical_line in contents.splitlines():
            line = physical_line.rstrip()
            continued = line.endswith("\\")
            if continued:
                line = line[:-1]
            pending += line if not pending else f" {line.lstrip()}"
            if not continued:
                lines.append(pending)
                pending = ""

        if pending:
            lines.append(pending)
        return lines

    @staticmethod
    def _strip_comment(line: str) -> str:
        escaped = False
        for index, character in enumerate(line):
            if character == "#" and not escaped:
                return line[:index]
            if character == "\\":
                escaped = not escaped
            else:
                escaped = False
        return line

    def _variable_value(self, name: str, seen: set[str]) -> str:
        name = name.strip()
        if name.startswith("CONFIG_"):
            return self._config.get_raw(name)

        if name in seen:
            return ""
        value = self._variables.get(name, "")
        if name in self._simple_variables:
            return value
        return self._expand(value, seen | {name})

    def _expand(self, value: str, seen: set[str] | None = None) -> str:
        seen = set() if seen is None else seen

        # Repeated substitution supports ordinary nested variable references.
        # Make functions are intentionally unsupported and therefore expand to
        # an empty value rather than being executed or mistaken for filenames.
        for _ in range(100):
            expanded, count = self._variable_re.subn(
                lambda match: self._variable_value(
                    match.group(1) or match.group(2), seen
                ),
                value,
            )
            if count == 0 or expanded == value:
                return expanded
            value = expanded
        return value

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            return value[1:-1]
        return value

    def _condition(self, directive: str, expression: str) -> bool:
        expression = expression.strip()
        if directive in ("ifdef", "ifndef"):
            result = bool(self._variable_value(expression, set()))
            return not result if directive == "ifndef" else result

        left = right = ""
        if expression.startswith("(") and expression.endswith(")"):
            arguments = expression[1:-1].split(",", 1)
            if len(arguments) == 2:
                left, right = arguments
        else:
            match = re.match(
                r'''^("[^"]*"|'[^']*'|\S+)\s+("[^"]*"|'[^']*'|\S+)$''',
                expression,
            )
            if match is not None:
                left, right = match.groups()

        equal = self._unquote(self._expand(left)) == self._unquote(
            self._expand(right)
        )
        return not equal if directive == "ifneq" else equal

    def _assign(self, name: str, operator: str, value: str) -> None:
        name = self._expand(name).strip()
        if not name:
            return

        if operator == "?=" and name in self._variables:
            return
        if operator == ":=":
            self._variables[name] = self._expand(value)
            self._simple_variables.add(name)
        elif operator == "+=":
            if name in self._simple_variables:
                value = self._expand(value)
            previous = self._variables.get(name, "")
            self._variables[name] = f"{previous} {value}".strip()
        else:
            self._variables[name] = value
            self._simple_variables.discard(name)

    def _parse(self, contents: str) -> None:
        conditionals: list[KbuildMakefile._Conditional] = []

        for logical_line in self._logical_lines(contents):
            line = self._strip_comment(logical_line).strip()
            if not line:
                continue

            directive_parts = line.split(None, 1)
            directive = directive_parts[0]
            expression = directive_parts[1] if len(directive_parts) == 2 else ""
            if directive in ("ifdef", "ifndef", "ifeq", "ifneq"):
                parent_active = conditionals[-1].active if conditionals else True
                result = self._condition(directive, expression)
                conditionals.append(
                    self._Conditional(
                        parent_active=parent_active,
                        branch_taken=result,
                        active=parent_active and result,
                    )
                )
                continue

            if directive == "else" and conditionals:
                frame = conditionals[-1]
                nested_parts = expression.split(None, 1)
                nested_directive = nested_parts[0] if nested_parts else ""
                nested_expression = nested_parts[1] if len(nested_parts) == 2 else ""
                if nested_directive in ("ifdef", "ifndef", "ifeq", "ifneq"):
                    result = self._condition(nested_directive, nested_expression)
                    frame.active = (
                        frame.parent_active and not frame.branch_taken and result
                    )
                    frame.branch_taken = frame.branch_taken or result
                else:
                    frame.active = frame.parent_active and not frame.branch_taken
                    frame.branch_taken = True
                continue

            if directive == "endif":
                if conditionals:
                    _ = conditionals.pop()
                continue

            if conditionals and not conditionals[-1].active:
                continue

            match = self._assignment_re.match(line)
            if match is not None:
                self._assign(
                    match.group("name"),
                    match.group("operator"),
                    match.group("value"),
                )

    @staticmethod
    def _merge_mode(
        current: ConfigValue | None, new: ConfigValue
    ) -> ConfigValue:
        if current is ConfigValue.ENABLED or new is ConfigValue.ENABLED:
            return ConfigValue.ENABLED
        return ConfigValue.MODULE

    def _record(self, path: str, mode: ConfigValue) -> None:
        relative_path = path.removeprefix("./").rstrip("/")
        if relative_path:
            absolute_path = posixpath.normpath(
                posixpath.join(self.folder, relative_path)
            )
            self._included[absolute_path] = self._merge_mode(
                self._included.get(absolute_path), mode
            )

    def _tokens(self, variable: str) -> list[str]:
        return self._expand(self._variables.get(variable, "")).split()

    def _add_goal(
        self,
        goal: str,
        mode: ConfigValue,
        resolving: set[tuple[str, ConfigValue]],
    ) -> None:
        goal = goal.strip()
        if not goal or "$" in goal:
            return
        if goal.endswith("/"):
            self._record(goal, mode)
            return
        if not goal.endswith(".o"):
            return

        stem = goal[:-2]
        component_variables = (f"{stem}-objs", f"{stem}-y", f"{stem}-m")
        is_composite = any(name in self._variables for name in component_variables)
        if not is_composite:
            self._record(goal, mode)
            return

        key = (goal, mode)
        if key in resolving:
            return
        resolving.add(key)
        variables: tuple[str, ...] = component_variables[:2]
        if mode is ConfigValue.MODULE:
            variables = component_variables
        for variable in variables:
            for component in self._tokens(variable):
                self._add_goal(component, mode, resolving)
        resolving.remove(key)

    def _collect_goals(self) -> None:
        for variable, mode in (
            ("obj-y", ConfigValue.ENABLED),
            ("obj-m", ConfigValue.MODULE),
            ("lib-y", ConfigValue.ENABLED),
            # Kbuild folds both lib-y and lib-m into the directory's lib.a.
            ("lib-m", ConfigValue.ENABLED),
        ):
            for goal in self._tokens(variable):
                self._add_goal(goal, mode, set())

    def get(self, file: str) -> ConfigValue | None:
        normalized = file.rstrip("/")
        root, extension = posixpath.splitext(normalized)
        if extension in CODE_FILES:
            normalized = f"{root}.o"
        return self._included.get(normalized)

    def includes(self, file: str) -> bool:
        value = self.get(file)
        return value is not None and value != ConfigValue.DISABLED

class CacheEntryType(Enum):
    KBUILD = 0
    MAKEFILE = 1

@dataclass
class KbuildCacheEntry:
    path: str
    parent: Self | None
    cache_type: CacheEntryType
    makefile: KbuildMakefile
    enabled: bool
    children: dict[str, Self]

    def set_enabled(self, new_enabled: bool):
        if self.enabled != new_enabled:
            for child in self.children.values():
                child.set_enabled(new_enabled and self.makefile.includes(child.path))

            self.enabled = new_enabled

class ConfigFilter:
    repo: GitRepo
    config: KernelConfig
    base_commit: str

    # mapping from folder to kbuild file inside it
    kbuild_cache: dict[str, KbuildCacheEntry]
    # set of paths which are known to have no makefile and should delegate to parent
    delegated: set[str]

    def __init__(self, repo: GitRepo, config: KernelConfig, base_commit: str):
        self.repo = repo
        self.config = config
        self.base_commit = base_commit
        self.kbuild_cache = {}
        self.delegated = set()

    def _kbuild_cache_add(self, parent: KbuildCacheEntry | None, folder: str, cache_type: CacheEntryType, makefile: KbuildMakefile) -> KbuildCacheEntry:
        if makefile.folder != folder:
            raise ValueError("KbuildMakefile folder does not match cache path")

        if parent is None:
            enabled = True
        else:
            enabled = parent.enabled and parent.makefile.includes(folder)

        entry = KbuildCacheEntry(
            path=folder,
            parent=parent,
            cache_type=cache_type,
            makefile=makefile,
            enabled=enabled,
            children={},
        )

        self.kbuild_cache[folder] = entry
        if parent is not None:
            parent.children[folder] = entry

        return entry

    # returns none if this folder is excluded
    def _kbuild_cache_get(self, folder: str) -> KbuildCacheEntry | None:
        # root dir doesn't have kbuild makefile
        if folder == "":
            return None

        if folder in self.delegated:
            parent = posixpath.dirname(folder)
            return self._kbuild_cache_get(parent)

        entry = self.kbuild_cache.get(folder)
        if entry is None:
            parent = posixpath.dirname(folder)
            parent_entry = self._kbuild_cache_get(parent)

            # use Kbuild if it exists, otherwise Makefile
            try:
                contents = self.repo.read_file(
                    self.base_commit,
                    posixpath.join(folder, "Kbuild"),
                )
                cache_type = CacheEntryType.KBUILD
            except Exception:
                try:
                    contents = self.repo.read_file(
                        self.base_commit,
                        posixpath.join(folder, "Makefile"),
                    )
                    cache_type = CacheEntryType.MAKEFILE
                except Exception:
                    # no makefile and no parent is an error
                    if parent_entry is None:
                        return None

                    # makefile is in higher up level, delegate to it
                    self.delegated.add(folder)
                    return parent_entry

            makefile = KbuildMakefile(contents.decode(), self.config, folder)

            return self._kbuild_cache_add(parent_entry, folder, cache_type, makefile)
        else:
            return entry

    def _path_included(self, path: str) -> bool:
        # folder in root dir always excluded
        if posixpath.dirname(path) == "":
            return False

        parent = posixpath.dirname(path)
        cache_entry = self._kbuild_cache_get(parent)
        if cache_entry is None:
            return False

        return cache_entry.enabled and cache_entry.makefile.includes(path)

    def file_included(self, file: str) -> bool:
        extension = posixpath.splitext(file)[-1]

        if extension in CODE_FILES:
            return self._path_included(file)
        elif extension in HEADER_FILES:
            # FIXME: actually trace header changes
            # the hypothesis is header only changes are very rare for vuln fixes
            # so just ignore them for now so we can be lazy
            return False
        else:
            # other files we ignore
            return False

    def _delete_kbuild_makefile(self, path: str, cache_type: CacheEntryType | None, delete_from_parent: bool = True):
        """Call to signal kbuild makefile deleted."""
        cache_entry = self.kbuild_cache.get(path)
        # if cache type match required, only delete same cache type
        # NOTE: this may unneceasrily delete children, not an issue since delete kbuild fallback to makefile should be rare
        if cache_entry is None or (cache_type is not None and cache_entry.cache_type != cache_type):
            return

        del self.kbuild_cache[path]

        if delete_from_parent and cache_entry.parent is not None:
            del cache_entry.parent.children[path]

        for child in cache_entry.children:
            # don't delete while we are iterating
            self._delete_kbuild_makefile(child, cache_type=None, delete_from_parent=False)

    # used for both create and update
    def _update_kbuild_makefile(self, path: str, cache_type: CacheEntryType, new_contents: str):
        if path in self.kbuild_cache:
            # fall back to update existing if one already exists
            self._update_existing_kbuild_makefile(path, cache_type, new_contents)
        else:
            # otherwise just clear delegation
            if path in self.delegated:
                self.delegated.remove(path)

    def _update_existing_kbuild_makefile(self, path: str, cache_type: CacheEntryType, new_contents: str):
        cache_entry = self.kbuild_cache.get(path)
        if cache_entry is None:
            return

        # don't update if only a makefile change, and this is a kbuild change
        if cache_entry.cache_type == CacheEntryType.KBUILD and cache_type == CacheEntryType.MAKEFILE:
            return

        cache_entry.makefile = KbuildMakefile(new_contents, self.config, path)
        cache_entry.cache_type = cache_type
        if cache_entry.enabled:
            # recompute child enabled status
            for child in cache_entry.children.values():
                child.set_enabled(cache_entry.makefile.includes(child.path))

    @staticmethod
    def _kbuild_makefile_cache_type(filename: str) -> CacheEntryType | None:
        parent, child = posixpath.split(filename)

        if parent == "":
            return None

        if child == "Kbuild":
            return CacheEntryType.KBUILD
        elif child == "Makefile":
            return CacheEntryType.MAKEFILE
        else:
            return None

    def update_filter_state(self, diff: Diff, new_commit: str):
        """Call for every commit in chain of analyzed commits to keep filter in sync."""

        self.base_commit = new_commit

        for file in diff.files:
            cache_type = self._kbuild_makefile_cache_type(file.file)

            if cache_type is not None:
                folder = posixpath.dirname(file.file)

                if file.change_type == DiffFileType.DEFAULT or file.change_type == DiffFileType.NEW or file.change_type == DiffFileType.COPY or file.change_type == DiffFileType.RENAME:
                    new_contents = self.repo.read_file(
                        new_commit, file.file
                    ).decode()
                    self._update_kbuild_makefile(folder, cache_type, new_contents)
                elif file.change_type == DiffFileType.DELETE:
                    self._delete_kbuild_makefile(folder, cache_type)

            if file.change_type == DiffFileType.RENAME and (file.old_file is not None):
                old_cache_type = self._kbuild_makefile_cache_type(file.old_file)

                if old_cache_type is not None:
                    old_folder = posixpath.dirname(
                        file.old_file
                    )
                    self._delete_kbuild_makefile(old_folder, old_cache_type)
