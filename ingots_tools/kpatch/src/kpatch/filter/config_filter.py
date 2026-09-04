from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
import posixpath
import re
import subprocess
from typing import Self

from kexploit_utils import Architecture

from ..git import GitRepo
from ..diff import Diff


class ConfigValue(StrEnum):
    ENABLED = "y"
    MODULE = "m"
    DISABLED = "n"


class KernelConfig:
    _unset_re = re.compile(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set\s*$")
    _key_re = re.compile(r"^CONFIG_[A-Za-z0-9_]+$")

    values: dict[str, ConfigValue]
    raw_values: dict[str, str]
    architecture: Architecture | None

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

        architectures = [
            architecture
            for symbol, architecture in (
                ("CONFIG_X86_32", Architecture.X86),
                ("CONFIG_X86_64", Architecture.AMD64),
                ("CONFIG_ARM", Architecture.ARM),
                ("CONFIG_ARM64", Architecture.AARCH64),
            )
            if self.get(symbol) is ConfigValue.ENABLED
        ]
        if len(architectures) > 1:
            raise ValueError("Kernel config enables multiple architectures")
        self.architecture = architectures[0] if architectures else None

    def get(self, key: str) -> ConfigValue:
        return self.values.get(key, ConfigValue.DISABLED)

    def get_raw(self, key: str) -> str:
        return self.raw_values.get(key, "")


CODE_FILES = [".c", ".S"]
HEADER_FILES = [".h"]


def _linux_srcarch(architecture: Architecture | None) -> str:
    if architecture in (Architecture.X86, Architecture.AMD64):
        return "x86"
    if architecture is Architecture.ARM:
        return "arm"
    if architecture is Architecture.AARCH64:
        return "arm64"
    return ""


class KbuildMakefile:
    """A small, non-executing parser for the declarative Kbuild subset.

    Files named ``Kbuild`` and per-directory kernel ``Makefile`` files use the
    same syntax.  The distinction only matters when choosing which file to
    read, so this parser deliberately has no file-kind flag.
    """

    _assignment_re = re.compile(
        r"^(?P<name>.+?)\s*(?P<operator>:=|\+=|\?=|=)\s*(?P<value>.*)$"
    )
    _variable_re = re.compile(r"\$\(([^()]+)\)|\$\{([^{}]+)\}")
    _include_re = re.compile(r"^(?:-?include|sinclude)\s+(.+)$")

    _DEFAULT_GOALS = (
        ("obj-y", ConfigValue.ENABLED),
        ("obj-m", ConfigValue.MODULE),
        ("lib-y", ConfigValue.ENABLED),
        # Kbuild folds both lib-y and lib-m into the directory's lib.a.
        ("lib-m", ConfigValue.ENABLED),
    )

    @dataclass(slots=True)
    class _Conditional:
        parent_active: bool
        branch_taken: bool
        active: bool

    def __init__(
        self,
        contents: str,
        config: KernelConfig,
        folder: str,
        *,
        variables: Mapping[str, str] | None = None,
        include_reader: Callable[[str], tuple[str, str | None]] | None = None,
        source_path: str | None = None,
        goals: tuple[tuple[str, ConfigValue], ...] | None = None,
    ):
        self._config: KernelConfig = config
        self.folder: str = folder
        self._variables: dict[str, str] = dict(variables or {})
        self._simple_variables: set[str] = set(self._variables)
        self._included: dict[str, ConfigValue] = {}
        self._directories: set[str] = set()
        self.included_files: set[str] = set()
        self._include_reader = include_reader
        self._goals = self._DEFAULT_GOALS if goals is None else goals

        include_stack = {source_path} if source_path is not None else set()
        self._parse(contents, include_stack)
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

        function, separator, arguments = name.partition(" ")
        if separator and function == "subst":
            fields = self._expand(arguments, seen).split(",", 2)
            if len(fields) != 3:
                return ""
            old, new, value = fields
            return value.replace(old, new)

        if name in seen:
            return ""
        value = self._variables.get(name, "")
        if name in self._simple_variables:
            return value
        return self._expand(value, seen | {name})

    def _expand(self, value: str, seen: set[str] | None = None) -> str:
        seen = set() if seen is None else seen

        # Innermost references are substituted first, which also permits the
        # supported functions to contain ordinary variable references.
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
        if (
            not name
            or any(character.isspace() for character in name)
            or ":" in name
        ):
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

    def _parse(self, contents: str, include_stack: set[str]) -> None:
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

            include_match = self._include_re.fullmatch(line)
            if include_match is not None and self._include_reader is not None:
                for requested_path in self._expand(include_match.group(1)).split():
                    include_path, include_contents = self._include_reader(
                        requested_path
                    )
                    self.included_files.add(include_path)
                    if include_contents is None or include_path in include_stack:
                        continue
                    self._parse(
                        include_contents,
                        include_stack | {include_path},
                    )
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
        is_directory = path.endswith("/")
        is_root_relative = path.startswith("/")
        relative_path = path.removeprefix("./").lstrip("/").rstrip("/")
        if relative_path:
            absolute_path = posixpath.normpath(
                posixpath.join(
                    "" if is_root_relative else self.folder,
                    relative_path,
                )
            )
            self._included[absolute_path] = self._merge_mode(
                self._included.get(absolute_path), mode
            )
            if is_directory:
                self._directories.add(absolute_path)

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
        for variable, mode in self._goals:
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

    @property
    def directories(self) -> frozenset[str]:
        return frozenset(self._directories)


class KbuildDirectory:
    """Resolved Kbuild rules for one repository directory.

    Ordinary directories use ``Kbuild`` when present and otherwise fall back
    to ``Makefile``.  The repository root deliberately uses only ``Kbuild``.
    The selected architecture directory additionally contributes the global,
    root-relative directory lists from its architecture ``Makefile``.
    """

    _ARCHITECTURE_GOALS = (
        ("core-y", ConfigValue.ENABLED),
        ("drivers-y", ConfigValue.ENABLED),
        ("drivers-m", ConfigValue.ENABLED),
        ("libs-y", ConfigValue.ENABLED),
    )

    def __init__(
        self,
        repo: GitRepo,
        commit: str,
        config: KernelConfig,
        folder: str,
    ):
        self.folder = folder
        self.source_files: set[str] = set()
        self._makefiles: list[KbuildMakefile] = []
        self._repo = repo
        self._commit = commit
        self._config = config

        architecture_folder = f"arch/{_linux_srcarch(config.architecture)}"
        kbuild_path = self._path(folder, "Kbuild")
        makefile_path = self._path(folder, "Makefile")
        kbuild_contents = self._read_optional(kbuild_path)
        makefile_contents = (
            self._read_optional(makefile_path)
            if folder and (kbuild_contents is None or folder == architecture_folder)
            else None
        )

        if kbuild_contents is not None:
            self._add_makefile(kbuild_path, kbuild_contents, folder)
        elif makefile_contents is not None:
            self._add_makefile(makefile_path, makefile_contents, folder)

        if folder == architecture_folder and makefile_contents is not None:
            self._add_makefile(
                makefile_path,
                makefile_contents,
                "",
                goals=self._ARCHITECTURE_GOALS,
            )

    @staticmethod
    def _path(folder: str, filename: str) -> str:
        return posixpath.join(folder, filename) if folder else filename

    @staticmethod
    def _normalize_path(path: str) -> str:
        normalized = posixpath.normpath(path.removeprefix("./").lstrip("/"))
        return "" if normalized == "." else normalized

    def _read_optional(self, path: str) -> str | None:
        if not path or "$" in path:
            return None
        try:
            return self._repo.read_file(self._commit, path).decode()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None

    def _read_include(self, requested_path: str) -> tuple[str, str | None]:
        path = self._normalize_path(requested_path)
        return path, self._read_optional(path)

    def _variables(self) -> dict[str, str]:
        variables = {
            "src": self.folder,
            "obj": self.folder,
            "srctree": "",
            "objtree": "",
        }
        srcarch = _linux_srcarch(self._config.architecture)
        if srcarch:
            variables["SRCARCH"] = srcarch
        return variables

    def _add_makefile(
        self,
        path: str,
        contents: str,
        record_folder: str,
        *,
        goals: tuple[tuple[str, ConfigValue], ...] | None = None,
    ) -> None:
        makefile = KbuildMakefile(
            contents,
            self._config,
            record_folder,
            variables=self._variables(),
            include_reader=self._read_include,
            source_path=path,
            goals=goals,
        )
        self._makefiles.append(makefile)
        self.source_files.add(path)
        self.source_files.update(makefile.included_files)

    @property
    def exists(self) -> bool:
        return bool(self._makefiles)

    def get(self, file: str) -> ConfigValue | None:
        value: ConfigValue | None = None
        for makefile in self._makefiles:
            candidate = makefile.get(file)
            if candidate is not None:
                value = KbuildMakefile._merge_mode(value, candidate)
        return value

    def includes(self, file: str) -> bool:
        return self.get(file) is not None

    @property
    def directories(self) -> frozenset[str]:
        return frozenset(
            directory
            for makefile in self._makefiles
            for directory in makefile.directories
        )


@dataclass
class KbuildCacheEntry:
    path: str
    parent: Self | None
    rules: KbuildDirectory
    enabled: bool
    children: dict[str, Self]

    def set_enabled(self, new_enabled: bool):
        if self.enabled != new_enabled:
            for child in self.children.values():
                child.set_enabled(new_enabled and self.rules.includes(child.path))

            self.enabled = new_enabled


class ConfigFilter:
    repo: GitRepo
    config: KernelConfig
    base_commit: str

    # mapping from folder to kbuild file inside it
    kbuild_cache: dict[str, KbuildCacheEntry]
    # set of paths which are known to have no makefile and should delegate to parent
    delegated: set[str]
    # whether cross-directory rules in the selected architecture tree are loaded
    _architecture_indexed: bool

    def __init__(self, repo: GitRepo, config: KernelConfig, base_commit: str):
        self.repo = repo
        self.config = config
        self.base_commit = base_commit
        self.kbuild_cache = {}
        self.delegated = set()
        self._architecture_indexed = False

    @classmethod
    def copy(cls, other: Self) -> Self:
        # config, repo, etc don't need to be copied, only cache details
        out = cls(other.repo, other.config, other.base_commit)

        # copy kbuild cache
        out.kbuild_cache = {
            path: KbuildCacheEntry(
                path=entry.path,
                parent=None,
                rules=entry.rules,
                enabled=entry.enabled,
                children={},
            )
            for path, entry in other.kbuild_cache.items()
        }

        # Rebuild links using copied entries so the two cache trees can be
        # mutated independently. KbuildDirectory is immutable during normal
        # cache use, so it is intentionally shared.
        for path, entry in other.kbuild_cache.items():
            copied_entry = out.kbuild_cache[path]
            if entry.parent is not None:
                copied_entry.parent = out.kbuild_cache[entry.parent.path]
            copied_entry.children = {
                child_path: out.kbuild_cache[child_path]
                for child_path in entry.children
            }

        # copy delegated
        out.delegated = set(other.delegated)
        out._architecture_indexed = other._architecture_indexed

        return out

    def _kbuild_cache_add(
        self,
        parent: KbuildCacheEntry | None,
        folder: str,
        rules: KbuildDirectory,
    ) -> KbuildCacheEntry:
        if rules.folder != folder:
            raise ValueError("KbuildDirectory folder does not match cache path")

        if parent is None:
            enabled = True
        else:
            enabled = parent.enabled and parent.rules.includes(folder)

        entry = KbuildCacheEntry(
            path=folder,
            parent=parent,
            rules=rules,
            enabled=enabled,
            children={},
        )

        self.kbuild_cache[folder] = entry
        if parent is not None:
            parent.children[folder] = entry

        return entry

    # returns none if this folder is excluded
    def _kbuild_cache_get(self, folder: str) -> KbuildCacheEntry | None:
        if folder in self.delegated:
            parent = posixpath.dirname(folder)
            return self._kbuild_cache_get(parent)

        entry = self.kbuild_cache.get(folder)
        if entry is None:
            parent_entry = None
            if folder:
                parent_entry = self._kbuild_cache_get(posixpath.dirname(folder))

            rules = KbuildDirectory(
                self.repo,
                self.base_commit,
                self.config,
                folder,
            )
            if not rules.exists:
                if parent_entry is None:
                    return None

                # No local build file: paths in this directory remain owned by
                # the closest ancestor that does have one.
                self.delegated.add(folder)
                return parent_entry

            return self._kbuild_cache_add(parent_entry, folder, rules)
        else:
            return entry

    def _index_architecture_rules(self) -> None:
        """Load the selected architecture's enabled Kbuild subtree.

        Architecture Makefiles sometimes include shared fragments whose
        object paths live elsewhere in the repository.  Loading this small
        subtree makes those cross-directory ownership rules discoverable
        without eagerly walking the entire kernel build tree.
        """

        self._architecture_indexed = True
        srcarch = _linux_srcarch(self.config.architecture)
        if not srcarch:
            return

        pending = [f"arch/{srcarch}"]
        visited: set[str] = set()
        while pending:
            folder = pending.pop()
            if folder in visited:
                continue
            visited.add(folder)

            entry = self._kbuild_cache_get(folder)
            if entry is None or entry.path != folder or not entry.enabled:
                continue
            pending.extend(entry.rules.directories - visited)

    def _get_cached_cross_directory_rule(
        self,
        file: str,
    ) -> ConfigValue | None:
        value: ConfigValue | None = None
        for entry in self.kbuild_cache.values():
            if not entry.enabled:
                continue
            candidate = entry.rules.get(file)
            if candidate is not None:
                value = KbuildMakefile._merge_mode(value, candidate)
        return value

    def get(self, file: str) -> ConfigValue | None:
        if posixpath.dirname(file) == "":
            return None

        parent = posixpath.dirname(file)
        cache_entry = self._kbuild_cache_get(parent)
        value: ConfigValue | None = None
        while cache_entry is not None:
            if cache_entry.enabled:
                candidate = cache_entry.rules.get(file)
                if candidate is not None:
                    value = KbuildMakefile._merge_mode(value, candidate)
            cache_entry = cache_entry.parent

        if value is None:
            if not self._architecture_indexed:
                self._index_architecture_rules()
            value = self._get_cached_cross_directory_rule(file)
        return value

    def _path_included(self, path: str) -> bool:
        # folder in root dir always excluded
        if posixpath.dirname(path) == "":
            return False

        return self.get(path) is not None

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

    def _delete_cache_subtree(
        self,
        path: str,
        *,
        delete_from_parent: bool = True,
    ) -> None:
        cache_entry = self.kbuild_cache.get(path)
        if cache_entry is None:
            return

        del self.kbuild_cache[path]

        if delete_from_parent and cache_entry.parent is not None:
            cache_entry.parent.children.pop(path, None)

        for child in list(cache_entry.children):
            self._delete_cache_subtree(child, delete_from_parent=False)

    @staticmethod
    def _build_file_folder(filename: str) -> str | None:
        parent, child = posixpath.split(filename)

        if child == "Kbuild":
            return parent
        if child == "Makefile" and parent:
            return parent
        return None

    def update_filter_state(self, diff: Diff, new_commit: str):
        """Call for every commit in chain of analyzed commits to keep filter in sync."""

        self.base_commit = new_commit
        changed_paths = {
            path
            for file in diff.files
            for path in (file.file, file.old_file)
            if path is not None
        }
        affected_folders = {
            folder
            for path in changed_paths
            if (folder := self._build_file_folder(path)) is not None
        }

        for folder, entry in self.kbuild_cache.items():
            if changed_paths & entry.rules.source_files:
                affected_folders.add(folder)

        if affected_folders:
            self._architecture_indexed = False

        # Invalidating a parent also invalidates all of its cached descendants.
        # Reload remains lazy, so an untouched part of the tree incurs no reads.
        for folder in sorted(
            affected_folders,
            key=lambda value: (value.count("/"), len(value)),
        ):
            self.delegated.discard(folder)
            self._delete_cache_subtree(folder)
