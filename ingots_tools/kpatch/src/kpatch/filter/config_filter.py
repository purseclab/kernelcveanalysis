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
from .source_filter import SourceIncludeIndex


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

    @property
    def srcarch(self) -> str:
        """Return the Linux ``SRCARCH`` name selected by this config."""

        return _linux_srcarch(self.architecture)


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
    _rule_re = re.compile(r"^(?P<targets>[^:=]+?)\s*:(?!=)\s*(?P<deps>.*)$")

    _DEFAULT_GOALS = (
        ("obj-y", ConfigValue.ENABLED),
        ("obj-m", ConfigValue.MODULE),
        ("lib-y", ConfigValue.ENABLED),
        # Kbuild folds both lib-y and lib-m into the directory's lib.a.
        ("lib-m", ConfigValue.ENABLED),
    )
    _BUILD_DEPENDENCY_EXTENSIONS = {
        ".S",
        ".a",
        ".bin",
        ".c",
        ".dbg",
        ".lds",
        ".o",
        ".raw",
        ".so",
    }

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
        extra_goals: Mapping[str, ConfigValue] | None = None,
    ):
        self._config: KernelConfig = config
        self.folder: str = folder
        self._variables: dict[str, str] = dict(variables or {})
        self._simple_variables: set[str] = set(self._variables)
        self._included: dict[str, ConfigValue] = {}
        self._directories: set[str] = set()
        self._dependencies: dict[str, list[str]] = {}
        self._pattern_dependencies: list[tuple[str, list[str]]] = []
        self._external_goals: dict[str, dict[str, ConfigValue]] = {}
        self.included_files: set[str] = set()
        self._include_reader = include_reader
        self._goals = self._DEFAULT_GOALS if goals is None else goals

        include_stack = {source_path} if source_path is not None else set()
        self._parse(contents, include_stack)
        self._collect_goals()
        for goal, mode in (extra_goals or {}).items():
            self._add_goal(goal, mode, set())

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
        if separator:
            fields = self._expand(arguments, seen).split(",", 2)
            if function == "subst" and len(fields) == 3:
                old, new, value = fields
                return value.replace(old, new)
            if function == "patsubst" and len(fields) == 3:
                pattern, replacement, value = fields
                return " ".join(
                    self._replace_make_pattern(word, pattern, replacement)
                    for word in value.split()
                    if self._make_pattern_stem(word, pattern) is not None
                )
            if function in ("addprefix", "addsuffix") and len(fields) >= 2:
                affix, value = fields[0], ",".join(fields[1:])
                return " ".join(
                    f"{affix}{word}"
                    if function == "addprefix"
                    else f"{word}{affix}"
                    for word in value.split()
                )
            if function in ("filter", "filter-out") and len(fields) >= 2:
                patterns = fields[0].split()
                words = ",".join(fields[1:]).split()
                return " ".join(
                    word
                    for word in words
                    if any(
                        self._make_pattern_stem(word, pattern) is not None
                        for pattern in patterns
                    )
                    == (function == "filter")
                )
            if function == "if" and len(fields) >= 2:
                condition, when_true = fields[:2]
                when_false = fields[2] if len(fields) == 3 else ""
                return when_true if condition.strip() else when_false

        if name in seen:
            return ""
        value = self._variables.get(name, "")
        if name in self._simple_variables:
            return value
        return self._expand(value, seen | {name})

    @staticmethod
    def _make_pattern_stem(value: str, pattern: str) -> str | None:
        if "%" not in pattern:
            return "" if value == pattern else None
        prefix, suffix = pattern.split("%", 1)
        if not value.startswith(prefix) or not value.endswith(suffix):
            return None
        end = len(value) - len(suffix) if suffix else len(value)
        return value[len(prefix) : end]

    @classmethod
    def _replace_make_pattern(
        cls,
        value: str,
        pattern: str,
        replacement: str,
    ) -> str:
        stem = cls._make_pattern_stem(value, pattern)
        if stem is None:
            return value
        return replacement.replace("%", stem, 1)

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
        define_depth = 0
        recipe_context = False

        for logical_line in self._logical_lines(contents):
            line = self._strip_comment(logical_line).strip()
            if not line:
                continue

            if re.match(r"^(?:override\s+)?define(?:\s|$)", line):
                define_depth += 1
                recipe_context = False
                continue
            if line == "endef":
                define_depth = max(define_depth - 1, 0)
                continue
            if define_depth:
                continue

            directive_parts = line.split(None, 1)
            directive = directive_parts[0]
            expression = directive_parts[1] if len(directive_parts) == 2 else ""
            conditional_directives = {
                "ifdef",
                "ifndef",
                "ifeq",
                "ifneq",
                "else",
                "endif",
            }
            if logical_line.startswith("\t") and recipe_context:
                continue
            if (
                not logical_line.startswith("\t")
                and directive not in conditional_directives
            ):
                recipe_context = False

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
                continue

            rule_match = self._rule_re.match(line)
            if rule_match is not None:
                recipe_context = True
                targets = self._expand(rule_match.group("targets")).split()
                dependency_expression = self._expand(rule_match.group("deps"))
                static_pattern, static_separator, static_dependencies = (
                    dependency_expression.partition(":")
                )
                is_static_pattern = bool(static_separator) and "%" in static_pattern
                dependencies = (
                    static_dependencies if is_static_pattern else dependency_expression
                ).split()
                for target in targets:
                    repository_target = self._repository_expression(target)
                    target_dependencies = dependencies
                    if is_static_pattern:
                        stem = self._make_pattern_stem(
                            repository_target, static_pattern.strip()
                        )
                        if stem is None:
                            continue
                        target_dependencies = [
                            dependency.replace("%", stem, 1)
                            for dependency in dependencies
                        ]
                    repository_dependencies = [
                        self._repository_expression(dependency)
                        for dependency in target_dependencies
                    ]
                    if "%" in repository_target and not is_static_pattern:
                        self._pattern_dependencies.append(
                            (repository_target, repository_dependencies)
                        )
                    else:
                        self._dependencies.setdefault(
                            posixpath.normpath(repository_target), []
                        ).extend(repository_dependencies)

    @staticmethod
    def _merge_mode(
        current: ConfigValue | None, new: ConfigValue
    ) -> ConfigValue:
        if current is ConfigValue.ENABLED or new is ConfigValue.ENABLED:
            return ConfigValue.ENABLED
        return ConfigValue.MODULE

    def _repository_expression(self, path: str) -> str:
        is_root_relative = path.startswith("/")
        relative_path = path.removeprefix("./").lstrip("/").rstrip("/")
        if not relative_path:
            return ""
        if (
            not is_root_relative
            and self.folder
            and relative_path != self.folder
            and not relative_path.startswith(f"{self.folder}/")
        ):
            relative_path = posixpath.join(self.folder, relative_path)
        return relative_path

    def _repository_path(self, path: str) -> str:
        expression = self._repository_expression(path)
        return posixpath.normpath(expression) if expression else ""

    def _record(self, path: str, mode: ConfigValue) -> None:
        is_directory = path.endswith("/")
        absolute_path = self._repository_path(path)
        if absolute_path:
            self._included[absolute_path] = self._merge_mode(
                self._included.get(absolute_path), mode
            )
            if is_directory:
                self._directories.add(absolute_path)

    def _record_external_goal(self, path: str, mode: ConfigValue) -> None:
        repository_path = self._repository_path(path)
        folder = posixpath.dirname(repository_path)
        if not folder or folder == self.folder:
            return

        folders = [folder]
        prefix = f"{self.folder}/" if self.folder else ""
        if folder.startswith(prefix):
            components = folder[len(prefix) :].split("/")
            folders = [
                posixpath.join(self.folder, *components[:index])
                for index in range(1, len(components) + 1)
            ]

        for ancestor in folders:
            goals = self._external_goals.setdefault(ancestor, {})
            goals[repository_path] = self._merge_mode(
                goals.get(repository_path), mode
            )
            self._included[ancestor] = self._merge_mode(
                self._included.get(ancestor), mode
            )
            self._directories.add(ancestor)

    def _tokens(self, variable: str) -> list[str]:
        return self._expand(self._variables.get(variable, "")).split()

    def _is_build_dependency(self, dependency: str) -> bool:
        """Whether a prerequisite replaces an object's implicit source.

        Kbuild commonly adds ``FORCE`` and header prerequisites to an object
        while still compiling its matching source through the implicit rule.
        Generated objects and linker inputs, on the other hand, describe the
        actual source chain and must be followed.
        """

        repository_dependency = self._repository_path(dependency)
        if (
            not repository_dependency
            or posixpath.basename(repository_dependency) == "FORCE"
        ):
            return False
        if repository_dependency in self._dependencies:
            return True
        if any(
            self._make_pattern_stem(repository_dependency, pattern) is not None
            for pattern, _ in self._pattern_dependencies
        ):
            return True
        return posixpath.splitext(repository_dependency)[1] in (
            self._BUILD_DEPENDENCY_EXTENSIONS
        )

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

        repository_goal = self._repository_path(goal)
        dependencies = self._dependencies.get(repository_goal)
        if dependencies is None:
            repository_expression = self._repository_expression(goal)
            for target_pattern, pattern_dependencies in self._pattern_dependencies:
                stem = self._make_pattern_stem(
                    repository_expression, target_pattern
                )
                if stem is not None:
                    dependencies = [
                        dependency.replace("%", stem, 1)
                        for dependency in pattern_dependencies
                    ]
                    break

        build_dependencies = (
            [
                dependency
                for dependency in dependencies
                if self._is_build_dependency(dependency)
            ]
            if dependencies is not None
            else None
        )
        if build_dependencies:
            key = (repository_goal, mode)
            if key in resolving:
                return
            resolving.add(key)
            for dependency in build_dependencies:
                self._add_goal(dependency, mode, resolving)
            resolving.remove(key)
            return

        if goal.endswith((".c", ".S")):
            self._record(goal, mode)
            return
        if goal.endswith(".lds"):
            self._record(f"{goal}.S", mode)
            return
        if not goal.endswith(".o"):
            self._record_external_goal(goal, mode)
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
        direct = self._included.get(normalized)
        root, extension = posixpath.splitext(normalized)
        if extension in CODE_FILES:
            normalized = f"{root}.o"
        value = self._included.get(normalized)
        if direct is None:
            return value
        if value is None:
            return direct
        return self._merge_mode(direct, value)

    def includes(self, file: str) -> bool:
        value = self.get(file)
        return value is not None and value != ConfigValue.DISABLED

    @property
    def directories(self) -> frozenset[str]:
        return frozenset(self._directories)

    def goals_for(self, folder: str) -> Mapping[str, ConfigValue]:
        return self._external_goals.get(folder, {})


class KbuildDirectory:
    """Resolved Kbuild rules for one repository directory.

    Ordinary directories use ``Kbuild`` when present and otherwise fall back
    to ``Makefile``.  The repository root uses ``Kbuild`` for its ordinary
    objects and the selected architecture ``Makefile`` for the global
    ``core-y``, ``drivers-y``, and ``libs-y`` directory lists.
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
        extra_goals: Mapping[str, ConfigValue] | None = None,
        read_file: Callable[[str, str], bytes] | None = None,
    ):
        self.folder = folder
        self.source_files: set[str] = set()
        self._makefiles: list[KbuildMakefile] = []
        self._repo = repo
        self._read_file = read_file or repo.read_file
        self._commit = commit
        self._config = config

        kbuild_path = self._path(folder, "Kbuild")
        makefile_path = self._path(folder, "Makefile")
        architecture_folder = f"arch/{config.srcarch}" if config.srcarch else None
        kbuild_contents = self._read_optional(kbuild_path)
        makefile_contents = (
            self._read_optional(makefile_path)
            if folder
            and (kbuild_contents is None or folder == architecture_folder)
            else None
        )

        if kbuild_contents is not None:
            self._add_makefile(
                kbuild_path,
                kbuild_contents,
                folder,
                extra_goals=extra_goals,
            )
        elif makefile_contents is not None:
            self._add_makefile(
                makefile_path,
                makefile_contents,
                folder,
                extra_goals=extra_goals,
            )

        if folder == "" and kbuild_contents is not None:
            # These values are initialized by the top-level Makefile before it
            # includes the architecture Makefile.  Parsing that very large
            # Makefile is unnecessary for the small declarative subset used
            # here, but the initial values are significant (notably lib/).
            architecture_path = (
                self._path(f"arch/{config.srcarch}", "Makefile")
                if config.srcarch
                else "Makefile"
            )
            architecture_contents = (
                self._read_optional(architecture_path)
                if config.srcarch
                else None
            )
            self._add_makefile(
                architecture_path,
                architecture_contents or "",
                "",
                goals=self._ARCHITECTURE_GOALS,
                variables={
                    "core-y": "",
                    "drivers-y": "",
                    "drivers-m": "",
                    "libs-y": "lib/",
                },
            )
            # A change to the initial global lists should invalidate the root
            # rules even though we intentionally do not parse this file.
            self.source_files.add("Makefile")

        if folder == architecture_folder and makefile_contents is not None:
            # Keep these rules on the architecture cache node as well.  Paths
            # such as arch/arm64/lib are direct global goals even though the
            # intermediate arch/arm64 Kbuild does not descend into lib/.
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
            return self._read_file(self._commit, path).decode()
        except (FileNotFoundError, subprocess.CalledProcessError):
            return None

    def _read_include(self, requested_path: str) -> tuple[str, str | None]:
        if requested_path.startswith(("./", "../")):
            requested_path = posixpath.join(self.folder, requested_path)
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
        variables: Mapping[str, str] | None = None,
        extra_goals: Mapping[str, ConfigValue] | None = None,
    ) -> None:
        make_variables = self._variables()
        make_variables.update(variables or {})
        makefile = KbuildMakefile(
            contents,
            self._config,
            record_folder,
            variables=make_variables,
            include_reader=self._read_include,
            source_path=path,
            goals=goals,
            extra_goals=extra_goals,
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

    def goals_for(self, folder: str) -> dict[str, ConfigValue]:
        goals: dict[str, ConfigValue] = {}
        for makefile in self._makefiles:
            for goal, mode in makefile.goals_for(folder).items():
                goals[goal] = KbuildMakefile._merge_mode(goals.get(goal), mode)
        return goals


@dataclass
class KbuildCacheEntry:
    path: str
    parent: Self | None
    rules: KbuildDirectory
    mode: ConfigValue | None
    children: dict[str, Self]

    @property
    def enabled(self) -> bool:
        return self.mode is not None

    def resolve(self, local_mode: ConfigValue | None) -> ConfigValue | None:
        if self.mode is None or local_mode is None:
            return None
        if self.mode is ConfigValue.MODULE:
            return ConfigValue.MODULE
        return local_mode


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

    # Possible C preprocessor include edges shared by every branch state.
    source_includes: SourceIncludeIndex | None

    def __init__(
        self,
        repo: GitRepo,
        config: KernelConfig,
        base_commit: str,
        source_includes: SourceIncludeIndex | None = None,
        read_file: Callable[[str, str], bytes] | None = None,
    ):
        self.repo = repo
        self.config = config
        self.base_commit = base_commit
        self.source_includes = source_includes
        self._read_file = read_file or repo.read_file
        self.kbuild_cache = {}
        self.delegated = set()
        self._architecture_indexed = False
        self._active_includes_cache: dict[
            tuple[str, ConfigValue], frozenset[str]
        ] = {}
        self._include_value_cache: dict[str, ConfigValue | None] = {}

    @classmethod
    def copy(cls, other: Self) -> Self:
        # config, repo, etc don't need to be copied, only cache details
        out = cls(
            other.repo,
            other.config,
            other.base_commit,
            other.source_includes,
            other._read_file,
        )

        # copy kbuild cache
        out.kbuild_cache = {
            path: KbuildCacheEntry(
                path=entry.path,
                parent=None,
                rules=entry.rules,
                mode=entry.mode,
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
        out._active_includes_cache = dict(other._active_includes_cache)
        out._include_value_cache = dict(other._include_value_cache)

        return out

    def _kbuild_cache_add(
        self,
        parent: KbuildCacheEntry | None,
        folder: str,
        rules: KbuildDirectory,
    ) -> KbuildCacheEntry:
        if rules.folder != folder:
            raise ValueError("KbuildDirectory folder does not match cache path")

        mode: ConfigValue | None
        if parent is None:
            mode = ConfigValue.ENABLED
        else:
            mode = parent.resolve(parent.rules.get(folder))

        entry = KbuildCacheEntry(
            path=folder,
            parent=parent,
            rules=rules,
            mode=mode,
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
                (
                    parent_entry.rules.goals_for(folder)
                    if parent_entry is not None
                    else None
                ),
                self._read_file,
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
            candidate = entry.resolve(entry.rules.get(file))
            if candidate is not None:
                value = KbuildMakefile._merge_mode(value, candidate)
        return value

    def _get_kbuild(self, file: str) -> ConfigValue | None:
        if posixpath.dirname(file) == "":
            return None

        parent = posixpath.dirname(file)
        cache_entry = self._kbuild_cache_get(parent)
        value: ConfigValue | None = None
        while cache_entry is not None:
            if cache_entry.enabled:
                candidate = cache_entry.resolve(cache_entry.rules.get(file))
                if candidate is not None:
                    value = KbuildMakefile._merge_mode(value, candidate)
            cache_entry = cache_entry.parent

        if value is None:
            if not self._architecture_indexed:
                self._index_architecture_rules()
            value = self._get_cached_cross_directory_rule(file)
        return value

    def _active_source_includes(
        self,
        source: str,
        mode: ConfigValue,
    ) -> frozenset[str]:
        key = (source, mode)
        cached = self._active_includes_cache.get(key)
        if cached is not None:
            return cached

        assert self.source_includes is not None
        result: frozenset[str]
        try:
            contents = self._read_file(self.base_commit, source).decode(
                "utf-8", errors="replace"
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            result = frozenset()
        else:
            # Import lazily because ifdef_filter imports KernelConfig from this
            # module.  Candidate edges are validated against the exact commit.
            from .ifdef_filter import get_active_lines

            active_lines = get_active_lines(
                contents,
                self.config,
                is_module=mode is ConfigValue.MODULE,
            )
            result = frozenset(
                target
                for line_number, line in enumerate(
                    contents.splitlines(), start=1
                )
                if line_number in active_lines
                if (
                    target := self.source_includes.target_from_line(source, line)
                )
                is not None
            )

        self._active_includes_cache[key] = result
        return result

    def _get_with_includes(
        self,
        file: str,
        resolving: set[str],
    ) -> ConfigValue | None:
        if file in self._include_value_cache:
            return self._include_value_cache[file]
        if file in resolving:
            return None

        value = self._get_kbuild(file)
        if self.source_includes is not None and value is not ConfigValue.ENABLED:
            resolving.add(file)
            for source in self.source_includes.includers(file):
                source_mode = self._get_with_includes(source, resolving)
                if source_mode is None:
                    continue
                if file not in self._active_source_includes(source, source_mode):
                    continue
                value = KbuildMakefile._merge_mode(value, source_mode)
                if value is ConfigValue.ENABLED:
                    break
            resolving.remove(file)

        self._include_value_cache[file] = value
        return value

    def get(self, file: str) -> ConfigValue | None:
        return self._get_with_includes(file, set())

    def read_file(self, commit: str, path: str) -> bytes:
        return self._read_file(commit, path)

    def _path_included(self, path: str) -> bool:
        # folder in root dir always excluded
        if posixpath.dirname(path) == "":
            return False

        return self.get(path) is not None

    def file_included(self, file: str) -> bool:
        extension = posixpath.splitext(file)[-1]

        if extension in CODE_FILES or extension in HEADER_FILES:
            return self._path_included(file)
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
        if child == "Makefile":
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
        for key in list(self._active_includes_cache):
            if key[0] in changed_paths:
                del self._active_includes_cache[key]
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
            self._include_value_cache.clear()
        elif self.source_includes is not None:
            for path in self.source_includes.transitive_targets(changed_paths):
                self._include_value_cache.pop(path, None)

        # Invalidating a parent also invalidates all of its cached descendants.
        # Reload remains lazy, so an untouched part of the tree incurs no reads.
        for folder in sorted(
            affected_folders,
            key=lambda value: (value.count("/"), len(value)),
        ):
            self.delegated.discard(folder)
            self._delete_cache_subtree(folder)
