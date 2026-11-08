from collections.abc import Callable, Generator, Iterable
from dataclasses import dataclass, replace
import re
from typing import ClassVar

from .base import (
    FilterContext,
    FilteredCommit,
    StreamingCommitFilter,
    diff_file_key,
    repository_file_reader,
)
from .input_role_models import SourceRoleStatus
from .source_roles import SourceMaskPlan, publish_source_masks, source_role_decision
from .config_filter import ConfigValue, KernelConfig
from .cpp_expression import evaluate_cpp_expression, parse_cpp_integer
from ..diff import DiffFile, DiffFileType
from .masking import CodeMask, FileIdentity, MaskReason, SourceSide, has_compiler_source_locations, line_ranges, line_macro_locations
from .whitespace.c_lexer import preprocessor_directive_text, replace_c_comments
from .source_modes import regular_source_change
from ..git import GitRepo

C_SOURCE_EXTENSIONS = (
    ".c",
    ".h",
    ".S",
    ".s",
    ".cpp",
    ".hpp",
    ".cc",
    ".cxx",
    ".C",
    ".H",
)


def is_c_source_file(path: str) -> bool:
    return any(path.endswith(ext) for ext in C_SOURCE_EXTENSIONS)


def _symbol_defined(
    symbol: str,
    config: KernelConfig,
    is_module: bool,
) -> bool | None:
    symbol = symbol.strip()
    if symbol.endswith("_MODULE") and symbol[:-7].startswith("CONFIG_"):
        return config.get(symbol[:-7]) == ConfigValue.MODULE

    if symbol.startswith("CONFIG_"):
        val = config.get(symbol)
        if val == ConfigValue.ENABLED:
            return True
        if val == ConfigValue.MODULE:
            # In kernel autoconf.h, CONFIG_FOO=m defines CONFIG_FOO_MODULE, not CONFIG_FOO
            return False
        raw = config.get_raw(symbol)
        return bool(raw)

    if symbol == "__KERNEL__":
        return True
    if symbol in ("__cplusplus",):
        return False
    if symbol == "MODULE":
        return is_module

    architecture_symbols = {
        "__i386__": "CONFIG_X86_32",
        "__x86_64__": "CONFIG_X86_64",
        "__arm__": "CONFIG_ARM",
        "__aarch64__": "CONFIG_ARM64",
    }
    if symbol in architecture_symbols:
        if not config.srcarch:
            return None
        return config.get(architecture_symbols[symbol]) is ConfigValue.ENABLED

    return None


def _evaluate_ifdef(
    symbol: str,
    config: KernelConfig,
    is_module: bool = False,
) -> bool | None:
    return _symbol_defined(symbol, config, is_module)


def evaluate_ifdef(symbol: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate ``#ifdef``, conservatively accepting unknown symbols."""

    return _evaluate_ifdef(symbol, config, is_module) is not False


def _evaluate_ifndef(
    symbol: str,
    config: KernelConfig,
    is_module: bool = False,
) -> bool | None:
    result = _symbol_defined(symbol, config, is_module)
    return None if result is None else not result


def evaluate_ifndef(symbol: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate ``#ifndef``, conservatively accepting unknown symbols."""

    return _evaluate_ifndef(symbol, config, is_module) is not False


def _evaluate_condition(
    expr: str,
    config: KernelConfig,
    is_module: bool = False,
) -> bool | None:
    """Evaluate an expression, returning ``None`` when it is not understood."""
    if len(expr) > 4096:
        return None
    cleaned = replace_c_comments(expr)
    if cleaned is None:
        return None
    expr = cleaned.strip()
    # These kernel predicates model boolean/tristate configuration symbols.
    # Numeric/string options need actual macro expansion, not ConfigValue's
    # generic ENABLED representation for every non-tristate value.
    def _predicate_value(symbol: str) -> ConfigValue | None:
        if symbol.endswith("_MODULE") and symbol[:-7].startswith("CONFIG_"):
            return ConfigValue.ENABLED if config.get(symbol[:-7]) is ConfigValue.MODULE else ConfigValue.DISABLED
        return config.get(symbol) if config.get_raw(symbol) in {"", "y", "m", "n"} else None

    predicates = re.finditer(r"\bIS_(?:ENABLED|BUILTIN|MODULE|REACHABLE)\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)", expr)
    predicate_values = {match[1]: _predicate_value(match[1]) for match in predicates}
    if any(value is None for value in predicate_values.values()):
        return None

    # 2. IS_ENABLED(CONFIG_X)
    expr = re.sub(
        r"\bIS_ENABLED\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: " 1 " if predicate_values[m.group(1)] in (ConfigValue.ENABLED, ConfigValue.MODULE) else " 0 ",
        expr,
    )

    # 3. IS_BUILTIN(CONFIG_X)
    expr = re.sub(
        r"\bIS_BUILTIN\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: " 1 " if predicate_values[m.group(1)] == ConfigValue.ENABLED else " 0 ",
        expr,
    )

    # 4. IS_MODULE(CONFIG_X)
    expr = re.sub(
        r"\bIS_MODULE\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: " 1 " if predicate_values[m.group(1)] == ConfigValue.MODULE else " 0 ",
        expr,
    )

    # 5. IS_REACHABLE(CONFIG_X)
    def _repl_is_reachable(m: re.Match[str]) -> str:
        sym = m.group(1)
        val = predicate_values[sym]
        if is_module:
            return "1" if val in (ConfigValue.ENABLED, ConfigValue.MODULE) else "0"
        return "1" if val == ConfigValue.ENABLED else "0"

    expr = re.sub(r"\bIS_REACHABLE\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)", lambda match: " " + _repl_is_reachable(match) + " ", expr)

    # 6. defined(X) or defined X
    def _repl_defined(m: re.Match[str]) -> str:
        sym = m.group(1) or m.group(2)
        if sym.endswith("_MODULE") and sym[:-7].startswith("CONFIG_"):
            return "1" if config.get(sym[:-7]) == ConfigValue.MODULE else "0"
        if sym.startswith("CONFIG_"):
            val = config.get(sym)
            if val == ConfigValue.ENABLED:
                return "1"
            if val in (ConfigValue.MODULE, ConfigValue.DISABLED):
                return "0"
            raw = config.get_raw(sym)
            return "1" if bool(raw) else "0"
        if sym == "__KERNEL__":
            return "1"
        if sym in ("__cplusplus",):
            return "0"
        if sym == "MODULE":
            return "1" if is_module else "0"
        known = _symbol_defined(sym, config, is_module)
        if known is None:
            return "__KPATCH_UNKNOWN_SYMBOL"
        return "1" if known else "0"

    expr = re.sub(r"\bdefined\s*\(\s*([A-Za-z0-9_]+)\s*\)|\bdefined\s+([A-Za-z0-9_]+)", lambda match: " " + _repl_defined(match) + " ", expr)

    # 7. Unadorned CONFIG_X identifiers
    def _repl_config_ident(m: re.Match[str]) -> str:
        sym = m.group(0)
        if sym.endswith("_MODULE") and sym[:-7].startswith("CONFIG_"):
            return "1" if config.get(sym[:-7]) is ConfigValue.MODULE else "0"
        raw = config.get_raw(sym)
        if raw == "y":
            return "1"
        if raw in {"", "m", "n"}:
            return "0"
        # Keep macro token boundaries when a signed constant is substituted:
        # -CONFIG_NEGATIVE must become - -1, never a newly lexed --1 token.
        return " " + raw + " " if parse_cpp_integer(raw) is not None else "__KPATCH_UNKNOWN_SYMBOL"

    expr = re.sub(r"\bCONFIG_[A-Za-z0-9_]+\b", _repl_config_ident, expr)

    value = evaluate_cpp_expression(expr.strip())
    return value.value != 0 if value is not None else None


def evaluate_condition(expr: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate ``#if``, conservatively accepting unknown expressions."""

    return _evaluate_condition(expr, config, is_module) is not False


@dataclass(slots=True)
class _Conditional:
    parent_active: bool
    # True only when a previous branch is known to have been selected.
    branch_taken: bool
    active: bool
    has_else: bool = False


_DIRECTIVE_RE = re.compile(r"^\s*(?:#|%:)\s*([A-Za-z_][A-Za-z_0-9]*)\b(.*)$")
_NONSTANDARD_LAYOUT = re.compile(r"\r(?!\n)|[\v\f\x1c-\x1e\x85\u2028\u2029\ufeff\0]|\\[ \t]+\r?\n")
_MODELED_PREDICATES = frozenset({"IS_ENABLED", "IS_BUILTIN", "IS_MODULE", "IS_REACHABLE"})


@dataclass(frozen=True, slots=True)
class _LogicalLine:
    text: str
    first_line: int
    stop_line: int

    def physical_lines(self) -> range:
        return range(self.first_line, self.stop_line)


def _logical_lines(content: str) -> tuple[_LogicalLine, ...] | None:
    """Keep original line coordinates through phase-two splicing/comments."""
    if _NONSTANDARD_LAYOUT.search(content):
        return None
    normalized = preprocessor_directive_text(content, strict_multiline=True)
    if normalized is None:
        return None
    logical = iter(normalized.splitlines())
    result: list[_LogicalLine] = []
    first = 1
    for number, physical in enumerate(content.splitlines(keepends=True), 1):
        if physical.endswith(("\\\n", "\\\r\n")):
            continue
        text = next(logical, None)
        if text is None:
            return None
        result.append(_LogicalLine(text, first, number + 1))
        first = number + 1
    if next(logical, None) is not None:
        return None
    # A terminal backslash-newline is not a complete logical line. Retain it
    # instead of silently losing its physical coordinates.
    if first <= len(content.splitlines()):
        return None
    return tuple(result)


def _overrides_modeled_symbol(rest: str, config: KernelConfig, is_module: bool) -> bool:
    match = re.match(r"\s*([A-Za-z_][A-Za-z_0-9]*)", rest)
    return match is not None and (
        match[1] in _MODELED_PREDICATES
        or _symbol_defined(match[1], config, is_module) is not None
    )


def get_active_lines(content: str, config: KernelConfig, is_module: bool = False) -> set[int]:
    """Return possibly active physical CPP lines, retaining unsupported state."""
    all_lines = set(range(1, len(content.splitlines()) + 1))
    logical = _logical_lines(content)
    if logical is None:
        return all_lines
    active_lines: set[int] = set()
    stack: list[_Conditional] = []
    for line in logical:
        parent_active = stack[-1].active if stack else True
        match = _DIRECTIVE_RE.match(line.text)
        if match is None:
            if parent_active:
                active_lines.update(line.physical_lines())
            continue
        directive, rest = match[1], match[2].strip()
        if directive in {"define", "undef"} and parent_active and _overrides_modeled_symbol(rest, config, is_module):
            # Captured config no longer represents this source environment.
            # Macro expansion and local state updates need a real CPP context.
            return all_lines
        if directive in ("if", "ifdef", "ifndef"):
            if directive != "if" and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", rest) is None:
                result = None
            elif directive == "ifdef":
                result = _evaluate_ifdef(rest, config, is_module) if parent_active else False
            elif directive == "ifndef":
                result = _evaluate_ifndef(rest, config, is_module) if parent_active else False
            else:  # if
                result = _evaluate_condition(rest, config, is_module) if parent_active else False

            stack.append(
                _Conditional(
                    parent_active=parent_active,
                    branch_taken=result is True,
                    active=parent_active and result is not False,
                )
            )
            if parent_active:
                active_lines.update(line.physical_lines())

        elif directive == "elif":
            if not stack or stack[-1].has_else:
                return all_lines
            frame = stack[-1]
            result = _evaluate_condition(rest, config, is_module) if frame.parent_active and not frame.branch_taken else False
            frame.active = frame.parent_active and not frame.branch_taken and result is not False
            frame.branch_taken = frame.branch_taken or result is True
            if frame.parent_active:
                active_lines.update(line.physical_lines())

        elif directive == "else":
            if not stack or stack[-1].has_else or rest:
                return all_lines
            frame = stack[-1]
            frame.active = frame.parent_active and not frame.branch_taken
            frame.branch_taken = frame.has_else = True
            if frame.parent_active:
                active_lines.update(line.physical_lines())

        elif directive == "endif":
            if not stack or rest:
                return all_lines
            frame = stack.pop()
            if frame.parent_active:
                active_lines.update(line.physical_lines())
        elif directive in {"elifdef", "elifndef"}:
            return all_lines
        elif parent_active:
            active_lines.update(line.physical_lines())
    return all_lines if stack else active_lines


def diff_file_touches_active_code(
    repo: GitRepo,
    parent_commit: str | None,
    current_commit: str,
    diff_file: DiffFile,
    config: KernelConfig,
    is_module: bool = False,
    check_old: bool = True,
    check_new: bool = True,
    read_file: Callable[[str, str], bytes] | None = None,
) -> bool:
    """Determine whether any changed line in `diff_file` touches an active portion of the file."""
    read = read_file or repo.read_file
    if not diff_file.chunks:
        if diff_file.change_type is DiffFileType.NEW:
            return check_new
        if diff_file.change_type is DiffFileType.DELETE:
            return check_old
        if diff_file.change_type is DiffFileType.RENAME:
            return check_old or check_new
        if diff_file.change_type is DiffFileType.COPY:
            return check_new
        return False

    # For non-C files, we treat any change as active if the file is built
    if not is_c_source_file(diff_file.file) and (
        diff_file.old_file is None or not is_c_source_file(diff_file.old_file)
    ):
        return check_old or check_new

    old_touched: list[int] = []
    new_touched: list[int] = []

    for chunk in diff_file.chunks:
        old_line = chunk.old_start
        new_line = chunk.new_start
        for raw_line in chunk.lines:
            if raw_line.startswith("-"):
                old_touched.append(old_line)
                old_line += 1
            elif raw_line.startswith("+"):
                new_touched.append(new_line)
                new_line += 1
            elif raw_line.startswith(" "):
                old_line += 1
                new_line += 1

    if diff_file.change_type == DiffFileType.NEW:
        if not check_new or not new_touched:
            return False
        try:
            new_bytes = read(current_commit, diff_file.file)
            new_active = get_active_lines(
                new_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            return any(line in new_active for line in new_touched)
        except Exception:
            return True

    if diff_file.change_type == DiffFileType.DELETE:
        if not check_old or not old_touched:
            return False
        if parent_commit is None:
            return True
        try:
            old_path = diff_file.old_file or diff_file.file
            old_bytes = read(parent_commit, old_path)
            old_active = get_active_lines(
                old_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            return any(line in old_active for line in old_touched)
        except Exception:
            return True

    # For DEFAULT, RENAME, COPY: check new additions and old deletions
    if not new_touched and not old_touched:
        return False

    if check_new and new_touched:
        try:
            new_bytes = read(current_commit, diff_file.file)
            new_active = get_active_lines(
                new_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            if any(line in new_active for line in new_touched):
                return True
        except Exception:
            return True

    if check_old and old_touched:
        if parent_commit is None:
            return True
        try:
            old_path = diff_file.old_file or diff_file.file
            old_bytes = read(parent_commit, old_path)
            old_active = get_active_lines(
                old_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            if any(line in old_active for line in old_touched):
                return True
        except Exception:
            return True

    return False


def _active_lines_for_modes(
    content: str,
    config: KernelConfig,
    modes: tuple[bool, ...],
) -> set[int]:
    active: set[int] = set()
    for is_module in modes:
        active.update(get_active_lines(content, config, is_module=is_module))
    return active


@dataclass(frozen=True, slots=True)
class _SourceActivity:
    active: set[int]
    line_count: int
    whole_inactive: bool = False
    line_macros: tuple[int, ...] = ()
    has_counter: bool = False


class IfdefFilter(StreamingCommitFilter):
    """Remove changed lines disabled by C preprocessor conditionals."""

    name: ClassVar[str] = "Filtering preprocessor branches"

    def __init__(self, config: KernelConfig):
        self.config = config
        self._read_file: Callable[[str, str], bytes] | None = None

    @staticmethod
    def _modes(value: str | None) -> tuple[bool, ...]:
        if value is None:
            return ()
        return (value == ConfigValue.MODULE,)

    def _active_side(
        self,
        context: FilterContext,
        commit_id: str | None,
        path: str,
        modes: tuple[bool, ...],
    ) -> _SourceActivity | None:
        if not modes:
            return _SourceActivity(set(), 0, True)
        if commit_id is None:
            return None
        read_file = self._read_file or context.repo.read_file
        try:
            raw = read_file(commit_id, path)
            content = raw.decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            return None
        if re.search(r"\r(?!\n)|[\v\f\x1c-\x1e\x85\u2028\u2029]", content):
            return None
        locations = line_macro_locations(raw) if b"__LINE__" in raw else ()
        return _SourceActivity(_active_lines_for_modes(content, self.config, modes), len(content.splitlines()),
                               line_macros=locations, has_counter=b"__COUNTER__" in raw or has_compiler_source_locations(raw))

    def _filter_file(
        self,
        commit: FilteredCommit,
        context: FilterContext,
        diff_file: DiffFile,
    ) -> bool:
        if not is_c_source_file(diff_file.file) and (
            diff_file.old_file is None
            or not is_c_source_file(diff_file.old_file)
        ):
            return True
        if diff_file.binary:
            return True
        if diff_file.change_type in (DiffFileType.RENAME, DiffFileType.COPY):
            return True

        modes = commit.build_modes.get(diff_file_key(diff_file))
        if modes is None or not modes.complete:
            # Inclusion strength does not establish an exclusive MODULE mode
            # or a closed preprocessor environment for an uncertain input.
            return True
        old_modes: tuple[bool, ...]
        new_modes: tuple[bool, ...]
        if modes is None:
            old_modes = new_modes = (False, True)
        else:
            old_modes = self._modes(modes.old)
            new_modes = self._modes(modes.new)

        parent_id = (
            commit.original.parent.commit_id
            if commit.original.parent is not None
            else None
        )
        old_path = diff_file.old_file or diff_file.file
        if not regular_source_change(diff_file, context.repo, parent_id, commit.original.commit_id):
            return True
        old_active = self._active_side(
            context,
            parent_id,
            old_path,
            old_modes,
        )
        new_active = self._active_side(
            context,
            commit.original.commit_id,
            diff_file.file,
            new_modes,
        )
        if old_active is None or new_active is None:
            return True
        if old_active.line_macros != new_active.line_macros or old_active.has_counter or new_active.has_counter:
            return True

        old_inactive = line_ranges(number for number in range(1, old_active.line_count + 1)
                                   if number not in old_active.active)
        new_inactive = line_ranges(number for number in range(1, new_active.line_count + 1)
                                   if number not in new_active.active)
        if not (old_inactive or new_inactive or old_active.whole_inactive or new_active.whole_inactive):
            return True
        roles = source_role_decision(commit, diff_file, context)
        if roles.status is SourceRoleStatus.BLOCKED:
            return True
        identity = FileIdentity.of(diff_file)
        codes = (CodeMask(identity, SourceSide.OLD, MaskReason.IFDEF, old_inactive, old_active.whole_inactive),
                 CodeMask(identity, SourceSide.NEW, MaskReason.IFDEF, new_inactive, new_active.whole_inactive))
        publish_source_masks(commit, context, SourceMaskPlan((roles,), code_masks=codes))
        return True

    def filter_mutable_commit(
        self, commit: FilteredCommit, context: FilterContext,
    ) -> FilteredCommit | None:
        for diff_file in commit.diff.files:
            self._filter_file(commit, context, diff_file)
        return commit if commit.diff.files else None

    def iter_filter_mutable_commits(
        self,
        commits: Iterable[FilteredCommit],
        context: FilterContext,
        show_progress: bool = True,
        *,
        total: int | None = None,
    ) -> Generator[FilteredCommit, None, None]:
        with repository_file_reader(context) as reader:
            self._read_file = reader.read_file
            try:
                yield from super().iter_filter_mutable_commits(
                    commits,
                    replace(context, file_reader=reader),
                    show_progress=show_progress,
                    total=total,
                )
            finally:
                self._read_file = None
