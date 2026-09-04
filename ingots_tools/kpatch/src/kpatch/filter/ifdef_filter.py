import ast
from dataclasses import dataclass
import operator as op
import re

from typing import Any, Callable

from .config_filter import ConfigValue, KernelConfig
from ..diff import DiffFile, DiffFileType
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


_SAFE_OPERATORS: dict[type, Callable[..., Any]] = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.FloorDiv: op.floordiv,
    ast.Mod: op.mod,
    ast.BitAnd: op.and_,
    ast.BitOr: op.or_,
    ast.BitXor: op.xor,
    ast.LShift: op.lshift,
    ast.RShift: op.rshift,
    ast.Eq: op.eq,
    ast.NotEq: op.ne,
    ast.Lt: op.lt,
    ast.LtE: op.le,
    ast.Gt: op.gt,
    ast.GtE: op.ge,
    ast.And: lambda a, b: a and b,
    ast.Or: lambda a, b: a or b,
    ast.Not: op.not_,
    ast.Invert: op.invert,
    ast.UAdd: op.pos,
    ast.USub: op.neg,
}


def _eval_ast(node: ast.AST) -> int:
    if isinstance(node, ast.Expression):
        return _eval_ast(node.body)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, (int, bool)):
            return int(node.value)
        return int(bool(node.value))
    elif isinstance(node, ast.UnaryOp):
        oper = _SAFE_OPERATORS.get(type(node.op))
        if oper is None:
            raise ValueError(f"Unsupported unary operator: {type(node.op)}")
        res = oper(_eval_ast(node.operand))
        return int(res) if isinstance(res, bool) else int(res)
    elif isinstance(node, ast.BinOp):
        oper = _SAFE_OPERATORS.get(type(node.op))
        if oper is None:
            raise ValueError(f"Unsupported binary operator: {type(node.op)}")
        left = _eval_ast(node.left)
        right = _eval_ast(node.right)
        return int(oper(left, right))
    elif isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            for val in node.values:
                if not _eval_ast(val):
                    return 0
            return 1
        elif isinstance(node.op, ast.Or):
            for val in node.values:
                if _eval_ast(val):
                    return 1
            return 0
    elif isinstance(node, ast.Compare):
        left = _eval_ast(node.left)
        for oper_node, comparator in zip(node.ops, node.comparators):
            oper = _SAFE_OPERATORS.get(type(oper_node))
            if oper is None:
                raise ValueError(f"Unsupported compare operator: {type(oper_node)}")
            right = _eval_ast(comparator)
            if not oper(left, right):
                return 0
            left = right
        return 1
    elif isinstance(node, ast.Name):
        return 1 if node.id == "True" else 0
    raise ValueError(f"Unsupported AST node: {type(node)}")


def evaluate_ifdef(symbol: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate an `#ifdef <symbol>` directive."""
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

    # Conservative fallback for unknown non-config symbols (e.g. DEBUG, architecture symbols)
    return True


def evaluate_ifndef(symbol: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate an `#ifndef <symbol>` directive."""
    symbol = symbol.strip()
    if symbol.endswith("_MODULE") and symbol[:-7].startswith("CONFIG_"):
        return config.get(symbol[:-7]) != ConfigValue.MODULE

    if symbol.startswith("CONFIG_"):
        val = config.get(symbol)
        if val == ConfigValue.ENABLED:
            return False
        if val == ConfigValue.MODULE:
            return True
        raw = config.get_raw(symbol)
        return not bool(raw)

    if symbol == "__KERNEL__":
        return False
    if symbol in ("__cplusplus",):
        return True
    if symbol == "MODULE":
        return not is_module

    # For unknown non-config symbols (such as header guards _LINUX_FOO_H or __DEBUG):
    # We cannot prove they are defined, so evaluate to True so the header/code is included.
    return True


def evaluate_condition(expr: str, config: KernelConfig, is_module: bool = False) -> bool:
    """Evaluate a C preprocessor `#if` or `#elif` expression under a given `KernelConfig`."""
    expr = expr.strip()
    if not expr:
        return True

    # 1. Strip comments
    expr = re.sub(r"/\*.*?\*/", " ", expr)
    expr = re.sub(r"//.*$", "", expr)

    # 2. IS_ENABLED(CONFIG_X)
    expr = re.sub(
        r"\bIS_ENABLED\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: "1" if config.get(m.group(1)) in (ConfigValue.ENABLED, ConfigValue.MODULE) else "0",
        expr,
    )

    # 3. IS_BUILTIN(CONFIG_X)
    expr = re.sub(
        r"\bIS_BUILTIN\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: "1" if config.get(m.group(1)) == ConfigValue.ENABLED else "0",
        expr,
    )

    # 4. IS_MODULE(CONFIG_X)
    expr = re.sub(
        r"\bIS_MODULE\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)",
        lambda m: "1" if config.get(m.group(1)) == ConfigValue.MODULE else "0",
        expr,
    )

    # 5. IS_REACHABLE(CONFIG_X)
    def _repl_is_reachable(m: re.Match[str]) -> str:
        sym = m.group(1)
        val = config.get(sym)
        if is_module:
            return "1" if val in (ConfigValue.ENABLED, ConfigValue.MODULE) else "0"
        return "1" if val == ConfigValue.ENABLED else "0"

    expr = re.sub(r"\bIS_REACHABLE\s*\(\s*(CONFIG_[A-Za-z0-9_]+)\s*\)", _repl_is_reachable, expr)

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
        # Unknown non-config symbol: treat conservatively as 1 (defined)
        return "1"

    expr = re.sub(r"\bdefined\s*\(\s*([A-Za-z0-9_]+)\s*\)|\bdefined\s+([A-Za-z0-9_]+)", _repl_defined, expr)

    # 7. Unadorned CONFIG_X identifiers
    def _repl_config_ident(m: re.Match[str]) -> str:
        sym = m.group(0)
        raw = config.get_raw(sym)
        if raw:
            try:
                # If it is integer/hex (e.g. 64 or 0x40)
                int(raw, 0)
                return raw
            except ValueError:
                pass
        val = config.get(sym)
        if val == ConfigValue.ENABLED:
            return "1"
        return "0"

    expr = re.sub(r"\bCONFIG_[A-Za-z0-9_]+\b", _repl_config_ident, expr)

    # 8. C operators to Python
    expr = expr.replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r"!(?!=)", " not ", expr)

    # Clean and strip any residual whitespace
    expr = expr.strip()
    if not expr:
        return True

    try:
        parsed = ast.parse(expr, mode="eval")
        return bool(_eval_ast(parsed))
    except Exception:
        # Conservative fallback: treat as True if expression could not be evaluated
        return True


@dataclass(slots=True)
class _Conditional:
    parent_active: bool
    branch_taken: bool
    active: bool


_DIRECTIVE_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$")


def get_active_lines(content: str, config: KernelConfig, is_module: bool = False) -> set[int]:
    """Return the set of 1-indexed line numbers that are actively compiled under `config`."""
    lines = content.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return set()

    # Fast path: if no CONFIG_ and no explicit #if 0 / __cplusplus directives, all lines are active
    if "CONFIG_" not in content and "#if 0" not in content and "__cplusplus" not in content:
        return set(range(1, total_lines + 1))

    active_lines: set[int] = set()
    stack: list[_Conditional] = []
    in_block_comment = False

    idx = 0
    while idx < total_lines:
        line_no = idx + 1
        raw_line = lines[idx]

        # Handle multi-line C block comments
        if in_block_comment:
            if "*/" in raw_line:
                in_block_comment = False
                raw_line = raw_line.split("*/", 1)[1]
            else:
                # Entire line is inside block comment
                current_active = stack[-1].active if stack else True
                if current_active:
                    active_lines.add(line_no)
                idx += 1
                continue

        # Check if an unclosed block comment starts on this line before a directive
        # But if a directive starts first, check directive first
        stripped = raw_line.strip()
        match = _DIRECTIVE_RE.match(stripped)

        if match is None:
            # Check if block comment starts
            if "/*" in raw_line:
                # Strip all closed /* ... */ pairs
                cleaned = re.sub(r"/\*.*?\*/", "", raw_line)
                if "/*" in cleaned:
                    in_block_comment = True

            current_active = stack[-1].active if stack else True
            if current_active:
                active_lines.add(line_no)
            idx += 1
            continue

        # We found a directive line! Handle line continuations with backslash
        directive = match.group(1)
        rest = match.group(2)
        directive_line_numbers = [line_no]

        while raw_line.rstrip().endswith("\\") and idx + 1 < total_lines:
            idx += 1
            raw_line = lines[idx]
            directive_line_numbers.append(idx + 1)
            rest = f"{rest.rstrip('\\')} {raw_line.strip()}"

        idx += 1

        # Current parent state
        parent_active = stack[-1].active if stack else True

        if directive in ("if", "ifdef", "ifndef"):
            if directive == "ifdef":
                result = evaluate_ifdef(rest, config, is_module) if parent_active else False
            elif directive == "ifndef":
                result = evaluate_ifndef(rest, config, is_module) if parent_active else False
            else:  # if
                result = evaluate_condition(rest, config, is_module) if parent_active else False

            stack.append(
                _Conditional(
                    parent_active=parent_active,
                    branch_taken=result,
                    active=parent_active and result,
                )
            )
            # Directive lines are active if their enclosing parent scope was active
            if parent_active:
                active_lines.update(directive_line_numbers)

        elif directive == "elif":
            if stack:
                frame = stack[-1]
                if frame.parent_active and not frame.branch_taken:
                    result = evaluate_condition(rest, config, is_module)
                else:
                    result = False

                frame.active = frame.parent_active and not frame.branch_taken and result
                frame.branch_taken = frame.branch_taken or result
                if frame.parent_active:
                    active_lines.update(directive_line_numbers)
            elif parent_active:
                active_lines.update(directive_line_numbers)

        elif directive == "else":
            if stack:
                frame = stack[-1]
                frame.active = frame.parent_active and not frame.branch_taken
                frame.branch_taken = True
                if frame.parent_active:
                    active_lines.update(directive_line_numbers)
            elif parent_active:
                active_lines.update(directive_line_numbers)

        elif directive == "endif":
            if stack:
                frame = stack.pop()
                if frame.parent_active:
                    active_lines.update(directive_line_numbers)
            elif parent_active:
                active_lines.update(directive_line_numbers)

    return active_lines


def diff_file_touches_active_code(
    repo: GitRepo,
    parent_commit: str | None,
    current_commit: str,
    diff_file: DiffFile,
    config: KernelConfig,
    is_module: bool = False,
) -> bool:
    """Determine whether any changed line in `diff_file` touches an active portion of the file."""
    if not diff_file.chunks:
        return False

    # For non-C files, we treat any change as active if the file is built
    if not is_c_source_file(diff_file.file) and (
        diff_file.old_file is None or not is_c_source_file(diff_file.old_file)
    ):
        return True

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
        if not new_touched:
            return False
        try:
            new_bytes = repo.read_file(current_commit, diff_file.file)
            new_active = get_active_lines(
                new_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            return any(line in new_active for line in new_touched)
        except Exception:
            return True

    if diff_file.change_type == DiffFileType.DELETE:
        if not old_touched:
            return False
        if parent_commit is None:
            return True
        try:
            old_path = diff_file.old_file or diff_file.file
            old_bytes = repo.read_file(parent_commit, old_path)
            old_active = get_active_lines(
                old_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            return any(line in old_active for line in old_touched)
        except Exception:
            return True

    # For DEFAULT, RENAME, COPY: check new additions and old deletions
    if not new_touched and not old_touched:
        return False

    if new_touched:
        try:
            new_bytes = repo.read_file(current_commit, diff_file.file)
            new_active = get_active_lines(
                new_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            if any(line in new_active for line in new_touched):
                return True
        except Exception:
            return True

    if old_touched:
        if parent_commit is None:
            return True
        try:
            old_path = diff_file.old_file or diff_file.file
            old_bytes = repo.read_file(parent_commit, old_path)
            old_active = get_active_lines(
                old_bytes.decode("utf-8", errors="replace"), config, is_module
            )
            if any(line in old_active for line in old_touched):
                return True
        except Exception:
            return True

    return False
