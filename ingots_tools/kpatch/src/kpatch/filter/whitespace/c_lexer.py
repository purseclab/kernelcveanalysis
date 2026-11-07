from dataclasses import dataclass
from enum import StrEnum
import re


class CTokenKind(StrEnum):
    """The syntactic category of a C preprocessing token."""

    IDENTIFIER = "identifier"
    PP_NUMBER = "pp_number"
    STRING_LITERAL = "string_literal"
    CHAR_CONSTANT = "char_constant"
    HEADER_NAME = "header_name"
    PUNCTUATOR = "punctuator"
    DIRECTIVE_NEWLINE = "directive_newline"
    MACRO_FUNCTION_LPAREN = "macro_function_lparen"
    NEWLINE = "newline"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class CToken:
    """An immutable preprocessing token."""

    kind: CTokenKind
    value: str


_PUNCTUATORS = [
    "...",
    "<<=",
    ">>=",
    "->*",
    "##",
    "<<",
    ">>",
    "<=",
    ">=",
    "==",
    "!=",
    "&&",
    "||",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "^=",
    "|=",
    "->",
    "++",
    "--",
    "::",
    "<:",
    ":>",
    "<%",
    "%>",
    "%:",
    "[",
    "]",
    "(",
    ")",
    "{",
    "}",
    ".",
    "&",
    "*",
    "+",
    "-",
    "~",
    "!",
    "/",
    "%",
    "<",
    ">",
    "^",
    "|",
    "?",
    ":",
    ";",
    "=",
    ",",
    "#",
]
_PUNCTUATORS.sort(key=len, reverse=True)
_PUNCT_PATTERN = "|".join(re.escape(p) for p in _PUNCTUATORS)

_IDENT_RE = r"[a-zA-Z_$][a-zA-Z0-9_$]*"
_PP_NUMBER_RE = r"(?:\.[0-9]|[0-9])[0-9a-zA-Z_.]*(?:[eEpP][+-][0-9a-zA-Z_.]*)*"
_STRING_PREFIX_RE = r"(?:u8|u|U|L)?"

_TOKEN_SPEC: list[tuple[str, str]] = [
    ("BLOCK_COMMENT", r"/\*[\s\S]*?(?:\*/|$)"),
    ("LINE_COMMENT", r"//[^\r\n]*"),
    ("STRING", rf'{_STRING_PREFIX_RE}"(?:\\.|[^"\\\r\n])*"'),
    ("CHAR", rf"{_STRING_PREFIX_RE}'(?:\\.|[^'\\\r\n])*'"),
    ("UNCLOSED_STRING", rf'{_STRING_PREFIX_RE}"(?:\\.|[^"\\\r\n])*$'),
    ("UNCLOSED_CHAR", rf"{_STRING_PREFIX_RE}'(?:\\.|[^'\\\r\n])*$"),
    ("PP_NUMBER", _PP_NUMBER_RE),
    ("IDENTIFIER", _IDENT_RE),
    ("PUNCT", _PUNCT_PATTERN),
    ("NEWLINE", r"\r?\n"),
    ("WHITESPACE", r"[^\S\r\n]+"),
    ("OTHER", r"."),
]

_MASTER_RE = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _TOKEN_SPEC)
)

_HEADER_NAME_RE = re.compile(r"<[^>\r\n]+>")

# String prefixes do not affect comment recognition. Starting at the quote
# avoids trying optional identifier prefixes at every ordinary code character.
_COMMENT_CONTEXT_RE = re.compile("|".join(
    f"(?P<{name}>{pattern.removeprefix(_STRING_PREFIX_RE)})"
    for name, pattern in _TOKEN_SPEC
    if name in {
        "BLOCK_COMMENT", "LINE_COMMENT", "STRING", "CHAR",
        "UNCLOSED_STRING", "UNCLOSED_CHAR",
    }
))

_NON_HORIZONTAL_SPACE = re.compile(r"[^ \t\v\f\r]")
_IMPORT_WORD = re.compile(r"\bimport\b")


@dataclass(slots=True)
class _CommentDirectiveContext:
    """Track directive/angle context over disjoint gaps between literals.

    Comments are whitespace, including their internal newlines for directive
    recognition. Only a newline outside a comment starts a new logical line.
    Scanning each gap once avoids repeatedly copying/searching a growing line.
    """

    source: str
    position: int = 0
    leading: bool = True
    directive: bool = False
    angle_open: bool = False
    unsupported_import: bool = False

    def _imports_outside_directives(self, start: int, stop: int) -> bool:
        leading, directive = self.leading, self.directive
        cursor = start
        for word in _IMPORT_WORD.finditer(self.source, start, stop):
            newline = self.source.rfind("\n", cursor, word.start())
            if newline >= 0:
                cursor, leading, directive = newline + 1, True, False
            if leading:
                first = _NON_HORIZONTAL_SPACE.search(self.source, cursor, word.start())
                if first is not None:
                    leading = False
                    directive = self.source.startswith(("#", "%:"), first.start())
            if not directive:
                return True
            leading, cursor = False, word.end()
        return False

    def before(self, stop: int) -> None:
        start = self.position
        # Header-unit imports have header-name lexing outside # directives.
        # They need a C++ preprocessing model; do not reinterpret their text as
        # an ordinary comparison. Strings/comments are excluded from the gaps.
        if not self.unsupported_import:
            self.unsupported_import = self._imports_outside_directives(start, stop)
        newline = self.source.rfind("\n", start, stop)
        if newline >= 0:
            start = newline + 1
            self.leading, self.directive, self.angle_open = True, False, False
        if self.leading:
            first = _NON_HORIZONTAL_SPACE.search(self.source, start, stop)
            if first is not None:
                self.leading = False
                self.directive = self.source.startswith(("#", "%:"), first.start())
        if self.directive:
            opener = self.source.rfind("<", start, stop)
            closer = self.source.rfind(">", start, stop)
            if opener >= 0 or closer >= 0:
                self.angle_open = opener > closer

    def after(self, stop: int, *, comment: bool) -> None:
        self.position = stop
        if not comment:
            self.leading = False


def _unsupported_comment_context(source: str) -> bool:
    # Unsupported phase-one spellings must not fall through to an ordinary
    # token comparison after a comment-normalization refusal.
    return ("??" in source or "\ufeff" in source
            or "\r" in source and re.search(r"\r(?!\n)", source) is not None)


def source_line_starts_in_block_comment(source: str, line_number: int) -> bool:
    """Recover comment context omitted by a diff hunk, without emitting tokens."""

    if line_number <= 1:
        return False
    lines = source.split("\n", line_number - 1)
    if len(lines) < line_number:
        return False
    prefix = "\n".join(lines[:-1]) + "\n"
    prefix = re.sub(r"\\(?:\r\n|\n)", "", prefix)
    # Ordinary code usually follows a closed comment. Reject that case with
    # string searches; only ambiguous marker order needs the lexical scan.
    opener = prefix.rfind("/*")
    if opener < 0 or prefix.rfind("*/") >= opener + 2:
        return False
    # A standalone opener cannot be inside a continued string or // comment
    # after line splicing. This covers ordinary kernel-doc without a scan.
    line_start = prefix.rfind("\n", 0, opener) + 1
    if not prefix[line_start:opener].strip():
        return True
    for match in _COMMENT_CONTEXT_RE.finditer(prefix):
        if match.lastgroup == "BLOCK_COMMENT" and (
            len(match.group()) < 4 or not match.group().endswith("*/")
        ):
            return True
    return False


def preprocessor_directive_text(source: str, *, strict_multiline: bool = False) -> str | None:
    """Normalize phase-two splices/comments while preserving directive lines.

    Ambiguous angle-header/comment spellings remain unknown instead of being
    interpreted as a different include path. This is intended for conservative
    directive inventory, not full macro expansion.
    """
    source = re.sub(r"\\(?:\r\n|\n)", "", source)
    if _unsupported_comment_context(source):
        return None
    invalid = False
    context = _CommentDirectiveContext(source)

    def replace(match: re.Match[str]) -> str:
        nonlocal invalid
        value = match.group()
        context.before(match.start())
        comment = match.lastgroup in {"BLOCK_COMMENT", "LINE_COMMENT"}
        if match.lastgroup in {"UNCLOSED_STRING", "UNCLOSED_CHAR"}:
            invalid = True
        if comment:
            if match.lastgroup == "BLOCK_COMMENT" and not value.endswith("*/"):
                invalid = True
            if strict_multiline and "\n" in value and context.directive:
                # Newlines inside a directive's comment need different logical
                # line handling. Do not feed a truncated condition to callers.
                invalid = True
            if context.directive and context.angle_open:
                invalid = True
            context.after(match.end(), comment=True)
            return " " + "\n" * value.count("\n")
        context.after(match.end(), comment=False)
        return value

    output = _COMMENT_CONTEXT_RE.sub(replace, source)
    context.before(len(source))
    return None if invalid or context.unsupported_import else output


def replace_c_comments(source: str) -> str | None:
    """Replace comments with spaces, protecting literals and angle headers.

    Equality of these strings proves a token no-op without allocating a token
    object for every unchanged identifier. Unequal strings are inconclusive.
    """

    source = re.sub(r"\\(?:\r\n|\n)", "", source)
    if _unsupported_comment_context(source):
        return None
    invalid = False
    context = _CommentDirectiveContext(source)

    def replace(match: re.Match[str]) -> str:
        nonlocal invalid
        context.before(match.start())
        comment = match.lastgroup in {"BLOCK_COMMENT", "LINE_COMMENT"}
        if match.lastgroup in {"UNCLOSED_STRING", "UNCLOSED_CHAR"}:
            invalid = True
        if comment:
            # A directive's angle operand can contain comment-looking text.
            # Ordinary comparisons/shifts do not give it header-name meaning.
            context.after(match.end(), comment=True)
            if context.directive and context.angle_open:
                return match.group()
            return " "
        context.after(match.end(), comment=False)
        return match.group()

    result = _COMMENT_CONTEXT_RE.sub(replace, source)
    context.before(len(source))
    return None if invalid or context.unsupported_import else result


def tokenize_c_source(
    source: str,
    ignore_non_directive_newlines: bool = True,
) -> tuple[CToken, ...] | None:
    """Decompose C source text into an ISO C preprocessing-token stream.

    Translation phase 2 backslash-newlines are spliced, comments and
    insignificant whitespace are discarded, and preprocessor directive boundaries
    are preserved. If the source contains unterminated tokens (such as unclosed
    string literals), None is returned so callers can conservatively retain the file.
    """
    # Phase 2: line splicing of escaped newlines
    source = re.sub(r"\\(?:\r\n|\n)", "", source)
    if _unsupported_comment_context(source):
        return None

    tokens: list[CToken] = []
    in_directive = False
    at_line_start = True
    directive_name: str | None = None
    macro_name_seen = False
    saw_whitespace_after_macro_name = False
    expect_header_name = False
    last_end = 0

    for match in _MASTER_RE.finditer(source):
        kind = match.lastgroup
        val = match.group()
        start = match.start()

        if kind == "IDENTIFIER" and val == "import" and not in_directive:
            return None

        if kind in ("UNCLOSED_STRING", "UNCLOSED_CHAR"):
            return None

        if kind == "WHITESPACE":
            if in_directive and directive_name == "define" and macro_name_seen:
                saw_whitespace_after_macro_name = True
            continue

        if kind in ("BLOCK_COMMENT", "LINE_COMMENT"):
            if in_directive and directive_name == "define" and macro_name_seen:
                saw_whitespace_after_macro_name = True
            continue

        if kind == "NEWLINE":
            if in_directive:
                tokens.append(CToken(CTokenKind.DIRECTIVE_NEWLINE, "\n"))
                in_directive = False
                directive_name = None
                macro_name_seen = False
                saw_whitespace_after_macro_name = False
                expect_header_name = False
            elif not ignore_non_directive_newlines:
                tokens.append(CToken(CTokenKind.NEWLINE, "\n"))
            at_line_start = True
            continue

        if at_line_start:
            if val in {"#", "%:"}:
                in_directive = True
                directive_name = None
                macro_name_seen = False
                saw_whitespace_after_macro_name = False
                expect_header_name = False
            at_line_start = False

        if in_directive:
            if directive_name is None and val not in {"#", "%:"}:
                directive_name = val
                if directive_name in {"include", "include_next", "import"}:
                    expect_header_name = True
            elif directive_name == "define":
                if not macro_name_seen and kind == "IDENTIFIER":
                    macro_name_seen = True
                    saw_whitespace_after_macro_name = False
                elif macro_name_seen:
                    if val == "(" and not saw_whitespace_after_macro_name and start == last_end:
                        tokens.append(CToken(CTokenKind.MACRO_FUNCTION_LPAREN, "("))
                        last_end = match.end()
                        macro_name_seen = False
                        continue
                    macro_name_seen = False
            elif expect_header_name:
                expect_header_name = False
                if val == "<":
                    header_match = _HEADER_NAME_RE.match(source, start)
                    if header_match is not None:
                        tokens.append(
                            CToken(CTokenKind.HEADER_NAME, header_match.group())
                        )
                        last_end = header_match.end()
                        continue

        last_end = match.end()

        match kind:
            case "IDENTIFIER":
                tokens.append(CToken(CTokenKind.IDENTIFIER, val))
            case "PP_NUMBER":
                tokens.append(CToken(CTokenKind.PP_NUMBER, val))
            case "STRING":
                tokens.append(CToken(CTokenKind.STRING_LITERAL, val))
            case "CHAR":
                tokens.append(CToken(CTokenKind.CHAR_CONSTANT, val))
            case "PUNCT":
                tokens.append(CToken(CTokenKind.PUNCTUATOR, val))
            case _:
                tokens.append(CToken(CTokenKind.OTHER, val))

    if in_directive:
        tokens.append(CToken(CTokenKind.DIRECTIVE_NEWLINE, "\n"))

    return tuple(tokens)
