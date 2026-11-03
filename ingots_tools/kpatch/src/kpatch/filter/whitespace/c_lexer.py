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


def replace_c_comments(source: str) -> str | None:
    """Replace comments with spaces, protecting literals and angle headers.

    Equality of these strings proves a token no-op without allocating a token
    object for every unchanged identifier. Unequal strings are inconclusive.
    """

    source = re.sub(r"\\(?:\r\n|\n)", "", source)
    invalid = False

    def replace(match: re.Match[str]) -> str:
        nonlocal invalid
        if match.lastgroup in {"UNCLOSED_STRING", "UNCLOSED_CHAR"}:
            invalid = True
        if match.lastgroup in {"BLOCK_COMMENT", "LINE_COMMENT"}:
            # Comment-looking text can be part of an angle header name. Keep
            # it opaque; doing so for a comparison/shift too is conservative.
            line_start = source.rfind("\n", 0, match.start()) + 1
            opener = source.rfind("<", line_start, match.start())
            if opener >= 0 and source.rfind(">", line_start, match.start()) < opener:
                return match.group()
            return " "
        return match.group()

    result = _COMMENT_CONTEXT_RE.sub(replace, source)
    return None if invalid else result


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
            if val == "#":
                in_directive = True
                directive_name = None
                macro_name_seen = False
                saw_whitespace_after_macro_name = False
                expect_header_name = False
            at_line_start = False

        if in_directive:
            if directive_name is None and val != "#":
                directive_name = val
                if directive_name == "include":
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
