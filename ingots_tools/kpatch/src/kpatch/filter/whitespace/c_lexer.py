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
