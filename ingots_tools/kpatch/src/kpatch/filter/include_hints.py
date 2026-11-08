"""Positive include hints; none of these lexical observations prove absence.

Literal strings and filename operands may overapproximate real includes. The
caller resolves them against tracked paths and verifies relevant consumers.
"""

import re


# Shared by Git's ERE and PCRE matchers. Continuation rows let the caller spot
# a filename split across physical lines without normalizing every C source.
INCLUDE_HINT_PATTERN = (
    r'^.*(\\|\?\?/)[[:space:]]*$|include.*|import.*|define.*\..*|".*"|<[A-Za-z_0-9./+-]+>'
    r'|[A-Za-z_0-9./+-]+\.(h|c|S|s|inc|txt|rst|def|tbl|lds)([^A-Za-z_0-9]|$)'
    r'|\\[[:space:]]*$'
)

_SPLICE = re.compile(r"\\[^\S\r\n]*(?:\r\n|\n|\r)")
_LITERAL = re.compile(r'"([^"\r\n]+)"|<([^<>\r\n]+)>')
_BARE_PATH = re.compile(r"(?<![A-Za-z_0-9./+-])[A-Za-z_0-9./+-]*\.[A-Za-z_0-9]+(?![A-Za-z_0-9./+-])")
_INPUT_TAIL = re.compile(r"\b(?:include|include_next|import|__has_include|__has_include_next|__has_embed)\b([^\r\n]*)")
_OPERAND = re.compile(r"[A-Za-z_0-9./+-]+")
_TRIGRAPH = re.compile(r"\?\?([=/'()!<>-])")
_TRIGRAPH_VALUES = {"=": "#", "/": "\\", "'": "^", "(": "[", ")": "]",
                    "!": "|", "<": "{", ">": "}", "-": "~"}


def literal_include_hints(text: str) -> frozenset[str]:
    """Return canonical include lines for possible literal source inputs.

    Hints also cover stringification operands and literal macro replacements.
    Original and trigraph-enabled spellings are both positive possibilities.
    """
    variants = (text, _TRIGRAPH.sub(lambda match: _TRIGRAPH_VALUES[match[1]], text)) if "??" in text else (text,)
    result: set[str] = set()
    for variant in variants:
        source = _SPLICE.sub("", variant)
        for match in _LITERAL.finditer(source):
            path = match[1] if match[1] is not None else match[2]
            if len(path) <= 4096 and "\0" not in path:
                result.add('#include "' + path + '"' if match[1] is not None else '#include <' + path + '>')
        operands = {match[0] for match in _BARE_PATH.finditer(source)}
        for tail in _INPUT_TAIL.finditer(source):
            operands.update(match[0] for match in _OPERAND.finditer(tail[1]))
        for path in operands:
            if len(path) <= 4096:
                result.add('#include "' + path + '"')
                result.add('#include <' + path + '>')
    return frozenset(result)


def needs_normalization(line: str) -> bool:
    """Recognize physical continuations that can hide a complete filename.

    Ordinary multi-line macro bodies use indexed literal hints directly and do
    not trigger a complete-source read just because they end in a backslash.
    """
    source = _TRIGRAPH.sub(lambda match: _TRIGRAPH_VALUES[match[1]], line).rstrip()
    if not source.endswith("\\"):
        return False
    prefix = source[:-1]
    if len(re.findall(r'(?<!\\)(?:\\\\)*"', prefix)) % 2:
        return True
    directive = re.search(r"(?:#|%:)\s*([A-Za-z_0-9]*)", prefix)
    if directive is None:
        return False
    keyword = directive[1]
    if keyword in {"include", "include_next", "import"}:
        return _LITERAL.search(prefix[directive.end():]) is None
    return any(word.startswith(keyword) for word in ("include", "include_next", "import"))
