"""Bounded binary Git streams and strict framing for ``grep -n -z -a``.

Grep filenames end at NUL, not newline. Only after the second NUL does a
newline delimit the source line; its contents may themselves contain NUL.
"""

from collections.abc import Generator, Iterable
from contextlib import closing
from dataclasses import dataclass
import subprocess

from ..git import GitRepo


_READ_SIZE = 64 * 1024
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_LINE_NUMBER_BYTES = 20


class GitGrepProtocolError(ValueError):
    """Git output cannot safely establish a complete set of grep matches."""


@dataclass(frozen=True, slots=True)
class GitGrepRow:
    path: bytes
    line: int
    contents: bytes


def _iter_git_chunks(
    repo: GitRepo, args: list[str], success_codes: tuple[int, ...]
) -> Generator[bytes, None, None]:
    # Explicit grep options override output-formatting configuration without
    # altering source ESC bytes. Other commands retain their output semantics.
    if args and args[0] == "grep":
        args = ["grep", "--no-color", "--no-column", *args[1:]]
    # Internal callers pass exact tracked paths. Git pathspec magic (including
    # negative patterns) must not reinterpret those filenames and hide matches.
    command = ["git", "--literal-pathspecs", "-C", str(repo.repo), *args]
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
    )
    assert process.stdout is not None
    try:
        while chunk := process.stdout.read(_READ_SIZE):
            yield chunk
        returncode = process.wait()
        if returncode not in success_codes:
            raise subprocess.CalledProcessError(returncode, command)
    finally:
        try:
            process.stdout.close()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def _check_record_size(size: int) -> None:
    if size > _MAX_RECORD_BYTES:
        raise GitGrepProtocolError("Git output record exceeds the bounded buffer")


def _iter_delimited_records(
    chunks: Iterable[bytes], delimiter: bytes
) -> Generator[bytes, None, None]:
    pending = bytearray()
    search_start = 0
    for chunk in chunks:
        pending.extend(chunk)
        record_start = 0
        while (end := pending.find(delimiter, search_start)) >= 0:
            _check_record_size(end - record_start)
            yield bytes(pending[record_start:end])
            record_start = end + len(delimiter)
            search_start = record_start
        # A delimiter prefix at the end may still complete in the next chunk.
        _check_record_size(max(0, len(pending) - record_start - len(delimiter) + 1))
        if record_start:
            del pending[:record_start]
        search_start = max(0, len(pending) - len(delimiter) + 1)
    if pending:
        _check_record_size(len(pending))
        yield bytes(pending)


def iter_git_records(
    repo: GitRepo,
    args: list[str],
    delimiter: bytes,
    success_codes: tuple[int, ...],
) -> Generator[bytes, None, None]:
    """Yield bounded delimiter-separated records, retaining a nonempty tail.

    Close the generator when stopping early so its child process is reaped.
    Grep callers using this interface must request paths only (``-l -z``);
    matching source rows need :func:`iter_git_grep_rows` instead.
    """

    if not delimiter:
        raise ValueError("Git output delimiter must not be empty")
    with closing(_iter_git_chunks(repo, args, success_codes)) as chunks:
        yield from _iter_delimited_records(chunks, delimiter)


def _grep_line_number(field: bytearray) -> int:
    if not field or len(field) > _MAX_LINE_NUMBER_BYTES or not field.isdigit():
        raise GitGrepProtocolError("Git grep line number is not a positive decimal")
    number = int(field)
    if number == 0:
        raise GitGrepProtocolError("Git grep line number is not positive")
    return number


def _iter_grep_rows(chunks: Iterable[bytes]) -> Generator[GitGrepRow, None, None]:
    field = bytearray()
    phase = 0
    row_size = 0
    path = b""
    number = 0
    for chunk in chunks:
        offset = 0
        while offset < len(chunk):
            delimiter = b"\n" if phase == 2 else b"\0"
            end = chunk.find(delimiter, offset)
            field_end = len(chunk) if end < 0 else end
            row_size += field_end - offset + (end >= 0)
            _check_record_size(row_size)
            field.extend(chunk[offset:field_end])
            if phase == 1 and len(field) > _MAX_LINE_NUMBER_BYTES:
                raise GitGrepProtocolError("Git grep line number is too long")
            if end < 0:
                break
            offset = end + 1

            if phase == 0:
                if not field:
                    raise GitGrepProtocolError("Git grep path is empty")
                path = bytes(field)
            elif phase == 1:
                number = _grep_line_number(field)
            else:
                yield GitGrepRow(path, number, bytes(field))
                row_size = 0
            field.clear()
            phase = (phase + 1) % 3
    if phase or field:
        raise GitGrepProtocolError("Git grep output ends inside a row")


def iter_git_grep_rows(
    repo: GitRepo,
    args: list[str],
    success_codes: tuple[int, ...] = (0, 1),
) -> Generator[GitGrepRow, None, None]:
    """Parse ``git grep -n -z -a`` rows without decoding paths or source bytes.

    Malformed, truncated, or oversized output raises rather than establishing
    absence. Git failures retain their original ``CalledProcessError`` status;
    regex syntax is never changed or retried with another matcher.
    """

    with closing(_iter_git_chunks(repo, args, success_codes)) as chunks:
        yield from _iter_grep_rows(chunks)
