from collections.abc import Iterator
from dataclasses import dataclass, field
from io import BytesIO
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from kpatch.filter.git_output import (
    GitGrepProtocolError,
    GitGrepRow,
    _MAX_RECORD_BYTES,
    _iter_delimited_records,
    _iter_grep_rows,
    iter_git_grep_rows,
    iter_git_records,
)
from kpatch.git import GitRepo


def chunks_of(data: bytes, size: int) -> Iterator[bytes]:
    for offset in range(0, len(data), size):
        yield data[offset:offset + size]


class GrepFramingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            GitGrepRow(b"HEAD:odd\nfile:name\xff.c", 12, b"needle\0\x1b[35m bytes"),
            GitGrepRow(b"HEAD:normal.c", 1, b""),
            GitGrepRow(b"HEAD:utf8-\xc3\xa9.c", 456, b"last\0part"),
        ]
        self.wire = b"".join(
            row.path + b"\0" + str(row.line).encode() + b"\0" + row.contents + b"\n"
            for row in self.rows
        )

    def test_single_byte_seven_byte_and_large_chunks(self) -> None:
        for size in (1, 7, 65536):
            with self.subTest(size=size):
                self.assertEqual(list(_iter_grep_rows(chunks_of(self.wire, size))), self.rows)

    def test_all_two_chunk_boundaries(self) -> None:
        for offset in range(len(self.wire) + 1):
            with self.subTest(offset=offset):
                self.assertEqual(
                    list(_iter_grep_rows((self.wire[:offset], self.wire[offset:]))),
                    self.rows,
                )

    def test_random_chunk_partitions(self) -> None:
        rng = random.Random(5217)
        for _ in range(100):
            pieces: list[bytes] = []
            offset = 0
            while offset < len(self.wire):
                size = rng.randrange(1, 32)
                pieces.append(self.wire[offset:offset + size])
                offset += size
            self.assertEqual(list(_iter_grep_rows(pieces)), self.rows)

    def test_malformed_headers_and_every_truncated_field_raise(self) -> None:
        malformed = (
            b"\0" + b"1\0text\n", b"path\0\0text\n", b"path\0" + b"0\0text\n",
            b"path\0-1\0text\n", b"path\0+1\0text\n", b"path\0 1\0text\n",
            b"path\0\xff\0text\n", b"path\0" + b"1" * 21 + b"\0text\n",
            b"path", b"path\0", b"path\0" + b"12", b"path\0" + b"12\0", b"path\0" + b"12\0text",
        )
        for wire in malformed:
            with self.subTest(wire=wire):
                with self.assertRaises(GitGrepProtocolError):
                    list(_iter_grep_rows(chunks_of(wire, 1)))
        self.assertEqual(list(_iter_grep_rows((b"",))), [])

    def test_truncation_after_a_valid_row_does_not_silently_finish(self) -> None:
        output = _iter_grep_rows((b"path\0" + b"1\0ok\nnext\0" + b"2\0partial",))
        self.assertEqual(next(output), GitGrepRow(b"path", 1, b"ok"))
        with self.assertRaises(GitGrepProtocolError):
            next(output)

    def test_large_valid_row_and_oversized_path_or_contents(self) -> None:
        contents = b"x" * (2 * 1024 * 1024)
        wire = b"path\0" + b"1\0" + contents + b"\n"
        self.assertEqual(
            list(_iter_grep_rows(chunks_of(wire, 65536))),
            [GitGrepRow(b"path", 1, contents)],
        )
        for prefix in (b"", b"path\0" + b"1\0"):
            with self.subTest(prefix=prefix):
                with self.assertRaises(GitGrepProtocolError):
                    list(_iter_grep_rows(chunks_of(prefix + b"x" * (_MAX_RECORD_BYTES + 1), 65536)))

    def test_generic_records_keep_empty_records_and_unterminated_tail(self) -> None:
        self.assertEqual(
            list(_iter_delimited_records(chunks_of(b"first\0\0odd\nfile\0tail", 7), b"\0")),
            [b"first", b"", b"odd\nfile", b"tail"],
        )
        self.assertEqual(list(_iter_delimited_records((b"one\n",), b"\n")), [b"one"])
        self.assertEqual(
            list(_iter_delimited_records(chunks_of(b"oneENDtwoENDlast", 1), b"END")),
            [b"one", b"two", b"last"],
        )

    def test_generic_record_limit_raises(self) -> None:
        with self.assertRaises(GitGrepProtocolError):
            list(_iter_delimited_records(chunks_of(b"x" * (_MAX_RECORD_BYTES + 1), 65536), b"\0"))

    def test_exact_buffer_limit_and_split_multibyte_delimiter(self) -> None:
        with patch("kpatch.filter.git_output._MAX_RECORD_BYTES", 32):
            self.assertEqual(
                list(_iter_delimited_records(chunks_of(b"x" * 32 + b"END", 1), b"END")),
                [b"x" * 32],
            )
            with self.assertRaises(GitGrepProtocolError):
                list(_iter_delimited_records(chunks_of(b"x" * 33, 1), b"END"))
            self.assertEqual(
                list(_iter_grep_rows(chunks_of(b"p\0" + b"1\0" + b"x" * 27 + b"\n", 7))),
                [GitGrepRow(b"p", 1, b"x" * 27)],
            )
            with self.assertRaises(GitGrepProtocolError):
                list(_iter_grep_rows(chunks_of(b"p\0" + b"1\0" + b"x" * 28 + b"\n", 7)))


class ControlledStream(BytesIO):
    def __init__(self, data: bytes, *, fail_after: int | None = None) -> None:
        super().__init__(data)
        self.read_sizes: list[int] = []
        self.fail_after = fail_after

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if self.fail_after is not None and len(self.read_sizes) > self.fail_after:
            raise OSError("controlled read failure")
        return super().read(size)


@dataclass
class ControlledProcess:
    stdout: ControlledStream
    exit_code: int = 0
    running: bool = True
    killed: bool = False
    events: list[str] = field(default_factory=list)

    def wait(self) -> int:
        self.events.append("wait")
        self.running = False
        return self.exit_code

    def poll(self) -> int | None:
        return None if self.running else self.exit_code

    def kill(self) -> None:
        self.events.append("kill")
        self.killed = True


class GitStreamLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = GitRepo(Path("unused"))

    def assert_reaped(self, process: ControlledProcess, *, killed: bool) -> None:
        self.assertTrue(process.stdout.closed)
        self.assertFalse(process.running)
        self.assertEqual(process.killed, killed)
        self.assertEqual(process.events, ["kill", "wait"] if killed else ["wait"])

    def test_normal_completion_reads_fixed_chunks_and_does_not_kill(self) -> None:
        process = ControlledProcess(ControlledStream(b"a" * 65537 + b"\0tail"))
        with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process):
            self.assertEqual(
                list(iter_git_records(self.repo, ["ls-tree"], b"\0", (0,))),
                [b"a" * 65537, b"tail"],
            )
        self.assertEqual(set(process.stdout.read_sizes), {65536})
        self.assert_reaped(process, killed=False)

    def test_early_close_for_both_interfaces_kills_and_reaps(self) -> None:
        cases = ((False, b"first\0second\0"), (True, b"file\0" + b"1\0first\nfile\0" + b"2\0second\n"))
        for grep, wire in cases:
            with self.subTest(grep=grep):
                process = ControlledProcess(ControlledStream(wire))
                with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process):
                    output = iter_git_grep_rows(self.repo, ["grep"]) if grep else iter_git_records(self.repo, [], b"\0", (0,))
                    next(output)
                    output.close()
                self.assert_reaped(process, killed=True)

    def test_protocol_error_kills_and_reaps(self) -> None:
        process = ControlledProcess(ControlledStream(b"file\0wrong\0text\n"))
        with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process):
            with self.assertRaises(GitGrepProtocolError):
                list(iter_git_grep_rows(self.repo, ["grep"]))
        self.assert_reaped(process, killed=True)

    def test_read_error_kills_and_reaps(self) -> None:
        process = ControlledProcess(ControlledStream(b"", fail_after=0))
        with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(OSError, "controlled read failure"):
                list(iter_git_records(self.repo, [], b"\0", (0,)))
        self.assert_reaped(process, killed=True)

    def test_regex_failure_is_not_retried_or_reinterpreted(self) -> None:
        process = ControlledProcess(ControlledStream(b""), exit_code=128)
        with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process) as launch:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                list(iter_git_grep_rows(self.repo, ["grep", "-P", "-e", "(?<=prefix)needle"]))
        self.assertEqual(raised.exception.returncode, 128)
        self.assertIn("-P", raised.exception.cmd)
        self.assertEqual(launch.call_count, 1)
        self.assert_reaped(process, killed=False)

    def test_successful_no_matches_and_empty_delimiter(self) -> None:
        process = ControlledProcess(ControlledStream(b""), exit_code=1)
        with patch("kpatch.filter.git_output.subprocess.Popen", return_value=process):
            self.assertEqual(list(iter_git_grep_rows(self.repo, ["grep"])), [])
        self.assert_reaped(process, killed=False)
        with patch("kpatch.filter.git_output.subprocess.Popen") as launch:
            with self.assertRaises(ValueError):
                list(iter_git_records(self.repo, [], b"", (0,)))
        launch.assert_not_called()


class RealGitOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = GitRepo(Path(self.directory.name))
        self.repo._run_git(["init", "--quiet"])
        self.repo._run_git(["config", "color.grep", "always"])
        self.repo._run_git(["config", "grep.column", "true"])
        self.repo._run_git(["config", "grep.lineNumber", "true"])
        self.repo._run_git(["config", "grep.fullName", "true"])
        self.paths = (b"normal.c", b"odd\nfilename.fragment", b"colon:name.c", b"utf8-\xc3\xa9.c", b"raw-\xff.c")
        for raw_path in self.paths:
            path = self.repo.repo / os.fsdecode(raw_path)
            path.write_bytes(b"plain\nneedle\0real \x1b[35mESC\x1b[0m\nneedle end")
        self.repo._run_git(["add", "--all"])
        self.repo._run_git(["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"])

    def test_raw_filenames_and_source_bytes_survive_color_and_column_config(self) -> None:
        rows = list(iter_git_grep_rows(self.repo, ["grep", "-n", "-z", "-a", "-F", "-e", "needle", "HEAD", "--"]))
        expected = [
            GitGrepRow(b"HEAD:" + path, line, contents)
            for path in sorted(self.paths)
            for line, contents in ((2, b"needle\0real \x1b[35mESC\x1b[0m"), (3, b"needle end"))
        ]
        self.assertEqual(rows, expected)

    def test_paths_only_grep_also_disables_color_and_keeps_newlines(self) -> None:
        output = list(iter_git_records(self.repo, ["grep", "-l", "-z", "-a", "-F", "-e", "needle", "HEAD", "--"], b"\0", (0, 1)))
        self.assertEqual(output, [b"HEAD:" + path for path in sorted(self.paths)])

    def test_ls_tree_raw_names_and_diff_lines_keep_generic_semantics(self) -> None:
        entries = list(iter_git_records(self.repo, ["ls-tree", "-r", "-z", "HEAD"], b"\0", (0,)))
        self.assertEqual([entry.split(b"\t", 1)[1] for entry in entries], sorted(self.paths))
        (self.repo.repo / "normal.c").write_bytes(b"changed\n")
        args = ["diff", "--no-ext-diff", "--no-color", "--", "normal.c"]
        expected = self.repo._run_git(args).split(b"\n")[:-1]
        self.assertEqual(list(iter_git_records(self.repo, args, b"\n", (0,))), expected)

    def test_invalid_pcre_expression_keeps_git_failure(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            list(iter_git_grep_rows(self.repo, ["grep", "-n", "-z", "-a", "-P", "-e", "(", "HEAD", "--"]))
        self.assertNotIn("-E", raised.exception.cmd)
        self.assertIn("-P", raised.exception.cmd)


if __name__ == "__main__":
    unittest.main()
