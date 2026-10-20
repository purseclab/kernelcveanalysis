from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from kpatch.filter.repository_file import (
    RepositoryFileReader,
    _CONTENT_CACHE_BYTES,
    _CONTENT_CACHE_ENTRIES,
)
from kpatch.git import GitRepo


def _oid(number: int) -> bytes:
    return f"{number:040x}".encode()


def _info(oid: bytes, contents: bytes) -> bytes:
    return oid + b" blob " + str(len(contents)).encode() + b"\n"


def _contents(oid: bytes, contents: bytes) -> bytes:
    return _info(oid, contents) + contents + b"\n"


class BatchInput(BytesIO):
    def __init__(self) -> None:
        super().__init__()
        self.sent_commands: list[bytes] = []

    def close(self) -> None:
        if not self.closed:
            self.sent_commands = self.getvalue().splitlines()
        super().close()


@dataclass
class BatchProcess:
    stdout: BytesIO
    stdin: BatchInput = field(default_factory=BatchInput)
    waits: list[float | None] = field(default_factory=list)
    timeout: bool = False
    terminated: bool = False

    def poll(self) -> int:
        return 128

    def wait(self, timeout: float | None = None) -> int:
        self.waits.append(timeout)
        if self.timeout and timeout is not None:
            raise subprocess.TimeoutExpired("git cat-file", timeout)
        return 0

    def terminate(self) -> None:
        self.terminated = True

    def commands(self) -> list[bytes]:
        if self.stdin.closed:
            return self.stdin.sent_commands
        return self.stdin.getvalue().splitlines()


class FallbackRepo(GitRepo):
    def __init__(self) -> None:
        self.expressions: list[str] = []
        self.error: Exception | None = None

    def read_file(self, commit: str, path: str) -> bytes:
        self.expressions.append(f"{commit}:{path}")
        if self.error is not None:
            raise self.error
        return b"fallback"


class RepositoryFileReaderTests(unittest.TestCase):
    def reader(self, process: BatchProcess) -> RepositoryFileReader:
        with patch(
            "kpatch.filter.repository_file.subprocess.Popen", return_value=process
        ) as popen:
            reader = RepositoryFileReader(GitRepo(Path("unused")))
        self.addCleanup(reader.close)
        self.assertEqual(
            popen.call_args.args[0],
            ["git", "-C", "unused", "cat-file", "--batch-command"],
        )
        return reader

    def test_oid_cache_reuses_bytes_across_commits_and_normalized_paths(self) -> None:
        oid = _oid(1)
        data = b"obj-y += source.o\n"
        process = BatchProcess(BytesIO(
            _contents(oid, data) + _info(oid, data) * 2
        ))
        reader = self.reader(process)

        first = reader.read_file("first", "Makefile")
        self.assertIs(reader.read_file("second", "./Makefile"), first)
        self.assertIs(reader.read_file("third", "nested/../Makefile"), first)
        self.assertEqual(first, data)
        self.assertEqual(process.commands(), [
            b"contents first:Makefile",
            b"info second:Makefile", b"info third:Makefile",
        ])
        self.assertEqual(reader._content_bytes, len(data))
        self.assertEqual(len(reader._contents), 1)

    def test_oid_cache_is_shared_between_known_paths(self) -> None:
        one, two = _oid(1), _oid(2)
        process = BatchProcess(BytesIO(
            _contents(one, b"shared") + _contents(two, b"other")
            + _info(one, b"shared")
        ))
        reader = self.reader(process)
        shared = reader.read_file("first", "include/one.h")
        self.assertEqual(reader.read_file("first", "include/two.h"), b"other")
        self.assertIs(reader.read_file("second", "include/two.h"), shared)
        self.assertEqual(process.commands(), [
            b"contents first:include/one.h", b"contents first:include/two.h",
            b"info second:include/two.h",
        ])

    def test_new_path_with_cached_oid_does_not_double_count_bytes(self) -> None:
        oid = _oid(1)
        process = BatchProcess(BytesIO(_contents(oid, b"shared") * 2))
        reader = self.reader(process)
        reader.read_file("HEAD", "one.h")
        reader.read_file("HEAD", "two.h")
        self.assertEqual(reader._content_bytes, len(b"shared"))
        self.assertEqual(len(reader._contents), 1)

    def test_one_pass_source_fixture_uses_one_contents_request_per_path(self) -> None:
        paths = 128
        data = b"int value;\n"
        process = BatchProcess(BytesIO(b"".join(
            _contents(_oid(number), data) for number in range(paths)
        )))
        reader = self.reader(process)
        for number in range(paths):
            self.assertEqual(reader.read_file("HEAD", f"source-{number}.c"), data)
        self.assertEqual(process.commands(), [
            f"contents HEAD:source-{number}.c".encode() for number in range(paths)
        ])

    def test_changed_blob_at_same_path_is_not_stale(self) -> None:
        first, second = _oid(1), _oid(2)
        before, after = b"int before;\n", b"int after;\n"
        process = BatchProcess(BytesIO(
            _contents(first, before)
            + _info(second, after) + _contents(second, after)
            + _info(first, before)
        ))
        reader = self.reader(process)
        self.assertEqual(reader.read_file("HEAD", "source.c"), before)
        self.assertEqual(reader.read_file("HEAD", "source.c"), after)
        self.assertEqual(reader.read_file("old", "source.c"), before)
        self.assertEqual(sum(c.startswith(b"contents ") for c in process.commands()), 2)

    def test_empty_blobs_are_cache_hits(self) -> None:
        oid = _oid(1)
        process = BatchProcess(BytesIO(
            _contents(oid, b"") + _info(oid, b"")
        ))
        reader = self.reader(process)
        self.assertEqual(reader.read_file("one", "empty.h"), b"")
        self.assertEqual(reader.read_file("two", "empty.h"), b"")
        self.assertEqual(len(process.commands()), 2)
        self.assertEqual(reader._content_bytes, 0)
        self.assertEqual(len(reader._contents), 1)

    def test_cache_entry_bound_and_hits_refresh_lru_order(self) -> None:
        one, two, three = _oid(1), _oid(2), _oid(3)
        process = BatchProcess(BytesIO(
            _contents(one, b"a")
            + _info(two, b"b") + _contents(two, b"b")
            + _info(one, b"a")
            + _info(three, b"c") + _contents(three, b"c")
            + _info(two, b"b") + _contents(two, b"b")
        ))
        reader = self.reader(process)
        with patch("kpatch.filter.repository_file._CONTENT_CACHE_ENTRIES", 2):
            for commit, data in (("one", b"a"), ("two", b"b"), ("one", b"a")):
                self.assertEqual(reader.read_file(commit, "source.c"), data)
            self.assertEqual(reader.read_file("three", "source.c"), b"c")
            self.assertEqual(list(reader._contents), [one, three])
            self.assertEqual(reader.read_file("two", "source.c"), b"b")
            self.assertEqual(list(reader._contents), [three, two])
        self.assertEqual(reader._content_bytes, 2)
        self.assertEqual(sum(c.startswith(b"contents ") for c in process.commands()), 4)

    def test_cache_byte_budget_evicts_until_new_blob_fits(self) -> None:
        process = BatchProcess(BytesIO())
        reader = self.reader(process)
        with patch("kpatch.filter.repository_file._CONTENT_CACHE_BYTES", 6):
            for number in range(3):
                reader._cache_contents(_oid(number), b"ab")
            reader._cache_contents(_oid(3), b"cdef")
            self.assertEqual(list(reader._contents), [_oid(2), _oid(3)])
            self.assertEqual(reader._content_bytes, 6)
        self.assertEqual(reader._content_bytes, sum(map(len, reader._contents.values())))

    def test_oversized_blob_is_returned_without_evicting_useful_contents(self) -> None:
        small, large = _oid(1), _oid(2)
        process = BatchProcess(BytesIO(
            _contents(small, b"a") + _contents(large, b"large")
            + _info(large, b"large") + _contents(large, b"large")
            + _info(small, b"a")
        ))
        reader = self.reader(process)
        with patch("kpatch.filter.repository_file._CONTENT_CACHE_BYTES", 3):
            self.assertEqual(reader.read_file("one", "small.h"), b"a")
            for _ in range(2):
                self.assertEqual(reader.read_file("one", "large.h"), b"large")
            self.assertEqual(reader.read_file("two", "small.h"), b"a")
        self.assertEqual(list(reader._contents), [small])
        self.assertEqual(reader._content_bytes, 1)

    def test_default_bounds_also_limit_zero_byte_entries(self) -> None:
        reader = self.reader(BatchProcess(BytesIO()))
        self.assertEqual(_CONTENT_CACHE_BYTES, 16 * 1024 * 1024)
        for number in range(_CONTENT_CACHE_ENTRIES + 1):
            reader._cache_contents(_oid(number), b"")
            reader._remember_path(f"source-{number}.c")
        self.assertEqual(len(reader._contents), _CONTENT_CACHE_ENTRIES)
        self.assertEqual(len(reader._paths), _CONTENT_CACHE_ENTRIES)
        self.assertNotIn(_oid(0), reader._contents)
        self.assertNotIn("source-0.c", reader._paths)
        self.assertEqual(reader._content_bytes, 0)

    def test_snapshot_fixture_counts_contents_once_per_distinct_blob(self) -> None:
        """Microbenchmark invariant: stable build/includes do not transfer per commit."""
        snapshots = 128
        makefile = b"obj-y += source.o\n" * 4096
        header = b"struct shared;\n" * 4096
        response = bytearray()
        for number in range(snapshots):
            for oid, data in (
                (_oid(1), makefile),
                (_oid(2), header),
                (_oid(number + 3), f"int value = {number};\n".encode()),
            ):
                if number > 0:
                    response.extend(_info(oid, data))
                if number == 0 or oid not in (_oid(1), _oid(2)):
                    response.extend(_contents(oid, data))
        process = BatchProcess(BytesIO(response))
        reader = self.reader(process)
        transferred = len(makefile) + len(header)
        for number in range(snapshots):
            commit = f"commit-{number}"
            self.assertEqual(reader.read_file(commit, "Makefile"), makefile)
            self.assertEqual(reader.read_file(commit, "include/shared.h"), header)
            source = f"int value = {number};\n".encode()
            self.assertEqual(reader.read_file(commit, "source.c"), source)
            transferred += len(source)

        commands = process.commands()
        self.assertEqual(sum(c.startswith(b"info ") for c in commands), (snapshots - 1) * 3)
        self.assertEqual(sum(c.startswith(b"contents ") for c in commands), snapshots + 2)
        baseline_bytes = transferred + (snapshots - 1) * (len(makefile) + len(header))
        self.assertLess(transferred, baseline_bytes // 100)
        self.assertLessEqual(reader._content_bytes, _CONTENT_CACHE_BYTES)

    def test_missing_file_is_not_cached_and_later_reads_stay_in_sync(self) -> None:
        oid, data = _oid(1), b"source\0\n"
        process = BatchProcess(BytesIO(
            b"first:missing.h missing\n" + _contents(oid, data)
        ))
        reader = self.reader(process)
        with self.assertRaises(FileNotFoundError) as raised:
            reader.read_file("first", "./missing.h")
        self.assertEqual(str(raised.exception), "first:missing.h")
        self.assertEqual(reader.read_file("second", "missing.h"), data)

    def test_invalid_paths_and_newlines_do_not_send_commands_even_after_cache_hit(self) -> None:
        oid, data = _oid(1), b"source"
        process = BatchProcess(BytesIO(_contents(oid, data)))
        reader = self.reader(process)
        reader.read_file("HEAD", "source.c")
        commands = process.commands()
        for path in ("/source.c", "../source.c", "..", "a/../../source.c"):
            with self.subTest(path=path), self.assertRaises(FileNotFoundError):
                reader.read_file("HEAD", path)
        for commit, path in (("HEAD\ninfo HEAD", "source.c"), ("HEAD", "source.c\n")):
            with self.subTest(commit=commit, path=path), self.assertRaises(ValueError):
                reader.read_file(commit, path)
        self.assertEqual(process.commands(), commands)

    def test_failed_headers_preserve_read_errors(self) -> None:
        for response, message in (
            (b"", "terminated unexpectedly"),
            (b"bad header\n", "Unexpected git cat-file response"),
            (b"oid blob size\n", "Unexpected git cat-file object size"),
        ):
            with self.subTest(response=response):
                reader = self.reader(BatchProcess(BytesIO(response)))
                with self.assertRaisesRegex(RuntimeError, message):
                    reader.read_file("HEAD", "source.c")
                self.assertEqual(reader._content_bytes, 0)

    def test_contents_failures_do_not_populate_cache(self) -> None:
        oid, data = _oid(1), b"source"
        for response, error, message in (
            (b"", RuntimeError, "terminated unexpectedly"),
            (oid + b" missing\n", FileNotFoundError, "HEAD:source.c"),
            (b"bad header\n", RuntimeError, "Unexpected git cat-file response"),
            (_info(oid, data) + b"sho", RuntimeError, "Truncated"),
            (_info(oid, data) + data + b"!", RuntimeError, "Truncated"),
        ):
            with self.subTest(response=response):
                reader = self.reader(BatchProcess(BytesIO(_info(oid, data) + response)))
                reader._remember_path("source.c")
                with self.assertRaisesRegex(error, message):
                    reader.read_file("HEAD", "source.c")
                self.assertFalse(reader._contents)
                self.assertEqual(reader._content_bytes, 0)

    def test_fake_repo_fallback_preserves_arguments_and_errors(self) -> None:
        repo = FallbackRepo()
        with patch("kpatch.filter.repository_file.subprocess.Popen") as popen:
            with RepositoryFileReader(repo) as reader:
                self.assertEqual(reader.read_file("HEAD\n", "../source.c"), b"fallback")
                repo.error = subprocess.CalledProcessError(128, "fake read")
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    reader.read_file("invalid", "/source.c")
                self.assertIs(raised.exception, repo.error)
            popen.assert_not_called()
        self.assertEqual(repo.expressions, ["HEAD\n:../source.c", "invalid:/source.c"])

    def test_close_reaps_process_clears_cache_and_is_idempotent(self) -> None:
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                process = BatchProcess(BytesIO(), timeout=timeout)
                reader = self.reader(process)
                reader._cache_contents(_oid(1), b"source")
                reader.close()
                reader.close()
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
                self.assertEqual(process.waits, [5, None] if timeout else [5])
                self.assertEqual(process.terminated, timeout)
                self.assertIsNone(reader._process)
                self.assertFalse(reader._contents)
                self.assertFalse(reader._paths)
                self.assertEqual(reader._content_bytes, 0)

    def test_rotation_preserves_oid_and_path_cache(self) -> None:
        oid, data = _oid(1), b"obj-y += source.o\n"
        first = BatchProcess(BytesIO(_contents(oid, data)))
        second = BatchProcess(BytesIO(_info(oid, data)))
        with (
            patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 1),
            patch(
                "kpatch.filter.repository_file.subprocess.Popen",
                side_effect=[first, second],
            ) as popen,
            RepositoryFileReader(GitRepo(Path("unused"))) as reader,
        ):
            initial = reader.read_file("first", "Makefile")
            self.assertEqual(popen.call_count, 1)
            self.assertIs(reader.read_file("second", "Makefile"), initial)
            self.assertEqual(reader._content_bytes, len(data))
            self.assertEqual(list(reader._contents), [oid])
            self.assertEqual(list(reader._paths), ["Makefile"])
            self.assertEqual(reader._process_reads, 1)
            self.assertEqual(popen.call_count, 2)
            self.assertTrue(first.stdout.closed)
            self.assertFalse(second.stdout.closed)
        self.assertEqual(first.commands(), [b"contents first:Makefile"])
        self.assertEqual(second.commands(), [b"info second:Makefile"])
        self.assertTrue(second.stdout.closed)
        self.assertFalse(reader._contents)
        self.assertFalse(reader._paths)

    def test_rotation_miss_reads_info_contents_and_body_from_new_process(self) -> None:
        before, after = b"before", b"after"
        first = BatchProcess(BytesIO(_contents(_oid(1), before)))
        second = BatchProcess(BytesIO(
            _info(_oid(2), after) + _contents(_oid(2), after)
        ))
        with (
            patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 1),
            patch(
                "kpatch.filter.repository_file.subprocess.Popen",
                side_effect=[first, second],
            ) as popen,
            RepositoryFileReader(GitRepo(Path("unused"))) as reader,
        ):
            self.assertEqual(reader.read_file("first", "source.c"), before)
            self.assertEqual(reader.read_file("second", "source.c"), after)
            self.assertEqual(popen.call_count, 2)
            self.assertEqual(reader._process_reads, 1)
            self.assertEqual(second.commands(), [
                b"info second:source.c", b"contents " + _oid(2),
            ])
        self.assertEqual(first.commands(), [b"contents first:source.c"])
        self.assertTrue(second.stdout.closed)

    def test_process_read_quota_and_single_active_daemon(self) -> None:
        processes = [
            BatchProcess(BytesIO(
                _contents(_oid(1), b"1")
                + _info(_oid(2), b"2") + _contents(_oid(2), b"2")
            ), timeout=True),
            BatchProcess(BytesIO(
                _info(_oid(3), b"3") + _contents(_oid(3), b"3")
                + _info(_oid(4), b"4") + _contents(_oid(4), b"4")
            )),
            BatchProcess(BytesIO(
                _info(_oid(5), b"5") + _contents(_oid(5), b"5")
            )),
        ]
        started: list[BatchProcess] = []

        def start(
            command: list[str], *, stdin: int, stdout: int, stderr: int,
        ) -> BatchProcess:
            self.assertEqual(command[-1], "--batch-command")
            if started:
                previous = started[-1]
                self.assertTrue(previous.stdin.closed)
                self.assertTrue(previous.stdout.closed)
                self.assertEqual(previous.waits[-1], None if previous.timeout else 5)
                self.assertEqual(previous.terminated, previous.timeout)
            process = processes[len(started)]
            started.append(process)
            return process

        with (
            patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 2),
            patch("kpatch.filter.repository_file.subprocess.Popen", side_effect=start),
            RepositoryFileReader(GitRepo(Path("unused"))) as reader,
        ):
            for number in range(1, 6):
                self.assertEqual(reader.read_file(str(number), "source.c"), str(number).encode())
                self.assertLessEqual(reader._process_reads, 2)
                self.assertEqual(len(started), (number + 1) // 2)
            self.assertFalse(processes[-1].stdout.closed)
        self.assertEqual([len(p.commands()) for p in processes], [3, 4, 2])
        self.assertTrue(all(p.stdin.closed and p.stdout.closed for p in processes))
        self.assertEqual(processes[0].waits, [5, None])
        self.assertEqual(processes[1].waits, [5])
        self.assertEqual(processes[2].waits, [5])

    def test_missing_reads_count_toward_process_quota(self) -> None:
        first = BatchProcess(BytesIO(b"first:missing.h missing\n"))
        second = BatchProcess(BytesIO(_contents(_oid(1), b"later")))
        with (
            patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 1),
            patch(
                "kpatch.filter.repository_file.subprocess.Popen",
                side_effect=[first, second],
            ),
            RepositoryFileReader(GitRepo(Path("unused"))) as reader,
        ):
            with self.assertRaises(FileNotFoundError):
                reader.read_file("first", "missing.h")
            self.assertEqual(reader.read_file("second", "missing.h"), b"later")
        self.assertEqual(first.commands(), [b"contents first:missing.h"])
        self.assertEqual(second.commands(), [b"contents second:missing.h"])

    def test_early_close_at_quota_does_not_start_replacement(self) -> None:
        process = BatchProcess(BytesIO(_contents(_oid(1), b"data")))
        with (
            patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 1),
            patch(
                "kpatch.filter.repository_file.subprocess.Popen", return_value=process,
            ) as popen,
            RepositoryFileReader(GitRepo(Path("unused"))) as reader,
        ):
            self.assertEqual(reader.read_file("HEAD", "source.c"), b"data")
            reader.close()
            self.assertIsNone(reader._process)
            self.assertEqual(reader._process_reads, 0)
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(process.waits, [5])
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)

    def test_context_exit_reaps_process_on_read_error(self) -> None:
        process = BatchProcess(BytesIO())
        reader = self.reader(process)
        with self.assertRaises(RuntimeError), reader:
            reader.read_file("HEAD", "source.c")
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertEqual(process.waits, [5])

    def test_packed_snapshot_fixture_counts_actual_git_requests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)

            def git(*args: str) -> bytes:
                return subprocess.run(
                    ["git", "-C", str(repository), *args], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                ).stdout

            git("init", "--quiet")
            (repository / "include").mkdir()
            makefile = b"obj-y += source.o\n" * 4096
            header = b"struct shared;\n" * 4096
            (repository / "Makefile").write_bytes(makefile)
            (repository / "include/shared.h").write_bytes(header)
            snapshots: list[str] = []
            for number in range(8):
                (repository / "source.c").write_text(f"int value = {number};\n")
                git("add", ".")
                git(
                    "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "commit", "--quiet", "-m", "snapshot",
                )
                snapshots.append(git("rev-parse", "HEAD").decode().strip())
            git("gc", "--quiet")

            with RepositoryFileReader(GitRepo(repository)) as reader:
                process = reader._process
                with patch.object(reader, "_request", wraps=reader._request) as request:
                    for number, commit in enumerate(snapshots):
                        self.assertEqual(reader.read_file(commit, "Makefile"), makefile)
                        self.assertEqual(reader.read_file(commit, "include/shared.h"), header)
                        self.assertEqual(
                            reader.read_file(commit, "source.c"),
                            f"int value = {number};\n".encode(),
                        )
                commands = [call.args[0] for call in request.call_args_list]
                self.assertEqual(sum(c.startswith(b"contents ") for c in commands), 10)
                self.assertEqual(sum(c.startswith(b"info ") for c in commands), 21)
                self.assertIs(reader._process, process)
            assert process is not None
            self.assertEqual(process.poll(), 0)

    def test_batch_reader_handles_files_and_missing_paths_without_exiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
            (repository / "source.c").write_bytes(b"int value;\n")
            (repository / "empty.h").write_bytes(b"")
            (repository / "space name.h").write_bytes(b"space\0\n")
            subprocess.run(
                ["git", "-C", str(repository), "add", "."], check=True,
            )
            subprocess.run(
                [
                    "git", "-C", str(repository), "-c", "user.name=Test",
                    "-c", "user.email=test@example.com", "commit", "--quiet",
                    "-m", "test",
                ],
                check=True,
            )

            with (
                patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 3),
                RepositoryFileReader(GitRepo(repository)) as reader,
            ):
                first_process = reader._process
                self.assertEqual(reader.read_file("HEAD", "source.c"), b"int value;\n")
                with self.assertRaises(FileNotFoundError):
                    reader.read_file("HEAD", "missing.c")
                with self.assertRaises(FileNotFoundError):
                    reader.read_file("HEAD", "../source.c")
                self.assertEqual(reader.read_file("HEAD", "source.c"), b"int value;\n")
                self.assertEqual(reader.read_file("HEAD", "empty.h"), b"")
                self.assertEqual(reader.read_file("HEAD", "space name.h"), b"space\0\n")
                self.assertEqual(reader.read_file("HEAD", "./a/../source.c"), b"int value;\n")
                self.assertIsNot(reader._process, first_process)
            self.assertIsNone(reader._process)
            assert first_process is not None
            self.assertEqual(first_process.poll(), 0)


if __name__ == "__main__":
    unittest.main()
