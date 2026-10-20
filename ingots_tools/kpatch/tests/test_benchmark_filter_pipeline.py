from collections.abc import Generator
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, current_thread, main_thread
import unittest
from unittest.mock import patch

from benchmarks import filter_pipeline as benchmark
from kpatch.filter import FilterContext, MergeCommitFilter
from kpatch.git import GitCommit, GitRepo


def _empty_commits() -> Generator[GitCommit, None, None]:
    yield from ()


class ProcessTreeMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.proc_root = Path(self.directory.name)

    def _memory(self, pid: int, rss_kib: int, pss_kib: int) -> None:
        process = self.proc_root / str(pid)
        process.mkdir(parents=True, exist_ok=True)
        (process / "status").write_text(f"Name:\tfake\nVmRSS:\t{rss_kib} kB\n")
        (process / "smaps_rollup").write_text(
            "00000000-ffffffff ---p 00000000 00:00 0 [rollup]\n"
            f"Rss: {rss_kib} kB\nPss: {pss_kib} kB\nPss_Anon: 999 kB\n"
        )

    def _children(self, pid: int, tid: int, children: list[int]) -> None:
        task = self.proc_root / str(pid) / "task" / str(tid)
        task.mkdir(parents=True, exist_ok=True)
        (task / "children").write_text(" ".join(str(child) for child in children))

    def test_counts_root_workers_and_git_children_once_across_all_threads(self) -> None:
        self._memory(100, 1024, 512)
        self._memory(200, 2048, 1024)
        self._memory(300, 4096, 2048)
        self._memory(400, 512, 256)
        self._children(100, 100, [200, 300])
        self._children(100, 101, [300])
        self._children(200, 200, [400, 100])
        self._children(300, 300, [400])

        sample = benchmark.sample_tree_memory(100, self.proc_root, include_pss=True)

        self.assertEqual(sample.rss_kib, 7680)
        self.assertEqual(sample.pss_kib, 3840)

    def test_rss_only_samples_do_not_require_smaps_rollup(self) -> None:
        self._memory(100, 1024, 512)
        (self.proc_root / "100" / "smaps_rollup").unlink()

        sample = benchmark.sample_tree_memory(100, self.proc_root, include_pss=False)

        self.assertEqual(sample.rss_kib, 1024)
        self.assertIsNone(sample.pss_kib)

    def test_process_and_task_disappearance_is_tolerated(self) -> None:
        self._memory(100, 1024, 512)
        self._memory(200, 2048, 1024)
        self._children(100, 100, [200, 999])
        self._children(100, 101, [])
        missing_task_children = self.proc_root / "100" / "task" / "101" / "children"
        original_read = Path.read_text

        def disappearing_read(path: Path) -> str:
            if path == self.proc_root / "200" / "smaps_rollup":
                raise ProcessLookupError("process exited after discovery")
            if path == missing_task_children:
                raise FileNotFoundError("thread exited after discovery")
            return original_read(path)

        with patch.object(Path, "read_text", disappearing_read):
            sample = benchmark.sample_tree_memory(100, self.proc_root, include_pss=True)

        self.assertEqual(sample.rss_kib, 1024)
        self.assertEqual(sample.pss_kib, 512)

    def test_peak_is_maximum_simultaneous_total_not_sum_of_individual_peaks(self) -> None:
        self._memory(100, 1024, 512)
        self._memory(200, 4096, 2048)
        self._children(100, 100, [200])
        sampler = benchmark.ProcessTreeMemorySampler(
            100, proc_root=self.proc_root, rss_interval=10, pss_interval=10
        )
        sampler.start()
        try:
            self._memory(100, 4096, 2048)
            self._memory(200, 1024, 512)
        finally:
            sampler.stop()

        self.assertEqual(sampler.peak_tree_rss_mib, 5)
        self.assertEqual(sampler.peak_tree_pss_mib, 2.5)
        self.assertFalse(sampler._thread.is_alive())

    def test_sampler_runs_in_background_and_stop_joins(self) -> None:
        self._memory(100, 1024, 512)
        background_sampled = Event()
        background_pss_sampled = Event()
        original_sample = benchmark.sample_tree_memory

        def record_sample(
            root_pid: int, proc_root: Path, *, include_pss: bool
        ) -> benchmark.TreeMemorySample:
            if current_thread() is not main_thread():
                background_sampled.set()
                if include_pss:
                    background_pss_sampled.set()
            return original_sample(root_pid, proc_root, include_pss=include_pss)

        sampler = benchmark.ProcessTreeMemorySampler(
            100, proc_root=self.proc_root, rss_interval=0.01, pss_interval=0.03
        )
        with patch.object(benchmark, "sample_tree_memory", side_effect=record_sample):
            sampler.start()
            try:
                self.assertTrue(background_sampled.wait(2))
                self.assertTrue(background_pss_sampled.wait(2))
            finally:
                sampler.stop()

        self.assertTrue(sampler._stop.is_set())
        self.assertFalse(sampler._thread.is_alive())

    def test_sampling_intervals_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            benchmark.ProcessTreeMemorySampler(100, rss_interval=0)
        with self.assertRaisesRegex(ValueError, "positive"):
            benchmark.ProcessTreeMemorySampler(100, pss_interval=-1)


class FilterBenchmarkTests(unittest.TestCase):
    def _assert_workers(self, arguments: list[str], expected: int) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "unused.sqlite"
            database.touch()
            config = root / "kernel.config"
            config.write_text("CONFIG_TEST=y\n")
            context = FilterContext(GitRepo(root))
            sampler = benchmark.ProcessTreeMemorySampler(
                100, proc_root=root, rss_interval=10, pss_interval=10
            )
            output = StringIO()
            with (
                patch("sys.argv", [
                    "filter_pipeline.py", "--db", str(database),
                    "--config", str(config), *arguments,
                ]),
                patch.object(benchmark, "GitDb"),
                patch.object(benchmark.FilterContext, "from_db_range", return_value=context),
                patch.object(benchmark, "ConfigFilter", return_value=MergeCommitFilter()) as configured,
                patch.object(benchmark, "FilterPipeline") as pipeline,
                patch.object(benchmark, "ProcessTreeMemorySampler", return_value=sampler),
                redirect_stdout(output),
            ):
                pipeline.return_value.iter_filter_commits.return_value = _empty_commits()
                benchmark.main()
                configured.assert_called_once()
                self.assertEqual(configured.call_args.kwargs, {"workers": expected})
            result = benchmark.BenchmarkResult(**json.loads(output.getvalue()))
            self.assertEqual(result.workers, expected)
            self.assertEqual(result.input_commits, 0)
            self.assertEqual(result.output_commits, 0)
            self.assertEqual(result.output_sha256, hashlib.sha256().hexdigest())
            self.assertEqual(result.peak_tree_rss_mib, 0)
            self.assertEqual(result.peak_tree_pss_mib, 0)
            self.assertFalse(sampler._thread.is_alive())

    def test_default_and_explicit_workers_are_in_json(self) -> None:
        self._assert_workers([], 4)
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                self._assert_workers(["--workers", str(workers)], workers)

    def test_nonpositive_workers_fail_before_loading_database(self) -> None:
        for workers in ("0", "-1"):
            with (
                self.subTest(workers=workers),
                patch("sys.argv", ["filter_pipeline.py", "--workers", workers]),
                patch.object(benchmark, "GitDb") as database,
                redirect_stderr(StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                benchmark.main()
            self.assertEqual(raised.exception.code, 2)
            database.assert_not_called()

    def test_cap_guard_rejects_long_or_nonpositive_ranges(self) -> None:
        for start, end in (
            ("07-01-2026", "10-03-2026"),
            ("07-01-2026", "07-01-2026"),
            ("08-01-2026", "07-01-2026"),
        ):
            with (
                self.subTest(start=start, end=end),
                patch("sys.argv", ["filter_pipeline.py", "--start", start, "--end", end]),
                patch.object(benchmark, "GitDb") as database,
                redirect_stderr(StringIO()) as errors,
                self.assertRaises(SystemExit) as raised,
            ):
                benchmark.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("at most 93 days", errors.getvalue())
            database.assert_not_called()

    def test_sampler_is_stopped_and_joined_when_loading_fails(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "unused.sqlite"
            database.touch()
            sampler = benchmark.ProcessTreeMemorySampler(
                100, proc_root=root, rss_interval=10, pss_interval=10
            )
            with (
                patch("sys.argv", ["filter_pipeline.py", "--db", str(database)]),
                patch.object(benchmark, "ProcessTreeMemorySampler", return_value=sampler),
                patch.object(benchmark, "GitDb", side_effect=RuntimeError("load failed")),
                self.assertRaisesRegex(RuntimeError, "load failed"),
            ):
                benchmark.main()
            self.assertTrue(sampler._stop.is_set())
            self.assertFalse(sampler._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
