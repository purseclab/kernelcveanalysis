from concurrent.futures import CancelledError, Future, ProcessPoolExecutor
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from kpatch.diff import Diff
from kpatch.filter import (
    ConfigFilter,
    FileBuildModes,
    FilterContext,
    FilteredCommit,
    FilterPipeline,
    IfdefFilter,
    MergeCommitFilter,
    WhitespaceFilter,
)
from kpatch.filter.config import parallel
from kpatch.filter.config.decisions import FileKey, changed_paths, decide_commit
from kpatch.filter.config.history import (
    ConfigHistoryReader,
    ConfigHistoryStore,
    FileDecision,
    HistoryCommit,
    PrimaryHistory,
    parse_history_diff,
)
from kpatch.filter.config.parallel import (
    RootJob,
    RootResult,
    _WorkerSettings,
    _initialize_worker,
    _root_jobs,
    _run_root,
    _shutdown_executor,
    _submit_roots,
    collect_parallel_decisions,
)
from kpatch.filter.config.traversal import walk_history
from kpatch.filter.config_filter import (
    ConfigValue,
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
    SourceAnalysisCache,
)
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.filter.source_filter import SourceIncludeIndex
from kpatch.git import CommitParent, GitCommit, GitRepo, StructuredCommits


type Decisions = dict[str, dict[FileKey, FileDecision]]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    commit: GitCommit
    build_modes: dict[FileKey, FileBuildModes]


@dataclass(frozen=True, slots=True)
class WorkerObservation:
    worker_pid: int
    git_pid: int
    source_identity: int
    makefile_identity: int
    analysis_identity: int
    source_entries: int
    makefile_entries: int
    content_entries: int
    content_bytes: int


def observe_worker() -> WorkerObservation:
    resources = parallel._worker_resources
    assert resources is not None
    process = resources.file_reader._process
    assert process is not None
    return WorkerObservation(
        os.getpid(),
        process.pid,
        id(resources.source_includes),
        id(resources.makefile_cache),
        id(resources.source_cache),
        len(resources.source_cache),
        len(resources.makefile_cache),
        len(resources.file_reader._contents),
        resources.file_reader._content_bytes,
    )


def cancel_after_first_commit(job: RootJob) -> RootResult:
    resources = parallel._worker_resources
    assert resources is not None

    def decide_and_cancel(
        state: KbuildState, commit: HistoryCommit, diff: Diff
    ) -> dict[FileKey, FileDecision]:
        result = decide_commit(state, commit, diff)
        resources.cancellation.set()
        return result

    with patch.object(parallel, "decide_commit", side_effect=decide_and_cancel):
        return _run_root(job)


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class RepositoryFixture:
    """Several selected roots share an excluded parent, with an interior merge."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.headers: dict[str, HistoryCommit] = {}
        self.diffs: dict[str, Diff] = {}
        self.git("init", "--quiet")
        self.git("config", "user.name", "Parallel Test")
        self.git("config", "user.email", "parallel@example.com")
        self.write({
            "Kbuild": "obj-y += drivers/\n",
            "drivers/Makefile": "obj-y += wrapper.o\n",
            "drivers/wrapper.c": '#include "before.h"\nint value;\n',
            "drivers/before.h": "#define BEFORE 1\n",
            "drivers/after.h": "#define AFTER 1\n",
            "drivers/extra.c": "int extra;\n",
            "drivers/hidden.c": "int hidden;\n",
        })
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "excluded base")
        base = self.git("rev-parse", "HEAD").strip()
        self.roots: list[str] = []
        for number in range(6):
            self.git("checkout", "--quiet", "-b", f"root-{number}", base)
            root = self.commit({
                "drivers/wrapper.c": (
                    '#include "before.h"\n'
                    f"int value = {number};\n"
                )
            })
            self.roots.append(root)
            if number == 0:
                self.add_fork_and_merge(root)
                continue
            for step in range(number % 3):
                self.commit({"drivers/before.h": f"#define BEFORE {step + 2}\n"})

        children: dict[str, list[str]] = {commit_id: [] for commit_id in self.headers}
        for header in self.headers.values():
            if header.parent_id in children:
                children[header.parent_id].append(header.commit_id)
        sizes: dict[str, int] = {}
        for commit_id in reversed(self.headers):
            sizes[commit_id] = 1 + sum(sizes[child] for child in children[commit_id])
        self.history = PrimaryHistory(self.headers, children, sizes, tuple(self.roots))
        self.root_sizes = {root: sizes[root] for root in self.roots}
        paths = {path for diff in self.diffs.values() for path in changed_paths(diff)}
        self.index = SourceIncludeIndex.from_repository(
            GitRepo(path), self.git("rev-parse", "HEAD").strip(), "", paths
        )
        for diff in self.diffs.values():
            self.index.add_diff(diff)

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.path), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

    def write(self, files: dict[str, str]) -> None:
        for name, contents in files.items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)

    def record(self) -> str:
        ids = self.git("rev-list", "--parents", "-n", "1", "HEAD").split()
        commit_id, *parents = ids
        self.headers[commit_id] = HistoryCommit(commit_id, tuple(parents))
        self.diffs[commit_id] = parse_history_diff(
            self.git("diff", "--binary", parents[0], commit_id)
        )
        return commit_id

    def commit(self, files: dict[str, str]) -> str:
        self.write(files)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "selected change")
        return self.record()

    def add_fork_and_merge(self, root: str) -> None:
        self.git("checkout", "--quiet", "-b", "side", root)
        self.commit({
            "drivers/wrapper.c": '#include "after.h"\nint value = 0;\n'
        })
        self.git("checkout", "--quiet", "root-0")
        self.commit({"drivers/Makefile": "obj-m += wrapper.o extra.o\n"})
        self.git("merge", "--quiet", "--no-ff", "side", "-m", "selected merge")
        self.merge_id = self.record()
        self.post_merge = self.commit({"drivers/after.h": "#define AFTER 2\n"})
        self.commit({
            "drivers/Makefile": "obj-y += wrapper.o\n",
            "drivers/wrapper.c": (
                "#ifdef CONFIG_OPTIONAL\n"
                '#include "hidden.c"\n'
                "#endif\n"
                '#include "after.h"\n'
                "#if 0\nint inactive = 0;\n#endif\nint value = 0;\n"
            ),
        })
        self.active_change_id = self.commit({
            "drivers/wrapper.c": (
                "#ifdef CONFIG_OPTIONAL\n"
                '#include "hidden.c"\n'
                "#endif\n"
                '#include "after.h"\n'
                "#if 0\nint inactive = 1;\n#endif\nint value = 1;\n"
            ),
        })
        self.whitespace_id = self.commit({
            "drivers/wrapper.c": (
                "#ifdef CONFIG_OPTIONAL\n"
                '#include "hidden.c"\n'
                "#endif\n"
                '#include "after.h"\n'
                "#if 0\nint inactive = 1;\n#endif\nint  value = 1;\n"
            ),
        })

    def git_commits(self) -> list[GitCommit]:
        commits: list[GitCommit] = []
        for ordinal, header in enumerate(self.headers.values()):
            date = datetime(2026, 7, 1, tzinfo=UTC) + timedelta(seconds=ordinal)
            parents = tuple(
                CommitParent(
                    parent_id,
                    self.git("diff", "--binary", parent_id, header.commit_id)
                    if index == 0 else "",
                )
                for index, parent_id in enumerate(header.parent_ids)
            )
            commits.append(GitCommit(
                header.commit_id, "Fixture", "fixture@example.test", date, date,
                parents, f"fixture-{ordinal}",
            ))
        return commits

    def populate(self, store: ConfigHistoryStore) -> None:
        for commit_id, header in self.headers.items():
            store.add_history(header, self.diffs[commit_id], self.history.subtree_sizes[commit_id])
        store.commit()

    def serial_decisions(self, config: KernelConfig) -> Decisions:
        repo = GitRepo(self.path)
        makefiles = KbuildMakefileCache(config)
        analyses = SourceAnalysisCache(config, self.index)
        results: Decisions = {}
        with RepositoryFileReader(repo) as reader:
            def create_state(commit_id: str) -> KbuildState:
                return KbuildState(
                    repo,
                    config,
                    self.headers[commit_id].parent_id or commit_id,
                    self.index,
                    reader.read_file,
                    makefile_cache=makefiles,
                    source_analysis_cache=analyses,
                )

            for visit in walk_history(self.history, create_state):
                results[visit.commit_id] = decide_commit(
                    visit.state, self.headers[visit.commit_id], self.diffs[visit.commit_id]
                )
        return results

    def decision_hash(self, decisions: Decisions) -> str:
        ordered = [
            (commit_id, [
                (old_path, path, modes.old, modes.new)
                for (old_path, path), modes in sorted(
                    decisions[commit_id].items(),
                    key=lambda item: (item[0][0] or "", item[0][1]),
                )
            ])
            for commit_id in self.headers
        ]
        return sha256(json.dumps(ordered).encode()).hexdigest()


class RootSchedulingTests(unittest.TestCase):
    def test_jobs_are_whole_roots_largest_first_and_id_only(self) -> None:
        jobs = list(_root_jobs({"small": 1, "large": 20, "middle": 5}, Path("shards")))
        self.assertEqual([job.root_id for job in jobs], ["large", "middle", "small"])
        self.assertEqual([job.ordinal for job in jobs], [0, 1, 2])
        self.assertEqual(jobs[1].shard_path, Path("shards/root-1.sqlite"))
        self.assertEqual(RootJob.__slots__, ("root_id", "ordinal", "shard_path"))
        self.assertEqual(RootResult.__slots__, ("root_id", "processed_commits", "shard_path"))

    def test_shutdown_defers_its_first_interrupt_until_every_worker_has_joined(self) -> None:
        executor = Mock(spec=ProcessPoolExecutor)
        interruption = KeyboardInterrupt("shutdown interrupted")
        executor.shutdown.side_effect = [interruption, None]
        with self.assertRaises(KeyboardInterrupt) as raised:
            _shutdown_executor(executor, propagate_interrupt=True)
        self.assertIs(raised.exception, interruption)
        self.assertEqual(executor.shutdown.call_count, 2)
        for call in executor.shutdown.call_args_list:
            self.assertEqual(call.kwargs, {"wait": True, "cancel_futures": True})

    def test_outstanding_jobs_never_exceed_twice_workers(self) -> None:
        executor = Mock(spec=ProcessPoolExecutor)
        executor.submit.side_effect = lambda *args: Future()
        jobs = _root_jobs({str(number): number + 1 for number in range(100)}, Path("."))
        pending: set[Future[RootResult]] = set()
        _submit_roots(executor, jobs, pending, 8)
        self.assertEqual(len(pending), 8)
        self.assertEqual(executor.submit.call_count, 8)
        _submit_roots(executor, jobs, pending, 8)
        self.assertEqual(executor.submit.call_count, 8)
        pending.pop().set_result(RootResult("99", 100, Path("unused")))
        _submit_roots(executor, jobs, pending, 8)
        self.assertEqual(len(pending), 8)
        self.assertEqual(executor.submit.call_count, 9)
        for call in executor.submit.call_args_list:
            self.assertEqual(len(call.args), 2)
            self.assertIs(call.args[0], _run_root)


class ParallelConfigTests(unittest.TestCase):
    fixture_directory: TemporaryDirectory[str]
    fixture: RepositoryFixture

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_directory = TemporaryDirectory(prefix="kpatch-parallel-test-")
        cls.fixture = RepositoryFixture(Path(cls.fixture_directory.name))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_directory.cleanup()

    def test_spawn_one_two_four_workers_match_serial_decisions_and_hash(self) -> None:
        config = KernelConfig("")
        fixture = self.fixture
        expected = fixture.serial_decisions(config)
        self.assertEqual(expected[fixture.merge_id], {})
        self.assertEqual(
            expected[fixture.post_merge][(None, "drivers/after.h")],
            FileDecision(ConfigValue.MODULE, ConfigValue.MODULE),
        )
        expected_hash = fixture.decision_hash(expected)
        for workers in (1, 2, 4):
            with self.subTest(workers=workers), ConfigHistoryStore() as store:
                fixture.populate(store)
                before = set(store.path.parent.iterdir())
                collect_parallel_decisions(
                    config, fixture.path, store, fixture.index,
                    fixture.root_sizes, workers, False,
                )
                actual = {commit_id: store.get_decisions(commit_id) for commit_id in fixture.headers}
                self.assertEqual(actual, expected)
                self.assertEqual(fixture.decision_hash(actual), expected_hash)
                self.assertEqual(set(store.path.parent.iterdir()), before)

    def run_pipeline(self, commits: list[GitCommit], workers: int) -> list[PipelineResult]:
        config = KernelConfig("")
        pipeline = FilterPipeline([
            MergeCommitFilter(), ConfigFilter(config, workers=workers),
            IfdefFilter(config), WhitespaceFilter(),
        ])
        context = FilterContext(
            GitRepo(self.fixture.path), StructuredCommits.from_commits(commits)
        )
        mutable = (FilteredCommit.from_commit(commit) for commit in commits)
        with closing(mutable), closing(pipeline.iter_filter_mutable_commits(
            mutable, context, show_progress=False, total=len(commits),
        )) as filtered:
            return [
                PipelineResult(commit.materialize(), dict(commit.build_modes))
                for commit in filtered
            ]

    def test_full_pipeline_spawn_preserves_order_build_modes_and_materialized_patches(self) -> None:
        commits = self.fixture.git_commits()
        original_patches = [commit.diff_str for commit in commits]
        expected = self.run_pipeline(commits, workers=1)
        self.assertTrue(expected)
        retained_ids = [result.commit.commit_id for result in expected]
        self.assertNotIn(self.fixture.merge_id, retained_ids)
        self.assertNotIn(self.fixture.whitespace_id, retained_ids)
        active = next(
            result for result in expected
            if result.commit.commit_id == self.fixture.active_change_id
        )
        self.assertIn("+int value = 1;", active.commit.diff_str)
        self.assertNotIn("+int inactive = 1;", active.commit.diff_str)
        self.assertIn(" int inactive = 0;", active.commit.diff_str)
        self.assertEqual(
            active.build_modes[(None, "drivers/wrapper.c")],
            FileBuildModes(ConfigValue.ENABLED, ConfigValue.ENABLED),
        )
        module = next(
            result for result in expected
            if result.commit.commit_id == self.fixture.post_merge
        )
        self.assertEqual(
            module.build_modes[(None, "drivers/after.h")],
            FileBuildModes(ConfigValue.MODULE, ConfigValue.MODULE),
        )
        self.assertEqual(retained_ids, [
            commit.commit_id for commit in commits if commit.commit_id in retained_ids
        ])
        for workers in (2, 4):
            with self.subTest(workers=workers):
                actual = self.run_pipeline(commits, workers)
                self.assertEqual(actual, expected)
                self.assertEqual(
                    [(result.commit.commit_id, result.commit.diff_str) for result in actual],
                    [(result.commit.commit_id, result.commit.diff_str) for result in expected],
                )
        self.assertEqual([commit.diff_str for commit in commits], original_patches)

    def test_config_filter_rejects_zero_workers(self) -> None:
        with self.assertRaisesRegex(ValueError, "workers"):
            ConfigFilter(KernelConfig(""), workers=0)

    def test_single_primary_root_requested_four_workers_uses_serial_fallback(self) -> None:
        commits = [
            commit for commit in self.fixture.git_commits()
            if commit.commit_id == self.fixture.roots[0]
        ]
        expected = self.run_pipeline(commits, workers=1)
        self.assertTrue(expected)
        with patch(
            "kpatch.filter.config.collect_parallel_decisions",
            side_effect=AssertionError("A single root must not spawn workers"),
        ) as collect:
            self.assertEqual(self.run_pipeline(commits, workers=4), expected)
            collect.assert_not_called()

    def make_settings(self, store: ConfigHistoryStore) -> _WorkerSettings:
        snapshot = store.path.parent / "source-index.json"
        self.fixture.index.write_snapshot(snapshot)
        return _WorkerSettings(KernelConfig(""), self.fixture.path, store.path, snapshot)

    def test_worker_distinguishes_empty_parent_id_from_absent_parent(self) -> None:
        headers = (
            HistoryCommit("empty-parent", ("",)),
            HistoryCommit("absent-parent", ()),
        )
        config = KernelConfig("")
        repo = GitRepo(self.fixture.path)
        with ConfigHistoryStore() as store, RepositoryFileReader(repo) as reader:
            for header in headers:
                store.add_history(header, Diff.parse(""), 1)
            store.commit()
            with ConfigHistoryReader(store.path) as history:
                resources = parallel._WorkerResources(
                    config, repo, history, self.fixture.index, reader,
                    KbuildMakefileCache(config), SourceAnalysisCache(config, self.fixture.index),
                    multiprocessing.get_context("spawn").Event(),
                )
                with (
                    patch.object(parallel, "_worker_resources", resources),
                    patch.object(parallel, "KbuildState", wraps=KbuildState) as create,
                ):
                    for ordinal, header in enumerate(headers):
                        result = _run_root(RootJob(
                            header.commit_id, ordinal, store.path.parent / f"root-{ordinal}.sqlite",
                        ))
                        self.assertEqual(result.processed_commits, 1)
                    self.assertEqual(
                        [call.args[2] for call in create.call_args_list],
                        ["", "absent-parent"],
                    )

    def test_worker_reuses_bounded_resources_and_reaps_git_on_shutdown(self) -> None:
        context = multiprocessing.get_context("spawn")
        with ConfigHistoryStore() as store:
            self.fixture.populate(store)
            settings = self.make_settings(store)
            with ProcessPoolExecutor(
                max_workers=1, mp_context=context, initializer=_initialize_worker,
                initargs=(settings, context.Event()),
            ) as executor:
                before = executor.submit(observe_worker).result(timeout=20)
                for job in _root_jobs(self.fixture.root_sizes, store.path.parent):
                    result = executor.submit(_run_root, job).result(timeout=20)
                    self.assertEqual(result.processed_commits, self.fixture.root_sizes[job.root_id])
                    self.assertTrue(result.shard_path.exists())
                after = executor.submit(observe_worker).result(timeout=20)
            self.assertEqual(before.worker_pid, after.worker_pid)
            self.assertEqual(before.git_pid, after.git_pid)
            self.assertEqual(before.source_identity, after.source_identity)
            self.assertEqual(before.makefile_identity, after.makefile_identity)
            self.assertEqual(before.analysis_identity, after.analysis_identity)
            self.assertGreater(after.source_entries, 0)
            self.assertGreater(after.makefile_entries, 0)
            self.assertLessEqual(after.source_entries, 4096)
            self.assertLessEqual(after.makefile_entries, 1024)
            self.assertLessEqual(after.content_entries, 4096)
            self.assertLessEqual(after.content_bytes, 16 * 1024 * 1024)
            self.assertFalse(process_exists(after.worker_pid))
            self.assertFalse(process_exists(after.git_pid))

    def test_worker_cancellation_stops_before_next_commit_and_closes_shard(self) -> None:
        context = multiprocessing.get_context("spawn")
        cancellation = context.Event()
        with ConfigHistoryStore() as store:
            self.fixture.populate(store)
            settings = self.make_settings(store)
            job = next(_root_jobs(self.fixture.root_sizes, store.path.parent))
            with ProcessPoolExecutor(
                max_workers=1, mp_context=context, initializer=_initialize_worker,
                initargs=(settings, cancellation),
            ) as executor:
                before = executor.submit(observe_worker).result(timeout=20)
                with self.assertRaises(CancelledError):
                    executor.submit(cancel_after_first_commit, job).result(timeout=20)
                self.assertTrue(cancellation.is_set())
                # The failed shard is closed, so it can be removed before the
                # worker exits. It is never merged into the parent's store.
                job.shard_path.unlink()
                self.assertEqual(store.get_decisions(job.root_id), {})
            self.assertFalse(process_exists(before.worker_pid))
            self.assertFalse(process_exists(before.git_pid))

    def test_spawn_worker_failure_cancels_pool_and_removes_temporary_files(self) -> None:
        existing = {process.pid for process in multiprocessing.active_children()}
        with ConfigHistoryStore() as store:
            self.fixture.populate(store)
            before = set(store.path.parent.iterdir())
            roots = {"unknown-root": 1000, **self.fixture.root_sizes}
            with self.assertRaises(KeyError):
                collect_parallel_decisions(
                    KernelConfig(""), self.fixture.path, store, self.fixture.index,
                    roots, 2, False,
                )
            self.assertEqual(set(store.path.parent.iterdir()), before)
        self.assertEqual({process.pid for process in multiprocessing.active_children()}, existing)

    def test_interrupt_sets_event_cancels_queued_futures_and_waits_for_shutdown(self) -> None:
        context = multiprocessing.get_context("spawn")
        cancellation = context.Event()
        future: Future[RootResult] = Future()
        executor = Mock(spec=ProcessPoolExecutor)
        executor.submit.return_value = future
        with ConfigHistoryStore() as store:
            self.fixture.populate(store)
            before = set(store.path.parent.iterdir())
            with (
                patch.object(context, "Event", return_value=cancellation),
                patch.object(parallel, "ProcessPoolExecutor", return_value=executor),
                patch.object(parallel, "wait", side_effect=KeyboardInterrupt),
                self.assertRaises(KeyboardInterrupt),
            ):
                collect_parallel_decisions(
                    KernelConfig(""), self.fixture.path, store, self.fixture.index,
                    {self.fixture.roots[0]: 6}, 2, False,
                )
            self.assertTrue(cancellation.is_set())
            self.assertTrue(future.cancelled())
            executor.shutdown.assert_called_once_with(wait=True, cancel_futures=True)
            self.assertEqual(set(store.path.parent.iterdir()), before)

    def test_repeated_shutdown_interrupt_preserves_original_error_and_scratch_until_join(self) -> None:
        context = multiprocessing.get_context("spawn")
        for original in (KeyboardInterrupt("original interrupt"), ValueError("original failure")):
            with self.subTest(error=type(original).__name__), ConfigHistoryStore() as store:
                self.fixture.populate(store)
                before = set(store.path.parent.iterdir())
                cancellation = context.Event()
                future: Future[RootResult] = Future()
                executor = Mock(spec=ProcessPoolExecutor)
                executor.submit.return_value = future
                outcomes = [KeyboardInterrupt("second interrupt"), None]

                def shutdown(*, wait: bool, cancel_futures: bool) -> None:
                    self.assertTrue(wait)
                    self.assertTrue(cancel_futures)
                    self.assertTrue(cancellation.is_set())
                    self.assertTrue(future.cancelled())
                    snapshots = list(store.path.parent.glob("parallel-*/source-includes.json"))
                    self.assertEqual(len(snapshots), 1)
                    self.assertGreater(snapshots[0].stat().st_size, 0)
                    outcome = outcomes.pop(0)
                    if outcome is not None:
                        raise outcome

                executor.shutdown.side_effect = shutdown
                with (
                    patch.object(context, "Event", return_value=cancellation),
                    patch.object(parallel, "ProcessPoolExecutor", return_value=executor),
                    patch.object(parallel, "wait", side_effect=original),
                    self.assertRaises(type(original)) as raised,
                ):
                    collect_parallel_decisions(
                        KernelConfig(""), self.fixture.path, store, self.fixture.index,
                        {self.fixture.roots[0]: 8}, 2, False,
                    )
                self.assertIs(raised.exception, original)
                self.assertEqual(executor.shutdown.call_count, 2)
                self.assertEqual(outcomes, [])
                self.assertEqual(set(store.path.parent.iterdir()), before)

    def test_nonpositive_worker_count_is_rejected_before_allocating(self) -> None:
        with ConfigHistoryStore() as store, self.assertRaises(ValueError):
            collect_parallel_decisions(
                KernelConfig(""), self.fixture.path, store, self.fixture.index,
                self.fixture.root_sizes, 0, False,
            )


if __name__ == "__main__":
    unittest.main()
