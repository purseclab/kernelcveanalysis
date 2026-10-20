"""Spawned, bounded execution of whole existing primary-root subtrees."""

from collections.abc import Iterator
from concurrent.futures import CancelledError, Future, ProcessPoolExecutor, wait
from concurrent.futures import FIRST_COMPLETED
from dataclasses import dataclass
import multiprocessing
from multiprocessing.synchronize import Event
from multiprocessing.util import Finalize
from pathlib import Path
import signal
from tempfile import TemporaryDirectory

from ..base import filter_progress
from ..config_filter import (
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
    SourceAnalysisCache,
)
from ..repository_file import RepositoryFileReader
from ..source_filter import SourceIncludeIndex
from ...git import GitRepo
from .decisions import decide_commit
from .history import ConfigHistoryReader, ConfigHistoryStore, DecisionShard
from .traversal import walk_history


@dataclass(frozen=True, slots=True)
class RootJob:
    root_id: str
    ordinal: int
    shard_path: Path


@dataclass(frozen=True, slots=True)
class RootResult:
    root_id: str
    processed_commits: int
    shard_path: Path


@dataclass(frozen=True, slots=True)
class _WorkerSettings:
    config: KernelConfig
    repo_path: Path
    history_path: Path
    source_snapshot_path: Path


@dataclass(slots=True)
class _WorkerResources:
    config: KernelConfig
    repo: GitRepo
    history: ConfigHistoryReader
    source_includes: SourceIncludeIndex
    file_reader: RepositoryFileReader
    makefile_cache: KbuildMakefileCache
    source_cache: SourceAnalysisCache
    cancellation: Event


_worker_resources: _WorkerResources | None = None


def _close_worker_resources(
    file_reader: RepositoryFileReader,
    history: ConfigHistoryReader,
) -> None:
    # multiprocessing workers bypass ordinary atexit handlers. Finalize runs
    # before their process exits, and explicitly reaps the Git child as well.
    try:
        file_reader.close()
    finally:
        history.close()


def _initialize_worker(settings: _WorkerSettings, cancellation: Event) -> None:
    global _worker_resources

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    source_includes = SourceIncludeIndex.read_snapshot(settings.source_snapshot_path)
    history = ConfigHistoryReader(settings.history_path)
    try:
        repo = GitRepo(settings.repo_path)
        file_reader = RepositoryFileReader(repo)
    except BaseException:
        history.close()
        raise
    Finalize(
        None,
        _close_worker_resources,
        args=(file_reader, history),
        exitpriority=10,
    )
    _worker_resources = _WorkerResources(
        settings.config,
        repo,
        history,
        source_includes,
        file_reader,
        KbuildMakefileCache(settings.config),
        SourceAnalysisCache(settings.config, source_includes),
        cancellation,
    )


def _run_root(job: RootJob) -> RootResult:
    resources = _worker_resources
    if resources is None:
        raise RuntimeError("Configuration root worker was not initialized")
    if resources.cancellation.is_set():
        raise CancelledError("Configuration preparation was cancelled")
    history = resources.history.load_root(job.root_id)

    def create_state(commit_id: str) -> KbuildState:
        header = history.commits[commit_id]
        return KbuildState(
            resources.repo,
            resources.config,
            header.parent_id if header.parent_id is not None else commit_id,
            resources.source_includes,
            resources.file_reader.read_file,
            makefile_cache=resources.makefile_cache,
            source_analysis_cache=resources.source_cache,
        )

    processed = 0
    with DecisionShard(job.shard_path) as shard:
        for visit in walk_history(history, create_state):
            if resources.cancellation.is_set():
                raise CancelledError("Configuration preparation was cancelled")
            decisions = decide_commit(
                visit.state,
                history.commits[visit.commit_id],
                resources.history.get_history(visit.commit_id),
            )
            shard.add_decisions(visit.commit_id, decisions)
            processed += 1
        shard.commit()
    return RootResult(job.root_id, processed, job.shard_path)


def _root_jobs(root_sizes: dict[str, int], directory: Path) -> Iterator[RootJob]:
    # A root is the indivisible scheduling unit. Its existing state/cache walk
    # never restarts at a date boundary or at an interior fork.
    roots = sorted(root_sizes, key=lambda root: (-root_sizes[root], root))
    for ordinal, root_id in enumerate(roots):
        yield RootJob(root_id, ordinal, directory / f"root-{ordinal}.sqlite")


def _submit_roots(
    executor: ProcessPoolExecutor,
    jobs: Iterator[RootJob],
    pending: set[Future[RootResult]],
    maximum: int,
) -> None:
    while len(pending) < maximum:
        job = next(jobs, None)
        if job is None:
            return
        pending.add(executor.submit(_run_root, job))


def _shutdown_executor(
    executor: ProcessPoolExecutor,
    *,
    propagate_interrupt: bool,
) -> None:
    interruption: KeyboardInterrupt | None = None
    while True:
        try:
            executor.shutdown(wait=True, cancel_futures=True)
            break
        except KeyboardInterrupt as error:
            if interruption is None:
                interruption = error
    if interruption is not None and propagate_interrupt:
        raise interruption


def collect_parallel_decisions(
    config: KernelConfig,
    repo_path: Path,
    store: ConfigHistoryStore,
    source_includes: SourceIncludeIndex,
    root_sizes: dict[str, int],
    workers: int,
    show_progress: bool,
) -> None:
    """Merge closed root shards in the parent; workers receive no live state.

    Only a bounded number of ID-only jobs are outstanding. Each spawned worker
    opens one read-only history connection and one reusable Git batch reader,
    loads the global include snapshot once, and retains bounded content caches
    across root jobs. On failure, running jobs stop at a commit boundary after
    worker initialization and any root-header loading have finished.
    """

    if workers < 1:
        raise ValueError("Configuration workers must be at least one")
    if not root_sizes:
        return
    store.commit()
    context = multiprocessing.get_context("spawn")
    cancellation = context.Event()
    with TemporaryDirectory(prefix="parallel-", dir=store.path.parent) as temporary:
        directory = Path(temporary)
        snapshot = directory / "source-includes.json"
        source_includes.write_snapshot(snapshot)
        settings = _WorkerSettings(config, repo_path, store.path, snapshot)
        executor = ProcessPoolExecutor(
            max_workers=min(workers, len(root_sizes)),
            mp_context=context,
            initializer=_initialize_worker,
            initargs=(settings, cancellation),
        )
        pending: set[Future[RootResult]] = set()
        failed = False
        try:
            jobs = _root_jobs(root_sizes, directory)
            total = sum(root_sizes.values())
            name = "Filtering kernel configuration"
            with filter_progress(name, total, show_progress) as progress:
                task = progress.add_task(name, total=total)
                _submit_roots(executor, jobs, pending, 2 * workers)
                while pending:
                    completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in completed:
                        pending.remove(future)
                        result = future.result()
                        store.merge_decisions(result.shard_path)
                        progress.advance(task, result.processed_commits)
                    _submit_roots(executor, jobs, pending, 2 * workers)
            store.commit()
        except BaseException:
            failed = True
            raise
        finally:
            cancellation.set()
            for future in pending:
                future.cancel()
            # Let initialization, root-header loading, and the current commit
            # finish; Finalize then closes SQLite and reaps git cat-file. Repeated
            # Ctrl-C must not remove scratch files before every worker has joined,
            # or replace the preparation error already being propagated.
            _shutdown_executor(executor, propagate_interrupt=not failed)
