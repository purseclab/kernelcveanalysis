"""Benchmark filtering without saving results, using at most 93 days.

Tree memory peaks are samples, not hard peaks: RSS is sampled every 0.25s
from /proc status, and RSS/PSS every 1s from smaps_rollup. Processes that
exit between samples can be missed; inaccessible processes are skipped.
"""

import argparse
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import resource
from threading import Event, Thread
from time import monotonic, perf_counter

from kpatch.filter import (
    ConfigFilter,
    FilterContext,
    FilterPipeline,
    IfdefFilter,
    KernelConfig,
    MergeCommitFilter,
    WhitespaceFilter,
)
from kpatch.git import GitDb, GitRepo, parse_time


@dataclass(frozen=True, slots=True)
class TreeMemorySample:
    rss_kib: int
    pss_kib: int | None


def _process_tree(root_pid: int, proc_root: Path) -> set[int]:
    """Follow children of every thread, counting each process only once."""

    visited: set[int] = set()
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        try:
            tasks = list((proc_root / str(pid) / "task").iterdir())
        except OSError:
            continue
        for task in tasks:
            try:
                children = (task / "children").read_text()
            except OSError:
                continue
            pending.extend(int(child) for child in children.split())
    return visited


def _process_memory(pid: int, proc_root: Path, include_pss: bool) -> TreeMemorySample:
    filename = "smaps_rollup" if include_pss else "status"
    rss_field = "Rss:" if include_pss else "VmRSS:"
    rss_kib = 0
    pss_kib = 0 if include_pss else None
    try:
        contents = (proc_root / str(pid) / filename).read_text()
    except OSError:
        return TreeMemorySample(rss_kib, pss_kib)
    for line in contents.splitlines():
        fields = line.split()
        if fields and fields[0] == rss_field:
            rss_kib = int(fields[1])
        elif include_pss and fields and fields[0] == "Pss:":
            pss_kib = int(fields[1])
    return TreeMemorySample(rss_kib, pss_kib)


def sample_tree_memory(
    root_pid: int, proc_root: Path, *, include_pss: bool
) -> TreeMemorySample:
    rss_kib = 0
    pss_kib = 0 if include_pss else None
    for pid in _process_tree(root_pid, proc_root):
        memory = _process_memory(pid, proc_root, include_pss)
        rss_kib += memory.rss_kib
        if pss_kib is not None and memory.pss_kib is not None:
            pss_kib += memory.pss_kib
    return TreeMemorySample(rss_kib, pss_kib)


class ProcessTreeMemorySampler:
    """Sample simultaneous tree totals, including the root and Git children."""

    def __init__(
        self,
        root_pid: int,
        *,
        proc_root: Path = Path("/proc"),
        rss_interval: float = 0.25,
        pss_interval: float = 1.0,
    ) -> None:
        if rss_interval <= 0 or pss_interval <= 0:
            raise ValueError("Memory sampling intervals must be positive")
        self.root_pid = root_pid
        self.proc_root = proc_root
        self.rss_interval = rss_interval
        self.pss_interval = pss_interval
        self.peak_tree_rss_mib = 0.0
        self.peak_tree_pss_mib = 0.0
        self._stop = Event()
        self._thread = Thread(
            target=self._run, name="kpatch-memory-sampler", daemon=True
        )

    def _sample(self, *, include_pss: bool) -> None:
        memory = sample_tree_memory(
            self.root_pid, self.proc_root, include_pss=include_pss
        )
        self.peak_tree_rss_mib = max(self.peak_tree_rss_mib, memory.rss_kib / 1024)
        if memory.pss_kib is not None:
            self.peak_tree_pss_mib = max(
                self.peak_tree_pss_mib, memory.pss_kib / 1024
            )

    def _run(self) -> None:
        next_pss = monotonic() + self.pss_interval
        while not self._stop.wait(self.rss_interval):
            now = monotonic()
            include_pss = now >= next_pss
            self._sample(include_pss=include_pss)
            if include_pss:
                next_pss = now + self.pss_interval

    def start(self) -> None:
        self._sample(include_pss=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()
        self._sample(include_pss=True)


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    start: str
    end: str
    workers: int
    input_commits: int
    output_commits: int
    load_seconds: float
    filter_seconds: float
    peak_rss_mib: float
    largest_child_rss_mib: float
    peak_tree_rss_mib: float
    peak_tree_pss_mib: float
    output_sha256: str


def _positive_workers(value: str) -> int:
    workers = int(value)
    if workers < 1:
        raise argparse.ArgumentTypeError("workers must be at least 1")
    return workers


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("linux"))
    parser.add_argument("--db", type=Path, default=Path("db/all_commits.sqlite"))
    parser.add_argument("--config", type=Path, default=Path("kernel.config"))
    parser.add_argument("--start", default="07-01-2026", help="Inclusive MM-DD-YYYY")
    parser.add_argument("--end", default="08-01-2026", help="Exclusive MM-DD-YYYY")
    parser.add_argument(
        "--workers", type=_positive_workers, default=4,
        help="Processes for the Kbuild config phase only (default: 4)",
    )
    args = parser.parse_args()
    start, end = parse_time(args.start), parse_time(args.end)
    if not timedelta(0) < end - start <= timedelta(days=93):
        parser.error("Choose a positive date range of at most 93 days")
    if not args.db.is_file():
        parser.error(f"Database does not exist: {args.db}")

    sampler = ProcessTreeMemorySampler(os.getpid())
    sampler.start()
    try:
        begin = perf_counter()
        context = FilterContext.from_db_range(
            GitDb(args.db), GitRepo(args.repo), start, end
        )
        loaded = perf_counter()
        config = KernelConfig(args.config.read_text())
        pipeline = FilterPipeline(
            [
                MergeCommitFilter(),
                ConfigFilter(config, workers=args.workers),
                IfdefFilter(config),
                WhitespaceFilter(),
            ]
        )
        digest = hashlib.sha256()
        output_count = 0
        with closing(
            pipeline.iter_filter_commits(
                context.commits,
                context,
                show_progress=False,
                total=len(context.commits),
            )
        ) as commits:
            for commit in commits:
                digest.update(commit.commit_id.encode())
                digest.update(commit.diff_str.encode())
                output_count += 1
        filtered = perf_counter()
    finally:
        sampler.stop()

    result = BenchmarkResult(
        start=start.isoformat(),
        end=end.isoformat(),
        workers=args.workers,
        input_commits=len(context.commits),
        output_commits=output_count,
        load_seconds=loaded - begin,
        filter_seconds=filtered - loaded,
        peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        largest_child_rss_mib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024,
        peak_tree_rss_mib=sampler.peak_tree_rss_mib,
        peak_tree_pss_mib=sampler.peak_tree_pss_mib,
        output_sha256=digest.hexdigest(),
    )
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
