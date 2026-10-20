"""Benchmark filtering without saving results, using at most 93 days."""

import argparse
from dataclasses import asdict, dataclass
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import resource
from time import perf_counter

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
class BenchmarkResult:
    start: str
    end: str
    input_commits: int
    output_commits: int
    load_seconds: float
    filter_seconds: float
    peak_rss_mib: float
    output_sha256: str


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("linux"))
    parser.add_argument("--db", type=Path, default=Path("db/all_commits.sqlite"))
    parser.add_argument("--config", type=Path, default=Path("kernel.config"))
    parser.add_argument("--start", default="07-01-2026", help="Inclusive MM-DD-YYYY")
    parser.add_argument("--end", default="08-01-2026", help="Exclusive MM-DD-YYYY")
    args = parser.parse_args()
    start, end = parse_time(args.start), parse_time(args.end)
    if not timedelta(0) < end - start <= timedelta(days=93):
        parser.error("Choose a positive date range of at most 93 days")
    if not args.db.is_file():
        parser.error(f"Database does not exist: {args.db}")

    begin = perf_counter()
    context = FilterContext.from_db_range(
        GitDb(args.db), GitRepo(args.repo), start, end
    )
    loaded = perf_counter()
    config = KernelConfig(args.config.read_text())
    pipeline = FilterPipeline(
        [
            MergeCommitFilter(),
            ConfigFilter(config),
            IfdefFilter(config),
            WhitespaceFilter(),
        ]
    )
    commits = pipeline.filter_commits(
        context.commits, context, show_progress=False
    )
    filtered = perf_counter()

    digest = hashlib.sha256()
    for commit in commits:
        digest.update(commit.commit_id.encode())
        digest.update(commit.diff_str.encode())
    result = BenchmarkResult(
        start=start.isoformat(),
        end=end.isoformat(),
        input_commits=len(context.commits),
        output_commits=len(commits),
        load_seconds=loaded - begin,
        filter_seconds=filtered - loaded,
        peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        output_sha256=digest.hexdigest(),
    )
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
