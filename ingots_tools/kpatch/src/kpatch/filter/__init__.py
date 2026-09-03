from datetime import datetime
from pathlib import Path

from .file_filter import FileFilter
from .config_filter import ConfigFilter, KernelConfig
from ..git import GitRepo, GitDb, StructuredCommits, GitCommit

# pre classifier / llm filtering

# filters in individual commit
# returns true to include
def filter_commit(
    config_filter: ConfigFilter,
    commit: GitCommit,
) -> bool:
    changed = False

    for file in commit.diff.files:
        if file.old_file is not None and config_filter.file_included(file.old_file):
            changed = True
            break

    config_filter.update_filter_state(commit.diff, commit.commit_id)
    if changed:
        return True

    for file in commit.diff.files:
        if config_filter.file_included(file.file):
            return True

    return False

def filter_commits(
    repo: GitRepo,
    kernel_config: KernelConfig,
    all_commits: list[GitCommit]
) -> list[GitCommit]:
    out: list[GitCommit] = []
    commits = StructuredCommits.from_commits(all_commits)

    # need a bit of a hack sinde parent could be none on root, but would basically never happen
    def parent_or_self(commit: str) -> str:
        parent = commits.commits[commit].parent

        if parent is None:
            return commit
        else:
            return parent.commit_id

    commit_stack = [(commit, ConfigFilter(repo, kernel_config, parent_or_self(commit))) for commit in commits.root_commits]

    while len(commit_stack) > 0:
        current_commit_id, current_filter = commit_stack.pop()

        while True:
            current_commit = commits.commits[current_commit_id]

            if filter_commit(current_filter, current_commit):
                out.append(current_commit)

            children = commits.commit_children[current_commit_id]

            if len(children.primary_children) == 0:
                break
            else:
                current_commit_id = children.primary_children[0]

                for child in children.primary_children[1:]:
                    filter_copy = ConfigFilter.copy(current_filter)
                    # commit in stack is child, filter still is set on parents, matching initial stack construction
                    commit_stack.append((child, filter_copy))

    return out

def filter_commit_time_range(
    repo: GitRepo,
    db: GitDb,
    kernel_config_path: Path,
    start_date: datetime,
    end_date: datetime,
):
    kernel_config = KernelConfig(kernel_config_path.read_text())
    all_commits = db.commits_between(start_date, end_date, include_merges=True)

    filtered_commits = filter_commits(repo, kernel_config, all_commits)

    print(f"Orig len: {len(all_commits)}")
    print(f"New len: {len(filtered_commits)}")



__all__ = ["FileFilter", "filter_commits"]
