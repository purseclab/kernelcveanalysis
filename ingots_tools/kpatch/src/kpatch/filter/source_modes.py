"""Positive regular-file evidence before interpreting Git blobs as C source."""

import subprocess

from ..diff import DiffFile, DiffFileType
from ..git import GitRepo


_REGULAR_MODES = frozenset({"100644", "100755"})


def regular_source_change(
    file: DiffFile, repo: GitRepo, old_revision: str | None, new_revision: str,
) -> bool:
    """Require regular modes on every existing side of an original change.

    Complete index metadata avoids Git queries. Unknown metadata requires an
    exact historical tree lookup; a blob alone does not establish regular mode.
    This establishes source role only, not permission/structural equivalence.
    """
    if any(mode is not None and mode not in _REGULAR_MODES for mode in (file.old_mode, file.new_mode)):
        return False
    if file.change_type is not DiffFileType.NEW and old_revision is None:
        return False
    try:
        if file.change_type is not DiffFileType.NEW:
            assert old_revision is not None
            old_mode = file.old_mode or repo.read_file_mode(old_revision, file.old_file or file.file)
            if old_mode not in _REGULAR_MODES:
                return False
        if file.change_type is not DiffFileType.DELETE:
            new_mode = file.new_mode or repo.read_file_mode(new_revision, file.file)
            if new_mode not in _REGULAR_MODES:
                return False
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return True
