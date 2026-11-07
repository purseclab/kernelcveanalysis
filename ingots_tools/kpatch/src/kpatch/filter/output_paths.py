"""Read-only validation of report/cache destinations against frozen inputs."""

from dataclasses import dataclass
import os
from pathlib import Path
import stat
import subprocess

from ..git import GitRepo


_SQLITE_SUFFIXES = ("", "-wal", "-shm", "-journal")


def repository_input_roots(source_root: Path) -> tuple[Path, ...]:
    """Include Git metadata outside a checkout, as used by linked worktrees."""
    source_root = source_root.resolve()
    repo = GitRepo(source_root)
    metadata: list[Path] = []
    try:
        for option in ("--git-dir", "--git-common-dir"):
            path = Path(os.fsdecode(repo._run_git([
                "rev-parse", "--path-format=absolute", option,
            ]).removesuffix(b"\n")))
            if not path.is_absolute() or not path.is_dir():
                raise ValueError("Git metadata discovery did not return an absolute directory")
            metadata.append(path.resolve())
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Cannot discover protected Git metadata directories") from error
    return tuple(dict.fromkeys((source_root, *metadata)))


def _file_family(path: Path) -> tuple[Path, ...]:
    # Reserve sidecars even for a new database. Including every protected file
    # avoids guessing whether an input/cache uses SQLite from its extension.
    bases = (path.absolute(), path.resolve())
    return tuple(dict.fromkeys(Path(str(base) + suffix).resolve()
                               for base in bases for suffix in _SQLITE_SUFFIXES))


def _overlap(first: Path, second: Path) -> bool:
    return first.is_relative_to(second) or second.is_relative_to(first)


def _validate_regular_destination(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Output/cache destinations and sidecars must not be symlinks")
    if path.exists():
        status = path.stat()
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("Output/cache destinations and sidecars must be regular files")
        if status.st_nlink > 1:
            raise ValueError("Output/cache must not be hardlinked to another file")
    for parent in path.parents:
        if parent.exists() and not parent.is_dir():
            raise ValueError("Output/cache parent components must be directories")


@dataclass(frozen=True, slots=True)
class _Destination:
    path: Path
    family: tuple[Path, ...]


def validate_output_paths(
    outputs: tuple[Path, ...], *, protected: tuple[Path, ...] = (),
    protected_roots: tuple[Path, ...] = (),
) -> tuple[Path, ...]:
    """Validate all outputs before writes, including SQLite sidecar collisions.

    Existing destinations may be replaced only when they are single-link
    regular files. Symlink destination names are rejected; symlinked parent
    directories are resolved before checking protected roots and other paths.
    """
    destinations: list[_Destination] = []
    for output in outputs:
        _validate_regular_destination(output)
        path = output.resolve()
        for suffix in _SQLITE_SUFFIXES:
            _validate_regular_destination(Path(str(path) + suffix))
        destinations.append(_Destination(path, _file_family(path)))

    roots = tuple(root.resolve() for root in protected_roots)
    inputs = tuple(candidate for path in protected for candidate in _file_family(path))
    for index, destination in enumerate(destinations):
        if any(candidate.is_relative_to(root) for candidate in destination.family for root in roots):
            raise ValueError("Store output/cache outside protected source, Git and build roots")
        if any(_overlap(candidate, source) for candidate in destination.family for source in inputs):
            raise ValueError("Output/cache must differ from protected inputs, databases and their sidecars")
        for previous in destinations[:index]:
            if any(_overlap(first, second) for first in destination.family for second in previous.family):
                raise ValueError("Outputs/caches and their sidecars must have separate, non-nested paths")
    return tuple(destination.path for destination in destinations)
