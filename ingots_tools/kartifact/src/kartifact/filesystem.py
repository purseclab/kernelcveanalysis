from __future__ import annotations

import os
from pathlib import Path
import shutil
from uuid import uuid4

from .errors import DestinationNotEmptyError, UnsafeArtifactEntryError
from .toml_io import ARTIFACT_FILE_NAME


def ensure_outside_storage(path: Path, storage_root: Path) -> None:
    resolved = path.resolve()
    root = storage_root.resolve()
    if resolved == root or resolved.is_relative_to(root):
        raise UnsafeArtifactEntryError(
            f"working path must be outside kartifact storage: {path}"
        )


def validate_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise UnsafeArtifactEntryError(f"artifact root is not a regular directory: {root}")
    _validate_directory(root)


def _validate_directory(directory: Path) -> None:
    with os.scandir(directory) as entries:
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink():
                raise UnsafeArtifactEntryError(f"symbolic link is not allowed: {path}")
            if entry.is_dir(follow_symlinks=False):
                _validate_directory(path)
            elif not entry.is_file(follow_symlinks=False):
                raise UnsafeArtifactEntryError(
                    f"only regular files and directories are allowed: {path}"
                )


def prepare_empty_destination(path: Path) -> bool:
    """Prepare a destination and return whether this function created it."""
    if path.is_symlink():
        raise UnsafeArtifactEntryError(f"destination cannot be a symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise DestinationNotEmptyError(f"destination is not a directory: {path}")
        if any(path.iterdir()):
            raise DestinationNotEmptyError(f"destination is not empty: {path}")
        return False
    path.mkdir(parents=True)
    return True


def copy_tree_contents(
    source: Path,
    destination: Path,
    *,
    exclude_artifact_toml: bool = False,
) -> None:
    for child in source.iterdir():
        if exclude_artifact_toml and child.name == ARTIFACT_FILE_NAME:
            continue
        target = destination / child.name
        if child.is_dir():
            target.mkdir()
            copy_tree_contents(child, target)
        else:
            shutil.copy2(child, target)


def cleanup_destination(path: Path, created: bool) -> None:
    if not path.exists() or path.is_symlink():
        return
    if created:
        shutil.rmtree(path)
        return
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def atomic_write_text(path: Path, text: str) -> None:
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()

