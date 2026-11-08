from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
import posixpath
import re
import subprocess

from ..git import GitRepo


_CONTENT_CACHE_BYTES = 16 * 1024 * 1024
_CONTENT_CACHE_ENTRIES = 4096
_METADATA_CACHE_ENTRIES = 4096
_PROCESS_MAX_READS = 8192
_FULL_REVISION = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_OBJECT_ID = re.compile(rb"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")


@dataclass(frozen=True)
class _ObjectInfo:
    oid: bytes
    size: int


class RepositoryFileReader:
    """Read files with bounded metadata and bytes for one native process view.

    Exact full revision/path metadata avoids repeated object resolution. Both
    caches expire on process replacement: Git's replacement-object map belongs
    to that process, so an OID can expose different bytes in a later process.
    """

    def __init__(self, repo: GitRepo):
        self._repo = repo
        self._process: subprocess.Popen[bytes] | None = None
        self._contents: OrderedDict[bytes, bytes] = OrderedDict()
        self._metadata: OrderedDict[tuple[str, str], _ObjectInfo] = OrderedDict()
        self._paths: OrderedDict[str, None] = OrderedDict()
        self._content_bytes = 0
        self._process_reads = 0
        self._process_epoch = 0
        repository = getattr(repo, "repo", None)
        self._repository = Path(repository) if repository is not None else None
        if self._repository is not None:
            self._start_process()

    def _start_process(self) -> None:
        assert self._repository is not None
        self._process = subprocess.Popen(
            ["git", "-C", str(self._repository), "cat-file", "--batch-command"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._process_reads = 0
        self._process_epoch += 1

    @property
    def cache_epoch(self) -> int | None:
        """Identity of the active native object view; fallback reads are fresh."""
        return self._process_epoch if self._process is not None else None

    def read_file(self, commit: str, path: str) -> bytes:
        process = self._process
        if process is None:
            return self._repo.read_file(commit, path)
        if "\n" in commit or "\n" in path:
            raise ValueError("Git object expressions cannot contain newlines")
        normalized_path = posixpath.normpath(path)
        if (
            posixpath.isabs(path)
            or normalized_path == ".."
            or normalized_path.startswith("../")
        ):
            raise FileNotFoundError(f"{commit}:{path}")

        key = (commit, normalized_path) if _FULL_REVISION.fullmatch(commit) else None
        info = self._metadata.get(key) if key is not None else None
        if info is not None:
            cached = self._contents.get(info.oid)
            if cached is not None:
                assert key is not None
                self._metadata.move_to_end(key)
                self._contents.move_to_end(info.oid)
                self._remember_path(normalized_path)
                return cached

        # Cached reads do no native work. Rotate only before the next native
        # operation, never between its metadata and content requests.
        if self._process_reads >= _PROCESS_MAX_READS:
            self._stop_process()
            self._start_process()
            info = None
        process = self._process
        assert process is not None
        self._process_reads += 1
        expression = f"{commit}:{normalized_path}"
        # A new path cannot demonstrate reuse yet. Keep one-pass source scans
        # at one request per file instead of paying for info followed by contents.
        command = b"contents " + expression.encode()
        if info is not None:
            command = b"contents " + info.oid
        elif normalized_path in self._paths:
            info = self._request(b"info " + expression.encode(), expression)
            cached = self._contents.get(info.oid)
            if cached is not None:
                self._contents.move_to_end(info.oid)
                self._remember_path(normalized_path)
                self._remember_metadata(key, info)
                return cached
            command = b"contents " + info.oid

        info = self._request(command, expression)
        assert process.stdout is not None
        contents = process.stdout.read(info.size)
        terminator = process.stdout.read(1)
        if len(contents) != info.size or terminator != b"\n":
            raise RuntimeError("Truncated git cat-file response")
        self._cache_contents(info.oid, contents)
        self._remember_path(normalized_path)
        self._remember_metadata(key, info)
        return contents

    def _remember_metadata(self, key: tuple[str, str] | None, info: _ObjectInfo) -> None:
        # The response establishes the repository's hash width. A 40-digit
        # abbreviation in a SHA-256 repository (or a cross-width hex ref) is
        # not an immutable full object name and must retain native resolution.
        if key is None or len(key[0]) != len(info.oid) or _OBJECT_ID.fullmatch(info.oid) is None:
            return
        self._metadata[key] = info
        self._metadata.move_to_end(key)
        if len(self._metadata) > _METADATA_CACHE_ENTRIES:
            self._metadata.popitem(last=False)

    def _remember_path(self, path: str) -> None:
        self._paths[path] = None
        self._paths.move_to_end(path)
        if len(self._paths) > _CONTENT_CACHE_ENTRIES:
            self._paths.popitem(last=False)

    def _request(self, command: bytes, expression: str) -> _ObjectInfo:
        process = self._process
        assert process is not None
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(command + b"\n")
        process.stdin.flush()

        header = process.stdout.readline()
        if not header:
            raise RuntimeError(
                "git cat-file terminated unexpectedly while reading "
                f"{expression!r} (exit status {process.poll()})"
            )
        if header.rstrip().endswith(b" missing"):
            raise FileNotFoundError(expression)

        fields = header.rstrip().split()
        if len(fields) != 3:
            raise RuntimeError(f"Unexpected git cat-file response: {header!r}")
        try:
            size = int(fields[2])
        except ValueError as error:
            raise RuntimeError(
                f"Unexpected git cat-file object size: {header!r}"
            ) from error
        return _ObjectInfo(oid=fields[0], size=size)

    def _cache_contents(self, oid: bytes, contents: bytes) -> None:
        size = len(contents)
        if size > _CONTENT_CACHE_BYTES:
            return
        if oid in self._contents:
            self._contents.move_to_end(oid)
            return
        while self._contents and (
            self._content_bytes + size > _CONTENT_CACHE_BYTES
            or len(self._contents) >= _CONTENT_CACHE_ENTRIES
        ):
            _, evicted = self._contents.popitem(last=False)
            self._content_bytes -= len(evicted)
        self._contents[oid] = contents
        self._content_bytes += size

    def close(self) -> None:
        self._contents.clear()
        self._metadata.clear()
        self._paths.clear()
        self._content_bytes = 0
        self._stop_process()

    def _stop_process(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
        self._process_reads = 0
        self._contents.clear()
        self._metadata.clear()
        self._paths.clear()
        self._content_bytes = 0
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()

    def __enter__(self) -> "RepositoryFileReader":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
