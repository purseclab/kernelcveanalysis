from pathlib import Path
import posixpath
import subprocess

from ..git import GitRepo


class RepositoryFileReader:
    """Read commit files through one persistent ``git cat-file`` process."""

    def __init__(self, repo: GitRepo):
        self._repo = repo
        self._process: subprocess.Popen[bytes] | None = None
        repository = getattr(repo, "repo", None)
        if repository is not None:
            self._process = subprocess.Popen(
                ["git", "-C", str(Path(repository)), "cat-file", "--batch"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )

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

        assert process.stdin is not None
        assert process.stdout is not None
        expression = f"{commit}:{normalized_path}"
        process.stdin.write(f"{expression}\n".encode())
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

        contents = process.stdout.read(size)
        terminator = process.stdout.read(1)
        if len(contents) != size or terminator != b"\n":
            raise RuntimeError("Truncated git cat-file response")
        return contents

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        self._process = None
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
