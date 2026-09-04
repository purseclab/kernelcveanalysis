from pathlib import Path
import subprocess
import tempfile
import unittest

from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import GitRepo


class RepositoryFileReaderTests(unittest.TestCase):
    def test_batch_reader_handles_files_and_missing_paths_without_exiting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet", str(repository)],
                check=True,
            )
            (repository / "source.c").write_bytes(b"int value;\n")
            subprocess.run(
                ["git", "-C", str(repository), "add", "source.c"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "--quiet",
                    "-m",
                    "test",
                ],
                check=True,
            )

            with RepositoryFileReader(GitRepo(repository)) as reader:
                self.assertEqual(reader.read_file("HEAD", "source.c"), b"int value;\n")
                with self.assertRaises(FileNotFoundError):
                    reader.read_file("HEAD", "missing.c")
                with self.assertRaises(FileNotFoundError):
                    reader.read_file("HEAD", "../source.c")
                self.assertEqual(reader.read_file("HEAD", "source.c"), b"int value;\n")


if __name__ == "__main__":
    unittest.main()
