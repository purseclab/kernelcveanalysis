from io import BytesIO
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import GitRepo
from tests.test_repository_file import BatchProcess, _contents, _info, _oid


class RepositoryMetadataTests(unittest.TestCase):
    def reader(self, process: BatchProcess) -> RepositoryFileReader:
        with patch("kpatch.filter.repository_file.subprocess.Popen", return_value=process):
            reader = RepositoryFileReader(GitRepo(Path("unused")))
        self.addCleanup(reader.close)
        return reader

    def test_full_id_repeat_and_normalized_path_reuse_exact_bytes_without_git(self) -> None:
        revision, oid = _oid(100).decode(), _oid(1)
        process = BatchProcess(BytesIO(_contents(oid, b"value")))
        reader = self.reader(process)
        first = reader.read_file(revision, "unit.c")
        self.assertIs(reader.read_file(revision, "./unit.c"), first)
        self.assertIs(reader.read_file(revision, "a/../unit.c"), first)
        self.assertEqual(process.commands(), [f"contents {revision}:unit.c".encode()])
        self.assertEqual(reader._process_reads, 1)
        self.assertEqual(len(reader._metadata), 1)
        self.assertEqual(len(reader._contents), 1)

    def test_empty_blob_is_a_positive_cached_result(self) -> None:
        revision = _oid(100).decode()
        process = BatchProcess(BytesIO(_contents(_oid(1), b"")))
        reader = self.reader(process)
        self.assertEqual(reader.read_file(revision, "empty.h"), b"")
        self.assertEqual(reader.read_file(revision, "empty.h"), b"")
        self.assertEqual(len(process.commands()), 1)
        self.assertEqual(reader._content_bytes, 0)
        self.assertEqual(len(reader._metadata), 1)

    def test_symbolic_and_short_revisions_keep_native_resolution(self) -> None:
        for revision in ("HEAD", "branch", "123abcd", "a" * 39):
            process = BatchProcess(BytesIO(_contents(_oid(1), b"one")
                                          + _info(_oid(2), b"two") + _contents(_oid(2), b"two")))
            reader = self.reader(process)
            self.assertEqual(reader.read_file(revision, "unit.c"), b"one")
            self.assertEqual(reader.read_file(revision, "unit.c"), b"two")
            self.assertFalse(reader._metadata)
            self.assertEqual(len(process.commands()), 3)

    def test_different_full_revisions_have_distinct_positive_facts(self) -> None:
        one, two = _oid(100).decode(), _oid(200).decode()
        process = BatchProcess(BytesIO(_contents(_oid(1), b"one")
                                      + _info(_oid(2), b"two") + _contents(_oid(2), b"two")))
        reader = self.reader(process)
        original = reader.read_file(one, "unit.c")
        self.assertEqual(reader.read_file(two, "unit.c"), b"two")
        self.assertIs(reader.read_file(one, "unit.c"), original)
        self.assertEqual(len(process.commands()), 3)
        self.assertEqual(len(reader._metadata), 2)

    def test_evicted_content_uses_known_oid_without_info_roundtrip(self) -> None:
        revision = _oid(100).decode()
        process = BatchProcess(BytesIO(_contents(_oid(1), b"one") + _contents(_oid(2), b"two")
                                      + _contents(_oid(1), b"one")))
        reader = self.reader(process)
        with patch("kpatch.filter.repository_file._CONTENT_CACHE_ENTRIES", 1):
            reader.read_file(revision, "one.c")
            reader.read_file(revision, "two.c")
            self.assertEqual(reader.read_file(revision, "one.c"), b"one")
        self.assertEqual(process.commands()[-1], b"contents " + _oid(1))
        self.assertEqual(len(reader._metadata), 2)
        self.assertEqual(len(reader._contents), 1)

    def test_metadata_lru_bound_preserves_native_fallback(self) -> None:
        revisions = [_oid(number).decode() for number in (100, 200, 300)]
        process = BatchProcess(BytesIO(_contents(_oid(1), b"same") + _info(_oid(1), b"same") * 3))
        reader = self.reader(process)
        with patch("kpatch.filter.repository_file._METADATA_CACHE_ENTRIES", 2):
            for revision in revisions:
                reader.read_file(revision, "unit.c")
            self.assertEqual(list(reader._metadata), [(revisions[1], "unit.c"), (revisions[2], "unit.c")])
            reader.read_file(revisions[0], "unit.c")
        self.assertEqual(len(process.commands()), 4)
        self.assertEqual(len(reader._metadata), 2)

    def test_cross_width_hex_names_are_never_metadata_keys(self) -> None:
        for revision_width, oid_width in ((64, 40), (40, 64)):
            oid = b"a" * oid_width
            process = BatchProcess(BytesIO(_contents(oid, b"old") + _info(oid, b"old")))
            reader = self.reader(process)
            revision = "b" * revision_width
            reader.read_file(revision, "unit.c")
            reader.read_file(revision, "unit.c")
            self.assertFalse(reader._metadata)
            self.assertEqual(len(process.commands()), 2)

    def test_misses_and_truncated_reads_do_not_create_metadata_facts(self) -> None:
        revision = _oid(100).decode()
        process = BatchProcess(BytesIO(f"{revision}:unit.c missing\n".encode() + _contents(_oid(1), b"later")))
        reader = self.reader(process)
        with self.assertRaises(FileNotFoundError):
            reader.read_file(revision, "unit.c")
        self.assertFalse(reader._metadata)
        self.assertEqual(reader.read_file(revision, "unit.c"), b"later")
        self.assertEqual(len(process.commands()), 2)
        partial = self.reader(BatchProcess(BytesIO(_info(_oid(1), b"three") + b"th")))
        with self.assertRaises(RuntimeError):
            partial.read_file(revision, "unit.c")
        self.assertFalse(partial._metadata)
        self.assertFalse(partial._contents)

    def test_path_and_revision_validation_precedes_a_cache_lookup(self) -> None:
        revision = _oid(100).decode()
        process = BatchProcess(BytesIO(_contents(_oid(1), b"value")))
        reader = self.reader(process)
        reader.read_file(revision, "unit.c")
        for path in ("../unit.c", "/unit.c"):
            with self.assertRaises(FileNotFoundError):
                reader.read_file(revision, path)
        for commit, path in ((revision + "\n", "unit.c"), (revision, "unit.c\n")):
            with self.assertRaises(ValueError):
                reader.read_file(commit, path)
        self.assertEqual(len(process.commands()), 1)

    def test_cache_hit_defers_rotation_but_native_miss_expires_all_caches(self) -> None:
        revision = _oid(100).decode()
        first = BatchProcess(BytesIO(_contents(_oid(1), b"old")))
        second = BatchProcess(BytesIO(_contents(_oid(2), b"other") + _contents(_oid(3), b"new")))
        with (patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 1),
              patch("kpatch.filter.repository_file.subprocess.Popen", side_effect=(first, second)) as popen,
              RepositoryFileReader(GitRepo(Path("unused"))) as reader):
            original = reader.read_file(revision, "unit.c")
            self.assertIs(reader.read_file(revision, "unit.c"), original)
            self.assertEqual(popen.call_count, 1)
            reader.read_file(revision, "other.c")
            with patch("kpatch.filter.repository_file._PROCESS_MAX_READS", 10):
                self.assertEqual(reader.read_file(revision, "unit.c"), b"new")
            self.assertEqual(popen.call_count, 2)
            self.assertEqual(second.commands(), [f"contents {revision}:other.c".encode(), f"contents {revision}:unit.c".encode()])
        self.assertFalse(reader._metadata)
        self.assertFalse(reader._contents)
        self.assertFalse(reader._paths)


class NativeRepositoryMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Metadata fixture")
        self.git("config", "user.email", "metadata@example.invalid")
        (self.root / "unit.c").write_bytes(b"old")
        (self.root / "other.c").write_bytes(b"other")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "old")
        self.old = self.git("rev-parse", "HEAD")
        (self.root / "unit.c").write_bytes(b"new")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "new")
        self.new = self.git("rev-parse", "HEAD")

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], stderr=subprocess.PIPE).decode().strip()

    def test_symbolic_head_movement_and_full_commit_identity(self) -> None:
        self.git("update-ref", "refs/heads/main", self.old)
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        with RepositoryFileReader(GitRepo(self.root)) as reader:
            self.assertEqual(reader.read_file("HEAD", "unit.c"), b"old")
            self.assertEqual(reader.read_file(self.old, "unit.c"), b"old")
            self.git("update-ref", "refs/heads/main", self.new)
            self.assertEqual(reader.read_file("HEAD", "unit.c"), b"new")
            self.assertEqual(reader.read_file(self.old, "unit.c"), b"old")

    def test_commit_and_blob_replacement_follow_native_process_epochs(self) -> None:
        old_blob = self.git("rev-parse", self.old + ":unit.c")
        new_blob = self.git("rev-parse", self.new + ":unit.c")
        for target, replacement in ((self.old, self.new), (old_blob, new_blob)):
            with self.subTest(target=target), RepositoryFileReader(GitRepo(self.root)) as reader:
                self.assertEqual(reader.read_file(self.old, "unit.c"), b"old")
                self.git("replace", target, replacement)
                try:
                    # A cache hit keeps the existing native view. Force a real
                    # different-path miss to start a replacement-aware epoch.
                    reader._process_reads = 8192
                    self.assertEqual(reader.read_file(self.old, "unit.c"), b"old")
                    self.assertEqual(reader.read_file(self.old, "other.c"), b"other")
                    self.assertEqual(reader.read_file(self.old, "unit.c"), b"new")
                finally:
                    self.git("replace", "-d", target)

    def test_cross_width_mutable_hex_ref_is_resolved_each_time(self) -> None:
        name = "a" * 64
        self.git("update-ref", "refs/heads/" + name, self.old)
        with RepositoryFileReader(GitRepo(self.root)) as reader:
            self.assertEqual(reader.read_file(name, "unit.c"), b"old")
            self.git("update-ref", "refs/heads/" + name, self.new)
            self.assertEqual(reader.read_file(name, "unit.c"), b"new")
            self.assertFalse(reader._metadata)


if __name__ == "__main__":
    unittest.main()
