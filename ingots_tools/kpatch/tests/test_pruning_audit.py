import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter.output_paths import repository_input_roots, validate_output_paths
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.pruning_audit import PruningAudit
from kpatch.policy_cli import validate_policy_outputs


class PruningAuditSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        self.input = self.root / "raw.sqlite"
        self.input.write_bytes(b"raw database fixture")
        self.report = self.root / "report.jsonl"

    def test_direct_and_symlinked_protected_input_is_preserved(self) -> None:
        symbolic = self.root / "symbolic.jsonl"
        symbolic.symlink_to(self.input)
        before = self.input.read_bytes()
        for destination in (self.input, symbolic):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                PruningAudit.create(destination, self.source, (self.input,))
        self.assertEqual(self.input.read_bytes(), before)

    def test_hardlinked_raw_database_is_rejected_before_truncation(self) -> None:
        self.report.hardlink_to(self.input)
        before = self.input.read_bytes()
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            PruningAudit.create(self.report, self.source, (self.input,))
        self.assertEqual(self.input.read_bytes(), before)

    def test_unlisted_source_hardlink_is_also_rejected(self) -> None:
        source = self.source / "unit.c"
        source.write_text("int preserved = 7;\n")
        self.report.hardlink_to(source)
        before = source.read_bytes()
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            PruningAudit.create(self.report, self.source, ())
        self.assertEqual(source.read_bytes(), before)

    def test_existing_unlinked_report_can_be_reinitialized(self) -> None:
        self.report.write_text("previous audit\n")
        audit = PruningAudit.create(self.report, self.source, (self.input,))
        self.assertEqual(audit.path, self.report)
        self.assertEqual(self.report.read_text(), "")
        self.assertEqual(self.input.read_bytes(), b"raw database fixture")

    def test_separate_git_metadata_and_reference_cache_are_preserved(self) -> None:
        checkout, metadata = self.root / "separate", self.root / "git-metadata"
        subprocess.run(["git", "init", "-q", "--separate-git-dir", str(metadata), str(checkout)], check=True)
        cache = metadata / "kpatch-references-v8.sqlite"
        cache.write_bytes(b"reference cache sentinel")
        for destination in (metadata / "HEAD", cache):
            before = destination.read_bytes()
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                PruningAudit.create(destination, checkout, ())
            self.assertEqual(destination.read_bytes(), before)

    def test_metadata_directory_newlines_are_not_split_or_stripped(self) -> None:
        checkout = self.root / "checkout\nname"
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        metadata = checkout / ".git"
        self.assertIn(metadata.resolve(), repository_input_roots(checkout))
        before = (metadata / "HEAD").read_bytes()
        with self.assertRaises(ValueError):
            PruningAudit.create(metadata / "HEAD", checkout, ())
        self.assertEqual((metadata / "HEAD").read_bytes(), before)

    def test_linked_worktree_git_and_common_directories_are_preserved(self) -> None:
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "fixture"], check=True)
        checkout = self.root / "worktree"
        subprocess.run(["git", "-C", str(self.source), "worktree", "add", "--detach", "-q", str(checkout)], check=True)
        roots = repository_input_roots(checkout)
        self.assertIn((self.source / ".git").resolve(), roots)
        self.assertIn((self.source / ".git/worktrees/worktree").resolve(), roots)
        for root in roots[1:]:
            destination = root / "HEAD"
            before = destination.read_bytes()
            with self.subTest(root=root), self.assertRaises(ValueError):
                PruningAudit.create(destination, checkout, ())
            self.assertEqual(destination.read_bytes(), before)

    def test_live_database_wal_is_preserved_and_remains_readable(self) -> None:
        database = self.root / "live.sqlite"
        connection = sqlite3.connect(database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE t(value)")
        connection.execute("INSERT INTO t VALUES (7)")
        connection.commit()
        wal = Path(str(database) + "-wal")
        before = wal.read_bytes()
        with self.assertRaises(ValueError):
            PruningAudit.create(wal, self.source, (database,))
        self.assertEqual(wal.read_bytes(), before)
        reader = sqlite3.connect(database)
        try:
            self.assertEqual(reader.execute("SELECT value FROM t").fetchall(), [(7,)])
        finally:
            reader.close()

    def test_sidecars_are_reserved_before_the_database_exists(self) -> None:
        database = self.root / "future.sqlite"
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                PruningAudit.create(Path(str(database) + suffix), self.source, (database,))
        self.assertFalse(database.exists())

    def test_invalid_git_source_fails_before_report_initialization(self) -> None:
        other = self.root / "not-a-repository"
        other.mkdir()
        self.report.write_text("previous report")
        with self.assertRaisesRegex(ValueError, "Git metadata"):
            PruningAudit.create(self.report, other, ())
        self.assertEqual(self.report.read_text(), "previous report")


class OutputPathSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.report = self.root / "report.jsonl"
        self.report.write_text("previous report")

    def test_duplicate_nested_and_cross_sidecar_outputs_do_not_modify_report(self) -> None:
        alternatives = (self.report, self.report / "nested.jsonl",
                        Path(str(self.report) + "-wal"), Path(str(self.report) + "-shm"),
                        Path(str(self.report) + "-journal"))
        for other in alternatives:
            for outputs in ((self.report, other), (other, self.report)):
                with self.subTest(outputs=outputs), self.assertRaises(ValueError):
                    validate_output_paths(outputs)
                self.assertEqual(self.report.read_text(), "previous report")

    def test_nonexistent_nested_outputs_are_rejected_before_any_creation(self) -> None:
        first = self.root / "new"
        with self.assertRaises(ValueError):
            validate_output_paths((first, first / "nested"))
        self.assertFalse(first.exists())

    def test_nonregular_and_file_parent_destinations_are_rejected(self) -> None:
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for destination in (self.root, fifo, self.report / "child"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                validate_output_paths((destination,))
        self.assertEqual(self.report.read_text(), "previous report")

    def test_symlink_destinations_and_parent_aliases_are_checked(self) -> None:
        alias = self.root / "alias"
        alias.symlink_to(self.report)
        with self.assertRaises(ValueError):
            validate_output_paths((alias,))
        source = self.root / "source"
        source.mkdir()
        directory_alias = self.root / "directory-alias"
        directory_alias.symlink_to(source, target_is_directory=True)
        with self.assertRaises(ValueError):
            validate_output_paths((directory_alias / "report",), protected_roots=(source,))
        self.assertEqual(self.report.read_text(), "previous report")

    def test_hardlinked_sidecar_cannot_be_modified_by_cache_initialization(self) -> None:
        cache = self.root / "cache.sqlite"
        sidecar = Path(str(cache) + "-wal")
        sidecar.hardlink_to(self.report)
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            validate_output_paths((cache,))
        self.assertEqual(self.report.read_text(), "previous report")
        self.assertFalse(cache.exists())

    def test_sidecar_symlink_to_protected_input_is_rejected(self) -> None:
        cache = self.root / "cache.sqlite"
        Path(str(cache) + "-journal").symlink_to(self.report)
        with self.assertRaises(ValueError):
            validate_output_paths((cache,), protected=(self.report,))
        self.assertEqual(self.report.read_text(), "previous report")

    def test_protected_alias_reserves_original_and_resolved_sidecars(self) -> None:
        alias = self.root / "input-alias"
        alias.symlink_to(self.report)
        for name in (self.report, alias):
            sidecar = Path(str(name) + "-wal")
            with self.subTest(sidecar=sidecar), self.assertRaises(ValueError):
                validate_output_paths((sidecar,), protected=(alias,))

    def test_regular_distinct_outputs_are_resolved_without_writing(self) -> None:
        cache = self.root / "new-cache.sqlite"
        self.assertEqual(validate_output_paths((self.report, cache)), (self.report, cache))
        self.assertEqual(self.report.read_text(), "previous report")
        self.assertFalse(cache.exists())


class PolicyOutputSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = self.root / "source"
        build = self.root / "build"
        source.mkdir()
        build.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        config = build / ".config"
        config.write_text("CONFIG_ARM64=y\n")
        commands = build / "compile_commands.json"
        commands.write_text("[]\n")
        # Output validation consumes only paths; no compiler context is run.
        self.context = PolicyBuildContext(
            source_root=source, build_root=build, base_revision="0" * 40,
            compilation_database=commands, config_file=config,
            config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(), compiler_version="path fixture",
            generated_inputs=(), compilation_database_sha256=hashlib.sha256(commands.read_bytes()).hexdigest(),
            build_membership_sha256="0" * 64)

    def test_hardlinked_unlisted_source_and_generated_files_are_preserved(self) -> None:
        for directory in (self.context.source_root, self.context.build_root):
            original = directory / "unlisted.h"
            original.write_text("int preserved;\n")
            output = self.root / (directory.name + ".json")
            output.hardlink_to(original)
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, "hardlinked"):
                validate_policy_outputs((output,), self.context, ())
            self.assertEqual(original.read_text(), "int preserved;\n")

    def test_hardlinked_report_and_cache_are_rejected(self) -> None:
        report = self.root / "report.json"
        cache = self.root / "cache.sqlite"
        report.write_bytes(b"existing output")
        cache.hardlink_to(report)
        with self.assertRaisesRegex(ValueError, "hardlinked"):
            validate_policy_outputs((report, cache), self.context, ())
        self.assertEqual(report.read_bytes(), b"existing output")

    def test_distinct_single_link_outputs_are_allowed(self) -> None:
        report = self.root / "report.json"
        report.write_text("old output")
        cache = self.root / "cache.sqlite"
        validate_policy_outputs((report, cache), self.context, ())
        self.assertEqual(report.read_text(), "old output")
        self.assertFalse(cache.exists())

    def test_explicit_database_and_its_sidecars_are_protected(self) -> None:
        database = self.root / "raw.sqlite"
        database.write_bytes(b"database sentinel")
        for suffix in ("", "-wal", "-shm", "-journal"):
            destination = Path(str(database) + suffix)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                validate_policy_outputs((destination,), self.context, (database,))
        self.assertEqual(database.read_bytes(), b"database sentinel")

    def test_cross_report_cache_sidecars_are_rejected(self) -> None:
        report = self.root / "report"
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                validate_policy_outputs((report, Path(str(report) + suffix)), self.context, ())
        self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
