"""Streaming raw deltas preserve fresh-cold facts and fail closed on framing."""

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.input_roles as roles
from kpatch.filter.input_role_models import InputInventoryState, RawInputFailureKind, RawInputObservation
from kpatch.filter.input_roles import RawInputIndex
from kpatch.git import GitRepo


class InputRoleDeltaSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.initialize(self.root)

    def initialize(self, root: Path, *, sha256: bool = False) -> None:
        self.root = root
        arguments = ['git', 'init', '-q'] + (['--object-format=sha256'] if sha256 else []) + [str(root)]
        result = subprocess.run(arguments, capture_output=True)
        if result.returncode:
            if sha256:
                self.skipTest('Installed Git does not support SHA-256 repositories')
            result.check_returncode()
        self.repo = GitRepo(root)
        self.git('config', 'user.name', 'Streaming delta tests')
        self.git('config', 'user.email', 'delta@example.invalid')
        self.reads: list[tuple[str, str]] = []
        self.index = RawInputIndex(self.repo, self.read)

    def git(self, *arguments: str, input_data: bytes | None = None) -> bytes:
        result = subprocess.run(['git', '--literal-pathspecs', '-C', str(self.root), *arguments],
                                input=input_data, check=True, capture_output=True)
        return result.stdout

    def tree(self, files: dict[str, str], links: dict[str, str] | None = None) -> str:
        self.git('read-tree', '--empty')
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                path.unlink()
            path.write_text(text)
        for name, target in (links or {}).items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() or path.exists():
                path.unlink()
            path.symlink_to(target)
        names = [*files, *(links or {})]
        for offset in range(0, len(names), 256):
            self.git('add', '-f', '--', *names[offset:offset + 256])
        return self.git('write-tree').decode().strip()

    def read(self, revision: str, path: str) -> bytes:
        self.reads.append((revision, path))
        return self.repo.read_file(revision, path)

    def seed(self, revision: str) -> None:
        self.assertIs(self.index.lookup(revision, 'api.h').state, InputInventoryState.FULL)

    def assert_cold_equal(self, revision: str, paths: tuple[str, ...]) -> dict[str, RawInputObservation]:
        cold = RawInputIndex(self.repo, self.repo.read_file)
        actual: dict[str, RawInputObservation] = {}
        for path in paths:
            observed = self.index.lookup(revision, path)
            expected = cold.lookup(revision, path)
            self.assertIs(observed.state, expected.state, (revision, path))
            self.assertEqual(set(observed.consumers), set(expected.consumers), (revision, path))
            self.assertEqual(set(observed.unknowns), set(expected.unknowns), (revision, path))
            self.assertEqual(set(observed.failures), set(expected.failures), (revision, path))
            actual[path] = observed
        return actual

    def raw_delta(self, old: str, new: str) -> bytes:
        return self.git('diff-tree', '--no-commit-id', '-r', '--raw', '-z', '--no-abbrev', '--no-renames', old, new)

    def injected_delta(self, old: str, new: str, payload: bytes, *, status: int = 0) -> RawInputObservation:
        self.index = RawInputIndex(self.repo, self.read)
        self.seed(old)
        original = subprocess.Popen
        children: list[subprocess.Popen[bytes]] = []

        def spawn(command: list[str], **options: object) -> subprocess.Popen[bytes]:
            if 'diff-tree' in command:
                script = ('import sys;sys.stdout.buffer.write(bytes.fromhex(' + repr(payload.hex()) + '));'
                          'sys.stdout.buffer.flush();sys.exit(' + str(status) + ')')
                child = original([sys.executable, '-c', script], **options)
                children.append(child)
                return child
            return original(command, **options)

        # Use a real native producer through the production chunk transport;
        # replacing only raw diff output leaves every historical source read real.
        with patch('kpatch.filter.git_output.subprocess.Popen', side_effect=spawn):
            observed = self.index.lookup(new, 'api.h')
        self.assertEqual(len(children), 1)
        self.assertTrue(all(child.poll() is not None for child in children))
        return observed

    def test_more_than_1024_unrelated_paths_cannot_hide_a_late_consumer(self) -> None:
        old = self.tree({'api.h': '/* original */\n'})
        self.seed(old)
        files = {'api.h': '/* original */\n', **{f'noise/{n:05d}.txt': 'noise\n' for n in range(1400)},
                 'zz/late.S': '.incbin "api.h"\n'}
        new = self.tree(files)
        prior_reads = len(self.reads)
        actual = self.assert_cold_equal(new, ('api.h', 'unrelated.h'))
        self.assertIs(actual['api.h'].state, InputInventoryState.FULL)
        self.assertTrue(actual['api.h'].consumers)
        self.assertFalse(any(path.startswith('noise/') for _, path in self.reads[prior_reads:]))
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 1)

    def test_native_marker_batches_bound_count_and_bytes_and_ignore_other_paths(self) -> None:
        cases = (
            {f'candidate/{n:05d}.c': 'int value;\n' for n in range(2050)},
            {f'long/{n:05d}-' + 'x' * 115 + '.c': 'int value;\n' for n in range(600)},
        )
        for candidates in cases:
            old = self.tree({'api.h': '/* original */\n'})
            self.index = RawInputIndex(self.repo, self.read)
            self.seed(old)
            new = self.tree({'api.h': '/* original */\n', **candidates,
                             'unrelated.payload': 'not a source candidate\n',
                             'Makefile': 'out.c: api.h\n\tperl generate.pl $< $@\n',
                             'zz/raw.S': '.incbin "api.h"\n'}, {'unrelated-link': 'api.h'})
            with patch.object(self.index, '_markers', wraps=self.index._markers) as marker:
                incremental = self.index.lookup(new, 'api.h')
            self.assertGreaterEqual(marker.call_count, 2)
            for call in marker.call_args_list:
                paths = call.args[1]
                self.assertTrue(paths)
                self.assertLessEqual(len(paths), 2048)
                self.assertLessEqual(sum(len(path.encode()) + 1 for path in paths), 64 * 1024)
                self.assertTrue(all(path.endswith(('.c', '.h', '.cc', '.cpp', '.hpp', '.S', '.s', '.asm', '.inc')) for path in paths))
                self.assertNotIn('Makefile', paths)
                self.assertNotIn('unrelated-link', paths)
            self.assertTrue(incremental.consumers)
            self.assert_cold_equal(new, ('api.h', 'unrelated.h'))

    def test_marker_removal_and_rename_to_unrecognized_extension_delete_old_facts(self) -> None:
        first = self.tree({'api.h': '/* source */\n', 'driver/raw.S': '.incbin "api.h"\n'})
        self.seed(first)
        self.assertTrue(self.index.lookup(first, 'api.h').consumers)
        second = self.tree({'api.h': '/* source */\n', 'driver/raw.S': '.text\n'})
        self.assertFalse(self.assert_cold_equal(second, ('api.h',))['api.h'].consumers)
        third = self.tree({'api.h': '/* source */\n', 'driver/raw.S': '.incbin "api.h"\n'})
        self.assertTrue(self.assert_cold_equal(third, ('api.h',))['api.h'].consumers)
        fourth = self.tree({'api.h': '/* source */\n', 'hidden/raw.payload': '.incbin "api.h"\n'})
        self.assertFalse(self.assert_cold_equal(fourth, ('api.h',))['api.h'].consumers)

    def test_make_without_asm_markers_and_nonregular_mode_change_match_cold(self) -> None:
        first = self.tree({'api.h': '/* old */\n', 'other.h': '/* new */\n',
                           'Makefile': 'out.c: api.h\n\tperl generator.pl $< $@\n'})
        self.seed(first)
        second = self.tree({'api.h': '/* old */\n', 'other.h': '/* new */\n',
                            'Makefile': 'out.c: other.h\n\tperl generator.pl $< $@\n'})
        observed = self.assert_cold_equal(second, ('api.h', 'other.h'))
        self.assertFalse(observed['api.h'].consumers)
        self.assertTrue(observed['other.h'].consumers)
        commit = self.git('commit-tree', second, input_data=b'gitlink target\n').decode().strip()
        self.git('update-index', '--add', '--cacheinfo', f'160000,{commit},Makefile')
        third = self.git('write-tree').decode().strip()
        nonregular = self.assert_cold_equal(third, ('api.h', 'other.h'))['other.h']
        self.assertFalse(nonregular.consumers)
        self.assertIn(RawInputFailureKind.NONREGULAR_CONSUMER, {failure.kind for failure in nonregular.failures})

    def test_target_only_edits_and_multihop_alias_relinks_match_cold(self) -> None:
        first = self.tree({'api.h': '', 'other.h': '', 'hidden/one.payload': '.incbin "api.h"\n'},
                          {'driver/raw.S': '../via', 'via': 'hidden/one.payload'})
        self.seed(first)
        second = self.tree({'api.h': '', 'other.h': '', 'hidden/one.payload': '.incbin "other.h"\n'},
                           {'driver/raw.S': '../via', 'via': 'hidden/one.payload'})
        observed = self.assert_cold_equal(second, ('api.h', 'other.h'))
        self.assertFalse(observed['api.h'].consumers)
        self.assertTrue(observed['other.h'].consumers)
        third = self.tree({'api.h': '', 'other.h': '', 'hidden/two.payload': '.incbin "api.h"\n'},
                          {'driver/raw.S': '../via', 'via': 'hidden/two.payload'})
        observed = self.assert_cold_equal(third, ('api.h', 'other.h'))
        self.assertTrue(observed['api.h'].consumers)
        self.assertFalse(observed['other.h'].consumers)
        fourth = self.tree({'api.h': '', 'other.h': '', 'driver/raw.S': '.text\n',
                            'via': 'not a symlink\n'})
        self.assertFalse(self.assert_cold_equal(fourth, ('api.h', 'other.h'))['api.h'].consumers)

    def test_input_alias_changes_with_no_source_suffix_still_refresh_positive_bindings(self) -> None:
        first = self.tree({'api.h': '', 'other.h': '', 'driver/raw.S': '.incbin "payload.bin"\n'},
                          {'payload.bin': 'api.h'})
        self.seed(first)
        self.assertTrue(self.index.lookup(first, 'api.h').consumers)
        second = self.tree({'api.h': '', 'other.h': '', 'driver/raw.S': '.incbin "payload.bin"\n'},
                           {'payload.bin': 'other.h'})
        # Basename fallback cannot explain this change: the queried basenames
        # differ from payload.bin, so the actual alias mapping must update.
        observed = self.assert_cold_equal(second, ('api.h', 'other.h'))
        self.assertFalse(observed['api.h'].consumers)
        self.assertTrue(observed['other.h'].consumers)

    def test_odd_raw_paths_remain_literal_and_nul_framed(self) -> None:
        self.git('config', 'color.grep', 'always')
        old = self.tree({'api.h': ''})
        self.seed(old)
        names = ('odd\ncolon:raw[0]*.S', ':(exclude)*.S', 'unicodé:raw.S')
        new = self.tree({'api.h': '', **{name: '.incbin "api.h"\n' for name in names}})
        observed = self.assert_cold_equal(new, ('api.h',))['api.h']
        self.assertEqual({consumer.path for consumer in observed.consumers}, set(names))

    def test_sha256_repository_native_width_matches_fresh_cold(self) -> None:
        directory = self.root / 'sha256-repo'
        self.initialize(directory, sha256=True)
        old = self.tree({'api.h': ''})
        self.assertEqual(len(old), 64)
        self.seed(old)
        new = self.tree({'api.h': '', 'raw.S': '.incbin "api.h"\n'})
        self.assertEqual(len(new), 64)
        observed = self.assert_cold_equal(new, ('api.h',))['api.h']
        self.assertTrue(observed.consumers)

    def test_late_native_failure_after_valid_rows_never_becomes_full(self) -> None:
        old = self.tree({'api.h': ''})
        new = self.tree({'api.h': '', 'a/raw.S': '.incbin "api.h"\n', 'z/unrelated.txt': 'noise\n'})
        raw = self.raw_delta(old, new)
        cold = RawInputIndex(self.repo, self.repo.read_file).lookup(new, 'api.h')
        self.assertIs(cold.state, InputInventoryState.FULL)
        self.assertTrue(cold.consumers)
        observed = self.injected_delta(old, new, raw, status=7)
        self.assertIs(observed.state, InputInventoryState.INCOMPLETE)
        self.assertIn(RawInputFailureKind.NATIVE_SCAN, {failure.kind for failure in observed.failures})

    def test_truncated_nul_fields_and_late_malformed_header_never_become_full(self) -> None:
        old = self.tree({'api.h': ''})
        new = self.tree({'api.h': '', 'raw.S': '.incbin "api.h"\n'})
        raw = self.raw_delta(old, new)
        self.assertTrue(raw.endswith(b'\0'))
        header, path, ending = raw.split(b'\0')
        self.assertEqual(ending, b'')
        invalid = (raw[:-1], header + b'\0', raw + b':malformed\0missing.S\0',
                   header + b'\0\0', header + b'\0../escape.S\0')
        for payload in invalid:
            with self.subTest(payload=payload):
                observed = self.injected_delta(old, new, payload)
                self.assertIs(observed.state, InputInventoryState.INCOMPLETE)
                self.assertIn(RawInputFailureKind.PROTOCOL, {failure.kind for failure in observed.failures})

    def test_malformed_raw_modes_oid_widths_and_status_are_not_accepted(self) -> None:
        old = self.tree({'api.h': ''})
        new = self.tree({'api.h': '', 'raw.S': '.incbin "api.h"\n'})
        header, path, _ = self.raw_delta(old, new).split(b'\0')
        fields = header.split()
        changes = ((0, b':10064x'), (1, b'10064x'), (2, b'0' * 39),
                   (3, b'g' * 40), (4, b'R100'))
        for column, replacement in changes:
            corrupted = fields.copy();corrupted[column] = replacement
            with self.subTest(column=column, replacement=replacement):
                observed = self.injected_delta(old, new, b' '.join(corrupted) + b'\0' + path + b'\0')
                self.assertIs(observed.state, InputInventoryState.INCOMPLETE)
                self.assertIn(RawInputFailureKind.PROTOCOL, {failure.kind for failure in observed.failures})

    def test_raw_row_and_path_byte_budgets_have_exact_hard_boundaries(self) -> None:
        old = self.tree({'api.h': ''})
        files = {'api.h': '', 'a/raw.S': '.incbin "api.h"\n', 'z/noise.txt': 'noise\n'}
        new = self.tree(files)
        width = sum(len(path.encode()) + 1 for path in ('a/raw.S', 'z/noise.txt'))
        for rows, size, failure in ((2, width, None), (1, width, RawInputFailureKind.DELTA_ROW_BUDGET),
                                    (2, width - 1, RawInputFailureKind.DELTA_PATH_BUDGET)):
            self.index = RawInputIndex(self.repo, self.read)
            self.seed(old)
            with patch.object(roles, '_MAX_DELTA_ROWS', rows), patch.object(roles, '_MAX_DELTA_PATH_BYTES', size):
                observed = self.index.lookup(new, 'api.h')
            if failure is None:
                self.assert_cold_equal(new, ('api.h',))
                self.assertTrue(observed.consumers)
            else:
                self.assertIs(observed.state, InputInventoryState.INCOMPLETE)
                self.assertIn(failure, {item.kind for item in observed.failures})

    def test_actual_consumer_input_and_aggregate_reference_budgets_remain_hard(self) -> None:
        old = self.tree({'api.h': '', 'other.h': ''})
        source = 'out.c: api.h other.h\n\tperl generate.pl $^ $@\n'
        new = self.tree({'api.h': '', 'other.h': '', 'a/Makefile': source, 'b/Makefile': source})
        for constant, limit, expected in (('_MAX_FILES', 1, RawInputFailureKind.FILE_BUDGET),
                                           ('_MAX_BYTES', len(source.encode()) * 2 - 1, RawInputFailureKind.INPUT_BUDGET),
                                           ('_MAX_REFERENCES', 3, RawInputFailureKind.REFERENCE_BUDGET)):
            self.index = RawInputIndex(self.repo, self.read)
            self.seed(old)
            with self.subTest(constant=constant), patch.object(roles, constant, limit):
                observed = self.index.lookup(new, 'api.h')
            self.assertIs(observed.state, InputInventoryState.INCOMPLETE)
            self.assertIn(expected, {failure.kind for failure in observed.failures})
        fresh = RawInputIndex(self.repo, self.repo.read_file).lookup(new, 'api.h')
        self.assertIs(fresh.state, InputInventoryState.FULL)
        self.assertEqual(len(fresh.consumers), 2)


if __name__ == '__main__':
    unittest.main()
