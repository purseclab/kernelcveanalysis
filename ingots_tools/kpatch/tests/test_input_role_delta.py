from collections.abc import Iterator
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import kpatch.filter.input_roles as roles
from kpatch.filter.input_role_models import InputInventoryState, RawInputFailureKind, RawInputObservation
from kpatch.filter.input_roles import RawInputIndex
from kpatch.git import GitRepo


def canonical(observation: RawInputObservation) -> tuple[object, ...]:
    return (observation.state, frozenset(observation.consumers),
            frozenset(observation.unknowns), frozenset(observation.failures))


def raw_change(path: bytes, *, width: int = 40) -> bytes:
    return b':100644 100644 ' + b'a' * width + b' ' + b'b' * width + b' M\0' + path + b'\0'


class StreamingDeltaTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)
        self.git('init', '-q')
        self.repo = GitRepo(self.path)
        self.reads: list[str] = []
        self.index = RawInputIndex(self.repo, self.read)

    def git(self, *args: str) -> bytes:
        return subprocess.check_output(['git', '-C', str(self.path), *args], stderr=subprocess.PIPE)

    def read(self, revision: str, path: str) -> bytes:
        self.reads.append(path)
        return self.repo.read_file(revision, path)

    def tree(self, files: dict[str, str], links: dict[str, str] | None = None,
             executable: tuple[str, ...] = ()) -> str:
        for path in self.path.iterdir():
            if path.name == '.git':
                continue
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        for name, text in files.items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            if name in executable:
                path.chmod(0o755)
        for name, target in (links or {}).items():
            path = self.path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target)
        self.git('add', '-A')
        return self.git('write-tree').decode().strip()

    def assert_cold_equal(self, revision: str, *queries: str) -> None:
        cold = RawInputIndex(self.repo, self.repo.read_file)
        for query in queries:
            self.assertEqual(canonical(self.index.lookup(revision, query)),
                             canonical(cold.lookup(revision, query)), query)

    def test_large_delta_filters_scope_before_batched_markers_and_keeps_late_facts(self) -> None:
        first = self.tree({'base.h': '/* unchanged */\n'})
        self.index.lookup(first, 'api.h')
        files = {f'doc/{number:04}.txt': '.incbin "ignored.h"\n' for number in range(1100)}
        files.update({f'src/{number:04}.c': 'int ordinary;\n' for number in range(2050)})
        files.update({'zz/raw.S': '.incbin "api.h"\n',
                      'zz/Makefile': 'generated.c: $(INPUT)\n\tperl gen.pl $< $@\n'})
        second = self.tree(files)
        calls: list[tuple[str, ...]] = []
        original = self.index._markers

        def markers(revision: str, paths: tuple[str, ...]) -> set[str]:
            calls.append(paths)
            return original(revision, paths)

        self.reads.clear()
        with patch.object(self.index, '_markers', side_effect=markers):
            observed = self.index.lookup(second, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.FULL)
        self.assertTrue(observed.consumers)
        self.assertTrue(observed.unknowns)
        self.assertFalse(observed.failures)
        self.assertGreater(self.index.stats().delta_rows, 1024)
        self.assertEqual(self.index.stats().repository_scans, 1)
        self.assertEqual(self.index.stats().incremental_updates, 1)
        self.assertEqual(self.index.stats().candidate_paths, 2052)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(0 < len(paths) <= 2048 for paths in calls))
        self.assertTrue(all(sum(len(path.encode()) + 1 for path in paths) <= 65536 for paths in calls))
        self.assertTrue(all(path.endswith(roles._SOURCE_SUFFIXES) for paths in calls for path in paths))
        self.assertEqual(set(self.reads), {'zz/raw.S', 'zz/Makefile'})
        self.assert_cold_equal(second, 'api.h', 'ignored.h', 'unrelated.h')

    def test_alias_target_mode_rename_and_marker_deletion_match_cold(self) -> None:
        files = {'payload.data': '.incbin "api.h"\n', 'raw.S': '.include "other.h"\n',
                 'Makefile': 'gen.c: $(INPUT)\n\tperl gen.pl $< $@\n'}
        first = self.tree(files, {'alias.S': 'payload.data', 'plain-link': 'api.h'})
        self.index.lookup(first, 'api.h')
        revisions = [
            self.tree({'payload.data': '.incbin "changed.h"\n', 'raw.S': '/* marker removed */\n',
                       'renamed/Makefile': 'gen.c: final.h\n\tperl gen.pl $< $@\n'},
                      {'alias.S': 'payload.data', 'plain-link': 'changed.h'}),
            self.tree({'payload.data': '.incbin "hidden.h"\n', 'renamed/raw.inc': '.include "moved.h"\n',
                       'alias.S': '.incbin "regular.h"\n'}, {'plain-link': 'hidden.h'}, ('alias.S',)),
            self.tree({'other.data': '.incbin "last.h"\n'}, {'alias.S': 'other.data'}),
            self.tree({}),
        ]
        for revision in revisions:
            self.assert_cold_equal(revision, 'api.h', 'changed.h', 'other.h', 'final.h',
                                   'moved.h', 'regular.h', 'last.h')
            self.assertEqual(self.index.lookup(revision, 'anything.h').state, InputInventoryState.FULL)
        self.assertEqual(self.index.stats().repository_scans, 1)

    def test_path_byte_and_row_budget_exact_boundaries(self) -> None:
        first = self.tree({})
        second = self.tree({'a.txt': 'a', 'b.txt': 'b'})
        for rows, path_bytes, expected in (
            (2, 12, None),
            (1, 12, RawInputFailureKind.DELTA_ROW_BUDGET),
            (2, 11, RawInputFailureKind.DELTA_PATH_BUDGET),
        ):
            with self.subTest(rows=rows, path_bytes=path_bytes):
                index = RawInputIndex(self.repo, self.repo.read_file)
                index.lookup(first, 'api.h')
                with patch.object(roles, '_MAX_DELTA_ROWS', rows), patch.object(roles, '_MAX_DELTA_PATH_BYTES', path_bytes):
                    observed = index.lookup(second, 'api.h')
                if expected is None:
                    self.assertEqual(observed.state, InputInventoryState.FULL)
                    self.assertFalse(observed.failures)
                else:
                    self.assertEqual(observed.state, InputInventoryState.INCOMPLETE)
                    self.assertIn(expected, {failure.kind for failure in observed.failures})

    def test_chunk_framing_rejects_missing_final_nul_and_invalid_metadata(self) -> None:
        payload = raw_change(b'odd\n:(literal)*.S') + raw_change('unicode-é.c'.encode())
        for size in (1, 7, 64, len(payload)):
            entries = list(roles._iter_delta_entries((payload[n:n + size] for n in range(0, len(payload), size)), 40))
            self.assertEqual([entry.path for entry in entries], ['odd\n:(literal)*.S', 'unicode-é.c'])
        malformed = [
            payload[:-1], payload + b':', raw_change(b''),
            raw_change(b'../escape.c'), raw_change(b'/absolute.c'),
            raw_change(b'bad.c').replace(b'100644', b'100640', 1),
            raw_change(b'bad.c').replace(b' M\0', b' R100\0'),
            raw_change(b'bad.c').replace(b'a' * 40, b'a' * 39),
            raw_change(b'bad.c').replace(b'a' * 40, b'0' * 40),
        ]
        for source in malformed:
            with self.subTest(source=source[-80:]), self.assertRaises(ValueError):
                list(roles._iter_delta_entries((source[n:n + 7] for n in range(0, len(source), 7)), 40))

    def test_late_native_or_framing_failure_cannot_publish_complete_or_modify_anchor(self) -> None:
        first = self.tree({'raw.S': '.incbin "api.h"\n'})
        baseline = self.index.lookup(first, 'api.h')
        second = self.tree({'raw.S': '.incbin "other.h"\n', 'zz.c': 'int later;\n'})
        for native_failure in (False, True):
            index = RawInputIndex(self.repo, self.repo.read_file)
            index.lookup(first, 'api.h')
            closed: list[bool] = []

            def chunks(repo: GitRepo, args: list[str], success_codes: tuple[int, ...]) -> Iterator[bytes]:
                try:
                    yield raw_change(b'raw.S')
                    if native_failure:
                        raise subprocess.CalledProcessError(2, ['git', 'diff-tree'])
                    yield raw_change(b'zz.c')[:-1]
                finally:
                    closed.append(True)

            with patch.object(roles, '_iter_git_chunks', side_effect=chunks), patch.object(roles, '_MARKER_BATCH_PATHS', 1):
                observed = index.lookup(second, 'api.h')
            self.assertEqual(observed.state, InputInventoryState.INCOMPLETE)
            expected = RawInputFailureKind.NATIVE_SCAN if native_failure else RawInputFailureKind.PROTOCOL
            self.assertIn(expected, {failure.kind for failure in observed.failures})
            self.assertEqual(closed, [True])
            self.assertEqual(index.lookup(first, 'api.h'), baseline)

    def test_budget_abort_closes_active_native_stream(self) -> None:
        first = self.tree({})
        self.index.lookup(first, 'api.h')
        second = self.tree({'new.txt': 'new'})
        closed: list[bool] = []

        def chunks(repo: GitRepo, args: list[str], success_codes: tuple[int, ...]) -> Iterator[bytes]:
            try:
                yield raw_change(b'one.txt') + raw_change(b'two.txt')
                self.fail('budget must stop before further native output')
            finally:
                closed.append(True)

        with patch.object(roles, '_iter_git_chunks', side_effect=chunks), patch.object(roles, '_MAX_DELTA_ROWS', 1):
            observed = self.index.lookup(second, 'api.h')
        self.assertEqual(observed.state, InputInventoryState.INCOMPLETE)
        self.assertEqual(closed, [True])


if __name__ == '__main__':
    unittest.main()
