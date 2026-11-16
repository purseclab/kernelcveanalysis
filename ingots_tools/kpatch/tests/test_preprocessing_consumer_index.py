"""Actual dependency-index and native reader epoch controls."""

from contextlib import closing
import hashlib
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from kpatch.filter import FilterContext, FilteredCommit, FilterPipeline
from kpatch.filter.policy_context import RevisionCompiler, _CachedPreprocessing
from kpatch.filter.policy_clang import PreprocessorFingerprint
from kpatch.filter.preprocessing import TargetPreprocessorFilter
import test_policy_context as context_helpers
import test_target_preprocessing as helpers


class ConsumerIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        helpers.TargetPreprocessingTests.setUpClass()

    def setUp(self) -> None:
        self.case = helpers.TargetPreprocessingTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_more_than_128_unrelated_recorded_units_do_not_hit_match_cap(self) -> None:
        case = self.case
        files = {'api.h': '#define UNUSED 1\n',
                 'target.c': '#include "api.h"\nint target;\n',
                 **{f'other{index}.c': 'int other;\n' for index in range(129)},
                 'Makefile': 'obj-y += target.o\n'}
        commit, build = case.change(files, {'api.h': '#define UNUSED 2\n'})
        cache = case.root / 'preprocessed.sqlite'
        result, stage = case.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [], case.records)
        self.assertEqual(stage.stats.baseline_units, 130)
        self.assertEqual(stage.stats.dirty_units, 1)
        self.assertEqual([item.path for item in case.records[-1].units], ['target.c'])
        self.assertEqual(stage.compiler.stats.preprocessing_extractions, 131)
        result, warm = case.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [], case.records)
        self.assertEqual(warm.compiler.stats.preprocessing_extractions, 0)
        self.assertEqual(warm.compiler.stats.preprocessing_cache_hits, 131)

    def test_dependency_added_by_a_previous_changed_header_is_discovered(self) -> None:
        case = self.case
        files = {'selector.h': '#define SELECT 0\n', 'api.h': '#define VALUE 1\n',
                 'unit.c': '#include "selector.h"\n#if SELECT\n#include "api.h"\n'
                           'int value=VALUE;\n#else\nint value=3;\n#endif\n',
                 'Makefile': 'obj-y += unit.o\n'}
        activation, build = case.change(files, {'selector.h': '#define SELECT 1\n'})
        case.git('checkout', '--detach', '-q', activation.commit_id)
        (case.source / 'api.h').write_text('#define VALUE 2\n')
        case.git('add', '.')
        case.git('commit', '-qm', 'change newly included header')
        with closing(case.repo.iter_commits_from_revision('HEAD^!')) as commits:
            commit = next(commits)
        case.git('checkout', '--detach', '-q', build.base_revision)
        result, stage = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'expanded_inputs_changed')
        self.assertEqual([item.path for item in case.records[-1].units], ['unit.c'])
        self.assertEqual(stage.stats.baseline_units, 1)
        self.assertEqual(stage.stats.dirty_units, 2)

    def test_baseline_is_built_once_across_multiple_original_commits(self) -> None:
        case = self.case
        files = {'api.h': '#define UNUSED 1\n', 'target.c': '#include "api.h"\nint value;\n',
                 'other.c': 'int other;\n', 'Makefile': 'obj-y += target.o other.o\n'}
        first, build = case.change(files, {'api.h': '#define UNUSED 2\n'})
        case.git('checkout', '--detach', '-q', first.commit_id)
        (case.source / 'api.h').write_text('#define UNUSED 3\n')
        case.git('add', '.')
        case.git('commit', '-qm', 'next original')
        with closing(case.repo.iter_commits_from_revision('HEAD^!')) as commits:
            second = next(commits)
        case.git('checkout', '--detach', '-q', build.base_revision)
        stage = TargetPreprocessorFilter(build, analyzer=case.analyzer)
        output = FilterPipeline([stage]).filter_mutable_commits(
            [FilteredCommit(first), FilteredCommit(second)], FilterContext(case.repo), False)
        self.assertEqual(output, [])
        self.assertEqual(stage.stats.baseline_units, 2)
        self.assertEqual(stage.stats.dirty_units, 2)
        self.assertEqual(stage.compiler.stats.preprocessing_extractions, 4)

    def test_main_source_changes_invalidate_its_cached_digest(self) -> None:
        case = self.case
        commit, build = case.change({'unit.c': 'int value=1;\n', 'unrelated.c': 'int other;\n'},
                                    {'unit.c': 'int value=2;\n'})
        result, stage = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(case.records[-1].reason, 'expanded_inputs_changed')
        self.assertEqual(stage.stats.baseline_units, 2)
        self.assertEqual(stage.stats.dirty_units, 1)
        self.assertEqual([item.path for item in case.records[-1].units], ['unit.c'])

    def test_late_dirty_consumer_failure_publishes_no_partial_masks(self) -> None:
        case = self.case
        files = {'api.h': '#define UNUSED 1\n', 'unit.c': '#include "api.h"\nint value;\n',
                 'other.c': '#include "api.h"\nint other;\n', 'Makefile': 'obj-y += unit.o other.o\n'}
        commit, build = case.change(files, {'api.h': '#define UNUSED 2\n'})
        actual = case.analyzer.preprocess
        calls = 0

        def failing_preprocess(command, *, overlays=()):
            nonlocal calls
            if overlays:
                calls += 1
                if calls == 2:
                    return PreprocessorFingerprint.failure('injected_late_native_failure')
            return actual(command, overlays=overlays)

        with patch.object(case.analyzer, 'preprocess', side_effect=failing_preprocess):
            result, stage = case.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(case.records[-1].reason, 'injected_late_native_failure')
        self.assertNotIn(commit.commit_id, stage._revision_units)


class InputDigestEpochTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = context_helpers.PolicyContextTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.compiler = RevisionCompiler(self.case.repo, self.case.build, self.case.analyzer())
        self.addCleanup(self.compiler.close)

    def replacement(self, contents: bytes) -> str:
        return subprocess.check_output(['git', '-C', str(self.case.source), 'hash-object', '-w', '--stdin'],
                                       input=contents).decode().strip()

    def test_digest_memo_expires_on_real_native_process_rotation(self) -> None:
        case, compiler = self.case, self.compiler
        original = compiler._input(case.base, case.header).sha256
        epoch = compiler.reader.cache_epoch
        blob = case.git('rev-parse', case.base + ':include/api.h')
        replacement = b'#define VALUE 999\n'
        case.git('replace', blob, self.replacement(replacement))
        try:
            self.assertEqual(compiler._input(case.base, case.header).sha256, original)
            compiler.reader._process_reads = 8192
            compiler.reader.read_file(case.base, 'other.c')
            self.assertGreater(compiler.reader.cache_epoch, epoch)
            self.assertEqual(compiler._input(case.base, case.header).sha256, hashlib.sha256(replacement).hexdigest())
        finally:
            case.git('replace', '-d', blob)

    def test_closed_reader_fallback_never_memoizes_native_replacement_state(self) -> None:
        case, compiler = self.case, self.compiler
        compiler.reader.close()
        self.assertIsNone(compiler.reader.cache_epoch)
        original = compiler._input(case.base, case.header).sha256
        blob = case.git('rev-parse', case.base + ':include/api.h')
        replacement = b'#define VALUE 77\n'
        case.git('replace', blob, self.replacement(replacement))
        try:
            self.assertNotEqual(compiler._input(case.base, case.header).sha256, original)
            self.assertEqual(compiler._input(case.base, case.header).sha256, hashlib.sha256(replacement).hexdigest())
            self.assertFalse(compiler._git_digests)
        finally:
            case.git('replace', '-d', blob)

    def test_symbolic_revision_movement_is_not_digest_memoized(self) -> None:
        case, compiler = self.case, self.compiler
        changed = case.revision({'include/api.h': '#define VALUE 9\n'})
        case.git('update-ref', 'refs/heads/moving', case.base)
        before = compiler._input('moving', case.header).sha256
        case.git('update-ref', 'refs/heads/moving', changed)
        after = compiler._input('moving', case.header).sha256
        self.assertNotEqual(before, after)
        self.assertNotIn(('moving', 'include/api.h'), compiler._git_digests)


class PreprocessingDiskCacheTests(unittest.TestCase):
    """Typed transport fixtures; no semantic equivalence is inferred here."""

    def setUp(self) -> None:
        self.case = context_helpers.PolicyContextTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.path = self.case.root / 'preprocessing.sqlite'
        self.analyzer = self.case.analyzer()
        self.compiler = RevisionCompiler(self.case.repo, self.case.build, self.analyzer, cache_path=self.path)
        self.addCleanup(self.compiler.close)
        self.cached = _CachedPreprocessing(
            fingerprint=PreprocessorFingerprint(complete=True, digest='a' * 64, tokens=3),
            inputs=(self.compiler._input(self.case.base, self.case.unit),),
        )

    def test_700_baselines_survive_restart_without_512_variant_self_eviction(self) -> None:
        for index in range(700):
            self.compiler._remember_preprocessing(f'family{index}', self.cached, f'unit{index}.c', self.case.base)
        self.assertEqual(len(self.compiler._preprocessed), 32)
        self.compiler.close()
        restored = RevisionCompiler(self.case.repo, self.case.build, self.analyzer, cache_path=self.path)
        self.addCleanup(restored.close)
        for index in range(700):
            result = restored._preprocessing_cache(f'family{index}', self.case.base, f'unit{index}.c')
            self.assertIsNotNone(result)
            self.assertEqual(result.fingerprint.digest, 'a' * 64)
        rows = restored._database.execute('SELECT COUNT(*),SUM(baseline),typeof(payload) FROM compiler_preprocessed_v2').fetchone()
        self.assertEqual(rows, (700, 700, 'blob'))

    def test_history_is_bounded_per_unit_without_evicting_its_baseline(self) -> None:
        self.compiler._remember_preprocessing('baseline', self.cached, 'unit.c', self.case.base)
        for index in range(10):
            self.compiler._remember_preprocessing(f'history{index}', self.cached, 'unit.c', f'revision{index}')
        rows = self.compiler._database.execute('SELECT family,baseline FROM compiler_preprocessed_v2').fetchall()
        self.assertEqual(len(rows), 5)
        self.assertIn(('baseline', 1), rows)

    def test_byte_budget_does_not_delete_current_baseline_records(self) -> None:
        with patch('kpatch.filter.policy_context._MAX_PREPROCESSING_CACHE_BYTES', 2048):
            for index in range(100):
                self.compiler._remember_preprocessing(f'family{index}', self.cached, f'unit{index}.c', self.case.base)
        self.assertGreater(self.compiler.stats.preprocessing_cache_budget_skips, 0)
        first = self.compiler._database.execute('SELECT baseline FROM compiler_preprocessed_v2 WHERE family=?', ('family0',)).fetchone()
        self.assertEqual(first, (1,))
        size = self.compiler._database.execute('SELECT SUM(LENGTH(payload)) FROM compiler_preprocessed_v2').fetchone()[0]
        self.assertLessEqual(size, 2048)

    def test_corrupt_compressed_row_is_not_positive_cache_evidence(self) -> None:
        self.compiler._database.execute('INSERT INTO compiler_preprocessed_v2 VALUES (?,?,?,?,?,?,?,0)',
                                       (self.compiler._preprocessing_context, 'unit.c', 'bad', 'bad', b'bad-zlib', 'a' * 64, 1))
        self.compiler._database.commit()
        self.assertIsNone(self.compiler._preprocessing_cache('bad', self.case.base, 'unit.c'))

    def test_worker_content_identity_invalidates_persistent_entries(self) -> None:
        self.compiler._remember_preprocessing('family', self.cached, 'unit.c', self.case.base)
        self.compiler.close()
        self.analyzer.worker_path.write_bytes(b'different typed fixture worker')
        changed = RevisionCompiler(self.case.repo, self.case.build, self.analyzer, cache_path=self.path)
        self.addCleanup(changed.close)
        self.assertIsNone(changed._preprocessing_cache('family', self.case.base, 'unit.c'))


if __name__ == '__main__':
    unittest.main()
