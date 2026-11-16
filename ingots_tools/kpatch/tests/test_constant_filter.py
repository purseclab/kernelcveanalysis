from dataclasses import replace
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter import FilterContext, FilteredCommit, MaskReason
from kpatch.filter.constant_filter import ConstantConditionalFilter
from kpatch.filter.masking import LineRange, SourceSide
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.git import CommitParent, GitRepo


class ConstantFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = GitRepo(self.root)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Constant branch tests')
        self.git('config', 'user.email', 'constants@example.invalid')

    def git(self, *args: str) -> str:
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.PIPE).decode().strip()

    def change(self, old: str, new: str, path: str = 'unit.c') -> FilteredCommit:
        unit = self.root / path
        unit.write_text(old)
        self.git('add', '.')
        self.git('commit', '-qm', 'parent')
        unit.write_text(new)
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        child = self.git('rev-parse', 'HEAD')
        return FilteredCommit(next(self.repo.iter_commits_from_revision(child + '^!')))

    def run_stage(self, commit: FilteredCommit, *, lossy: bool = False) -> tuple[FilteredCommit | None, list[PruningDecision]]:
        decisions: list[PruningDecision] = []
        stage = ConstantConditionalFilter(decisions.append, line_numbers_lossy=lossy,
                                          on_line_numbers_assumed=decisions.append if lossy else None)
        return stage.filter_mutable_commit(commit, FilterContext(self.repo)), decisions

    def test_constant_dead_body_change_prunes_without_config(self) -> None:
        old = '#if 0\nint hidden = 1;\n#endif\nint live = 7;\n'
        commit = self.change(old, old.replace('hidden = 1', 'hidden = 2'))
        remaining, decisions = self.run_stage(commit)
        self.assertIsNone(remaining)
        self.assertEqual(decisions[0].rule, 'constant_preprocessor_branch')
        self.assertFalse(decisions[0].lossy)
        self.assertTrue(commit.code_masks)
        self.assertTrue(all(mask.reason is MaskReason.CONSTANT_BRANCH for mask in commit.code_masks))
        self.assertEqual(commit.original.diff_str, commit.original_diff.text)

    def test_line_shift_requires_explicit_audited_assumption(self) -> None:
        old = '#include "observer.h"\n#if 0\nint hidden;\n#endif\nint value = LOCATION;\n'
        new = '#include "observer.h"\nint value = LOCATION;\n'
        original = self.change(old, new)
        strict = FilteredCommit(original.original)
        remaining, records = self.run_stage(strict)
        self.assertIs(remaining, strict)
        self.assertEqual(records, [])
        self.assertEqual(strict.code_masks, ())
        remaining, records = self.run_stage(FilteredCommit(original.original), lossy=True)
        self.assertIsNone(remaining)
        self.assertTrue(records[0].lossy)
        self.assertEqual(records[0].rule, 'constant_preprocessor_branch_line_numbers_lossy')
        self.assertIn('source_line_number_observations_may_change_runtime_behavior', records[0].risk_reasons)

    def test_changed_live_code_does_not_publish_partial_masks(self) -> None:
        old = '#if 0\nint hidden = 1;\n#endif\nint live = 1;\n'
        commit = self.change(old, old.replace('= 1', '= 2'))
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])
        self.assertEqual(commit.code_masks, ())
        self.assertEqual(commit.edit_masks, ())

    def test_selected_preprocessor_side_effects_remain_observable(self) -> None:
        old = '#if 1\n#define VALUE 1\n#else\n#define VALUE 2\n#endif\nint x = VALUE;\n'
        commit = self.change(old, old.replace('VALUE 1', 'VALUE 3'))
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])

    def test_unknown_earlier_arm_prevents_unconditional_selection(self) -> None:
        old = '#if FLAG\nint x = 1;\n#elif 1\nint x = 2;\n#endif\n'
        commit = self.change(old, old.replace('x = 2', 'x = 3'))
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])

    def test_new_conditional_forms_remain_unsupported(self) -> None:
        old = '#define FLAG 1\n#if 0\n#elifdef FLAG\nint x = 1;\n#endif\n'
        commit = self.change(old, old.replace('x = 1', 'x = 2'))
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])

    def test_unsupported_original_cannot_be_hidden_by_projection(self) -> None:
        old = '#if 0\nconst char *s = "unterminated\n#endif\nint x;\n'
        commit = self.change(old, old.replace('unterminated', 'different'))
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])
        self.assertEqual(commit.code_masks, ())

    def test_assembly_is_retained(self) -> None:
        old = '#if 0\n.long 1\n#endif\n'
        commit = self.change(old, old.replace('.long 1', '.long 2'), path='unit.s')
        result, records = self.run_stage(commit, lossy=True)
        self.assertIs(result, commit)
        self.assertEqual(records, [])

    def test_no_constant_group_stays_for_other_stages(self) -> None:
        old = '/* old */\nint x;\n'
        commit = self.change(old, old.replace('old', 'new'))
        result, records = self.run_stage(commit)
        self.assertIs(result, commit)
        self.assertEqual(records, [])

    def test_file_budget_retains_entire_commit_before_source_or_mode_reads(self) -> None:
        old = '#if 0\nint hidden = 1;\n#endif\nint live;\n'
        for name in ('one.c', 'two.c'):
            (self.root / name).write_text(old)
        self.git('add', '.')
        self.git('commit', '-qm', 'parent')
        for name in ('one.c', 'two.c'):
            (self.root / name).write_text(old.replace('hidden = 1', 'hidden = 2'))
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        commit = FilteredCommit(next(self.repo.iter_commits_from_revision('HEAD^!')))
        records: list[PruningDecision] = []
        stage = ConstantConditionalFilter(records.append)
        with (patch('kpatch.filter.constant_filter._MAX_FILES_PER_COMMIT', 1),
              patch.object(self.repo, 'read_file', side_effect=AssertionError('source read')),
              patch.object(self.repo, 'read_file_mode', side_effect=AssertionError('mode read'))):
            self.assertIs(stage.filter_mutable_commit(commit, FilterContext(self.repo)), commit)
        self.assertEqual(stage.stats().budget_skipped_commits, 1)
        self.assertEqual(stage.stats().source_prechecks, 0)
        self.assertEqual(commit.edit_masks, ())
        self.assertEqual(commit.code_masks, ())
        self.assertEqual(records, [])

    def test_unknown_mode_uses_real_historical_regular_file_evidence(self) -> None:
        old = '#if 0\nint x = 1;\n#endif\nint y;\n'
        commit = self.change(old, old.replace('x = 1', 'x = 2'))
        original = commit.original
        assert original.parent is not None
        patch_text = '\n'.join(line for line in original.diff_str.split('\n') if not line.startswith('index '))
        no_modes = FilteredCommit(replace(original, parents=(CommitParent(original.parent.commit_id, patch_text),)))
        self.assertIsNone(no_modes.diff.files[0].old_mode)
        result, records = self.run_stage(no_modes)
        self.assertIsNone(result)
        self.assertFalse(records[0].lossy)

    def test_api_requires_lossy_callback_and_propagates_report_failure(self) -> None:
        with self.assertRaisesRegex(ValueError, 'decision callback'):
            ConstantConditionalFilter(line_numbers_lossy=True)
        def fail(decision: PruningDecision) -> None:
            raise OSError('audit failed')
        old = '#if 0\nint x = 1;\n#endif\nint y;\n'
        commit = self.change(old, old.replace('x = 1', 'x = 2'))
        with self.assertRaisesRegex(OSError, 'audit failed'):
            ConstantConditionalFilter(fail).filter_mutable_commit(commit, FilterContext(self.repo))


if __name__ == '__main__':
    unittest.main()
