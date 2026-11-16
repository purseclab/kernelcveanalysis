from filter_helpers import FixtureSourceRoles
from datetime import UTC, datetime
from difflib import unified_diff
import json
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import FilterContext, FilteredCommit, FilterPipeline, MaskReason
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.filter.source_pruning import source_pruning_tail
from kpatch.filter.whitespace.whitespace_filter import WhitespaceFilter
from kpatch.git import CommitParent, GitCommit, GitDb, GitRepo


class ByteRepo(GitRepo):
    def read_file_mode(self, commit: str, path: str) -> str:
        return "100644"

    def __init__(self, old: bytes, new: bytes) -> None:
        self.old, self.new = old, new

    def read_file(self, commit: str, path: str) -> bytes:
        return self.old if commit == 'parent' else self.new


def view(old: str, new: str) -> FilteredCommit:
    diff = 'diff --git a/unit.c b/unit.c\n' + ''.join(unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile='a/unit.c', tofile='b/unit.c',
    ))
    date = datetime(2026, 1, 1, tzinfo=UTC)
    return FilteredCommit(GitCommit('child', '', '', date, date, (CommitParent('parent', diff),), ''))


class LossyWhitespaceTests(unittest.TestCase):
    def compare(self, old: str, new: str, *, lossy: bool) -> tuple[FilteredCommit | None, list[PruningDecision], FilteredCommit]:
        commit = view(old, new)
        decisions: list[PruningDecision] = []
        stage = WhitespaceFilter(line_numbers_lossy=lossy, on_pruned=decisions.append)
        result = stage.filter_mutable_commit(commit, FilterContext(ByteRepo(old.encode(), new.encode()), input_roles=FixtureSourceRoles()))
        return result, decisions, commit

    def test_lossy_api_requires_audit_callback(self) -> None:
        with self.assertRaisesRegex(ValueError, 'decision callback'):
            WhitespaceFilter(line_numbers_lossy=True)

    def test_line_alias_retained_by_default_and_explicitly_audited_if_lossy(self) -> None:
        old = '#include "obs.h"\n/* old */\nint value(void) { return LOCATION; }\n'
        new = old.replace('/* old */', '/* old\n * extra */')
        strict, records, _ = self.compare(old, new, lossy=False)
        self.assertIsNotNone(strict)
        self.assertEqual(records, [])
        relaxed, records, commit = self.compare(old, new, lossy=True)
        self.assertIsNone(relaxed)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(record.lossy)
        self.assertEqual(record.rule, 'whitespace_line_numbers_lossy')
        self.assertEqual(record.paths, ('unit.c',))
        self.assertIn('source_line_number_observations_may_change_runtime_behavior', record.risk_reasons)
        self.assertEqual(commit.edit_masks[0].reason, MaskReason.WHITESPACE_LINES_LOSSY)
        self.assertTrue(record.edit_masks[0].whole_file)
        self.assertEqual(commit.original.diff_str, commit.original_diff.text)

    def test_lossy_mode_keeps_strict_acceptance_labeled_strict(self) -> None:
        old = '/* old */\nint value = 1;\n'
        new = old.replace('old', 'a much longer description')
        for lossy in (False, True):
            with self.subTest(lossy=lossy):
                result, records, _ = self.compare(old, new, lossy=lossy)
                self.assertIsNone(result)
                self.assertEqual(records[0].rule, 'whitespace_or_comments')
                self.assertFalse(records[0].lossy)
                self.assertEqual(records[0].risk_reasons, ())

    def test_lossy_mode_retains_column_gap_and_unsupported_changes(self) -> None:
        sources = [
            ('int value(void) {/*x*/return COL;}\n', 'int value(void) {/*longer*/return COL;}\n'),
            ('const char *s = S(1+ 2);\n', 'const char *s = S(1 +2);\n'),
            ('const char *s = R"(a"/*x*/"b)";\n', 'const char *s = R"(a"/*y*/"b)";\n'),
            ('#if __has_include(<foo/*x*/bar.h>)\nint x;\n#endif\n', '#if __has_include(<foo/*y*/bar.h>)\nint x;\n#endif\n'),
            ('/* old */\nint x = 1;\n', '/* old\n */\nint x = 2;\n'),
        ]
        for old, new in sources:
            with self.subTest(old=old):
                result, records, _ = self.compare(old, new, lossy=True)
                self.assertIsNotNone(result)
                self.assertEqual(records, [])

    def test_mixed_file_audits_keep_each_files_masks_and_risk_separate(self) -> None:
        old = '#include "obs.h"\n/* old */\nint x;\n'
        changed = old.replace('/* old */', '/* old\n */')
        typo = old.replace('old', 'new')
        one, two = view(old, changed), view(old, typo)
        patch_text = one.original.diff_str + two.original.diff_str.replace('unit.c', 'other.c')
        original = one.original
        commit = FilteredCommit(GitCommit('child', '', '', original.author_date, original.committer_date,
                                          (CommitParent('parent', patch_text),), ''))
        class FilesRepo(GitRepo):
            def read_file_mode(self, commit: str, path: str) -> str:
                return "100644"

            def read_file(self, revision: str, path: str) -> bytes:
                if revision == 'parent':
                    return old.encode()
                return (changed if path == 'unit.c' else typo).encode()
        records: list[PruningDecision] = []
        stage = WhitespaceFilter(line_numbers_lossy=True, on_pruned=records.append)
        self.assertIsNone(stage.filter_mutable_commit(commit, FilterContext(FilesRepo(Path('.')), input_roles=FixtureSourceRoles())))
        self.assertEqual([record.lossy for record in records], [True, False])
        for record in records:
            self.assertTrue(all(mask.file.path == record.paths[0] for mask in record.edit_masks))

    def test_audit_failure_propagates(self) -> None:
        old, new = '/* old */\nint x;\n', '/* old\n */\nint x;\n'
        def fail(decision: PruningDecision) -> None:
            raise OSError('report unavailable')
        stage = WhitespaceFilter(line_numbers_lossy=True, on_pruned=fail)
        with self.assertRaisesRegex(OSError, 'report unavailable'):
            stage.filter_mutable_commit(view(old, new), FilterContext(ByteRepo(old.encode(), new.encode()), input_roles=FixtureSourceRoles()))

    def test_source_lossy_flag_does_not_enable_line_number_assumption(self) -> None:
        stages = source_pruning_tail(lossy=True)
        self.assertFalse(stages[-2].line_numbers_lossy)


class LossyWhitespaceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        subprocess.run(['git', '-C', str(self.source), 'init', '-q'], check=True)
        self.raw = self.root / 'raw.sqlite'
        self.store = GitDb(self.raw)
        self.destination = self.root / 'filtered.sqlite'
        self.destination.write_bytes(b'destination sentinel')
        self.report = self.root / 'whitespace.jsonl'
        self.source_report = self.root / 'source.jsonl'
        self.arguments = ['filter', '--repo', str(self.source), '--db', 'raw-fixture', '--dest', 'dest-fixture', 'config']
        self.addCleanup(patch.stopall)
        patch('kpatch.cli.GitDb.load_name', return_value=self.store).start()
        patch('kpatch.cli._path_for_db_name', return_value=self.destination).start()

    def invoke(self, arguments: list[str]):
        with patch('kpatch.cli.run') as run:
            result = CliRunner().invoke(app, self.arguments + arguments)
        return result, run

    def test_lossy_cli_requires_report_before_running(self) -> None:
        result, run = self.invoke(['--whitespace-line-numbers-lossy'])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn('--whitespace-report', result.output)
        run.assert_not_called()

    def test_report_is_independent_and_serializes_runtime_risk(self) -> None:
        result, run = self.invoke(['--whitespace-line-numbers-lossy', '--whitespace-report', str(self.report)])
        self.assertEqual(result.exit_code, 0, result.output)
        pipeline = run.call_args.args[1]
        stage = pipeline.filters[-1]
        self.assertTrue(stage.line_numbers_lossy)
        old, new = '/* old */\nint x;\n', '/* old\n */\nint x;\n'
        self.assertIsNone(stage.filter_mutable_commit(view(old, new), FilterContext(ByteRepo(old.encode(), new.encode()), input_roles=FixtureSourceRoles())))
        record = json.loads(self.report.read_text())
        self.assertTrue(record['lossy'])
        self.assertEqual(record['rule'], 'whitespace_line_numbers_lossy')
        self.assertIn('source_line_number_observations_may_change_runtime_behavior', record['risk_reasons'])

    def test_source_tail_keeps_distinct_audit_destinations(self) -> None:
        result, run = self.invoke(['--source-pruning', '--source-pruning-report', str(self.source_report),
                                   '--whitespace-line-numbers-lossy', '--whitespace-report', str(self.report)])
        self.assertEqual(result.exit_code, 0, result.output)
        stages = run.call_args.args[1].filters
        self.assertTrue(stages[-2].line_numbers_lossy)
        self.assertFalse(stages[-1].lossy)
        self.assertEqual(stages[-2].on_pruned.path, self.report)
        self.assertEqual(stages[-1].on_pruned.path, self.source_report)

    def test_constant_branch_selection_preserves_separate_lossy_audit(self) -> None:
        for line_lossy in (False, True):
            with self.subTest(line_lossy=line_lossy):
                arguments = ['--source-pruning', '--constant-branches',
                             '--source-pruning-report', str(self.source_report),
                             '--whitespace-report', str(self.report)]
                if line_lossy:
                    arguments.append('--whitespace-line-numbers-lossy')
                result, run = self.invoke(arguments)
                self.assertEqual(result.exit_code, 0, result.output)
                stages = run.call_args.args[1].filters
                constant = stages[-4]
                self.assertEqual(constant.line_numbers_lossy, line_lossy)
                self.assertEqual(constant.on_pruned.path, self.source_report)
                self.assertEqual(constant.on_line_numbers_assumed.path, self.report)
                self.assertFalse(stages[-1].lossy)

    def test_aliasing_reports_fail_before_either_is_truncated(self) -> None:
        self.report.write_text('existing report')
        alias = self.root / 'alias.jsonl'
        alias.symlink_to(self.report)
        result, run = self.invoke(['--source-pruning', '--source-pruning-report', str(self.report),
                                   '--whitespace-report', str(alias)])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.report.read_text(), 'existing report')
        run.assert_not_called()

    def test_raw_destination_source_and_hardlink_inputs_are_preserved(self) -> None:
        header = self.source / 'unit.h'
        header.write_bytes(b'source sentinel')
        alias = self.root / 'raw-alias.jsonl'
        alias.hardlink_to(self.raw)
        for destination in (self.raw, self.destination, header, alias):
            with self.subTest(destination=destination):
                before = destination.read_bytes()
                result, run = self.invoke(['--whitespace-line-numbers-lossy', '--whitespace-report', str(destination)])
                self.assertEqual(result.exit_code, 2, result.output)
                run.assert_not_called()
                self.assertEqual(destination.read_bytes(), before)

    def test_second_report_validation_cannot_truncate_first(self) -> None:
        self.source_report.write_text('source report sentinel')
        result, run = self.invoke(['--source-pruning', '--source-pruning-report', str(self.source_report),
                                   '--whitespace-report', str(self.raw)])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.source_report.read_text(), 'source report sentinel')
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
