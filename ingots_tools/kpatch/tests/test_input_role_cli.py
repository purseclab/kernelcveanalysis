"""CLI assumption opt-in, audit protection and real sparse-database filtering."""

import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.git import GitDb, GitRepo, HistoryKind


class InputRoleCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.repo = GitRepo(self.source)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Input role CLI tests')
        self.git('config', 'user.email', 'roles@example.invalid')
        self.raw = GitDb(self.root / 'raw.sqlite')
        self.destination = self.root / 'filtered.sqlite'
        self.report = self.root / 'roles.jsonl'
        self.arguments = ['filter', '--repo', str(self.source), '--db', 'raw-fixture',
                          '--dest', 'filtered-fixture', 'config']

    def git(self, *arguments: str) -> None:
        subprocess.run(['git', '-C', str(self.source), *arguments], check=True, capture_output=True)

    def invoke(self, arguments: list[str]):
        with (patch('kpatch.cli.GitDb.load_name', return_value=self.raw),
              patch('kpatch.cli._path_for_db_name', return_value=self.destination),
              patch('kpatch.filter._path_for_db_name', return_value=self.destination),
              patch('kpatch.git._path_for_db_name', return_value=self.destination)):
            return CliRunner().invoke(app, self.arguments + arguments)

    def candidate(self, *, positive: bool = False) -> str:
        (self.source / 'Makefile').write_text('generated.c: $(UNMODELED_INPUT)\n\tpython gen.py $< >$@\n')
        (self.source / 'api.h').write_text('/*7*/\n')
        if positive:
            (self.source / 'blob.S').write_text('.incbin "api.h"\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'parent')
        (self.source / 'api.h').write_text('/*8*/\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        commit = next(self.repo.iter_commits_from_revision('HEAD^!'))
        self.raw.store_commits([commit], HistoryKind.SPARSE)
        return commit.commit_id

    def test_opt_in_and_report_are_required_together_before_writes(self) -> None:
        for arguments in (['--unresolved-inputs-lossy'], ['--input-role-report', str(self.report)]):
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertFalse(self.report.exists())
                self.assertFalse(self.destination.exists())

    def test_actual_cli_filters_and_serializes_both_historical_assumptions(self) -> None:
        commit_id = self.candidate()
        result = self.invoke([])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(GitDb(self.destination).commits_between()), 1)
        result = self.invoke(['--unresolved-inputs-lossy', '--input-role-report', str(self.report)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(GitDb(self.destination).commits_between(), [])
        records = [json.loads(line) for line in self.report.read_text().splitlines()]
        self.assertEqual(len(records), 1)
        record, = records
        self.assertEqual(record['commit_id'], commit_id)
        self.assertTrue(record['lossy'])
        self.assertEqual(record['rule'], 'unresolved_input_roles_assumed')
        self.assertEqual({item['side'] for item in record['input_role_evidence']}, {'old', 'new'})
        self.assertTrue(all(item['observation']['state'] == 'full' for item in record['input_role_evidence']))
        self.assertEqual(len(self.raw.commits_between()), 1)

    def test_actual_cli_retains_positive_raw_consumer_without_assumption_record(self) -> None:
        self.candidate(positive=True)
        result = self.invoke(['--unresolved-inputs-lossy', '--input-role-report', str(self.report)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(GitDb(self.destination).commits_between()), 1)
        self.assertEqual(self.report.read_text(), '')

    def test_report_cannot_alias_inputs_destination_or_another_report(self) -> None:
        header = self.source / 'api.h'
        header.write_text('source sentinel')
        self.destination.write_text('destination sentinel')
        for path in (self.raw.db, self.destination, header):
            with self.subTest(path=path):
                before = path.read_bytes()
                result = self.invoke(['--unresolved-inputs-lossy', '--input-role-report', str(path)])
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertEqual(path.read_bytes(), before)
        self.report.write_text('report sentinel')
        result = self.invoke(['--unresolved-inputs-lossy', '--input-role-report', str(self.report),
                              '--whitespace-report', str(self.report)])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.report.read_text(), 'report sentinel')


if __name__ == '__main__':
    unittest.main()
