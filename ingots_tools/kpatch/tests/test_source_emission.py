"""Unused runtime entry points can still emit startup registrations."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter import DeadCodeFilter, FilterContext, FilteredCommit, FilterPipeline, KernelConfig
from kpatch.filter.input_role_models import InputInventoryState, RawInputObservation
from kpatch.filter.input_roles import RawInputIndex
from kpatch.filter.macro_environment import MacroEnvironmentGuard
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.git import CommitParent, GitCommit, GitRepo


_HEADER = '''void boot_callback(void);
void registration_sink(void *);
static inline void register_site(void) {
 static void (*entry)(void) __attribute__((section("boot_hooks"))) = boot_callback;
 registration_sink(&entry);
}
'''
_FRAMEWORK = '''typedef void (*hook)(void);
int boot_state;
void boot_callback(void) { boot_state=1; }
void registration_sink(void *ignored) {}
extern hook __start_boot_hooks[] __attribute__((weak));
extern hook __stop_boot_hooks[] __attribute__((weak));
int main(void) {
 if (__start_boot_hooks && __stop_boot_hooks)
  for (hook *p=__start_boot_hooks; p<__stop_boot_hooks; ++p) (*p)();
 return boot_state;
}
'''


@dataclass(frozen=True)
class _ActualRoles:
    index: RawInputIndex

    def lookup(self, context: FilterContext, revision: str, path: str) -> RawInputObservation:
        return self.index.lookup(revision, path)


class SourceEmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = shutil.which('clang')
        if compiler is None:
            self.skipTest('Clang is required for the native callback witness')
        self.compiler = compiler
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'repo'
        self.path.mkdir()
        self.repo = GitRepo(self.path)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Source emission test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.path / 'registration.h').write_text(_HEADER)
        (self.path / 'framework.c').write_text(_FRAMEWORK)
        (self.path / 'Makefile').write_text('obj-y += unit.o framework.o\n')

    def git(self, *args: str) -> str:
        return subprocess.check_output(['git', '-C', str(self.path), *args], stderr=subprocess.PIPE).decode().strip()

    def save(self, source: str) -> str:
        (self.path / 'unit.c').write_text(source)
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def native_exit(self, label: str, source: str) -> int:
        main = self.root / f'{label}.c'
        obj = self.root / f'{label}.o'
        binary = self.root / f'{label}.bin'
        main.write_text(source)
        subprocess.run([self.compiler, '-O2', '-I', str(self.path), '-c', str(main), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run([self.compiler, '-O2', str(obj), str(self.path / 'framework.c'), '-o', str(binary)],
                       check=True, capture_output=True)
        return subprocess.run([str(binary)], check=False).returncode

    def assert_registration_preserved(self, before: str, after: str) -> None:
        parent, child = self.save(before), self.save(after)
        date = datetime(2026, 11, 8, tzinfo=UTC)
        commit = GitCommit(child, 'Test', 'test@example.invalid', date, date,
                           (CommitParent(parent, self.git('diff', parent, child)),), 'fixture')
        # No caller ever invokes the apparent unused function. The startup
        # walker nevertheless observes a slot emitted through its inline helper.
        self.assertEqual((self.native_exit('old', before), self.native_exit('new', after)), (0, 1))
        with RepositoryFileReader(self.repo) as reader:
            index = RawInputIndex(self.repo, reader.read_file)
            for revision in (parent, child):
                observation = index.lookup(revision, 'unit.c')
                self.assertEqual(observation.state, InputInventoryState.FULL)
                self.assertEqual(observation.consumers, ())
                self.assertEqual(observation.unknowns, ())
                self.assertEqual(observation.failures, ())
                self.assertTrue(MacroEnvironmentGuard(self.repo, reader.read_file).inspect(revision, 'unit.c').closed)
            for lossy in (False, True):
                with self.subTest(source_lossy=lossy):
                    decisions: list[PruningDecision] = []
                    view = FilteredCommit(commit)
                    stage = DeadCodeFilter(KernelConfig(''), on_pruned=decisions.append, lossy=lossy)
                    output = FilterPipeline([stage]).filter_mutable_commits(
                        [view], FilterContext(self.repo, file_reader=reader, input_roles=_ActualRoles(index)), False)
                    self.assertEqual(output, [view], decisions)
                    self.assertEqual(view.edit_masks, ())
                    self.assertEqual(view.code_masks, ())
                    self.assertEqual(decisions, [])

    def test_unused_function_call_cannot_erase_startup_registration(self) -> None:
        before = '#include "registration.h"\nint isolated_widget(void) {\n return 7;\n}\n'
        self.assert_registration_preserved(before, before.replace(' return 7;', ' register_site();\n return 7;'))

    def test_unused_function_helper_address_cannot_erase_startup_registration(self) -> None:
        before = '#include "registration.h"\nvoid *orphan(void) {\n return 0;\n}\n'
        self.assert_registration_preserved(before, before.replace(' return 0;', ' return (void *)register_site;'))

    def test_unused_function_type_macro_cannot_erase_startup_registration(self) -> None:
        before = ('#include "registration.h"\n'
                  '#define TYPE __typeof__((int (*)[(register_site(),1)])0)\n'
                  'int isolated_widget(void) {\n return 7;\n}\n')
        self.assert_registration_preserved(before, before.replace(' return 7;', ' TYPE unused=0;\n return 7;'))


if __name__ == '__main__':
    unittest.main()
