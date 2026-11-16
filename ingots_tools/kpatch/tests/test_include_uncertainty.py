from datetime import UTC, datetime
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest

from kpatch.diff import DiffFileType
from kpatch.filter import ConfigFilter, FilterContext, FilteredCommit, FilterPipeline, IfdefFilter
from kpatch.filter.config_filter import BuildInputClosure, ConfigValue, KbuildState, KernelConfig, SourceAnalysisCache
from kpatch.filter.config.decisions import decide_commit
from kpatch.filter.config.history import ConfigHistoryStore, FileDecision, HistoryCommit, parse_history_diff
from kpatch.diff import Diff
from kpatch.filter.source_filter import SourceIncludeIndex
from kpatch.git import CommitParent, GitCommit, GitRepo, StructuredCommits
from tests.test_config_filter import MemoryGitRepo, make_diff


class IncludeUncertaintyTests(unittest.TestCase):
    def test_cpp_completeness_survives_decision_store_roundtrip(self) -> None:
        decisions={(None,'drivers/known.c'):FileDecision(ConfigValue.ENABLED,ConfigValue.ENABLED,complete=True),
                   (None,'drivers/unknown.c'):FileDecision(None,ConfigValue.MODULE,complete=False)}
        with ConfigHistoryStore() as store:
            store.add_decisions('commit',decisions)
            self.assertEqual(store.get_decisions('commit'),decisions)

    def state(self, contents: str, *, mode: str = 'y', extra: dict[str, str] | None = None) -> tuple[KbuildState, SourceIncludeIndex]:
        files = {'Kbuild': 'obj-y += drivers/\n', 'drivers/Makefile': 'obj-$(CONFIG_DRIVER) += main.o\n',
                 'drivers/main.c': contents, 'drivers/api.h': 'int api;\n', **(extra or {})}
        index = SourceIncludeIndex('', files)
        for path, text in files.items():
            for line in text.splitlines():
                index.add_line(path, line)
        index.add_diff(make_diff('drivers/main.c', DiffFileType.DEFAULT))
        state = KbuildState(MemoryGitRepo({'base': files}), KernelConfig('CONFIG_DRIVER='+mode), 'base', index)
        return state, index

    def test_supported_comment_splice_digraph_and_arbitrary_targets(self) -> None:
        for directive in ('/* prefix */ #include "api.h"\n', '/* prefix\n*/ #include "api.h"\n',
                          '#/**/include "api.h"\n', '#include/**/"api.h"\n',
                          '#inc\\\nlude "api.h"\n', '%:include "api.h"\n'):
            with self.subTest(directive=directive):
                state, _ = self.state(directive)
                self.assertEqual(state.get('drivers/api.h'), ConfigValue.ENABLED)
                self.assertIn('drivers/api.h',state._active_source_includes('drivers/main.c',ConfigValue.ENABLED))
        state, _ = self.state('#include "fragment.txt"\n', extra={'drivers/fragment.txt': '#include "api.h"\n'})
        self.assertTrue(state.file_included('drivers/fragment.txt'))
        self.assertTrue(state.file_included('drivers/api.h'))

    def test_unmodeled_operands_do_not_enable_every_unrelated_input(self) -> None:
        for mode, expected in (('y', ConfigValue.ENABLED), ('m', ConfigValue.MODULE), ('n', None)):
            with self.subTest(mode=mode):
                state, _ = self.state('#include HEADER\n', mode=mode,
                                      extra={'drivers/fragment.c': '', 'drivers/fragment.S': '', 'drivers/fragment.txt': ''})
                for path in ('drivers/api.h', 'drivers/fragment.c', 'drivers/fragment.S', 'drivers/fragment.txt'):
                    self.assertIsNone(state.get(path))
                self.assertEqual(state.object_membership('drivers/main.c'),expected)
                self.assertEqual(state.build_input_closure,BuildInputClosure.UNKNOWN)
                self.assertEqual(state.cpp_context_complete('drivers/main.c'), expected is not None)
                self.assertEqual(state.get('drivers'), ConfigValue.ENABLED)

    def test_known_inactive_cpp_does_not_certify_external_input_absence(self) -> None:
        state, _ = self.state('#if 0\n#include HEADER\n#endif\n')
        self.assertFalse(state._active_source_facts('drivers/main.c',ConfigValue.ENABLED).unknown)
        self.assertIsNone(state.get('drivers/api.h'))

    def test_macro_override_and_unmodeled_directives_are_unknown(self) -> None:
        for source in ('#undef CONFIG_WIDGET\n#define CONFIG_WIDGET 1\n#if CONFIG_WIDGET\n#include "api.h"\n#endif\n',
                       '#include_next "api.h"\n', '#import "api.h"\n', '#include "generated.h"\n',
                       '#include /* first\nsecond */ "api.h"\n', '\0#include "api.h"\n',
                       '#inc\\ \nlude "api.h"\n', '#if __has_include("api.h")\n#endif\n'):
            with self.subTest(source=source):
                state, _ = self.state(source)
                self.assertEqual(state.get('drivers/api.h'), None if 'generated.h' in source else ConfigValue.ENABLED)
                self.assertTrue(state._active_source_facts('drivers/main.c',ConfigValue.ENABLED).unknown)

    def test_dynamic_literal_closure_reaches_nested_opaque_fragment(self) -> None:
        state, _ = self.state('#include "z-fragment.txt"\n', extra={
            'drivers/z-fragment.txt': '#include "a-middle.h"\n',
            'drivers/a-middle.h': '#include HEADER\n',
        })
        self.assertEqual(state.get('drivers/z-fragment.txt'), ConfigValue.ENABLED)
        self.assertEqual(state.get('drivers/a-middle.h'), ConfigValue.ENABLED)
        self.assertIsNone(state.get('drivers/api.h'))

    def test_unrelated_unknown_source_change_does_not_queue_global_discovery(self) -> None:
        source = 'drivers/main.c'
        state, index = self.state('#include HEADER\n')
        self.assertIsNone(state.get('drivers/api.h'))
        self.assertFalse(state._pending_include_sources)
        copied = KbuildState.copy(state)
        self.assertFalse(copied._pending_include_sources)
        files = dict(state.repo.commits['base'])
        files[source] = 'int main(void) { return 0; }\n'
        state.repo.commits['next'] = files
        state.update_filter_state(make_diff(source, DiffFileType.DEFAULT), 'next')
        self.assertNotIn(source, state._pending_include_sources)
        self.assertIsNone(state.get('drivers/api.h'))
        self.assertIsNone(state.modeled_inclusion('drivers/api.h'))
        self.assertIsNone(copied.get('drivers/api.h'))

    def test_new_local_binding_invalidates_analysis_and_reverse_absence(self) -> None:
        files = {'drivers/Makefile': 'obj-y += main.o\n', 'drivers/main.c': '#include "api.h"\n',
                 'include/api.h': '', 'drivers/api.h': ''}
        index = SourceIncludeIndex('', ('drivers/main.c', 'include/api.h'))
        index.add_line('drivers/main.c', '#include "api.h"')
        state = KbuildState(MemoryGitRepo({'base': files}), KernelConfig(''), 'base', index)
        self.assertEqual(state.modeled_inclusion('include/api.h'), ConfigValue.ENABLED)
        index.add_paths(('drivers/api.h',))
        self.assertIn('drivers/api.h',state._active_source_includes('drivers/main.c',ConfigValue.ENABLED))
        self.assertIsNone(state.modeled_inclusion('include/api.h'))
        self.assertIsNone(state.get('include/api.h'))

    def test_nonregular_mode_in_history_cannot_become_known_empty_input(self) -> None:
        state, index = self.state('int main(void) { return 0; }\n')
        diff = make_diff('drivers/main.c', DiffFileType.DEFAULT)
        diff.files[0].new_mode = '120000'
        index.add_diff(diff)
        self.assertIsNone(state.get('drivers/api.h'))

    def test_enabled_opaque_directory_is_a_seed_but_not_a_file_target(self) -> None:
        state, index = self.state('int main(void) { return 0; }\n')
        state.repo.commits['base']['drivers/Makefile'] = 'obj-y += unseen/\n'
        diff = make_diff('drivers/unseen', DiffFileType.NEW)
        diff.files[0].new_mode = '160000'
        index.add_diff(diff)
        self.assertIsNone(state.get('drivers/api.h'))
        self.assertFalse(index.has_path('drivers/unseen'))

    def test_closing_unknown_inclusion_does_not_erase_old_side_of_another_file(self) -> None:
        before={'drivers/Makefile':'obj-y += main.o\n','drivers/main.c':'#include /* first\nsecond */ "fragment.c"\n',
                'drivers/fragment.c':'int value=7;\n'}
        after={**before,'drivers/main.c':'int main(void) { return 0; }\n',
               'drivers/fragment.c':'int value=8;\n'}
        diff=parse_history_diff('diff --git a/drivers/main.c b/drivers/main.c\n--- a/drivers/main.c\n+++ b/drivers/main.c\n@@ -1,2 +1 @@\n-#include /* first\n-second */ "fragment.c"\n+int main(void) { return 0; }\n'
                        'diff --git a/drivers/fragment.c b/drivers/fragment.c\n--- a/drivers/fragment.c\n+++ b/drivers/fragment.c\n@@ -1 +1 @@\n-int value=7;\n+int value=8;\n')
        index=SourceIncludeIndex('',before)
        index.add_diff(diff)
        state=KbuildState(MemoryGitRepo({'base':before,'next':after}),KernelConfig(''),'base',index)
        decisions=decide_commit(state,HistoryCommit('next',('base',)),diff)
        fragment=decisions[(None,'drivers/fragment.c')]
        self.assertEqual(fragment.old,ConfigValue.ENABLED)
        self.assertIsNone(fragment.new)
        self.assertFalse(fragment.complete)

    def test_unsupported_make_expansion_absence_cannot_remove_real_input(self) -> None:
        files={'drivers/Makefile':'obj-y += $(patsubst %.S,%.o,one.S two.o)\n',
               'drivers/one.S':'','drivers/two.c':'int value=7;\n'}
        state=KbuildState(MemoryGitRepo({'base':files}),KernelConfig(''),'base',SourceIncludeIndex('',files))
        # GNU Make retains the nonmatching two.o word. The partial parser does
        # not; its observation is useful but cannot authorize an exclusion.
        self.assertEqual(state.object_membership('drivers/two.c'), ConfigValue.ENABLED)
        self.assertEqual(state.get('drivers/two.c'),ConfigValue.ENABLED)


class ConfigHeaderCompilerTests(unittest.TestCase):
    def test_unknown_build_scope_covers_assembly_inline_asm_and_forced_inputs(self) -> None:
        compiler=shutil.which('gcc')
        if compiler is None:
            self.skipTest('GCC compile control required')
        data_asm=b'.section .rodata\n.global marker\nmarker:\n.incbin "drivers/api.h"\n.section .note.GNU-stack,"",@progbits\n'
        # Build the C spelling without confusing Python/C quote escaping.
        inline=b'asm(".section .rodata\\n.global marker\\nmarker:\\n.incbin \\\"drivers/api.h\\\"\\n.previous");\nextern unsigned char marker[]; int main(void) { return marker[0]; }\n'
        cases={
            'assembly':({'drivers/main.c':b'extern unsigned char marker[]; int main(void) { return marker[0]; }\n',
                         'drivers/data.S':data_asm},'obj-y += main.o data.o\n',[],False),
            'inline':({'drivers/main.c':inline},'obj-y += main.o\n',[],False),
            'forced':({'drivers/main.c':b'int main(void) { return api(); }\n'},
                      'obj-y += main.o\nccflags-y += -include $(src)/api.h\n',['-include','drivers/api.h'],True),
        }
        for name,(sources,makefile,flags,header_function) in cases.items():
            with self.subTest(name=name),TemporaryDirectory() as temporary:
                root=Path(temporary)
                def git(*arguments: str) -> str:
                    return subprocess.check_output(['git','-C',str(root),*arguments],stderr=subprocess.PIPE).decode().strip()
                git('init','-q');git('config','user.name','Test');git('config','user.email','test@example.invalid')
                (root/'drivers').mkdir()
                (root/'Kbuild').write_text('obj-y += drivers/\n')
                (root/'drivers/Makefile').write_text(makefile)
                for path,body in sources.items():
                    (root/path).write_bytes(body)
                revisions=[]
                for value in (7,8):
                    header=f'static inline int api(void) {{ return {value}; }}\n'.encode() if header_function else bytes([value])
                    (root/'drivers/api.h').write_bytes(header)
                    git('add','Kbuild','drivers');git('commit','-qm',str(value))
                    revisions.append(git('rev-parse','HEAD'))
                    compiled=subprocess.run([compiler,*flags,*sources,'-o','program'],cwd=root,capture_output=True)
                    self.assertEqual(compiled.returncode,0,compiled.stderr)
                    self.assertEqual(subprocess.run([str(root/'program')]).returncode,value)
                parent,child=revisions
                date=datetime.now(UTC)
                commit=GitCommit(child,'Test','test@example.invalid',date,date,
                                 (CommitParent(parent,git('diff',parent,child)),),'input changes behavior')
                context=FilterContext(GitRepo(root),StructuredCommits.from_commits([commit]))
                view=FilteredCommit.from_commit(commit)
                result=FilterPipeline([ConfigFilter(KernelConfig('CONFIG_X86_64=y'))]).filter_mutable_commits([view],context,False)
                self.assertEqual(len(result),1)
                self.assertFalse(next(iter(view.build_modes.values())).complete)

    def test_uncertain_builtin_inclusion_does_not_erase_module_only_change(self) -> None:
        compiler = shutil.which('gcc')
        if compiler is None:
            self.skipTest('GCC compile control required')
        with TemporaryDirectory() as temporary:
            root=Path(temporary)
            def git(*arguments: str) -> str:
                return subprocess.check_output(['git','-C',str(root),*arguments],stderr=subprocess.PIPE).decode().strip()
            git('init','-q')
            git('config','user.name','Test')
            git('config','user.email','test@example.invalid')
            (root/'drivers').mkdir()
            (root/'Kbuild').write_text('obj-y += drivers/\n')
            (root/'drivers/Makefile').write_text('obj-y += active.o\nobj-m += modu.o\n')
            (root/'drivers/active.c').write_text('#define HEADER "api.h"\n#include HEADER\n')
            (root/'drivers/api.h').write_text('')
            revisions=[]
            for value in (7,8):
                (root/'drivers/modu.c').write_text(f'#ifdef MODULE\nint main(void) {{ return {value}; }}\n#else\nint main(void) {{ return 0; }}\n#endif\n')
                git('add','Kbuild','drivers')
                git('commit','-qm',str(value))
                revisions.append(git('rev-parse','HEAD'))
                compiled=subprocess.run([compiler,'-DMODULE',str(root/'drivers/modu.c'),'-o',str(root/'program')],capture_output=True)
                self.assertEqual(compiled.returncode,0,compiled.stderr)
                self.assertEqual(subprocess.run([str(root/'program')]).returncode,value)
            parent,child=revisions
            date=datetime.now(UTC)
            commit=GitCommit(child,'Test','test@example.invalid',date,date,
                             (CommitParent(parent,git('diff',parent,child)),),'module changes behavior')
            context=FilterContext(GitRepo(root),StructuredCommits.from_commits([commit]))
            view=FilteredCommit.from_commit(commit)
            config=KernelConfig('CONFIG_X86_64=y')
            output=FilterPipeline([ConfigFilter(config),IfdefFilter(config)]).filter_mutable_commits([view],context,False)
            self.assertEqual(len(output),1)
            self.assertTrue(next(iter(view.build_modes.values())).complete)
            self.assertEqual(view.edit_masks,())
            self.assertTrue(view.code_masks)

    def test_compiler_positive_header_changes_survive_actual_config_stage(self) -> None:
        compiler = shutil.which('gcc')
        if compiler is None:
            self.skipTest('GCC compile control required')
        prefixes = (b'#include "api.h"\n', b'\0#include "api.h"\n', b'/* prefix */ #include "api.h"\n',
                    b'/* prefix\n*/ #include "api.h"\n', b'#/**/include "api.h"\n',
                    b'#inc\\\nlude "api.h"\n', b'#define HEADER "api.h"\n#include HEADER\n')
        for prefix in prefixes:
            with self.subTest(prefix=prefix), TemporaryDirectory() as temporary:
                root = Path(temporary)
                def git(*arguments: str) -> str:
                    return subprocess.check_output(['git', '-C', str(root), *arguments], stderr=subprocess.PIPE).decode().strip()
                git('init', '-q')
                git('config', 'user.name', 'Test')
                git('config', 'user.email', 'test@example.invalid')
                (root/'drivers').mkdir()
                (root/'Kbuild').write_text('obj-y += drivers/\n')
                (root/'drivers/Makefile').write_text('obj-y += main.o\n')
                (root/'drivers/main.c').write_bytes(prefix+b'int main(void) { return api(); }\n')
                revisions=[]
                for value in (7,8):
                    (root/'drivers/api.h').write_text(f'static inline int api(void) {{ return {value}; }}\n')
                    git('add', 'Kbuild', 'drivers')
                    git('commit', '-qm', str(value))
                    revisions.append(git('rev-parse', 'HEAD'))
                    executable=root/'program'
                    compiled=subprocess.run([compiler,'-std=gnu11',str(root/'drivers/main.c'),'-o',str(executable)],capture_output=True)
                    self.assertEqual(compiled.returncode,0,compiled.stderr)
                    self.assertEqual(subprocess.run([str(executable)]).returncode,value)
                parent,child=revisions
                date=datetime.now(UTC)
                commit=GitCommit(child,'Test','test@example.invalid',date,date,
                                 (CommitParent(parent,git('diff',parent,child)),),'header changes behavior')
                context=FilterContext(GitRepo(root),StructuredCommits.from_commits([commit]))
                view=FilteredCommit.from_commit(commit)
                output=FilterPipeline([ConfigFilter(KernelConfig('CONFIG_X86_64=y'))]).filter_mutable_commits([view],context,False)
                self.assertEqual(len(output),1)
                self.assertEqual(view.edit_masks,())
                self.assertEqual(view.code_masks,())


if __name__=='__main__':
    unittest.main()
