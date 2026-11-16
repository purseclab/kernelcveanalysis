from datetime import UTC, datetime
from pathlib import Path
import json
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import FilterContext, FilterPipeline
from kpatch.filter.pruning_audit import PruningAudit
from kpatch.filter.source_pruning import DeadCodeFilter, PruningDecision, RenameFilter
from kpatch.filter.syntax import definitions, parse_source
from kpatch.git import CommitParent, GitCommit, GitRepo


class BindingFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.repo = GitRepo(self.source)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Binding Test')
        self.git('config', 'user.email', 'binding@example.invalid')
        self.decisions: list[PruningDecision] = []

    def git(self, *args: str) -> str:
        return subprocess.check_output(['git', '-C', str(self.source), *args], stderr=subprocess.PIPE).decode().strip()

    def change(self, old: str, new: str, *, files: dict[str, str] | None = None) -> GitCommit:
        for name, text in {'unit.c': old, **(files or {})}.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git('add', '.')
        self.git('commit', '-qm', 'before')
        parent = self.git('rev-parse', 'HEAD')
        (self.source / 'unit.c').write_text(new)
        self.git('add', '.')
        self.git('commit', '-qm', 'after')
        child = self.git('rev-parse', 'HEAD')
        date = datetime(2025, 1, 1, tzinfo=UTC)
        return GitCommit(child, 'Binding', 'binding@example.invalid', date, date,
                         (CommitParent(parent, self.git('diff', parent, child)),), 'binding')

    def rename(self, commit: GitCommit, *, lossy: bool = False) -> list[GitCommit]:
        return FilterPipeline([RenameFilter(on_pruned=self.decisions.append, lossy=lossy)]).filter_commits(
            [commit], FilterContext(self.repo), False)

    def test_prototype_rename_ignores_unrelated_same_spelling(self) -> None:
        old = 'int value; int run(int value); int other(void) { return value; }\n'
        commit = self.change(old, old.replace('run(int value)', 'run(int input)'))
        self.assertEqual(self.rename(commit), [])
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertEqual(len(self.decisions), 2)
        for decision in self.decisions:
            self.assertEqual(decision.rule, 'prototype_parameter_names')
            self.assertFalse(decision.lossy)
            self.assertEqual(decision.symbols, ('value->input',))
            self.assertIn('debug_and_btf_parameter_names_may_change', decision.risk_reasons)
        report = self.root / 'prototype-audit.jsonl'
        PruningAudit.create(report, self.source, ())(self.decisions[0])
        self.assertFalse(json.loads(report.read_text())['lossy'])

    def test_prototype_name_metadata_exemption_preserves_type_changing_macros(self) -> None:
        old = '#include "binding.h"\nint run(int original);\n'
        commit = self.change(old, old.replace('original', 'renamed'), files={
            'binding.h': '#define renamed argument[4]\n'})
        for lossy in (False, True):
            with self.subTest(lossy=lossy):
                self.assertEqual(len(self.rename(commit, lossy=lossy)), 1)
                self.assertEqual(self.decisions, [])

    def test_local_body_mode_is_explicit_and_audited(self) -> None:
        old = 'int input, result; int run(int input) { int result=input+1; return result; }\n'
        new = 'int input, result; int run(int value) { int output=value+1; return output; }\n'
        commit = self.change(old, new)
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertTrue(self.decisions[-1].lossy)
        self.assertEqual(self.decisions[-1].rule, 'local_binding_rename_lossy')
        report = self.root / 'audit.jsonl'
        PruningAudit.create(report, self.source, ())(self.decisions[-1])
        self.assertTrue(json.loads(report.read_text())['lossy'])
        self.assertTrue(json.loads(report.read_text())['risk_reasons'])

    def test_incomplete_discovery_requires_lossy_mode_and_records_assumption(self) -> None:
        old = 'int run(int original);\n'
        commit = self.change(old, old.replace('original', 'renamed'), files={
            'opaque.dat': '\0# /**/ define UNRELATED 1\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertTrue(self.decisions[-1].lossy)
        self.assertIn('incomplete_macro_discovery_assumed', self.decisions[-1].risk_reasons)

    def test_known_binding_after_unrelated_opacity_retains_even_lossy(self) -> None:
        old = 'int run(int original);\n'
        commit = self.change(old, old.replace('original', 'renamed'), files={
            'a-opaque.dat': '\0# /**/ define UNRELATED 1\n',
            'z-binding.h': '#define renamed argument[4]\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_reorder_assuming_incomplete_discovery_is_audited_as_lossy(self) -> None:
        old = 'int run(int n) { switch(n) {case 1:return 1; case 2:return 2;} return 0; }\n'
        new = old.replace('case 1:return 1; case 2:return 2;', 'case 2:return 2; case 1:return 1;')
        commit = self.change(old, new, files={'opaque.dat': '\0# /**/ define UNRELATED 1\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertEqual(self.decisions[-1].rule, 'independent_return_case_reorder')
        self.assertTrue(self.decisions[-1].lossy)
        self.assertIn('incomplete_macro_discovery_assumed', self.decisions[-1].risk_reasons)

    def test_unused_discovery_assumption_is_explicit_and_audited(self) -> None:
        old = 'static int orphan(void) { return 1; }\n'
        commit = self.change(old, old.replace('return 1', 'return 2'), files={
            'opaque.dat': '\0# /**/ define UNRELATED 1\n'})
        strict = DeadCodeFilter(on_pruned=self.decisions.append)
        self.assertEqual(len(FilterPipeline([strict]).filter_commits([commit], FilterContext(self.repo), False)), 1)
        self.assertEqual(self.decisions, [])
        stage = DeadCodeFilter(lossy=True, on_pruned=self.decisions.append)
        self.assertEqual(FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), False), [])
        self.assertEqual(len(self.decisions), 1)
        self.assertEqual(self.decisions[0].rule, 'unreferenced_definition')
        self.assertEqual(self.decisions[0].symbols, ('orphan',))
        self.assertTrue(self.decisions[0].lossy)
        self.assertIn('incomplete_macro_discovery_assumed', self.decisions[0].risk_reasons)
        report = self.root / 'unused-audit.jsonl'
        PruningAudit.create(report, self.source, ())(self.decisions[0])
        self.assertTrue(json.loads(report.read_text())['lossy'])

    def test_unused_discovery_assumption_preserves_known_callbacks(self) -> None:
        old = 'static int orphan(void) { return 1; }\nint (*callback)(void) = orphan;\n'
        commit = self.change(old, old.replace('return 1', 'return 2'), files={
            'opaque.dat': '\0# /**/ define UNRELATED 1\n'})
        stage = DeadCodeFilter(lossy=True, on_pruned=self.decisions.append)
        self.assertEqual(len(FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), False)), 1)
        self.assertEqual(self.decisions, [])

    def test_known_line_macro_in_unrelated_function_prevents_prototype_pruning(self) -> None:
        old = '#include "position.h"\nint run(int input);\nint observe(void) {return POSITION();}\n'
        new = old.replace('input', 'value').replace('int observe', '\nint observe')
        commit = self.change(old, new, files={'position.h': '#define POSITION() __LINE__\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_known_column_alias_after_a_longer_binding_retains(self) -> None:
        old = '#include "position.h"\nint run(int input) {return input + POSITION();}\n'
        commit = self.change(old, old.replace('input', 'longer_value'), files={
            'position.h': '#define POSITION() __builtin_COLUMN()\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_same_position_line_macro_does_not_prevent_binding_comparison(self) -> None:
        old = '#include "position.h"\nint run(int input) {return input + POSITION();}\n'
        commit = self.change(old, old.replace('input', 'value'), files={'position.h': '#define POSITION() __LINE__\n'})
        self.assertEqual(self.rename(commit, lossy=True), [])

    def test_multiline_macro_end_position_is_checked_with_unchanged_name_site(self) -> None:
        old = '#include "position.h"\nint run(int input);\nint observe(void) {return POSITION(\n);}\n'
        new = old.replace('input', 'value').replace('POSITION(\n)', 'POSITION()')
        commit = self.change(old, new, files={'position.h': '#define POSITION() __LINE__\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_diagnostic_exemption_does_not_hide_a_later_column_alias(self) -> None:
        old = '#include "position.h"\nint main(void) {pr_info("short"); return POSITION();}\n'
        commit = self.change(old, old.replace('"short"', '"much longer wording"'), files={
            'position.h': '#define POSITION() __builtin_COLUMN()\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_logger_forwarding_keeps_first_argument_column_extent(self) -> None:
        old = '#include "position.h"\nint main(void) {dev_err(DEVICE, "short"); return 0;}\n'
        commit = self.change(old, old.replace('"short"', '"much longer wording"'), files={
            'position.h': '#define DEVICE __builtin_COLUMN()\n'})
        # Standard GNU variadic logger forwarding can attribute a builtin in
        # an unchanged first argument to the outer invocation's closing point.
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_logger_spelling_used_as_a_value_is_not_exempt(self) -> None:
        old = '#include "position.h"\nint main(void) {pr_info("short"); return printk;}\n'
        commit = self.change(old, old.replace('"short"', '"much longer wording"'), files={
            'position.h': '#define printk __builtin_COLUMN()\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_logger_spelling_used_as_an_argument_is_not_exempt(self) -> None:
        old = '#include "position.h"\nint main(void) {pr_info("short", printk); return 0;}\n'
        commit = self.change(old, old.replace('"short"', '"much longer wording"'), files={
            'position.h': '#define printk __builtin_COLUMN()\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_known_paste_cannot_synthesize_a_hidden_line_builtin(self) -> None:
        old = '#include "position.h"\nint run(int input);\nint main(void) {return POSITION();}\n'
        new = old.replace('input', 'value').replace('int main', '\nint main')
        commit = self.change(old, new, files={
            'position.h': '#define JOIN(a,b) a##b\n#define POSITION() JOIN(__,LINE__)\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_reorder_exemption_does_not_hide_other_line_sensitive_code(self) -> None:
        a, b = 'static int first(void) {return 1;}\n', 'static int second(void) {return 2;}\n'
        tail = 'int main(void) {return POSITION();}\n'
        prefix = '#include "position.h"\n'
        commit = self.change(prefix + a + b + tail, prefix + b + a + '\n' + tail,
                             files={'position.h': '#define POSITION() __LINE__\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_proto_macro_capture_in_arbitrary_included_extension_retains(self) -> None:
        old = '#include "macros.txt"\nint run(int original);\n'
        commit = self.change(old, old.replace('original', 'renamed'), files={'macros.txt': '#define renamed [4]\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.decisions, [])

    def test_known_compiler_definition_cannot_change_a_prototype_type(self) -> None:
        old = 'int f(int original);\n'
        commit = self.change(old, old.replace('original', 'renamed'),
                             files={'Makefile': 'ccflags-y += -Doriginal=arg[2]\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_compiler_macro_free_variable_capture_is_retained(self) -> None:
        old = 'int foo=7; int run(int foo) { return VALUE; }\n'
        commit = self.change(old, old.replace('run(int foo)', 'run(int bar)'),
                             files={'Makefile': 'ccflags-y += -DVALUE=foo\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_noncompiler_option_does_not_become_a_known_cpp_definition(self) -> None:
        old = 'int dev; int f(int dev);\n'
        commit = self.change(old, old.replace('f(int dev)', 'f(int parent)'),
                             files={'tool.c': 'const char *usage="-D dev selects a device";\n'})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertTrue(self.decisions[-1].lossy)

    def test_known_macro_stringification_is_retained_even_lossy(self) -> None:
        old = '#include "macros.h"\nint run(int original) { return check(TEXT(original)); }\n'
        new = old.replace('original', 'renamed')
        commit = self.change(old, new, files={'macros.h': '#define TEXT(x) #x\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)
        self.assertEqual(self.decisions, [])

    def test_known_macro_free_variable_capture_is_retained_even_lossy(self) -> None:
        old = '#include "macros.h"\nint run(int original) { return READ(); }\n'
        new = old.replace('original', 'renamed')
        commit = self.change(old, new, files={'macros.h': '#define READ() original\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_macro_formal_is_not_a_free_capture_or_global_dependency(self) -> None:
        old = '#include "macros.h"\nint original, renamed; int run(int original) { return ID(original); }\n'
        commit = self.change(old, old.replace('run(int original)', 'run(int renamed)').replace('ID(original)', 'ID(renamed)'),
                             files={'macros.h': '#define ID(original) (original)\n#define unused(x) #x\n'})
        self.assertEqual(self.rename(commit, lossy=True), [])
        self.assertTrue(self.decisions[-1].lossy)

    def test_unrelated_macro_named_like_a_formal_does_not_expand(self) -> None:
        old = '#include "macros.h"\nint original, renamed; int run(int original) { return ID(original); }\n'
        commit = self.change(old, old.replace('run(int original)', 'run(int renamed)').replace('ID(original)', 'ID(renamed)'),
                             files={'macros.h': '#define ID(arg) (arg)\n#define arg(x) #x\n'})
        self.assertEqual(self.rename(commit, lossy=True), [])

    def test_macro_actual_argument_still_reaches_free_variable_capture(self) -> None:
        old = '#include "macros.h"\nint original, renamed; int run(int original) { return APPLY(READ, 1); }\n'
        commit = self.change(old, old.replace('run(int original)', 'run(int renamed)'),
                             files={'macros.h': '#define APPLY(fn, arg) fn(arg)\n#define READ(ignored) original\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_macro_substitution_can_invoke_a_renamed_callback_spelling(self) -> None:
        old = ('#include "macros.h"\ntypedef int (*callback)(void);\n'
               'int original, renamed; int run(callback original) { return CALL(original); }\n')
        commit = self.change(old, old.replace('run(callback original)', 'run(callback renamed)').replace('CALL(original)', 'CALL(renamed)'),
                             files={'macros.h': '#define original() 1\n#define CALL(fn) fn()\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_rescan_can_invoke_an_argument_after_the_outer_macro(self) -> None:
        old = ('#include "macros.h"\ntypedef int (*callback)(void);\n'
               'int original, renamed; int run(callback original) { return ID(original)(); }\n')
        commit = self.change(old, old.replace('run(callback original)', 'run(callback renamed)').replace('ID(original)', 'ID(renamed)'),
                             files={'macros.h': '#define original() 1\n#define ID(fn) fn EMPTY\n#define EMPTY\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_macro_free_dependencies_are_traversed_past_bound_formals(self) -> None:
        old = '#include "macros.h"\nint original, renamed; int run(int original) { return OUTER(1); }\n'
        commit = self.change(old, old.replace('run(int original)', 'run(int renamed)'),
                             files={'macros.h': '#define OUTER(arg) INNER(arg)\n#define INNER(arg) VALUE\n#define VALUE original\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_standard_and_named_variadic_formals_are_substitutions(self) -> None:
        old = '#include "macros.h"\nint original, renamed; int run(int original) { return FIRST(original); }\n'
        commit = self.change(old, old.replace('run(int original)', 'run(int renamed)').replace('FIRST(original)', 'FIRST(renamed)'),
                             files={'macros.h': '#define FIRST(...) SECOND(__VA_ARGS__)\n#define SECOND(args...) (args)\n#define args(x) #x\n'})
        self.assertEqual(self.rename(commit, lossy=True), [])

    def test_generated_global_can_capture_an_apparent_parameter_rename(self) -> None:
        old = '#include "macros.h"\nint run(int foo) { return READ(); }\n'
        header = ('#define CAT(a,b,c) a ## b ## c\n'
                  '#define DECL(a,b,c) int CAT(a,b,c)=7;\n'
                  'DECL(f,o,o)\n#define READ() CAT(f,o,o)\n')
        commit = self.change(old, old.replace('run(int foo)', 'run(int bar)'), files={'macros.h': header})
        self.assertEqual(len(self.rename(commit)), 1)
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_token_paste_in_included_header_prevents_unused_proof(self) -> None:
        old = '#include "macros.h"\nstatic int isolated_helper(void) { return 1; }\nint run(void) { return CALL(isol, ated_, helper); }\n'
        commit = self.change(old, old.replace('return 1', 'return 2'), files={'macros.h': '#define CALL(a,b,c) a ## b ## c()\n'})
        output = FilterPipeline([DeadCodeFilter()]).filter_commits([commit], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_unresolved_includes_prevent_unused_proof(self) -> None:
        old = '#include "generated.h"\nstatic int isolated_helper(void) { return 1; }\n'
        commit = self.change(old, old.replace('return 1', 'return 2'))
        output = FilterPipeline([DeadCodeFilter()]).filter_commits([commit], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_pasting_in_a_header_consumer_prevents_unused_proof(self) -> None:
        old = 'static inline int foo(void) { return 1; }\n'
        commit = self.change('#include "api.h"\n', '#include "api.h"\nint unrelated;\n',
                             files={'api.h': old, 'consumer.txt': '#define CAT3(a,b,c) a ## b ## c\n#include "api.h"\nint run(void) { return CAT3(f,o,o)(); }\n'})
        assert commit.parent is not None
        parent = commit.parent.commit_id
        (self.source / 'unit.c').write_text('#include "api.h"\n')
        (self.source / 'api.h').write_text(old.replace('return 1', 'return 2'))
        self.git('add', '.')
        self.git('commit', '-qm', 'header change')
        child = self.git('rev-parse', 'HEAD')
        commit = GitCommit(child, 'Binding', 'binding@example.invalid', commit.author_date, commit.committer_date,
                           (CommitParent(parent, self.git('diff', parent, child)),), 'header change')
        output = FilterPipeline([DeadCodeFilter()]).filter_commits([commit], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_comment_prefixed_include_is_not_a_missing_consumer(self) -> None:
        old = 'static inline int foo(void) { return 1; }\n'
        commit = self.change('#include "api.h"\n', '#include "api.h"\nint unrelated;\n',
                             files={'api.h': old, 'consumer.c': '/* prefix */ #include "api.h"\n#define CAT3(a,b,c) a ## b ## c\nint run(void) { return CAT3(f,o,o)(); }\n'})
        assert commit.parent is not None
        parent = commit.parent.commit_id
        (self.source / 'unit.c').write_text('#include "api.h"\n')
        (self.source / 'api.h').write_text(old.replace('return 1', 'return 2'))
        self.git('add', '.')
        self.git('commit', '-qm', 'header change')
        child = self.git('rev-parse', 'HEAD')
        commit = GitCommit(child, 'Binding', 'binding@example.invalid', commit.author_date, commit.committer_date,
                           (CommitParent(parent, self.git('diff', parent, child)),), 'header change')
        output = FilterPipeline([DeadCodeFilter()]).filter_commits([commit], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_symlink_alias_is_an_unknown_include_environment(self) -> None:
        from kpatch.filter.macro_environment import MacroEnvironmentGuard
        from kpatch.filter.repository_file import RepositoryFileReader
        old = 'static inline int foo(void) { return 1; }\n'
        commit = self.change('#include "api.h"\n', '#include "api.h"\nint unrelated;\n', files={'api.h': old})
        (self.source / 'link.h').symlink_to('api.h')
        self.git('add', '.')
        self.git('commit', '-qm', 'symlink')
        with RepositoryFileReader(self.repo) as reader:
            guard = MacroEnvironmentGuard(self.repo, reader.read_file)
            self.assertFalse(guard.inspect(self.git('rev-parse', 'HEAD'), 'api.h').closed)

    def test_macro_environment_unions_all_header_consumers(self) -> None:
        from kpatch.filter.macro_environment import MacroEnvironmentGuard
        from kpatch.filter.repository_file import RepositoryFileReader
        self.change('#include "api.h"\n', '#include "api.h"\nint unrelated;\n',
                    files={'api.h': 'static int alpha(void) { return 1; }\n',
                           'a.c': '#define static\n#include "api.h"\n',
                           'z.c': '#include "api.h"\n'})
        with RepositoryFileReader(self.repo) as reader:
            environment = MacroEnvironmentGuard(self.repo, reader.read_file).inspect(self.git('rev-parse', 'HEAD'), 'api.h')
            self.assertTrue(environment.closed)
            self.assertIn('static', environment.macros)
            self.assertIn('a.c', environment.files)
            self.assertIn('z.c', environment.files)

    def test_function_like_macro_invocation_joins_physical_lines(self) -> None:
        old = ('#include "macros.h"\ntypedef int callback(int);\n'
               'int identity(int n) { return n; }\n'
               'int run(void) { callback *old=identity; return old' + chr(92) + '\n(5); }\n')
        commit = self.change(old, old.replace('*old=', '*renamed=').replace('return old', 'return renamed'),
                             files={'macros.h': '#define old(x) 7\n'})
        self.assertEqual(len(self.rename(commit, lossy=True)), 1)

    def test_macro_definition_end_line_does_not_cover_next_line(self) -> None:
        source = b'#define FIRST 1\n#define SECOND 2\n'
        items = definitions(source, parse_source(source))
        self.assertEqual([(item.name, item.line, item.end_line) for item in items], [('FIRST', 1, 1), ('SECOND', 2, 2)])

    def test_lossy_cli_requires_flag_and_report(self) -> None:
        db = self.root / 'input.sqlite'
        db.touch()
        args = ['filter', '--repo', str(self.source), '--db', str(db), '--dest', str(self.root / 'out.sqlite'), 'config']
        for options in (['--source-pruning-lossy'], ['--source-pruning', '--source-pruning-lossy']):
            with self.subTest(options=options):
                result = CliRunner().invoke(app, args + options)
                self.assertEqual(result.exit_code, 2, result.output)
        report = self.root / 'report.jsonl'
        with patch('kpatch.cli.run') as run:
            result = CliRunner().invoke(app, args + ['--source-pruning', '--source-pruning-lossy', '--source-pruning-report', str(report)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(run.call_args.args[1].filters[-1].lossy)
        self.assertTrue(report.is_file())

    def test_audit_cannot_overwrite_source_or_protected_input(self) -> None:
        path = self.root / 'input'
        path.write_text('preserve')
        with self.assertRaises(ValueError):
            PruningAudit.create(path, self.source, (path,))
        with self.assertRaises(ValueError):
            PruningAudit.create(self.source / 'unit.c', self.source, ())
        self.assertEqual(path.read_text(), 'preserve')
