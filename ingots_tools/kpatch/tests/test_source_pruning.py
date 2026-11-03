from datetime import UTC, datetime
from dataclasses import asdict
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter import DeadCodeFilter, FilterContext, FilteredCommit, FilterPipeline, IfdefFilter, KernelConfig, LineRange, MaskReason, RenameFilter, WhitespaceFilter
from kpatch.filter.reference_index import ReferenceIndex, ReferenceSite, spelling_guards
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.filter.source_pruning import PruningDecision, source_pruning_tail
from kpatch.filter.source_filter import SourceIncludeIndex, _iter_git_grep
from kpatch.git import CommitParent, GitCommit, GitRepo
from kpatch.diff import Diff
from benchmarks.ast_pruning.verify import Decision, Verifier


class SourcePruningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.repo = GitRepo(self.path)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.path), *args], stderr=subprocess.PIPE).decode().strip()

    def commit(self, files: dict[str, str]) -> str:
        for path, text in files.items():
            target = self.path / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", "test", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def change(self, before: dict[str, str], after: dict[str, str]) -> GitCommit:
        parent = self.commit(before)
        child = self.commit(after)
        date = datetime(2025, 10, 16, tzinfo=UTC)
        return GitCommit(child, "Test", "test@example.invalid", date, date,
                         (CommitParent(parent, self.git("diff", parent, child)),), "test")

    def run_stage(self, commit: GitCommit, *, rename: bool = False, config: KernelConfig | None = None) -> list[GitCommit]:
        self.decisions: list[PruningDecision] = []
        stage = RenameFilter(config, self.decisions.append) if rename else DeadCodeFilter(config, self.decisions.append)
        return FilterPipeline([stage]).filter_commits([commit], FilterContext(self.repo), show_progress=False)

    def test_static_function_rename_and_all_calls(self) -> None:
        a = "static int old_helper(int n) { return n + 1; }\nint run(void) { return old_helper(2); }\n"
        commit = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(commit, rename=True), [])
        self.assertEqual(self.decisions[0].rule, "consistent_rename")

    def test_rename_ignores_pruned_logic_and_unchanged_references_in_inactive_code(self) -> None:
        old = ("static int old_helper(void) { return 1; }\n"
               "#ifdef CONFIG_DISABLED\nstatic int unused(void) { return old_helper() + 10; }\n#endif\n"
               "int run(void) { return old_helper(); }\n")
        new = old.replace("static int old_helper", "static int new_helper").replace("return old_helper();", "return new_helper();").replace("+ 10", "+ 20")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("# CONFIG_DISABLED is not set\n")
        pipeline = FilterPipeline([IfdefFilter(config), DeadCodeFilter(config), RenameFilter(config)])
        self.assertEqual(pipeline.filter_commits([c], FilterContext(self.repo), False), [])

    def test_whitespace_confirmation_uses_the_remaining_patch_source(self) -> None:
        old = "#if 0\nint inactive = 1;\n#endif\n/* before */\nint run(void) { return 1; }\n"
        new = old.replace("inactive = 1", "inactive = 2").replace("/* before */", "/* after */")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("")
        output = FilterPipeline([IfdefFilter(config), WhitespaceFilter()]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(output, [])

    def test_dead_definition_mask_exposes_remaining_rename_in_the_same_file(self) -> None:
        old = ("static int old_helper(void) { return 1; }\n"
               "static int isolated_helper(void) { return 777; }\n"
               "int run(void) { return old_helper(); }\n")
        new = old.replace("old_helper", "new_helper").replace("777", "888")
        c = self.change({"unit.c": old}, {"unit.c": new})
        decisions: list[PruningDecision] = []
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)
        pipeline = FilterPipeline([DeadCodeFilter(on_pruned=decisions.append), RenameFilter(on_pruned=decisions.append)])
        self.assertEqual(pipeline.filter_commits([c], FilterContext(self.repo), False), [])
        self.assertEqual([item.rule for item in decisions], ["unreferenced_definition", "consistent_rename"])
        self.assertEqual(decisions[0].symbols, ("isolated_helper",))
        with RepositoryFileReader(self.repo) as reader:
            verifier = Verifier(self.repo, reader, KernelConfig(""))
            for decision in decisions:
                verifier.verify(Decision.model_validate(asdict(decision)))

    def test_unused_definition_documentation_does_not_keep_a_commit_alive(self) -> None:
        old = "int run(void) { return 0; }\n"
        new = "/** New unused helper. */\nstatic int isolated_helper(void) { return 1; }\n" + old
        c = self.change({"unit.c": old}, {"unit.c": new})
        self.assertEqual(FilterPipeline(list(source_pruning_tail())).filter_commits([c], FilterContext(self.repo), False), [])

    def test_unused_addition_cannot_hide_an_observable_line_macro(self) -> None:
        old = "int run(void) { return __LINE__; }\n"
        new = "static int isolated_helper(void) { return 1; }\n" + old
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline(list(source_pruning_tail())).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_partial_dead_mask_does_not_hide_active_value_change(self) -> None:
        old = ("static int old_helper(int n) { return n; }\n"
               "static int isolated_helper(void) { return 777; }\n"
               "int run(void) { return old_helper(1); }\n")
        new = old.replace("old_helper", "new_helper").replace("777", "888").replace("new_helper(1)", "new_helper(2)")
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline([DeadCodeFilter(), RenameFilter()]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)
        self.assertNotIn("888", output[0].diff_str)
        self.assertIn("return new_helper(2)", output[0].diff_str)

    def test_masked_unused_caller_does_not_block_cross_file_rename(self) -> None:
        old = {"api.h": "static inline int old_helper(void) { return 1; }\n",
               "live.c": '#include "api.h"\nint run(void) { return old_helper(); }\n',
               "unused.c": '#include "api.h"\nstatic int isolated_caller(void) { return old_helper() + 777; }\n'}
        new = {path: text.replace("old_helper", "new_helper").replace("777", "888") for path, text in old.items()}
        c = self.change(old, new)
        output = FilterPipeline([DeadCodeFilter(), RenameFilter()]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(output, [])

    def test_edit_mask_does_not_hide_a_new_live_foreign_reference(self) -> None:
        c = self.change({"api.h": "enum kind { OLD_KIND = 1 };\n", "caller.c": ""},
                        {"api.h": "enum kind { NEW_KIND = 1 };\n", "caller.c": "int value = NEW_KIND;\n"})
        view = FilteredCommit(c)
        caller = next(file for file in view.diff.files if file.file == "caller.c")
        view.mask_file(caller, MaskReason.FILE_SELECTION)
        output = RenameFilter().filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(output, [view])

    def test_edit_mask_restores_a_declaration_instead_of_deleting_it(self) -> None:
        old = "typedef int number;\nstatic number old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        new = old.replace("typedef int number;", "typedef int  number;").replace("old_helper", "new_helper")
        c = self.change({"unit.c": old}, {"unit.c": new})
        view = FilteredCommit(c)
        file = view.diff.files[0]
        view.mask_edits(file, (LineRange(1, 2),), (LineRange(1, 2),), MaskReason.WHITESPACE)
        decisions: list[PruningDecision] = []
        self.assertEqual(RenameFilter(on_pruned=decisions.append).filter_mutable_commits([view], FilterContext(self.repo), False), [])
        with RepositoryFileReader(self.repo) as reader:
            Verifier(self.repo, reader, KernelConfig("")).verify(Decision.model_validate(asdict(decisions[0])))

    def test_failed_source_projection_does_not_publish_new_masks(self) -> None:
        old = "#if 0\nint inactive;\n#endif\nstatic int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("old_helper", "new_helper")})
        assert c.parent is not None
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str.replace("-static int old_helper", "-static int wrong_helper")),)
        view = FilteredCommit(c)
        output = RenameFilter(KernelConfig("")).filter_mutable_commits([view], FilterContext(self.repo), False)
        self.assertEqual(output, [view])
        self.assertEqual(view.code_masks, ())

    def test_dead_code_requires_an_exact_original_source_patch(self) -> None:
        old = "static int isolated_helper(void) { return 1; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("return 1", "return 2")})
        assert c.parent is not None
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str.replace("-static int isolated_helper(void) { return 1; }", "-static int isolated_helper(void) { return 9; }")),)
        view = FilteredCommit(c)
        self.assertEqual(DeadCodeFilter().filter_mutable_commits([view], FilterContext(self.repo), False), [view])
        self.assertEqual(view.code_masks, ())

    def test_dead_code_mask_cannot_erase_an_active_same_line_neighbor(self) -> None:
        old = "static int isolated_helper(void) { return 777; } int run(void) { return 1; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("777", "888")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_unused_function_cannot_hide_global_preprocessor_effects(self) -> None:
        old = "static int isolated_helper(void) {\n#define POLICY_VALUE 1\nreturn 0;\n}\nint run(void) { return POLICY_VALUE; }\n"
        c = self.change({"unit.c": old}, {"unit.c": old.replace("POLICY_VALUE 1", "POLICY_VALUE 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_unused_structure_cannot_hide_pragma_effects(self) -> None:
        old = "struct isolated_type {\n#pragma pack(1)\nchar a;\n};\nstruct live_type { char a; int b; };\nint run(void) { return sizeof(struct live_type); }\n"
        c = self.change({"api.h": old}, {"api.h": old.replace("pack(1)", "pack(2)")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_inactive_line_insertion_cannot_hide_observable_line_number_change(self) -> None:
        old = "#if 0\nint ignored;\n#endif\nstatic int old_helper(void) { return __LINE__; }\nint run(void) { return old_helper(); }\n"
        new = old.replace("int ignored;", "int ignored;\nint another;").replace("old_helper", "new_helper")
        c = self.change({"unit.c": old}, {"unit.c": new})
        config = KernelConfig("")
        output = FilterPipeline([IfdefFilter(config), RenameFilter(config)]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_whitespace_masking_cannot_hide_a_shifted_line_macro(self) -> None:
        old = "#if 0\nint ignored;\n#endif\nint run(void) { return __LINE__; }\n"
        new = old.replace("int ignored;", "int ignored;\nint another;")
        c = self.change({"unit.c": old}, {"unit.c": new})
        output = FilterPipeline([IfdefFilter(KernelConfig("")), WhitespaceFilter()]).filter_commits([c], FilterContext(self.repo), False)
        self.assertEqual(len(output), 1)

    def test_parameter_rename(self) -> None:
        a = "int run(int old_arg) { return old_arg + 1; }\n"
        commit = self.change({"unit.c": a}, {"unit.c": a.replace("old_arg", "new_arg")})
        self.assertEqual(self.run_stage(commit, rename=True), [])

    def test_type_and_field_renames(self) -> None:
        for a, old, new in (
            ("typedef int old_type;\nold_type run(void) { return 1; }\n", "old_type", "new_type"),
            ("struct old_type { int value; };\nstruct old_type instance;\n", "old_type", "new_type"),
            ("struct data { int old_field; };\nint run(struct data *p) { return p->old_field; }\n", "old_field", "new_field"),
        ):
            with self.subTest(source=a):
                c = self.change({"unit.c": a}, {"unit.c": a.replace(old, new)})
                self.assertEqual(self.run_stage(c, rename=True), [])

    def test_rename_does_not_hide_type_or_layout_change(self) -> None:
        c = self.change({"unit.c": "typedef int old_type;\n"}, {"unit.c": "typedef long new_type;\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_macro_error_before_function_can_be_recovered(self) -> None:
        a = "#define DECLARE_DATA(x) int x;\nDECLARE_DATA(counter)\nstatic int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(c, rename=True), [])

    def test_foreign_macro_can_export_or_stringify_renamed_symbol(self) -> None:
        a = '#include "api.h"\nstatic int old_helper(void) { return 1; }\nREGISTER(old_helper);\n'
        c = self.change({"unit.c": a, "api.h": "#define REGISTER(x) EXPORT_SYMBOL(x)\n"},
                        {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_implicit_name_in_other_function_does_not_block_rename(self) -> None:
        a = 'static int old_helper(void) { return 1; }\nint run(void) { puts(__func__); return old_helper(); }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(self.run_stage(c, rename=True), [])

    def test_call_target_change_is_not_rename(self) -> None:
        commit = self.change({"unit.c": "int run(void) { return old_target(); }\n"},
                             {"unit.c": "int run(void) { return new_target(); }\n"})
        self.assertEqual(len(self.run_stage(commit, rename=True)), 1)

    def test_rename_plus_behavior_change_is_retained(self) -> None:
        a = "static int old_helper(void) { return 1; }\n"
        b = "static int new_helper(void) { return 2; }\n"
        self.assertEqual(len(self.run_stage(self.change({"unit.c": a}, {"unit.c": b}), rename=True)), 1)

    def test_primitive_type_change_is_not_rename(self) -> None:
        c = self.change({"unit.c": "int run(int n) { return n; }\n"},
                        {"unit.c": "long run(long n) { return n; }\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_renamed_export_is_retained(self) -> None:
        a = "int old_helper(void) { return 1; }\nEXPORT_SYMBOL(old_helper);\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_implicit_function_name_is_retained(self) -> None:
        a = 'static int old_helper(void) { puts(__func__); return 1; }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_literal_change_is_retained(self) -> None:
        a = 'static int old_helper(void) { puts("old_helper"); return 1; }\n'
        c = self.change({"unit.c": a}, {"unit.c": a.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_inconsistent_or_colliding_rename_is_retained(self) -> None:
        a = "static int old_helper(void) { return 1; }\nint run(void) { return old_helper(); }\n"
        b = a.replace("int old_helper", "int new_helper")
        self.assertEqual(len(self.run_stage(self.change({"unit.c": a}, {"unit.c": b}), rename=True)), 1)

    def test_cross_file_enum_rename(self) -> None:
        a = {"api.h": "enum kind { OLD_KIND = 1 };\n", "unit.c": '#include "api.h"\nint run(void) { return OLD_KIND; }\n'}
        b = {path: source.replace("OLD_KIND", "NEW_KIND") for path, source in a.items()}
        self.assertEqual(self.run_stage(self.change(a, b), rename=True), [])

    def test_reference_outside_patch_prevents_rename(self) -> None:
        a = {"api.h": "enum kind { OLD_KIND = 1 };\n", "unit.c": "int run(void) { return OLD_KIND; }\n"}
        c = self.change(a, {"api.h": "enum kind { NEW_KIND = 1 };\n"})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_local_shadow_cannot_hide_external_reference(self) -> None:
        old = "static int old_helper(void) { return 1; }\nint other(void) { int old_helper = 2; return old_helper; }\n"
        c = self.change({"api.h": old, "caller.c": '#include "api.h"\nint run(void) { return old_helper(); }\n'},
                        {"api.h": old.replace("old_helper", "new_helper")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_local_shadow_in_another_changed_file_cannot_hide_reference(self) -> None:
        a = {"api.h": "static int old_helper(void) { return 1; }\n",
             "other.c": "int other(void) { int old_helper = 2; return old_helper; }\n",
             "caller.c": '#include "api.h"\nint run(void) { return old_helper(); }\n'}
        b = {path: source.replace("old_helper", "new_helper") for path, source in a.items() if path != "caller.c"}
        self.assertEqual(len(self.run_stage(self.change(a, b), rename=True)), 1)

    def test_unused_static_function(self) -> None:
        a = "static int isolated_helper(void) { return 1; }\nint run(void) { return 0; }\n"
        c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c), [])

    def test_unused_header_inline_and_documentation(self) -> None:
        a = "/* isolated_helper returns a number. */\nstatic inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": '#include "api.h"\n'}, {"api.h": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c), [])

    def test_unused_macro_and_type(self) -> None:
        for path, a, b in (
            ("macro.h", "#define ISOLATED_LIMIT 1\n", "#define ISOLATED_LIMIT 2\n"),
            ("type.h", "struct isolated_type { int value; };\n", "struct isolated_type { long value; };\n"),
        ):
            with self.subTest(path=path):
                c = self.change({path: a}, {path: b})
                self.assertEqual(self.run_stage(c), [])

    def test_live_call_and_address_taken_are_retained(self) -> None:
        for reference in ("int run(void) { return isolated_helper(); }", "int (*callback)(void) = isolated_helper;"):
            with self.subTest(reference=reference):
                a = "static int isolated_helper(void) { return 1; }\n" + reference + "\n"
                c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_header_macro_can_reference_source_local_function(self) -> None:
        a = '#include "api.h"\nstatic int isolated_helper(void) { return 1; }\nint run(void) { return CALL_HELPER(); }\n'
        c = self.change({"unit.c": a, "api.h": "#define CALL_HELPER() isolated_helper()\n"},
                        {"unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_live_header_consumer_is_found_without_a_repository_scan(self) -> None:
        old = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": old, "wrapper.h": '#include "api.h"\nstatic inline int wrapper(void) { return isolated_helper(); }\n',
                         "unit.c": '#include "wrapper.h"\nint run(void) { return wrapper(); }\n'},
                        {"api.h": old.replace("return 1", "return 2")})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86"), c.commit_id)
            context = FilterContext(self.repo, file_reader=reader, reference_index=index)
            self.assertEqual(len(DeadCodeFilter().filter_commits([c], context, False)), 1)
            self.assertEqual(index.stats().repository_scans, 0)

    def test_disabled_consumer_can_be_ignored(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({
            "drivers/Makefile": "obj-y += enabled.o\nobj-$(CONFIG_FEATURE) += disabled.o\n",
            "drivers/api.h": a,
            "drivers/enabled.c": '#include "api.h"\n',
            "drivers/disabled.c": '#include "api.h"\nint run(void) { return isolated_helper(); }\n',
        }, {"drivers/api.h": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c, config=KernelConfig("# CONFIG_FEATURE is not set\n")), [])
        self.assertEqual(len(self.run_stage(c, config=KernelConfig("CONFIG_FEATURE=y\n"))), 1)

    def test_layout_use_prevents_struct_pruning(self) -> None:
        a = "struct isolated_type { int value; };\n"
        c = self.change({"api.h": a, "unit.c": 'int run(void) { return sizeof(struct isolated_type); }\n'},
                        {"api.h": a.replace("int", "long")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_nested_tags_and_enumerators_can_escape_outer_structure(self) -> None:
        for nested in ("enum { LIVE_VALUE = 1 } member;", "struct live_type { int value; } member;"):
            with self.subTest(nested=nested):
                a = "struct isolated_type { " + nested + " };\n"
                c = self.change({"api.h": a}, {"api.h": a.replace("1", "2").replace("int value", "long value")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_init_registration_and_pasting_are_retained(self) -> None:
        for a in (
            "static int __init isolated_helper(void) { return 1; }\n",
            "static int isolated_helper(void) { return 1; }\n#define JOIN(a,b) a##b\n",
        ):
            with self.subTest(source=a):
                c = self.change({"unit.c": a}, {"unit.c": a.replace("return 1", "return 2")})
                self.assertEqual(len(self.run_stage(c)), 1)

    def test_only_unused_files_removed_from_mixed_commit(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return 1; }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return 2; }\n"})
        output = self.run_stage(c)
        self.assertEqual(len(output), 1)
        self.assertNotIn("api.h", output[0].diff_str)
        self.assertIn("unit.c", output[0].diff_str)

    def test_use_added_in_same_commit_is_retained(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return 0; }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return isolated_helper(); }\n"})
        self.assertIn("api.h", self.run_stage(c)[0].diff_str)

    def test_parent_use_removed_in_same_commit_is_retained(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int run(void) { return isolated_helper(); }\n"},
                        {"api.h": a.replace("return 1", "return 2"), "unit.c": "int run(void) { return 0; }\n"})
        self.assertIn("api.h", self.run_stage(c)[0].diff_str)

    def test_inactive_caller_in_same_source_file(self) -> None:
        a = "static int isolated_helper(void) { return 1; }\n#ifdef CONFIG_FEATURE\nint run(void) { return isolated_helper(); }\n#endif\n"
        c = self.change({"drivers/Makefile": "obj-y += unit.o\n", "drivers/unit.c": a},
                        {"drivers/unit.c": a.replace("return 1", "return 2")})
        self.assertEqual(self.run_stage(c, config=KernelConfig("# CONFIG_FEATURE is not set\n")), [])
        self.assertEqual(len(self.run_stage(c, config=KernelConfig("CONFIG_FEATURE=y\n"))), 1)

    def test_foreign_reference_after_bare_carriage_return(self) -> None:
        a = "static inline int isolated_helper(void) { return 1; }\n"
        c = self.change({"api.h": a, "unit.c": "int x;\rint run(void) { return isolated_helper(); }\n"},
                        {"api.h": a.replace("return 1", "return 2")})
        self.assertEqual(len(self.run_stage(c)), 1)

    def test_live_probe_does_not_cache_incomplete_absence(self) -> None:
        revision = self.commit({"one.c": "int a = ISOLATED_LIMIT;\n", "two.c": "int b = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            names = frozenset({"ISOLATED_LIMIT"})
            self.assertIsNone(index.lookup(revision, names, is_live=lambda name, site: True)["ISOLATED_LIMIT"])
            sites = index.lookup(revision, names)["ISOLATED_LIMIT"]
            self.assertEqual({site.path for site in sites or ()}, {"one.c", "two.c"})
            self.assertEqual(index.stats().repository_scans, 2)

    def test_unrelated_prefetch_symbol_cannot_abort_the_requested_search(self) -> None:
        old = "static inline int existing_helper(void) { return 1; }\n"
        c = self.change({"api.h": old}, {"api.h": old.replace("existing_helper", "different_helper")})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.plan_diffs([Diff.parse(c.diff_str)])
            calls: list[str] = []
            def live(name: str, site: ReferenceSite) -> bool:
                calls.append(name)
                return True
            result = index.lookup(c.commit_id, frozenset({"absent_helper"}), is_live=live)
            self.assertEqual(result["absent_helper"], ())
            self.assertEqual(calls, [])

    def test_shared_include_scan_seeds_exact_revision_reference_facts(self) -> None:
        old = "static inline int old_helper(void) { return 1; }\n"
        c = self.change({"api.h": old, "unit.c": '\n  #include "api.h"\nint run(void) { return old_helper(); }\n'},
                        {"api.h": old.replace("old_helper", "new_helper"), "unit.c": '\n  #include "api.h"\nint run(void) { return new_helper(); }\n'})
        ordinary = SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86")
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(c.diff_str)
            names = index.begin_bootstrap(c.commit_id)
            shared = SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86", reference_names=names, reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            self.assertEqual(ordinary._snapshot(), shared._snapshot())
            self.assertEqual(len(index.lookup(c.commit_id, frozenset({"new_helper"}))["new_helper"] or ()), 2)
            self.assertEqual(index.stats().repository_scans, 0)
            assert c.parent is not None
            parent_sites = index.lookup(c.parent.commit_id, frozenset({"old_helper"}))["old_helper"]
            self.assertEqual({site.path for site in parent_sites or ()}, {"api.h", "unit.c"})

    def test_reference_index_updates_and_keeps_branches_separate(self) -> None:
        parent = self.commit({"api.h": "#define ISOLATED_LIMIT 1\n", "unit.c": "int x = ISOLATED_LIMIT;\n"})
        child = self.commit({"unit.c": "int x = 0;\n"})
        with RepositoryFileReader(self.repo) as reader:
            index = ReferenceIndex(self.repo, reader.read_file)
            names = frozenset({"ISOLATED_LIMIT"})
            a = index.lookup(parent, names)["ISOLATED_LIMIT"]
            b = index.lookup(child, names, parent=parent, changed_paths=frozenset({"unit.c"}))["ISOLATED_LIMIT"]
            self.assertEqual(len(a or ()), 2)
            self.assertEqual(len(b or ()), 1)
            self.assertEqual(index.lookup(parent, names)["ISOLATED_LIMIT"], a)
            self.assertEqual(index.stats().repository_scans, 1)
            self.assertEqual(index.stats().incremental_updates, 1)
            index.close()

    def test_persistent_reference_facts_avoid_second_scan(self) -> None:
        revision = self.commit({"unit.c": "int x = ISOLATED_LIMIT;\n"})
        names = frozenset({"ISOLATED_LIMIT"})
        with RepositoryFileReader(self.repo) as reader:
            with ReferenceIndex(self.repo, reader.read_file) as first:
                expected = first.lookup(revision, names)
                self.assertEqual(first.stats().repository_scans, 1)
            with ReferenceIndex(self.repo, reader.read_file) as second:
                self.assertEqual(second.lookup(revision, names), expected)
                self.assertEqual(second.stats().repository_scans, 0)

    def test_over_budget_query_retains_unknown_without_caching_absence(self) -> None:
        revision = self.commit({"unit.c": "int x = isolated_helper;\n"})
        names = frozenset({"isolated_helper"} | {f"other_{i}" for i in range(256)})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            self.assertTrue(all(sites is None for sites in index.lookup(revision, names).values()))
            self.assertEqual(index.stats().repository_scans, 0)
            self.assertEqual(len(index.lookup(revision, frozenset({"isolated_helper"}))["isolated_helper"] or ()), 1)

    def test_shared_scan_seeds_new_header_helpers_and_paste_guards(self) -> None:
        c = self.change({"include/linux/api.h": "", "unit.c": '#include "include/linux/api.h"\n'},
                        {"include/linux/api.h": "static inline int isolated_helper(void) { return 1; }\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.observe_patch(c.diff_str)
            names = index.begin_bootstrap(c.commit_id)
            self.assertTrue(spelling_guards("isolated_helper") <= names)
            SourceIncludeIndex.from_repository(self.repo, c.commit_id, "x86", reference_names=names, reference_hit=index.bootstrap_hit, prefer_pcre=True)
            index.finish_bootstrap()
            facts = index.lookup(c.commit_id, names)
            self.assertEqual(len(facts["isolated_helper"] or ()), 1)
            self.assertEqual(index.stats().repository_scans, 0)

    def test_identifier_prefix_cannot_hide_longer_whole_word(self) -> None:
        revision = self.commit({"unit.c": "int value = isolated_helper;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({"isolated", "isolated_helper"}))
            self.assertEqual(sites["isolated"], ())
            self.assertEqual(len(sites["isolated_helper"] or ()), 1)

    def test_scope_recovers_includes_removed_after_parent_revision(self) -> None:
        old = self.commit({"api.h": "#define ISOLATED_LIMIT 1\n", "unit.c": '#include "api.h"\nint x = ISOLATED_LIMIT;\n'})
        new = self.commit({"unit.c": "int x = 0;\n"})
        includes = SourceIncludeIndex.from_repository(self.repo, new, "x86")
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            index.bind_includes(includes, new)
            scope = index.scope_for(("api.h",), old)
            self.assertIsNotNone(scope)
            self.assertIn("unit.c", scope or ())
            sites = index.lookup(old, frozenset({"ISOLATED_LIMIT"}), scope=scope)["ISOLATED_LIMIT"]
            self.assertIn("unit.c", [site.path for site in sites or ()])

    def test_empty_scope_does_not_search_the_whole_repository(self) -> None:
        revision = self.commit({"unit.c": "int x = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            sites = index.lookup(revision, frozenset({"ISOLATED_LIMIT"}), scope=frozenset())
            self.assertEqual(sites["ISOLATED_LIMIT"], ())
            self.assertEqual(index.stats().repository_scans, 0)

    def test_pcre_search_falls_back_when_unavailable(self) -> None:
        def output(repo: GitRepo, arguments: list[str], separator: bytes, codes: tuple[int, ...]):
            if "-P" in arguments:
                raise subprocess.CalledProcessError(128, arguments)
            self.assertIn("-E", arguments)
            yield b"found"

        with patch("kpatch.filter.source_filter._iter_git_output", side_effect=output):
            self.assertEqual(list(_iter_git_grep(self.repo, ["grep", "-P", "-e", "name"])), [b"found"])

    def test_scoped_negative_cache_cannot_hide_reference_in_wider_scope(self) -> None:
        revision = self.commit({"one.c": "int a;\n", "two.c": "int b = ISOLATED_LIMIT;\n"})
        with RepositoryFileReader(self.repo) as reader, ReferenceIndex(self.repo, reader.read_file) as index:
            names = frozenset({"ISOLATED_LIMIT"})
            self.assertEqual(index.lookup(revision, names, scope=frozenset({"one.c"}))["ISOLATED_LIMIT"], ())
            self.assertEqual(len(index.lookup(revision, names)["ISOLATED_LIMIT"] or ()), 1)


    def test_foreign_macro_cannot_capture_a_renamed_parameter(self) -> None:
        old = '#include "aliases.h"\nint GLOBAL_VALUE = 10;\nint run(int n) { return n + GET_GLOBAL(); }\n'
        aliases = "#define value GLOBAL_VALUE\n#define GET_GLOBAL() GLOBAL_VALUE\n"
        c = self.change({"unit.c": old, "aliases.h": aliases},
                        {"unit.c": old.replace("int n", "int value").replace("return n", "return value")})
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_reduced_input_cannot_hide_new_references_in_build_fragments(self) -> None:
        c = self.change({"api.h": "enum kind { OLD_KIND = 1 };\n", "extra.mk": ""},
                        {"api.h": "enum kind { NEW_KIND = 1 };\n", "extra.mk": "REFERENCE = NEW_KIND\n"})
        assert c.parent is not None
        reduced = Diff.parse(c.diff_str)
        reduced.files = [file for file in reduced.files if file.file == "api.h"]
        c.parents = (CommitParent(c.parent.commit_id, reduced.render()),)
        self.assertEqual(len(self.run_stage(c, rename=True)), 1)

    def test_linker_preprocessor_references_are_not_disabled_translation_units(self) -> None:
        c = self.change({"api.h": "#define ISOLATED_LIMIT 1\n", "vmlinux.lds.S": "SECTIONS { . = ISOLATED_LIMIT; }\n"},
                        {"api.h": "#define ISOLATED_LIMIT 2\n"})
        self.assertEqual(len(self.run_stage(c, config=KernelConfig(""))), 1)

    def test_config_metadata_exclusion_does_not_hide_unchanged_build_references(self) -> None:
        from unittest.mock import Mock
        from kpatch.filter import ConfigFilter, ConfigValue, SourceSide
        from kpatch.filter.config.history import ConfigHistoryStore, FileDecision
        c = self.change({"unit.c": "int value = 1;\n", "extra.mk": "REFERENCE = OLD_KIND\n"},
                        {"unit.c": "int value = 2;\n", "extra.mk": "REFERENCE = NEW_KIND\n"})
        assert c.parent is not None
        copied = "diff --git a/foo.c b/bar.c\nsimilarity index 100%\ncopy from foo.c\ncopy to bar.c\n"
        c.parents = (CommitParent(c.parent.commit_id, c.diff_str + copied),)
        view = FilteredCommit(c)
        stage = ConfigFilter(KernelConfig(""))
        store = Mock(spec=ConfigHistoryStore)
        store.get_decisions.return_value = {(None, "unit.c"): FileDecision(ConfigValue.ENABLED, ConfigValue.ENABLED)}
        stage._store = store
        with patch.object(stage, "_prepare"):
            self.assertIs(stage.filter_mutable_commit(view, FilterContext(self.repo)), view)
        self.assertEqual([file.file for file in view.diff.files], ["unit.c"])
        self.assertFalse(any(mask.file.path == "extra.mk" for mask in view.code_masks))
        live_source = b"int still_live;\n"
        self.assertEqual(view.code_source("foo.c", SourceSide.OLD, live_source), live_source)


if __name__ == "__main__":
    unittest.main()
