"""Raw consumers veto C-source proofs without asserting consumer closure."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter import (
    DeadCodeFilter, FileBuildModes, FilterContext, FilteredCommit, FilterPipeline,
    IfdefFilter, KernelConfig, RenameFilter, StreamingCommitFilter, WhitespaceFilter,
)
from kpatch.filter.base import SourceInputRoleProvider
from kpatch.filter.constant_filter import ConstantConditionalFilter
from kpatch.filter.input_roles import RawInputIndex
from kpatch.filter.input_role_models import (
    InputInventoryState, RawInputConsumer, RawInputFailure, RawInputFailureKind,
    RawInputKind, RawInputObservation, RawInputUnknown, RawInputUnknownKind,
    SourceRoleStatus,
)
from kpatch.filter.source_roles import source_role_decision
from kpatch.filter.masking import LineRange, MaskReason, SourceSide
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.git import GitCommit, GitRepo


CLEAR = RawInputObservation(InputInventoryState.FULL)
UNKNOWN = RawInputObservation(InputInventoryState.FULL, unknowns=(
    RawInputUnknown('Makefile', 1, RawInputUnknownKind.MAKE_OPERAND, '$(INPUT)', '0' * 64),
))
HARD = RawInputObservation(InputInventoryState.INCOMPLETE, failures=(
    RawInputFailure(RawInputFailureKind.INPUT_BUDGET),
))


@dataclass
class FixtureRoles:
    """Only controls this fixture's role observation; an empty result is no closure."""

    observation: RawInputObservation = CLEAR
    by_revision: dict[str, RawInputObservation] = field(default_factory=dict)
    error: OSError | None = None
    calls: list[tuple[FilterContext, str, str]] = field(default_factory=list)

    def lookup(self, context: FilterContext, revision: str, path: str) -> RawInputObservation:
        self.calls.append((context, revision, path))
        if self.error is not None:
            raise self.error
        return self.by_revision.get(revision, self.observation)


@dataclass
class RecordingDefaultRoles:
    delegate: SourceInputRoleProvider
    contexts: list[FilterContext] = field(default_factory=list)

    def lookup(self, context: FilterContext, revision: str, path: str) -> RawInputObservation:
        self.contexts.append(context)
        return self.delegate.lookup(context, revision, path)


RAW = RawInputObservation(InputInventoryState.FULL, consumers=(
    RawInputConsumer('blob.S', 1, RawInputKind.ASSEMBLER_INCBIN),
))


class SourceRawRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.repo = GitRepo(self.root)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Raw-role tests')
        self.git('config', 'user.email', 'roles@example.invalid')

    def git(self, *arguments: str) -> str:
        result = subprocess.run(['git', '-C', str(self.root), *arguments], check=True, capture_output=True)
        return result.stdout.decode().strip()

    def write(self, files: dict[str, str]) -> None:
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def change(self, before: dict[str, str], after: dict[str, str]) -> GitCommit:
        self.write(before)
        self.git('add', '.')
        self.git('commit', '-qm', 'parent', '--allow-empty')
        self.write(after)
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        return next(self.repo.iter_commits_from_revision('HEAD^!'))

    def whitespace(self, commit: GitCommit) -> tuple[list[FilteredCommit], FilteredCommit, list[PruningDecision]]:
        decisions: list[PruningDecision] = []
        view = FilteredCommit(commit)
        output = FilterPipeline([WhitespaceFilter(on_pruned=decisions.append)]).filter_mutable_commits(
            [view], FilterContext(self.repo), False,
        )
        return output, view, decisions

    def test_literal_assembler_incbin_retains_comment_change(self) -> None:
        commit = self.change({'api.h': '/*7*/\n', 'blob.S': '.incbin "api.h"\n'}, {'api.h': '/*8*/\n'})
        output, view, decisions = self.whitespace(commit)
        self.assertEqual(output, [view])
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())
        self.assertEqual(decisions, [])

    def test_literal_c_inline_incbin_retains_comment_change(self) -> None:
        consumer = '__asm__(".section .rodata\\n.incbin \\"api.h\\"\\n.previous\\n");\n'
        commit = self.change({'api.h': '/*7*/\n', 'unit.c': consumer}, {'api.h': '/*8*/\n'})
        output, view, decisions = self.whitespace(commit)
        self.assertEqual(output, [view])
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(decisions, [])

    def test_assembler_include_retains_c_inactive_branch(self) -> None:
        old = '#if 0\n.byte 7\n#endif\n'
        commit = self.change({'api.h': old, 'blob.S': '.include "api.h"\n'}, {'api.h': old.replace('7', '8')})
        view = FilteredCommit(commit)
        decisions: list[PruningDecision] = []
        output = FilterPipeline([ConstantConditionalFilter(decisions.append)]).filter_mutable_commits(
            [view], FilterContext(self.repo), False,
        )
        self.assertEqual(output, [view])
        self.assertEqual(view.code_masks, ())
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(decisions, [])

    def test_explicit_make_generator_retains_header_comment_data(self) -> None:
        make = ('$(obj)/table.c: $(srctree)/include/oid.h $(src)/generator\n'
                '\t$(call cmd,generate_table)\n'
                'cmd_generate_table = perl $(src)/generator $< $@\n')
        commit = self.change({'include/oid.h': 'enum OID { X, /* 1.2 */ };\n', 'lib/Makefile': make,
                              'lib/generator': '#!/usr/bin/perl\n'},
                             {'include/oid.h': 'enum OID { X, /* 1.3 */ };\n'})
        output, view, decisions = self.whitespace(commit)
        self.assertEqual(output, [view])
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(decisions, [])

    def test_ordinary_cpp_dependencies_still_allow_comment_pruning(self) -> None:
        make = 'unit.o: unit.c api.h\n\t$(CC) -c unit.c -o unit.o\n'
        commit = self.change({'api.h': '/*7*/\n', 'unit.c': '#include "api.h"\nint unit;\n', 'Makefile': make},
                             {'api.h': '/*8*/\n'})
        output, view, decisions = self.whitespace(commit)
        self.assertEqual(output, [])
        self.assertEqual(len(view.edit_masks), 1)
        self.assertEqual(len(decisions), 1)

    def test_all_nonpolicy_source_stages_veto_before_any_new_mask_or_audit(self) -> None:
        stages: tuple[tuple[str, str, Callable[[list[PruningDecision]], StreamingCommitFilter]], ...] = (
            ('/*7*/\n', '/*8*/\n', lambda records: WhitespaceFilter(on_pruned=records.append)),
            ('#if 0\nint x = 7;\n#endif\n', '#if 0\nint x = 8;\n#endif\n',
             lambda records: ConstantConditionalFilter(records.append)),
            ('#if 0\nint x = 7;\n#endif\n', '#if 0\nint x = 8;\n#endif\n',
             lambda records: IfdefFilter(KernelConfig(''))),
            ('#define ISOLATED_WIDGET 7\n', '#define ISOLATED_WIDGET 8\n',
             lambda records: DeadCodeFilter(on_pruned=records.append)),
            ('static int old_helper(void) { return 7; }\nint run(void) { return old_helper(); }\n',
             'static int new_helper(void) { return 7; }\nint run(void) { return new_helper(); }\n',
             lambda records: RenameFilter(on_pruned=records.append, lossy=True)),
        )
        for old, new, factory in stages:
            commit = self.change({'unit.c': old}, {'unit.c': new})
            assert commit.parent is not None
            for observation in (CLEAR, RAW, UNKNOWN, HARD):
                with self.subTest(stage=type(factory([])).__name__, observation=observation):
                    records: list[PruningDecision] = []
                    roles = FixtureRoles(observation)
                    view = FilteredCommit(commit, build_modes={
                        (file.old_file, file.file): FileBuildModes('y', 'y', complete=True) for file in commit.diff.files
                    })
                    output = FilterPipeline([factory(records)]).filter_mutable_commits(
                        [view], FilterContext(self.repo, input_roles=roles), False,
                    )
                    self.assertTrue(roles.calls, 'The candidate must reach the raw-role publication guard')
                    if observation == CLEAR:
                        self.assertEqual(output, [])
                    else:
                        self.assertEqual(output, [view])
                        self.assertEqual(view.code_masks, ())
                        self.assertEqual(view.edit_masks, ())
                        self.assertEqual(records, [])

    def test_original_parent_and_child_are_checked_independently(self) -> None:
        commit = self.change({'api.h': '/*7*/\n'}, {'api.h': '/*8*/\n'})
        assert commit.parent is not None
        for positive in (commit.parent.commit_id, commit.commit_id):
            roles = FixtureRoles(by_revision={positive: RAW})
            view = FilteredCommit(commit)
            output = WhitespaceFilter().filter_mutable_commits([view], FilterContext(self.repo, input_roles=roles), False)
            self.assertEqual(output, [view])
            self.assertIn((positive, 'api.h'), [(rev, path) for _, rev, path in roles.calls])
            self.assertEqual(view.edit_masks, ())

    def test_lookup_failure_retains_and_preserves_earlier_masks(self) -> None:
        old = '/*same*/\n/*7*/\n'
        commit = self.change({'api.h': old}, {'api.h': old.replace('7', '8')})
        view = FilteredCommit(commit)
        file = commit.diff.files[0]
        view.mask_code(file, SourceSide.OLD, (LineRange(1, 2),), MaskReason.IFDEF)
        view.mask_code(file, SourceSide.NEW, (LineRange(1, 2),), MaskReason.IFDEF)
        existing = view.code_masks
        roles = FixtureRoles(error=OSError('inventory failed'))
        records: list[PruningDecision] = []
        output = WhitespaceFilter(on_pruned=records.append).filter_mutable_commits(
            [view], FilterContext(self.repo, input_roles=roles), False,
        )
        self.assertEqual(output, [view])
        self.assertTrue(roles.calls)
        self.assertEqual(view.code_masks, existing)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(records, [])

    def test_losing_semantic_candidate_does_not_query_input_roles(self) -> None:
        commit = self.change({'unit.c': 'int unit = 7;\n'}, {'unit.c': 'int unit = 8;\n'})
        roles = FixtureRoles(error=OSError('unexpected role lookup'))
        view = FilteredCommit(commit)
        output = WhitespaceFilter().filter_mutable_commits([view], FilterContext(self.repo, input_roles=roles), False)
        self.assertEqual(output, [view])
        self.assertEqual(roles.calls, [])

    def test_context_creation_and_replacement_are_lazy_and_share_provider(self) -> None:
        with (patch.object(self.repo, 'read_file', side_effect=AssertionError('source read')),
              patch('kpatch.filter.input_roles.RawInputIndex', side_effect=AssertionError('index construction'))):
            context = FilterContext(self.repo)
            nested = replace(context, commits=[])
        self.assertIs(nested.input_roles, context.input_roles)

    def test_nested_pipeline_preserves_injected_role_provider_and_borrowed_reader(self) -> None:
        old = '#if 0\nint x = 7;\n#endif\n'
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('7', '8')})
        roles = FixtureRoles(RAW)
        context = FilterContext(self.repo, input_roles=roles)
        view = FilteredCommit(commit)
        output = FilterPipeline([FilterPipeline([ConstantConditionalFilter()])]).filter_mutable_commits(
            [view], context, False,
        )
        self.assertEqual(output, [view])
        self.assertTrue(roles.calls)
        self.assertTrue(all(ctx.input_roles is roles and ctx.file_reader is not None for ctx, _, _ in roles.calls))
        self.assertIsNone(context.file_reader)
        self.assertEqual(view.code_masks, ())

    def test_standalone_batch_shares_its_reader_and_one_actual_role_index(self) -> None:
        first = self.change({'api.h': '/*7*/\n', 'Makefile': 'obj-y += unit.o\n'}, {'api.h': '/*8*/\n'})
        self.write({'api.h': '/*9*/\n'})
        self.git('add', 'api.h')
        self.git('commit', '-qm', 'third')
        second = next(self.repo.iter_commits_from_revision('HEAD^!'))
        initial = FilterContext(self.repo)
        roles = RecordingDefaultRoles(initial.input_roles)
        context = replace(initial, input_roles=roles)
        with (patch('kpatch.filter.input_roles.RawInputIndex', wraps=RawInputIndex) as create_index,
              patch.object(self.repo, 'read_file', side_effect=AssertionError('uncached content read'))):
            output = WhitespaceFilter().filter_commits([first, second], context, False)
        self.assertEqual(output, [])
        self.assertEqual(create_index.call_count, 1)
        self.assertEqual(len(roles.contexts), 4)
        reader = roles.contexts[0].file_reader
        self.assertIsNotNone(reader)
        self.assertTrue(all(item.file_reader is reader for item in roles.contexts))
        self.assertIsNone(context.file_reader)

    def test_actual_policy_exclusion_becomes_unknown_before_mask_publication(self) -> None:
        # Import the module, not its TestCase class, to avoid duplicate discovery.
        import test_policy_analysis as policy_helpers
        from kpatch.filter.policy_analysis import PolicyCommitDecision, PolicyFilter

        fixture = policy_helpers.PolicyAnalysisTests()
        self.addCleanup(fixture.doCleanups)
        type(fixture).setUpClass()
        fixture.setUp()
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = fixture.change(old, old.replace('return 7', 'return 8'))
        for roles in (FixtureRoles(), FixtureRoles(RAW),
                      FixtureRoles(UNKNOWN), FixtureRoles(HARD),
                      FixtureRoles(error=OSError('inventory failed'))):
            records: list[PolicyCommitDecision] = []
            stage = PolicyFilter(fixture.profile, build, fixture.evaluator,
                                 analyzer=fixture.analyzer, on_decision=records.append,
                                 cache_path=fixture.root / 'raw-roles.sqlite')
            view = FilteredCommit(commit)
            output = FilterPipeline([stage]).filter_mutable_commits(
                [view], FilterContext(fixture.repo, input_roles=roles), False,
            )
            self.assertTrue(roles.calls, 'An actual policy exclusion must reach the raw-role guard')
            if roles.observation == CLEAR and roles.error is None:
                self.assertEqual(output, [])
                self.assertEqual(records[0].status, 'excluded')
                continue
            self.assertEqual(output, [view])
            self.assertEqual(view.code_masks, ())
            self.assertEqual(view.edit_masks, ())
            self.assertEqual(records[0].status, 'unknown')
            self.assertEqual(records[0].reasons, ('raw_input_consumer_or_unresolved_consumer_inventory',))

    def test_helper_omits_nonexistent_added_and_deleted_sides(self) -> None:
        commit = self.change({}, {'api.h': '/*7*/\n'})
        roles = FixtureRoles()
        view = FilteredCommit(commit)
        self.assertIs(source_role_decision(view, commit.diff.files[0], FilterContext(self.repo, input_roles=roles)).status,
                      SourceRoleStatus.OBSERVED_CLEAR)
        self.assertEqual([(rev, path) for _, rev, path in roles.calls], [(commit.commit_id, 'api.h')])
        self.git('rm', 'api.h')
        self.git('commit', '-qm', 'delete')
        deleted = next(self.repo.iter_commits_from_revision('HEAD^!'))
        roles = FixtureRoles()
        self.assertIs(source_role_decision(FilteredCommit(deleted), deleted.diff.files[0],
                                           FilterContext(self.repo, input_roles=roles)).status,
                      SourceRoleStatus.OBSERVED_CLEAR)
        self.assertEqual([(rev, path) for _, rev, path in roles.calls], [(commit.commit_id, 'api.h')])


if __name__ == '__main__':
    unittest.main()
