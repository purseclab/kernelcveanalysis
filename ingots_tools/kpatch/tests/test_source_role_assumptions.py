"""Explicit input-role assumptions remain audited and preserve hard barriers."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter import (
    DeadCodeFilter, FileBuildModes, FilterContext, FilteredCommit, FilterPipeline,
    IfdefFilter, KernelConfig, RenameFilter, StreamingCommitFilter, WhitespaceFilter,
)
from kpatch.filter.constant_filter import ConstantConditionalFilter
from kpatch.filter.input_role_models import (
    InputInventoryState, RawInputConsumer, RawInputFailure, RawInputFailureKind,
    RawInputKind, RawInputObservation, RawInputUnknown, RawInputUnknownKind,
    SourceRoleDecision, SourceRoleStatus,
)
from kpatch.filter.input_roles import RawInputIndex
from kpatch.filter.masking import CodeMask, EditMask, FileIdentity, LineRange, MaskReason, SourceSide
from kpatch.filter.pruning_decision import PruningDecision
from kpatch.filter.repository_file import RepositoryFileReader
from kpatch.filter.source_roles import (
    INPUT_ROLE_RISK, SourceInputAssumptionPolicy, SourceMaskPlan,
    publish_source_masks, source_role_decision,
)
from kpatch.git import GitCommit, GitRepo

import test_source_raw_roles as raw_helpers


MAKE_SOURCE = 'generated.c: $(UNMODELED_INPUT)\n\tperl generator.pl $< $@\n'
CLEAR = RawInputObservation(InputInventoryState.FULL)
UNKNOWN = RawInputObservation(InputInventoryState.FULL, unknowns=(
    RawInputUnknown('Makefile', 1, RawInputUnknownKind.MAKE_OPERAND,
                    '$(UNMODELED_INPUT)', sha256(MAKE_SOURCE.encode()).hexdigest()),
))
POSITIVE = RawInputObservation(InputInventoryState.FULL, consumers=(
    RawInputConsumer('blob.S', 1, RawInputKind.ASSEMBLER_INCBIN),
), unknowns=UNKNOWN.unknowns)


@dataclass(frozen=True)
class StageCase:
    old: str
    new: str
    create: Callable[[list[PruningDecision]], StreamingCommitFilter]


STAGES = (
    StageCase('/*7*/\n', '/*8*/\n', lambda records: WhitespaceFilter(on_pruned=records.append)),
    StageCase('#if 0\nint x = 7;\n#endif\n', '#if 0\nint x = 8;\n#endif\n',
              lambda records: ConstantConditionalFilter(records.append)),
    StageCase('#if 0\nint x = 7;\n#endif\n', '#if 0\nint x = 8;\n#endif\n',
              lambda records: IfdefFilter(KernelConfig(''))),
    StageCase('#define ISOLATED_WIDGET 7\n', '#define ISOLATED_WIDGET 8\n',
              lambda records: DeadCodeFilter(on_pruned=records.append)),
    StageCase('static int old_helper(void) { return 7; }\nint run(void) { return old_helper(); }\n',
              'static int new_helper(void) { return 7; }\nint run(void) { return new_helper(); }\n',
              lambda records: RenameFilter(on_pruned=records.append, lossy=True)),
)


class SourceRoleAssumptionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = GitRepo(self.root)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Input-role assumption tests')
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
        self.write({'Makefile': MAKE_SOURCE, **before})
        self.git('add', '.')
        self.git('commit', '-qm', 'parent', '--allow-empty')
        self.write(after)
        self.git('add', '.')
        self.git('commit', '-qm', 'child')
        return next(self.repo.iter_commits_from_revision('HEAD^!'))

    @staticmethod
    def view(commit: GitCommit) -> FilteredCommit:
        # These small fixtures explicitly supply their sole CPP build mode.
        return FilteredCommit(commit, build_modes={
            (file.old_file, file.file): FileBuildModes('y', 'y', complete=True) for file in commit.diff.files
        })

    def context(self, roles: raw_helpers.FixtureRoles, audits: list[PruningDecision],
                *, assumed: bool = True) -> FilterContext:
        return FilterContext(self.repo, input_roles=roles,
                             input_role_policy=SourceInputAssumptionPolicy(audits.append) if assumed else None)

    def assert_audited(self, record: PruningDecision, commit: GitCommit) -> None:
        assert commit.parent is not None
        self.assertTrue(record.lossy)
        self.assertIn(INPUT_ROLE_RISK, record.risk_reasons)
        self.assertEqual(record.commit_id, commit.commit_id)
        self.assertEqual({item.side for item in record.input_role_evidence}, {SourceSide.OLD, SourceSide.NEW})
        self.assertEqual({item.revision for item in record.input_role_evidence},
                         {commit.parent.commit_id, commit.commit_id})
        self.assertTrue(all(item.path == 'unit.c' for item in record.input_role_evidence))
        self.assertTrue(all(item.observation.state is InputInventoryState.FULL
                            and item.observation.unknowns and not item.observation.failures
                            and not item.observation.consumers for item in record.input_role_evidence))

    def test_policy_requires_an_explicit_mandatory_sink(self) -> None:
        with self.assertRaises(TypeError):
            SourceInputAssumptionPolicy()  # type: ignore[call-arg]

    def test_role_decision_is_pure_and_only_full_local_unknowns_are_assumable(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        file = commit.diff.files[0]
        for observation, assumed, expected in (
            (CLEAR, False, SourceRoleStatus.OBSERVED_CLEAR),
            (CLEAR, True, SourceRoleStatus.OBSERVED_CLEAR),
            (UNKNOWN, False, SourceRoleStatus.BLOCKED),
            (UNKNOWN, True, SourceRoleStatus.ASSUMED),
            (replace(UNKNOWN, state=InputInventoryState.INCOMPLETE), True, SourceRoleStatus.BLOCKED),
            (replace(UNKNOWN, state=InputInventoryState.RETENTION_WITNESS), True, SourceRoleStatus.BLOCKED),
            (POSITIVE, True, SourceRoleStatus.BLOCKED),
        ):
            with self.subTest(state=observation.state, assumed=assumed, expected=expected):
                audits: list[PruningDecision] = []
                roles = raw_helpers.FixtureRoles(observation)
                view = self.view(commit)
                result = source_role_decision(view, file, self.context(roles, audits, assumed=assumed))
                self.assertIs(result.status, expected)
                self.assertEqual(result.file, FileIdentity.of(file))
                self.assertEqual(audits, [])
                self.assertEqual(view.code_masks, ())
                self.assertEqual(view.edit_masks, ())

    def test_every_typed_failure_is_hard_even_with_full_local_unknowns(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        for kind in RawInputFailureKind:
            with self.subTest(kind=kind):
                audits: list[PruningDecision] = []
                observation = replace(UNKNOWN, failures=(RawInputFailure(kind, 'Makefile'),))
                roles = raw_helpers.FixtureRoles(observation)
                view = self.view(commit)
                output = WhitespaceFilter().filter_mutable_commits([view], self.context(roles, audits), False)
                self.assertEqual(output, [view])
                self.assertEqual(view.edit_masks, ())
                self.assertEqual(view.code_masks, ())
                self.assertEqual(audits, [])

    def test_positive_on_either_original_side_remains_a_hard_veto(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        assert commit.parent is not None
        for positive in (commit.parent.commit_id, commit.commit_id):
            audits: list[PruningDecision] = []
            roles = raw_helpers.FixtureRoles(UNKNOWN, by_revision={positive: POSITIVE})
            view = self.view(commit)
            output = WhitespaceFilter().filter_mutable_commits([view], self.context(roles, audits), False)
            self.assertEqual(output, [view])
            self.assertIn(positive, [revision for _, revision, _ in roles.calls])
            self.assertEqual(view.edit_masks, ())
            self.assertEqual(audits, [])

    def test_five_source_publishers_require_audit_and_decorate_existing_records(self) -> None:
        for case in STAGES:
            commit = self.change({'unit.c': case.old}, {'unit.c': case.new})
            for assumed in (False, True):
                records: list[PruningDecision] = []
                audits: list[PruningDecision] = []
                roles = raw_helpers.FixtureRoles(UNKNOWN)
                view = self.view(commit)
                stage = case.create(records)
                with self.subTest(stage=type(stage).__name__, assumed=assumed):
                    output = FilterPipeline([stage]).filter_mutable_commits(
                        [view], self.context(roles, audits, assumed=assumed), False,
                    )
                    self.assertTrue(roles.calls, 'A real source proof must reach the role decision')
                    if not assumed:
                        self.assertEqual(output, [view])
                        self.assertEqual(view.edit_masks, ())
                        self.assertEqual(view.code_masks, ())
                        self.assertEqual(audits, [])
                        self.assertEqual(records, [])
                        continue
                    self.assertEqual(output, [])
                    self.assertEqual(len(audits), 1)
                    self.assert_audited(audits[0], commit)
                    self.assertEqual(audits[0].edit_masks, view.edit_masks)
                    self.assertEqual(audits[0].code_masks, view.code_masks)
                    for record in records:
                        self.assert_audited(record, commit)
                    if not isinstance(stage, IfdefFilter):
                        self.assertEqual(len(records), 1)

    def test_mandatory_audit_failure_propagates_before_each_source_publisher_masks(self) -> None:
        def fail(decision: PruningDecision) -> None:
            self.assertTrue(decision.lossy)
            raise OSError('mandatory input-role audit failed')

        for case in STAGES:
            commit = self.change({'unit.c': case.old}, {'unit.c': case.new})
            records: list[PruningDecision] = []
            view = self.view(commit)
            roles = raw_helpers.FixtureRoles(UNKNOWN)
            context = FilterContext(self.repo, input_roles=roles, input_role_policy=SourceInputAssumptionPolicy(fail))
            stage = case.create(records)
            with self.subTest(stage=type(stage).__name__):
                with self.assertRaisesRegex(OSError, 'mandatory input-role audit failed'):
                    FilterPipeline([stage]).filter_mutable_commits([view], context, False)
                self.assertEqual(view.edit_masks, ())
                self.assertEqual(view.code_masks, ())
                self.assertEqual(records, [])

    def test_clear_inventory_does_not_emit_an_assumption_event(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        records: list[PruningDecision] = []
        audits: list[PruningDecision] = []
        output = WhitespaceFilter(on_pruned=records.append).filter_mutable_commits(
            [self.view(commit)], self.context(raw_helpers.FixtureRoles(CLEAR), audits), False,
        )
        self.assertEqual(output, [])
        self.assertEqual(audits, [])
        self.assertFalse(records[0].lossy)
        self.assertEqual(records[0].input_role_evidence, ())

    def test_role_assumption_preserves_other_line_and_symbol_guards(self) -> None:
        cases = (
            StageCase('/* first */\n/* second */\nint run(void) { return __LINE__; }\n',
                      '/* third */\nint run(void) { return __LINE__; }\n',
                      lambda records: WhitespaceFilter(on_pruned=records.append)),
            StageCase(STAGES[-1].old + 'EXPORT_SYMBOL(old_helper);\n',
                      STAGES[-1].new + 'EXPORT_SYMBOL(new_helper);\n',
                      lambda records: RenameFilter(on_pruned=records.append)),
        )
        for case in cases:
            commit = self.change({'unit.c': case.old}, {'unit.c': case.new})
            audits: list[PruningDecision] = []
            records: list[PruningDecision] = []
            view = self.view(commit)
            output = FilterPipeline([case.create(records)]).filter_mutable_commits(
                [view], self.context(raw_helpers.FixtureRoles(UNKNOWN), audits), False,
            )
            self.assertEqual(output, [view])
            self.assertEqual(view.edit_masks, ())
            self.assertEqual(view.code_masks, ())
            self.assertEqual(audits, [])
            self.assertEqual(records, [])

    def test_default_name_metadata_exemption_keeps_role_assumption_audited(self) -> None:
        case = STAGES[-1]
        commit = self.change({'unit.c': case.old}, {'unit.c': case.new})
        audits: list[PruningDecision] = []
        records: list[PruningDecision] = []
        view = self.view(commit)
        output = FilterPipeline([RenameFilter(on_pruned=records.append)]).filter_mutable_commits(
            [view], self.context(raw_helpers.FixtureRoles(UNKNOWN), audits), False,
        )
        self.assertEqual(output, [])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(audits), 1)
        for decision in (records[0], audits[0]):
            self.assert_audited(decision, commit)
            self.assertNotIn('incomplete_macro_discovery_assumed', decision.risk_reasons)
        self.assertEqual(records[0].rule, 'consistent_rename')
        self.assertEqual(records[0].symbols, ('old_helper',))
        self.assertIn('symbol_type_and_member_names_may_be_observable_through_btf_or_kallsyms',
                      records[0].risk_reasons)
        self.assertEqual(audits[0].rule, 'unresolved_input_roles_assumed')
        self.assertTrue(view.edit_masks)
        self.assertEqual(audits[0].edit_masks, view.edit_masks)
        self.assertEqual(audits[0].code_masks, view.code_masks)

    def test_line_lossy_risks_compose_with_input_role_assumption(self) -> None:
        old = '/* first */\n/* second */\nint run(void) { return 0; }\n'
        new = '/* third */\nint run(void) { return 0; }\n'
        commit = self.change({'unit.c': old}, {'unit.c': new})
        records: list[PruningDecision] = []
        audits: list[PruningDecision] = []
        stage = WhitespaceFilter(line_numbers_lossy=True, on_pruned=records.append)
        output = stage.filter_mutable_commits(
            [self.view(commit)], self.context(raw_helpers.FixtureRoles(UNKNOWN), audits), False,
        )
        self.assertEqual(output, [])
        self.assert_audited(records[0], commit)
        self.assertIn('source_line_number_observations_may_change_runtime_behavior', records[0].risk_reasons)

    def test_assumed_default_provider_uses_full_lookup_even_with_seeded_retention_witness(self) -> None:
        commit = self.change({'api.h': '/*7*/\n'}, {'api.h': '/*8*/\n', 'blob.S': '.incbin "api.h"\n'})
        assert commit.parent is not None
        file = next(file for file in commit.diff.files if file.file == 'api.h')
        audits: list[PruningDecision] = []
        with RepositoryFileReader(self.repo) as reader:
            context = FilterContext(self.repo, file_reader=reader)
            seeded = context.input_roles.lookup(context, commit.parent.commit_id, 'api.h')
            self.assertTrue(seeded.unknowns)
            assumed = replace(context, input_role_policy=SourceInputAssumptionPolicy(audits.append))
            with patch.object(RawInputIndex, 'veto_observation', side_effect=AssertionError('retention shortcut in assumed mode')):
                decision = source_role_decision(self.view(commit), file, assumed)
        self.assertIs(decision.status, SourceRoleStatus.BLOCKED)
        self.assertTrue(any(item.observation.consumers for item in decision.evidence))
        self.assertEqual(audits, [])

    def test_mask_plan_rejects_unauthorized_files_and_skips_empty_publication(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        view = self.view(commit)
        audits: list[PruningDecision] = []
        context = self.context(raw_helpers.FixtureRoles(UNKNOWN), audits)
        decision = source_role_decision(view, commit.diff.files[0], context)
        publish_source_masks(view, context, SourceMaskPlan((decision,)))
        self.assertEqual(audits, [])
        other = EditMask(FileIdentity('other.c', 'other.c'), MaskReason.WHITESPACE, whole_file=True)
        with self.assertRaisesRegex(ValueError, 'authorization'):
            publish_source_masks(view, context, SourceMaskPlan((decision,), edit_masks=(other,)))
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(audits, [])

    def test_assumed_mask_plan_requires_its_evidence_and_mandatory_policy(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        view = self.view(commit)
        file = commit.diff.files[0]
        audits: list[PruningDecision] = []
        context = self.context(raw_helpers.FixtureRoles(UNKNOWN), audits)
        role = source_role_decision(view, file, context)
        edit = EditMask(role.file, MaskReason.WHITESPACE, whole_file=True)
        with self.assertRaises(ValueError):
            publish_source_masks(view, replace(context, input_role_policy=None),
                                 SourceMaskPlan((role,), edit_masks=(edit,)))
        with self.assertRaises(ValueError):
            missing = SourceRoleDecision(role.file, SourceRoleStatus.ASSUMED)
            publish_source_masks(view, context, SourceMaskPlan((missing,), edit_masks=(edit,)))
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(audits, [])

    def test_mask_plan_rejects_incoherent_manually_constructed_role_evidence(self) -> None:
        commit = self.change({'unit.c': '/*7*/\n'}, {'unit.c': '/*8*/\n'})
        view = self.view(commit)
        file = commit.diff.files[0]
        audits: list[PruningDecision] = []
        context = self.context(raw_helpers.FixtureRoles(UNKNOWN), audits)
        role = source_role_decision(view, file, context)
        edit = EditMask(role.file, MaskReason.WHITESPACE, whole_file=True)
        alternatives = (
            (SourceRoleStatus.OBSERVED_CLEAR, ()),
            (SourceRoleStatus.OBSERVED_CLEAR, role.evidence),
            (SourceRoleStatus.ASSUMED, tuple(replace(item, observation=CLEAR) for item in role.evidence)),
            (SourceRoleStatus.ASSUMED, tuple(replace(item, observation=POSITIVE) for item in role.evidence)),
            (SourceRoleStatus.ASSUMED, tuple(replace(item, observation=replace(UNKNOWN, state=InputInventoryState.INCOMPLETE))
                                           for item in role.evidence)),
            (SourceRoleStatus.ASSUMED, tuple(replace(item, observation=replace(UNKNOWN, state=InputInventoryState.RETENTION_WITNESS))
                                           for item in role.evidence)),
            (SourceRoleStatus.ASSUMED, tuple(replace(item, observation=replace(UNKNOWN, failures=(
                RawInputFailure(RawInputFailureKind.NATIVE_SCAN),))) for item in role.evidence)),
        )
        for status, evidence in alternatives:
            with self.subTest(status=status, evidence=evidence):
                with self.assertRaises(ValueError):
                    bad = SourceRoleDecision(role.file, status, evidence)
                    publish_source_masks(view, context, SourceMaskPlan((bad,), edit_masks=(edit,)))
                self.assertEqual(view.edit_masks, ())
                self.assertEqual(audits, [])

    def test_audit_failure_preserves_preexisting_code_masks(self) -> None:
        old = '/*same*/\n/*7*/\n'
        commit = self.change({'unit.c': old}, {'unit.c': old.replace('7', '8')})
        view = self.view(commit)
        identity = FileIdentity.of(commit.diff.files[0])
        for side in SourceSide:
            view.apply_code_mask(CodeMask(identity, side, MaskReason.IFDEF, (LineRange(1, 2),)))
        previous = view.code_masks
        def fail(decision: PruningDecision) -> None:
            raise OSError('mandatory input-role audit failed')
        context = FilterContext(self.repo, input_roles=raw_helpers.FixtureRoles(UNKNOWN),
                                input_role_policy=SourceInputAssumptionPolicy(fail))
        with self.assertRaisesRegex(OSError, 'mandatory input-role audit failed'):
            WhitespaceFilter().filter_mutable_commits([view], context, False)
        self.assertEqual(view.code_masks, previous)
        self.assertEqual(view.edit_masks, ())

    def test_actual_policy_publisher_audits_and_preserves_scope_and_hard_barriers(self) -> None:
        import test_policy_analysis as policy_helpers
        from kpatch.filter.policy_analysis import PolicyCommitDecision, PolicyFilter
        from kpatch.filter.policy_profile import AnalysisScope

        fixture = policy_helpers.PolicyAnalysisTests()
        self.addCleanup(fixture.doCleanups)
        type(fixture).setUpClass()
        fixture.setUp()
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = fixture.change(old, old.replace('return 7', 'return 8'))
        for observation, assumed in ((UNKNOWN, False), (UNKNOWN, True), (POSITIVE, True),
                                     (replace(UNKNOWN, failures=(RawInputFailure(RawInputFailureKind.NATIVE_SCAN),)), True)):
            audits: list[PruningDecision] = []
            records: list[PolicyCommitDecision] = []
            stage = PolicyFilter(fixture.profile, build, fixture.evaluator, analyzer=fixture.analyzer,
                                 on_decision=records.append, cache_path=fixture.root / 'assumed-roles.sqlite')
            view = FilteredCommit(commit)
            context = FilterContext(fixture.repo, input_roles=raw_helpers.FixtureRoles(observation),
                                    input_role_policy=SourceInputAssumptionPolicy(audits.append) if assumed else None)
            output = FilterPipeline([stage]).filter_mutable_commits([view], context, False)
            if observation == UNKNOWN and assumed:
                self.assertEqual(output, [])
                self.assertEqual(records[0].status, 'excluded')
                self.assertTrue(records[0].lossy)
                self.assertIn(INPUT_ROLE_RISK, records[0].risk_reasons)
                self.assertTrue(records[0].input_role_evidence)
                self.assertEqual(len(audits), 1)
                self.assert_audited(audits[0], commit)
                self.assertEqual(audits[0].edit_masks, view.edit_masks)
            else:
                self.assertEqual(output, [view])
                self.assertEqual(view.edit_masks, ())
                self.assertEqual(view.code_masks, ())
                self.assertEqual(audits, [])
        audits = []
        records = []
        profile = fixture.profile.model_copy(update={'scope': AnalysisScope.APP_WITH_SERVICES})
        stage = PolicyFilter(profile, build, fixture.evaluator, analyzer=fixture.analyzer,
                             on_decision=records.append, cache_path=fixture.root / 'assumed-roles.sqlite')
        view = FilteredCommit(commit)
        output = FilterPipeline([stage]).filter_mutable_commits(
            [view], FilterContext(fixture.repo, input_roles=raw_helpers.FixtureRoles(UNKNOWN),
                                 input_role_policy=SourceInputAssumptionPolicy(audits.append)), False,
        )
        self.assertEqual(output, [view])
        self.assertEqual(records[0].status, 'direct_app_candidate')
        self.assertEqual(audits, [])

    def test_policy_mandatory_audit_failure_precedes_masks_and_excluded_report(self) -> None:
        import test_policy_analysis as policy_helpers
        from kpatch.filter.policy_analysis import PolicyCommitDecision, PolicyFilter

        fixture = policy_helpers.PolicyAnalysisTests()
        self.addCleanup(fixture.doCleanups)
        type(fixture).setUpClass()
        fixture.setUp()
        old = 'SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n'
        commit, build = fixture.change(old, old.replace('return 7', 'return 8'))
        records: list[PolicyCommitDecision] = []
        def fail(decision: PruningDecision) -> None:
            raise OSError('mandatory input-role audit failed')
        stage = PolicyFilter(fixture.profile, build, fixture.evaluator, analyzer=fixture.analyzer,
                             on_decision=records.append, cache_path=fixture.root / 'audit-failure.sqlite')
        view = FilteredCommit(commit)
        context = FilterContext(fixture.repo, input_roles=raw_helpers.FixtureRoles(UNKNOWN),
                                input_role_policy=SourceInputAssumptionPolicy(fail))
        with self.assertRaisesRegex(OSError, 'mandatory input-role audit failed'):
            FilterPipeline([stage]).filter_mutable_commits([view], context, False)
        self.assertEqual(view.edit_masks, ())
        self.assertEqual(view.code_masks, ())
        self.assertEqual(records, [])


if __name__ == '__main__':
    unittest.main()
