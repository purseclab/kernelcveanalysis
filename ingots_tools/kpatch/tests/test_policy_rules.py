from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from kpatch.filter.config_filter import KernelConfig
from kpatch.filter.policy_clang import ClangArgument, ClangConstraint, ClangGuard, ClangSpan, SourcePoint
from kpatch.filter.policy_profile import (
    AnalysisScope, PolicyTargetProfile, SELinuxDecision, SELinuxPermissionQuery,
    SELinuxPolicyEvaluator, SELinuxResult,
)
from kpatch.filter.policy_rules import LinuxPolicyRules


class RulePolicyEvaluator(SELinuxPolicyEvaluator):
    """Deterministic permission evidence for contract tests, not a real policy."""

    def __init__(self, path: Path) -> None:
        super().__init__(path, enforcing=True)
        self.capability: bool | None = False
        self.decisions: dict[tuple[str, str, str], SELinuxDecision] = {}
        self.requests: list[SELinuxPermissionQuery] = []

    def capability_enabled(self, name: str) -> bool | None:
        return self.capability if name == "bpf_token_perms" else None

    def query(self, query: SELinuxPermissionQuery) -> SELinuxResult:
        self.requests.append(query)
        decisions = {self.decisions.get((query.subject_type, query.object_class, permission), SELinuxDecision.DENIED)
                     for permission in query.permissions}
        decision = (SELinuxDecision.UNKNOWN if SELinuxDecision.UNKNOWN in decisions
                    else SELinuxDecision.POSSIBLY_ALLOWED if SELinuxDecision.POSSIBLY_ALLOWED in decisions
                    else SELinuxDecision.DENIED)
        return SELinuxResult(decision, "unit-test permission fixture", self.policy_sha256)


class PolicyRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.policy_file = Path(self.temporary.name) / "policy"
        self.policy_file.write_bytes(b"rules-test-policy")
        self.evaluator = RulePolicyEvaluator(self.policy_file)
        self.profile = PolicyTargetProfile(name="rules-test", policy_file=self.policy_file,
                                           policy_sha256=self.evaluator.policy_sha256,
                                           subject_context="u:r:app:s0", selinux_enforcing=True,
                                           cap_effective=0, cap_permitted=0, cap_bounding=0,
                                           user_namespaces_enabled=False, scope=AnalysisScope.DIRECT_APP)
        self.config = KernelConfig('CONFIG_MULTIUSER=y\nCONFIG_SECURITY=y\nCONFIG_SECURITY_SELINUX=y\nCONFIG_LSM="selinux,bpf"\n')
        self.rules = LinuxPolicyRules(self.profile, self.evaluator, self.config)
        point = SourcePoint(path=Path("unit.c"), line=1, column=1, offset=0)
        self.span = ClangSpan(start=point, end=point)

    def guard(self, name: str, arguments: tuple[ClangArgument, ...], *, outcome: str = "zero") -> ClangGuard:
        return ClangGuard(callee=name, callee_usr="c:@F@" + name, arguments=arguments,
                          outcome=outcome, span=self.span)

    @staticmethod
    def integer(value: int) -> ClangArgument:
        return ClangArgument(expression=str(value), integer=value)

    def bpf(self, command: int = 5, *, outcome: str = "zero", kernel: int | None = 0) -> ClangGuard:
        origin = self.integer(kernel) if kernel is not None else ClangArgument(expression="origin")
        return self.guard("security_bpf", (self.integer(command), self.integer(0), self.integer(0), origin), outcome=outcome)

    def test_absent_capability_excludes_only_success_branch(self) -> None:
        for outcome, excluded in (("nonzero", True), ("zero", False), ("negative", True), ("nonnegative", False)):
            with self.subTest(outcome=outcome):
                guard = self.guard("capable", (self.integer(21),), outcome=outcome)
                self.assertEqual(self.rules.excludes(guard) is not None, excluded)

    def test_available_or_unknown_capability_is_not_excluded(self) -> None:
        guard = self.guard("capable", (self.integer(21),), outcome="nonzero")
        for bits in (None, 1 << 21):
            profile = self.profile.model_copy(update={"cap_effective": bits})
            self.assertIsNone(LinuxPolicyRules(profile, self.evaluator, self.config).excludes(guard))
        for value in (-1, 41, 1000):
            self.assertIsNone(self.rules.excludes(guard.model_copy(update={"arguments": (self.integer(value),)})))

    def test_capability_needs_multiuser_and_correct_arity(self) -> None:
        guard = self.guard("capable", (self.integer(21),), outcome="nonzero")
        self.assertIsNone(LinuxPolicyRules(self.profile, self.evaluator, KernelConfig("")).excludes(guard))
        self.assertIsNone(self.rules.excludes(guard.model_copy(update={"arguments": ()})))
        self.assertIsNone(self.rules.excludes(guard.model_copy(update={"arguments": (self.integer(0), self.integer(21))})))

    def test_namespace_and_saved_credential_contracts_are_not_guessed(self) -> None:
        for name in ("ns_capable", "ns_capable_noaudit"):
            known = self.guard(name, (ClangArgument(expression="&init_user_ns", declaration_usr="c:@init_user_ns"), self.integer(21)), outcome="nonzero")
            self.assertIsNotNone(self.rules.excludes(known))
            unknown = known.model_copy(update={"arguments": (ClangArgument(expression="ns"), self.integer(21))})
            self.assertIsNone(self.rules.excludes(unknown))
            shadowed = known.model_copy(update={"arguments": (ClangArgument(expression="&init_user_ns", declaration_usr="c:unit.c@10@F@test@init_user_ns"), self.integer(21))})
            self.assertIsNone(self.rules.excludes(shadowed))
        saved = self.guard("file_ns_capable", (ClangArgument(expression="file"), ClangArgument(expression="&init_user_ns"), self.integer(21)), outcome="nonzero")
        self.assertIsNone(self.rules.excludes(saved))

    def test_parameter_constraints_need_one_known_value(self) -> None:
        guard = self.guard("capable", (ClangArgument(expression="cap", parameter=0),), outcome="nonzero")
        self.assertIsNone(self.rules.excludes(guard))
        self.assertIsNotNone(self.rules.excludes(guard, (ClangConstraint(parameter=0, integer=21),)))
        self.assertIsNone(self.rules.excludes(guard, (ClangConstraint(parameter=0, integer=21), ClangConstraint(parameter=0, integer=12))))

    def test_same_named_static_or_unknown_function_is_not_a_gate(self) -> None:
        guard = self.bpf()
        for usr in ("", "c:unit.c@F@security_bpf", "other:security_bpf"):
            self.assertIsNone(self.rules.excludes(guard.model_copy(update={"callee_usr": usr})))

    def test_bpf_denial_excludes_only_allowed_result_branch(self) -> None:
        for outcome, excluded in (("zero", True), ("nonnegative", True), ("negative", False), ("nonzero", False)):
            with self.subTest(outcome=outcome):
                self.assertEqual(self.rules.excludes(self.bpf(outcome=outcome)) is not None, excluded)
        self.assertEqual(self.evaluator.requests[0].object_class, "bpf")
        self.assertEqual(self.evaluator.requests[0].permissions, frozenset({"prog_load"}))

    def test_only_map_create_and_prog_load_have_bpf_permission_contract(self) -> None:
        self.assertIsNotNone(self.rules.excludes(self.bpf(0)))
        for command in (1, 2, 3, 4, 6, 42):
            self.assertIsNone(self.rules.excludes(self.bpf(command)))

    def test_bpf_kernel_origin_and_unknown_origin_are_retained(self) -> None:
        self.assertIsNone(self.rules.excludes(self.bpf(kernel=1)))
        self.assertIsNone(self.rules.excludes(self.bpf(kernel=None)))
        self.assertIsNotNone(self.rules.excludes(self.bpf().model_copy(update={"arguments": self.bpf().arguments[:3]})))

    def test_policycap_bypass_enabled_or_unknown_retains(self) -> None:
        for enabled in (True, None):
            self.evaluator.capability = enabled
            self.assertIsNone(self.rules.excludes(self.bpf()))
        self.assertEqual(self.evaluator.requests, [])

    def test_allow_or_unknown_policy_evidence_retains(self) -> None:
        for decision in (SELinuxDecision.POSSIBLY_ALLOWED, SELinuxDecision.UNKNOWN):
            self.evaluator.decisions[("app", "bpf", "prog_load")] = decision
            self.assertIsNone(self.rules.excludes(self.bpf()))

    def test_missing_selinux_or_unselected_lsm_retains(self) -> None:
        configs = ('CONFIG_MULTIUSER=y\n',
                   'CONFIG_MULTIUSER=y\nCONFIG_SECURITY=y\nCONFIG_SECURITY_SELINUX=y\nCONFIG_LSM="bpf"\n')
        for config in configs:
            with self.subTest(config=config):
                self.assertIsNone(LinuxPolicyRules(self.profile, self.evaluator, KernelConfig(config)).excludes(self.bpf()))

    def test_mismatched_policy_hash_retains(self) -> None:
        profile = self.profile.model_copy(update={"policy_sha256": "0" * 64})
        self.assertIsNone(LinuxPolicyRules(profile, self.evaluator, self.config).excludes(self.bpf()))

    def test_full_service_scope_requires_every_modeled_subject_denied(self) -> None:
        profile = self.profile.model_copy(update={"scope": AnalysisScope.APP_WITH_SERVICES,
                                                 "modeled_subject_types": ("app", "server"), "mediation_complete": True})
        rules = LinuxPolicyRules(profile, self.evaluator, self.config)
        self.assertTrue(rules.scope_closed)
        self.assertIsNotNone(rules.excludes(self.bpf()))
        self.evaluator.decisions[("server", "bpf", "prog_load")] = SELinuxDecision.POSSIBLY_ALLOWED
        self.assertIsNone(rules.excludes(self.bpf()))
        self.assertIsNone(rules.excludes(self.guard("capable", (self.integer(21),), outcome="nonzero")))

    def test_default_scope_does_not_claim_service_closure(self) -> None:
        profile = self.profile.model_copy(update={"scope": AnalysisScope.APP_WITH_SERVICES})
        self.assertFalse(LinuxPolicyRules(profile, self.evaluator, self.config).scope_closed)

    def test_perf_unknown_kind_needs_denial_of_every_possible_permission(self) -> None:
        guard = self.guard("security_perf_event_open", (self.integer(0), ClangArgument(expression="kind")), outcome="nonnegative")
        self.assertIsNotNone(self.rules.excludes(guard))
        self.evaluator.decisions[("app", "perf_event", "cpu")] = SELinuxDecision.POSSIBLY_ALLOWED
        self.assertIsNone(self.rules.excludes(guard))

    def test_perf_supported_signatures_take_kind_from_last_argument(self) -> None:
        for arguments in ((self.integer(2),), (self.integer(0), self.integer(2))):
            with self.subTest(arguments=arguments):
                guard = self.guard("security_perf_event_open", arguments, outcome="zero")
                self.assertIsNotNone(self.rules.excludes(guard))
                self.assertEqual(self.evaluator.requests[-1].permissions, frozenset({"kernel"}))
        for invalid_arguments in ((), (self.integer(0), self.integer(1), self.integer(2))):
            self.assertIsNone(self.rules.excludes(self.guard("security_perf_event_open", invalid_arguments)))


if __name__ == "__main__":
    unittest.main()
