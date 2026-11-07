"""Small explicit Linux gate contracts; unknown APIs never become barriers."""

from dataclasses import dataclass

from .config_filter import ConfigValue, KernelConfig
from .policy_clang import ClangArgument, ClangConstraint, ClangGuard
from .policy_profile import AnalysisScope, PolicyTargetProfile, SELinuxDecision, SELinuxPermissionQuery, SELinuxPolicyEvaluator


POLICY_RULES_VERSION = "linux-necessary-gates-v2-seccomp-entry"


@dataclass(frozen=True, slots=True)
class GateExclusion:
    gate: str
    reason: str
    policy_sha256: str | None = None


def _matches(outcome: str, value: int) -> bool:
    return {"zero": value == 0, "nonzero": value != 0,
            "negative": value < 0, "nonnegative": value >= 0}[outcome]


def _value(argument: ClangArgument, constraints: tuple[ClangConstraint, ...]) -> int | None:
    if argument.integer is not None:
        return argument.integer
    matches = {item.integer for item in constraints if argument.parameter is not None and item.parameter == argument.parameter}
    return next(iter(matches)) if len(matches) == 1 else None


class LinuxPolicyRules:
    """Necessary gate outcomes under an explicit captured subject model.

    Contracts concern normal Linux APIs in a Clang-prepared Linux build. They
    do not establish caller/resource closure or credentials of an unknown worker.
    Runtime policy evaluation is separate from CFG branch requirements.
    """

    def __init__(self, profile: PolicyTargetProfile, evaluator: SELinuxPolicyEvaluator,
                 config: KernelConfig) -> None:
        self.profile, self.evaluator, self.config = profile, evaluator, config

    @property
    def scope_closed(self) -> bool:
        return self.profile.scope is AnalysisScope.DIRECT_APP or self.profile.mediation_complete

    def excludes(self, guard: ClangGuard, constraints: tuple[ClangConstraint, ...] = ()) -> GateExclusion | None:
        # A same-named static function or an implicit/unknown target is not a
        # recognized Linux API. The source model is explicitly versioned.
        if guard.callee_usr != "c:@F@" + guard.callee:
            return None
        if guard.callee in {"capable", "ns_capable", "ns_capable_noaudit"}:
            return self._capability(guard, constraints)
        if (self.config.get("CONFIG_SECURITY") is not ConfigValue.ENABLED
                or self.config.get("CONFIG_SECURITY_SELINUX") is not ConfigValue.ENABLED
                or "selinux" not in self.config.get_raw("CONFIG_LSM").strip('"').split(",")):
            return None
        if self.evaluator.policy_sha256 != self.profile.policy_sha256:
            return None
        if guard.callee == "security_bpf":
            return self._bpf(guard, constraints)
        if guard.callee == "security_perf_event_open":
            return self._perf(guard, constraints)
        return None

    def _capability(self, guard: ClangGuard, constraints: tuple[ClangConstraint, ...]) -> GateExclusion | None:
        if self.config.get("CONFIG_MULTIUSER") is not ConfigValue.ENABLED:
            return None
        # Captured app capability bits say nothing about a privileged broker.
        if self.profile.mediation_complete and any(subject != self.profile.subject_type for subject in self.profile.modeled_subject_types):
            return None
        if not guard.arguments or self.profile.cap_effective is None:
            return None
        if guard.callee == "capable" and len(guard.arguments) != 1:
            return None
        if guard.callee != "capable":
            if len(guard.arguments) != 2:
                return None
            namespace = guard.arguments[0].expression.replace(" ", "")
            if namespace != "&init_user_ns" or guard.arguments[0].declaration_usr != "c:@init_user_ns":
                # Arbitrary namespaces/saved creds need richer value flow.
                return None
        capability = _value(guard.arguments[-1], constraints)
        if capability is None or not 0 <= capability <= 40:
            return None
        if self.profile.cap_effective & (1 << capability) or _matches(guard.outcome, 0):
            return None
        return GateExclusion(guard.callee, f"Effective app capability {capability} is absent; required outcome {guard.outcome}")

    def _subjects(self) -> tuple[str, ...]:
        if self.profile.scope is AnalysisScope.APP_WITH_SERVICES and self.profile.mediation_complete:
            return self.profile.modeled_subject_types
        return (self.profile.subject_type,)

    def _permission_denied(self, object_class: str, permissions: tuple[str, ...]) -> bool:
        return all(self.evaluator.query(SELinuxPermissionQuery(
            subject_type=subject, object_class=object_class, permissions=frozenset({permission})
        )).decision is SELinuxDecision.DENIED for subject in self._subjects() for permission in permissions)

    def _bpf(self, guard: ClangGuard, constraints: tuple[ClangConstraint, ...]) -> GateExclusion | None:
        if not guard.arguments or len(guard.arguments) not in {3, 4}:
            return None
        # New kernels move these checks to token-specific hooks when this cap
        # is enabled. Absence of ordinary bpf allows then is not sufficient.
        if self.evaluator.capability_enabled("bpf_token_perms") is not False:
            return None
        if len(guard.arguments) == 4 and _value(guard.arguments[3], constraints) != 0:
            return None
        command = _value(guard.arguments[0], constraints)
        permission = {0: "map_create", 5: "prog_load"}.get(command) if command is not None else None
        if permission is None or not self._permission_denied("bpf", (permission,)):
            return None
        if _matches(guard.outcome, -13):
            return None
        return GateExclusion(guard.callee, f"SELinux denies bpf:{permission}; required outcome {guard.outcome}", self.profile.policy_sha256)

    def _perf(self, guard: ClangGuard, constraints: tuple[ClangConstraint, ...]) -> GateExclusion | None:
        if len(guard.arguments) not in {1, 2}:
            return None
        # Older kernels pass (attr, type), newer kernels only (type).
        kind = _value(guard.arguments[-1], constraints)
        # enum perf_event_security_index: check each alternative separately.
        permission = {0: "open", 1: "cpu", 2: "kernel", 3: "tracepoint"}.get(kind) if kind is not None else None
        permissions = (permission,) if permission is not None else ("open", "cpu", "kernel", "tracepoint")
        if not self._permission_denied("perf_event", permissions) or _matches(guard.outcome, -13):
            return None
        return GateExclusion(guard.callee, f"SELinux denies perf_event:{','.join(permissions)}; required outcome {guard.outcome}", self.profile.policy_sha256)
