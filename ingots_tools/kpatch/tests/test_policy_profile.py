from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import struct
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pydantic import ValidationError

from kpatch.filter.policy_profile import (
    AnalysisScope, PolicyTargetProfile, SeccompDenial, SeccompProfile,
    SELinuxDecision, SELinuxPermissionQuery, SELinuxPolicyEvaluator, SEToolsRuntime,
    _AllowFact, _ClassPermissions, _PolicySnapshot,
)


class PolicyProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "policy"
        self.binary.write_bytes(b"fixture-policy")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def profile(self) -> PolicyTargetProfile:
        return PolicyTargetProfile(name="fixture", policy_file=self.binary, policy_sha256=self.digest,
                                   subject_context="u:r:app:s0:c1,c2", selinux_enforcing=True)

    def snapshot(self, *, allows: tuple[_AllowFact, ...] = (), permissive: bool = False) -> _PolicySnapshot:
        return _PolicySnapshot(complete=True, policy_sha256=self.digest, subject_type="app",
                               subject_permissive=permissive, setools_version="fixture-1",
                               types=frozenset({"app", "file_a", "file_b"}),
                               classes=(_ClassPermissions(name="file", permissions=frozenset({"read", "write"})),),
                               allows=allows, policy_capabilities=frozenset({"open_perms"}))

    @staticmethod
    def query(*permissions: str, target: str | None = None) -> SELinuxPermissionQuery:
        return SELinuxPermissionQuery(subject_type="app", object_class="file",
                                      permissions=frozenset(permissions or ("read",)), target_type=target)

    def evaluate(self, snapshot: _PolicySnapshot, query: SELinuxPermissionQuery) -> SELinuxDecision:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_snapshot", return_value=snapshot):
            return evaluator.query(query).decision

    def test_profile_defaults_do_not_assert_service_closure(self) -> None:
        profile = self.profile()
        self.assertEqual(profile.scope, AnalysisScope.APP_WITH_SERVICES)
        self.assertFalse(profile.mediation_complete)
        self.assertEqual(profile.modeled_subject_types, ())
        self.assertIsNone(profile.cap_effective)
        self.assertIsNone(profile.user_namespaces_enabled)
        self.assertEqual(profile.subject_type, "app")

    def test_complete_mediation_requires_app_subject(self) -> None:
        with self.assertRaises(ValidationError):
            PolicyTargetProfile(name="fixture", policy_file=self.binary, policy_sha256=self.digest,
                                subject_context="u:r:app:s0", mediation_complete=True,
                                modeled_subject_types=("server",))

    def test_profile_load_resolves_relative_binary_and_checks_hash(self) -> None:
        profile = self.profile().model_copy(update={"policy_file": Path("policy")})
        path = self.root / "profile.json"
        path.write_text(profile.model_dump_json())
        loaded = PolicyTargetProfile.load(path)
        self.assertEqual(loaded.policy_file, self.binary)
        self.assertEqual(loaded.fingerprint, profile.fingerprint)
        self.binary.write_bytes(b"other-policy")
        with self.assertRaisesRegex(ValueError, "does not match"):
            PolicyTargetProfile.load(path)

    def test_unknown_profile_fields_and_incomplete_context_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            PolicyTargetProfile.model_validate({**self.profile().model_dump(), "uid_is_root": True})
        with self.assertRaises(ValidationError):
            PolicyTargetProfile.model_validate({**self.profile().model_dump(), "subject_context": "app"})
        for field, value in (("cap_effective", False), ("selinux_enforcing", "true"),
                             ("user_namespaces_enabled", "false")):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                PolicyTargetProfile.model_validate({**self.profile().model_dump(), field: value})

    def test_seccomp_probes_cannot_be_used_as_universal_denials(self) -> None:
        with self.assertRaises(ValidationError):
            SeccompDenial(architecture="aarch64", syscall_number=425, syscall_name="io_uring_setup",
                          filter_sha256=self.digest, all_arguments=False)
        denial = SeccompDenial(architecture="aarch64", syscall_number=425, syscall_name="io_uring_setup",
                              filter_sha256=self.digest, all_arguments=True)
        with self.assertRaises(ValidationError):
            SeccompProfile(mode=2, denials=(denial,))
        with self.assertRaises(ValidationError):
            SeccompProfile(mode=2, architecture="x86_64", filter_sha256=self.digest, denials=(denial,))

    def test_raw_seccomp_filter_requires_mode_two_and_a_pinned_hash(self) -> None:
        for mode in (None, 0, 1):
            with self.subTest(mode=mode), self.assertRaises(ValidationError):
                SeccompProfile(mode=mode, filter_sha256=self.digest, filter_file=Path("filter.bpf"))
        with self.assertRaises(ValidationError):
            SeccompProfile(mode=2, filter_file=Path("filter.bpf"))

    def test_profile_load_resolves_raw_seccomp_relative_path_and_checks_bytes(self) -> None:
        program = struct.pack("<HBBI", 0x06, 0, 0, 0x0005000D)
        raw = self.root / "filter.bpf"
        raw.write_bytes(program)
        seccomp = SeccompProfile(mode=2, architecture="aarch64", filter_file=Path("filter.bpf"),
                                 filter_sha256=hashlib.sha256(program).hexdigest())
        profile = self.profile().model_copy(update={"seccomp": seccomp})
        path = self.root / "profile.json"
        path.write_text(profile.model_dump_json())
        loaded = PolicyTargetProfile.load(path)
        self.assertEqual(loaded.seccomp.filter_file, raw)
        self.assertEqual(loaded.fingerprint, profile.fingerprint)
        raw.write_bytes(struct.pack("<HBBI", 0x06, 0, 0, 0x7FFF0000))
        with self.assertRaisesRegex(ValueError, "Seccomp filter does not match"):
            PolicyTargetProfile.load(path)

    def test_profile_fingerprint_uses_filter_bytes_hash_but_not_local_placement(self) -> None:
        seccomp = SeccompProfile(mode=2, filter_file=Path("one/filter.bpf"), filter_sha256="a" * 64)
        profile = self.profile().model_copy(update={"seccomp": seccomp})
        relocated = profile.model_copy(update={"seccomp": seccomp.model_copy(update={"filter_file": Path("other/filter.bpf")})})
        different = profile.model_copy(update={"seccomp": seccomp.model_copy(update={"filter_sha256": "b" * 64})})
        self.assertEqual(profile.fingerprint, relocated.fingerprint)
        self.assertNotEqual(profile.fingerprint, different.fingerprint)

    def test_profile_load_missing_or_oversized_raw_filter_fails(self) -> None:
        raw = self.root / "filter.bpf"
        seccomp = SeccompProfile(mode=2, filter_file=raw, filter_sha256="a" * 64)
        profile = self.profile().model_copy(update={"seccomp": seccomp})
        path = self.root / "profile.json"
        path.write_text(profile.model_dump_json())
        with self.assertRaises(FileNotFoundError):
            PolicyTargetProfile.load(path)
        raw.write_bytes(b"x" * (4096 * 8 + 1))
        with self.assertRaisesRegex(ValueError, "bounded input size"):
            PolicyTargetProfile.load(path)

    def test_absent_allow_is_denied_for_enforcing_nonpermissive_domain(self) -> None:
        self.assertEqual(self.evaluate(self.snapshot(), self.query()), SELinuxDecision.DENIED)

    def test_all_potential_conditional_allows_are_retained(self) -> None:
        fact = _AllowFact(object_class="file", targets=frozenset({"file_a"}), permissions=frozenset({"read"}))
        # The worker includes both branches; the evaluator must not attempt to
        # discard a fact based on a captured/assumed boolean value.
        self.assertEqual(self.evaluate(self.snapshot(allows=(fact,)), self.query()), SELinuxDecision.POSSIBLY_ALLOWED)

    def test_unknown_target_searches_all_attribute_expanded_targets(self) -> None:
        fact = _AllowFact(object_class="file", targets=frozenset({"file_a", "file_b"}),
                          permissions=frozenset({"read"}))
        snap = self.snapshot(allows=(fact,))
        self.assertEqual(self.evaluate(snap, self.query(target="file_b")), SELinuxDecision.POSSIBLY_ALLOWED)
        self.assertEqual(self.evaluate(snap, self.query()), SELinuxDecision.POSSIBLY_ALLOWED)

    def test_split_rules_for_same_object_combine_but_other_objects_do_not(self) -> None:
        read = _AllowFact(object_class="file", targets=frozenset({"file_a"}), permissions=frozenset({"read"}))
        write = _AllowFact(object_class="file", targets=frozenset({"file_b"}), permissions=frozenset({"write"}))
        self.assertEqual(self.evaluate(self.snapshot(allows=(read, write)), self.query("read", "write")), SELinuxDecision.DENIED)
        same = write.model_copy(update={"targets": frozenset({"file_a"})})
        self.assertEqual(self.evaluate(self.snapshot(allows=(read, same)), self.query("read", "write")), SELinuxDecision.POSSIBLY_ALLOWED)

    def test_unknown_types_class_and_permissions_retain(self) -> None:
        snapshot = self.snapshot()
        for query in (self.query("missing"), self.query(target="missing"),
                      self.query().model_copy(update={"object_class": "unknown"}),
                      self.query().model_copy(update={"subject_type": "unknown"})):
            with self.subTest(query=query):
                self.assertEqual(self.evaluate(snapshot, query), SELinuxDecision.UNKNOWN)

    def test_enforcement_unknown_and_permissive_never_deny(self) -> None:
        for enforcing, expected in ((None, SELinuxDecision.UNKNOWN), (False, SELinuxDecision.POSSIBLY_ALLOWED)):
            evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=enforcing)
            with patch.object(evaluator, "_snapshot") as extract:
                self.assertEqual(evaluator.query(self.query()).decision, expected)
                extract.assert_not_called()
        self.assertEqual(self.evaluate(self.snapshot(permissive=True), self.query()), SELinuxDecision.POSSIBLY_ALLOWED)

    def test_missing_or_invalid_binary_retains(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.root / "missing", enforcing=True)
        self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.UNKNOWN)
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_snapshot", side_effect=ValueError("parse failure")):
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.UNKNOWN)

    def test_permission_results_are_cached_without_new_worker_calls(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_snapshot", return_value=self.snapshot()) as extract:
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.DENIED)
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.DENIED)
            extract.assert_called_once()
        self.assertEqual(evaluator.stats.permission_cache_hits, 1)

    def test_cached_denial_is_not_reused_after_enforcement_changes(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_snapshot", return_value=self.snapshot()):
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.DENIED)
            evaluator.enforcing = False
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.POSSIBLY_ALLOWED)
            evaluator.enforcing = None
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.UNKNOWN)

    def test_disk_snapshot_reuse_and_policy_hash_invalidation(self) -> None:
        cache = self.root / "cache.sqlite"
        first = SELinuxPolicyEvaluator(self.binary, enforcing=True, cache_path=cache)
        with patch.object(first, "_runtime_version", return_value="fixture-1"), \
             patch.object(first, "_extract_snapshot", return_value=self.snapshot()) as extract:
            self.assertEqual(first.query(self.query()).decision, SELinuxDecision.DENIED)
            extract.assert_called_once()
        second = SELinuxPolicyEvaluator(self.binary, enforcing=True, cache_path=cache)
        with patch.object(second, "_runtime_version", return_value="fixture-1"), \
             patch.object(second, "_extract_snapshot") as extract:
            self.assertEqual(second.query(self.query()).decision, SELinuxDecision.DENIED)
            extract.assert_not_called()
        self.binary.write_bytes(b"changed-policy")
        third = SELinuxPolicyEvaluator(self.binary, enforcing=True, cache_path=cache)
        with patch.object(third, "_runtime_version", return_value="fixture-1"), \
             patch.object(third, "_extract_snapshot", side_effect=ValueError("new extraction required")) as extract:
            self.assertEqual(third.query(self.query()).decision, SELinuxDecision.UNKNOWN)
            extract.assert_called_once()

    def test_corrupt_cache_falls_back_to_fresh_extraction(self) -> None:
        cache = self.root / "cache.sqlite"
        first = SELinuxPolicyEvaluator(self.binary, enforcing=True, cache_path=cache)
        with patch.object(first, "_runtime_version", return_value="fixture-1"), \
             patch.object(first, "_extract_snapshot", return_value=self.snapshot()):
            first.query(self.query())
        with closing(sqlite3.connect(cache)) as database:
            database.execute("UPDATE selinux_snapshots SET payload='corrupt'")
            database.commit()
        second = SELinuxPolicyEvaluator(self.binary, enforcing=True, cache_path=cache)
        with patch.object(second, "_runtime_version", return_value="fixture-1"), \
             patch.object(second, "_extract_snapshot", return_value=self.snapshot()) as extract:
            self.assertEqual(second.query(self.query()).decision, SELinuxDecision.DENIED)
            extract.assert_called_once()

    def test_mismatched_snapshot_provenance_retains(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        other = self.snapshot().model_copy(update={"policy_sha256": "0" * 64})
        with patch.object(evaluator, "_runtime_version", return_value="fixture-1"), \
             patch.object(evaluator, "_extract_snapshot", return_value=other):
            self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.UNKNOWN)

    def test_policy_capability_absence_requires_a_known_complete_namespace(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_runtime_version", return_value="fixture-1"), \
             patch.object(evaluator, "_extract_snapshot", return_value=self.snapshot()):
            evaluator.query(self.query())
        self.assertTrue(evaluator.capability_enabled("open_perms"))
        self.assertFalse(evaluator.capability_enabled("bpf_token_perms"))
        self.assertIsNone(evaluator.capability_enabled("unknown_capability"))
        evaluator._capabilities = frozenset({"unknown_numeric_100"})
        self.assertIsNone(evaluator.capability_enabled("bpf_token_perms"))

    def test_policy_capability_errors_are_unknown(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True)
        with patch.object(evaluator, "_runtime_version", side_effect=ValueError("unavailable")):
            self.assertIsNone(evaluator.capability_enabled("bpf_token_perms"))

    def test_invalid_snapshot_or_worker_errors_never_become_empty_allow_sets(self) -> None:
        evaluator = SELinuxPolicyEvaluator(self.binary, enforcing=True, runtime=SEToolsRuntime(Path("missing")))
        self.assertEqual(evaluator.query(self.query()).decision, SELinuxDecision.UNKNOWN)
        with self.assertRaises(ValidationError):
            _PolicySnapshot.model_validate({**self.snapshot().model_dump(), "complete": False})

    @unittest.skipUnless(os.environ.get("KPATCH_TEST_SEPOLICY"), "Set KPATCH_TEST_SEPOLICY for binary integration")
    def test_actual_android_binary(self) -> None:
        binary = Path(os.environ["KPATCH_TEST_SEPOLICY"])
        python = Path(os.environ["KPATCH_TEST_SETOOLS_PYTHON"])
        module_paths = tuple(Path(path) for path in os.environ.get("KPATCH_TEST_SETOOLS_PATH", "").split(os.pathsep) if path)
        evaluator = SELinuxPolicyEvaluator(binary, enforcing=True, runtime=SEToolsRuntime(python, module_paths),
                                           cache_path=self.root / "actual.sqlite")
        self.assertFalse(evaluator.capability_enabled("bpf_token_perms"))
        blocked = SELinuxPermissionQuery(subject_type="untrusted_app", object_class="bpf", permissions=frozenset({"prog_load"}))
        ordinary = SELinuxPermissionQuery(subject_type="untrusted_app", object_class="tcp_socket", permissions=frozenset({"create"}))
        self.assertEqual(evaluator.query(blocked).decision, SELinuxDecision.DENIED)
        self.assertEqual(evaluator.query(ordinary).decision, SELinuxDecision.POSSIBLY_ALLOWED)
        self.assertEqual(evaluator.query(blocked.model_copy(update={"subject_type": "su"})).decision, SELinuxDecision.POSSIBLY_ALLOWED)
        self.assertEqual(evaluator.stats.snapshot_extractions, 2)
        self.assertFalse(evaluator.capability_enabled("bpf_token_perms"))


if __name__ == "__main__":
    unittest.main()
