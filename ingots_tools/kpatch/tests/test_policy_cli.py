import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
from tempfile import TemporaryDirectory
from typing import ClassVar, cast
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import CommitFilter, FilterContext, FilterPipeline, RunFilterArgs
from kpatch.filter.policy_analysis import PolicyFilter
from kpatch.filter.policy_clang import ClangToolchain, ClangUnavailable
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.policy_profile import (
    AnalysisScope, PolicyTargetProfile, SeccompProfile, SELinuxDecision, SELinuxPermissionQuery,
    SELinuxResult, SEToolsRuntime,
)
from kpatch.policy_cli import setools_runtime
from kpatch.git import GitDb, GitRepo


class PolicyInspectCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "sepolicy"
        self.binary.write_bytes(b"inspection-fixture")
        self.arguments = ["policy", "inspect", str(self.binary), "--subject", "app",
                          "--class", "file", "--permission", "read"]

    def test_unknown_enforcement_emits_unknown_json_without_assuming_policy(self) -> None:
        result = CliRunner().invoke(app, self.arguments)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output)["decision"], "unknown")

    def test_repeated_permissions_target_and_enforcement_are_forwarded(self) -> None:
        outcome = SELinuxResult(SELinuxDecision.POSSIBLY_ALLOWED, "allow fixture", "a" * 64)
        with patch("kpatch.policy_cli.SELinuxPolicyEvaluator") as evaluator:
            evaluator.return_value.query.return_value = outcome
            result = CliRunner().invoke(app, self.arguments + ["--permission", "write", "--target", "object", "--enforcing"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(evaluator.call_args.kwargs["enforcing"])
        self.assertEqual(evaluator.return_value.query.call_args.args, (
            SELinuxPermissionQuery(subject_type="app", object_class="file", target_type="object",
                                   permissions=frozenset({"read", "write"})),
        ))
        self.assertEqual(json.loads(result.output)["decision"], "possibly_allowed")

    def test_permissive_mode_does_not_assert_denial(self) -> None:
        result = CliRunner().invoke(app, self.arguments + ["--permissive"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output)["decision"], "possibly_allowed")

    def test_missing_policy_or_required_permission_fails_validation(self) -> None:
        for arguments in (self.arguments[:7], ["policy", "inspect", str(self.root / "missing"), *self.arguments[3:]]):
            with self.subTest(arguments=arguments):
                result = CliRunner().invoke(app, arguments)
                self.assertEqual(result.exit_code, 2, result.output)

    def test_invalid_subject_and_orphan_module_path_fail_cleanly(self) -> None:
        for arguments in (self.arguments + ["--subject", "invalid:type"],
                          self.arguments + ["--setools-module-path", str(self.root)]):
            with self.subTest(arguments=arguments):
                result = CliRunner().invoke(app, arguments)
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertIn("Policy inspection failed", result.output)

    def test_setools_runtime_resolves_paths_and_requires_interpreter(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires --setools-python"):
            setools_runtime(None, [self.root])
        self.assertEqual(setools_runtime(self.binary, [self.root]), SEToolsRuntime(self.binary.resolve(), (self.root.resolve(),)))
        self.assertIsNone(setools_runtime(None, None))

    @unittest.skipUnless(os.environ.get("KPATCH_TEST_SEPOLICY"), "Set KPATCH_TEST_SEPOLICY for real policy CLI integration")
    def test_actual_android_binary_denial_is_json(self) -> None:
        arguments = ["policy", "inspect", os.environ["KPATCH_TEST_SEPOLICY"], "--subject", "untrusted_app",
                     "--class", "bpf", "--permission", "prog_load", "--enforcing",
                     "--setools-python", os.environ["KPATCH_TEST_SETOOLS_PYTHON"]]
        for directory in os.environ.get("KPATCH_TEST_SETOOLS_PATH", "").split(os.pathsep):
            if directory:
                arguments.extend(("--setools-module-path", directory))
        result = CliRunner().invoke(app, arguments)
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["decision"], "denied")
        self.assertEqual(payload["policy_sha256"], hashlib.sha256(Path(os.environ["KPATCH_TEST_SEPOLICY"]).read_bytes()).hexdigest())


class PolicySourceCliTests(unittest.TestCase):
    compiler: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("clang")
        if compiler is None:
            raise unittest.SkipTest("Clang is required for compiler-context CLI integration")
        cls.compiler = compiler
        try:
            ClangToolchain.discover().build()
        except ClangUnavailable as error:
            raise unittest.SkipTest(str(error)) from error

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.build = self.root / "build"
        self.source.mkdir()
        self.build.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Policy CLI")
        self.git("config", "user.email", "policy-cli@example.invalid")
        self.unit = self.source / "unit.c"
        self.unit.write_text("SYSCALL_DEFINE0(test) { if (!capable(21)) return -1; return 7; }\n")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.unit.write_text(self.unit.read_text().replace("return 7", "return 8"))
        self.git("add", ".")
        self.git("commit", "-qm", "guarded change")
        self.child = self.git("rev-parse", "HEAD")
        self.unit.write_text(self.unit.read_text().replace("return 8", "return 9"))
        self.git("add", ".")
        self.git("commit", "-qm", "second guarded change")
        self.grandchild = self.git("rev-parse", "HEAD")
        self.git("checkout", "--detach", "-q", self.base)
        self.config = self.build / ".config"
        self.config.write_text("CONFIG_MULTIUSER=y\n")
        self.prelude = self.build / "syscalls.h"
        self.prelude.write_text("#define SYSCALL_DEFINE0(name) static long __do_sys_##name(void)\nint capable(int);\n")
        self.compdb = self.build / "compile_commands.json"
        self.compdb.write_text(json.dumps([{"directory": str(self.build), "file": str(self.unit),
                                          "arguments": [self.compiler, "-std=gnu11", "-nostdinc", "-include", str(self.prelude), "-c", str(self.unit)]}]))
        self.context = self.root / "context.json"
        self.context.write_text(PolicyBuildContext.capture(self.source, self.build, self.compdb, self.config).model_dump_json())
        self.binary = self.root / "sepolicy"
        self.binary.write_bytes(b"cli-capability-fixture")
        self.profile = self.root / "profile.json"
        target = PolicyTargetProfile(name="cli-app", policy_file=Path("sepolicy"),
                                     policy_sha256=hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                                     subject_context="u:r:app:s0", selinux_enforcing=True,
                                     cap_effective=0, cap_permitted=0, cap_bounding=0,
                                     user_namespaces_enabled=False)
        self.profile.write_text(target.model_dump_json())
        self.report = self.root / "audit.json"
        self.capture_arguments = ["policy", "build-context", "--source-root", str(self.source),
                                  "--build-root", str(self.build), "--compile-commands", str(self.compdb),
                                  "--config", str(self.config), "--output", str(self.context)]
        self.analysis_arguments = ["policy", "analyze", "--repo", str(self.source), "--profile", str(self.profile),
                                   "--build-context", str(self.context), "--output", str(self.report)]
        self.raw_database = GitDb(self.root / "raw.sqlite")
        self.filter_arguments = ["filter", "--repo", str(self.source), "--db", "raw", "--dest", "filtered", "config"]

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE).decode().strip()

    def pin_raw_seccomp(self) -> tuple[Path, ...]:
        raw = self.root / "filter.bpf"
        program = struct.pack("<HBBI", 0x06, 0, 0, 0x0005000D)
        raw.write_bytes(program)
        target = PolicyTargetProfile.model_validate_json(self.profile.read_text())
        seccomp = SeccompProfile(mode=2, architecture="aarch64", filter_file=Path("filter.bpf"),
                                 filter_sha256=hashlib.sha256(program).hexdigest())
        self.profile.write_text(target.model_copy(update={"seccomp": seccomp}).model_dump_json())
        symbolic = self.root / "filter-symlink.bpf"
        symbolic.symlink_to(raw)
        hardlink = self.root / "filter-hardlink.bpf"
        hardlink.hardlink_to(raw)
        return raw, symbolic, hardlink

    def test_build_context_command_captures_real_prepared_inputs(self) -> None:
        self.context.unlink()
        result = CliRunner().invoke(app, self.capture_arguments)
        self.assertEqual(result.exit_code, 0, result.output)
        context = PolicyBuildContext.load(self.context)
        self.assertEqual(context.base_revision, self.base)
        self.assertEqual(context.source_root, self.source)
        self.assertIn(self.prelude, {item.path for item in context.generated_inputs})
        self.assertIn("Pinned compiler context", result.output)

    def test_build_context_rejects_dirty_checkout_and_output_inside_frozen_roots(self) -> None:
        for destination in (self.source / "context.json", self.build / "context.json"):
            with self.subTest(destination=destination):
                result = CliRunner().invoke(app, self.capture_arguments[:-1] + [str(destination)])
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertFalse(destination.exists())
        self.unit.write_text("int dirty;\n")
        result = CliRunner().invoke(app, self.capture_arguments)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("clean source", result.output)

    def test_build_context_output_cannot_replace_external_config_or_compilation_database(self) -> None:
        for option, source in (("--config", self.config), ("--compile-commands", self.compdb)):
            with self.subTest(option=option):
                external = self.root / ("external-" + source.name)
                contents = source.read_bytes()
                external.write_bytes(contents)
                arguments = list(self.capture_arguments)
                arguments[arguments.index(option) + 1] = str(external)
                arguments[-1] = str(external)
                result = CliRunner().invoke(app, arguments)
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertEqual(external.read_bytes(), contents)

    def test_analyze_bare_commit_retains_full_scope_candidate_and_preserves_inputs(self) -> None:
        before = self.unit.read_bytes()
        result = CliRunner().invoke(app, self.analysis_arguments + ["--commit", self.child])
        self.assertEqual(result.exit_code, 0, result.output)
        report = json.loads(self.report.read_text())
        self.assertEqual((report["input_commits"], report["output_commits"]), (1, 1))
        self.assertEqual(report["scope"], "app_with_services")
        self.assertEqual(report["decision_counts"], {"direct_app_candidate": 1})
        self.assertEqual(report["decisions"][0]["commit_id"], self.child)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")
        self.assertEqual(self.unit.read_bytes(), before)

    def test_analyze_explicit_direct_app_scope_excludes_guarded_commit(self) -> None:
        result = CliRunner().invoke(app, self.analysis_arguments + ["--commit", self.child, "--direct-app"])
        self.assertEqual(result.exit_code, 0, result.output)
        report = json.loads(self.report.read_text())
        self.assertEqual((report["input_commits"], report["output_commits"]), (1, 0))
        self.assertEqual(report["scope"], "direct_app")
        self.assertEqual(report["decision_counts"], {"excluded": 1})
        self.assertIn("Policy exclusions: 1", result.output)

    def test_analyze_ranges_deduplicate_and_obey_limit(self) -> None:
        selections = ["--commit", self.child, "--commit", self.child, "--commit", self.child + ".." + self.grandchild]
        result = CliRunner().invoke(app, self.analysis_arguments + selections + ["--limit", "1"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(self.report.read_text())["input_commits"], 1)
        result = CliRunner().invoke(app, self.analysis_arguments + selections)
        self.assertEqual(result.exit_code, 0, result.output)
        report = json.loads(self.report.read_text())
        self.assertEqual(report["input_commits"], 2)
        self.assertEqual({item["commit_id"] for item in report["decisions"]}, {self.child, self.grandchild})

    def test_analyze_requires_commit_and_positive_limit(self) -> None:
        for arguments in (self.analysis_arguments, self.analysis_arguments + ["--commit", self.child, "--limit", "0"]):
            with self.subTest(arguments=arguments):
                result = CliRunner().invoke(app, arguments)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertFalse(self.report.exists())

    def test_analyze_invalid_revision_and_policy_hash_fail_without_report(self) -> None:
        result = CliRunner().invoke(app, self.analysis_arguments + ["--commit", "nonexistent-revision"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("Policy analysis failed", result.output)
        self.assertFalse(self.report.exists())
        self.binary.write_bytes(b"changed policy")
        result = CliRunner().invoke(app, self.analysis_arguments + ["--commit", self.child])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("does not match", result.output)
        self.assertFalse(self.report.exists())

    def test_analyze_report_cannot_overwrite_policy_or_source_inputs(self) -> None:
        for destination in (self.profile, self.binary, self.context, self.unit, self.prelude):
            with self.subTest(destination=destination):
                before = destination.read_bytes()
                arguments = self.analysis_arguments[:-1] + [str(destination), "--commit", self.child]
                result = CliRunner().invoke(app, arguments)
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertEqual(destination.read_bytes(), before)

    def test_analyze_cache_cannot_collide_with_report_or_frozen_inputs(self) -> None:
        for destination in (self.report, self.profile, self.unit, self.prelude):
            with self.subTest(destination=destination):
                result = CliRunner().invoke(app, self.analysis_arguments + ["--commit", self.child, "--cache", str(destination)])
                self.assertEqual(result.exit_code, 1, result.output)
                self.assertFalse(self.report.exists())

    def test_analyze_outputs_cannot_overwrite_raw_seccomp_or_aliases(self) -> None:
        destinations = self.pin_raw_seccomp()
        before = destinations[0].read_bytes()
        for option in ("--output", "--cache"):
            for destination in destinations:
                with self.subTest(option=option, destination=destination), patch("kpatch.policy_cli.PolicyFilter") as stage:
                    arguments = self.analysis_arguments + ["--commit", self.child]
                    if option == "--output":
                        arguments[arguments.index(option) + 1] = str(destination)
                    else:
                        arguments += [option, str(destination)]
                    result = CliRunner().invoke(app, arguments)
                    self.assertEqual(result.exit_code, 1, result.output)
                    stage.assert_not_called()
                    self.assertEqual(destinations[0].read_bytes(), before)
                    self.assertFalse(self.report.exists())

    def test_filter_requires_profile_context_and_decision_report_together(self) -> None:
        incomplete = (["--policy-profile", str(self.profile)],
                      ["--policy-build-context", str(self.context)],
                      ["--policy-report", str(self.report)], ["--policy-direct-app"],
                      ["--policy-cache", str(self.root / "cache.sqlite")],
                      ["--setools-python", self.compiler],
                      ["--setools-module-path", str(self.root)])
        for options in incomplete:
            with self.subTest(options=options), patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
                result = CliRunner().invoke(app, self.filter_arguments + options)
                self.assertEqual(result.exit_code, 2, result.output)
                run.assert_not_called()

    def test_filter_adds_policy_after_source_stages_and_writes_jsonl_report(self) -> None:
        options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                   "--policy-report", str(self.report), "--policy-direct-app"]

        def filter_fixture(arguments: RunFilterArgs, stage: CommitFilter) -> None:
            repository = GitRepo(self.source)
            commits = list(repository.iter_commits_from_revision(self.child + "^!"))
            self.assertEqual(stage.filter_commits(commits, FilterContext(repository), show_progress=False), [])

        with patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter", side_effect=filter_fixture) as run:
            result = CliRunner().invoke(app, self.filter_arguments + options)
        self.assertEqual(result.exit_code, 0, result.output)
        pipeline = cast(FilterPipeline, run.call_args.args[1])
        stage = cast(PolicyFilter, pipeline.filters[-1])
        self.assertIsInstance(stage, PolicyFilter)
        self.assertEqual(stage.profile.scope, AnalysisScope.DIRECT_APP)
        decisions = [json.loads(line) for line in self.report.read_text().splitlines()]
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["commit_id"], self.child)
        self.assertEqual(decisions[0]["status"], "excluded")

    def test_filter_rejects_config_mismatch_without_running_pipeline(self) -> None:
        config = self.root / "different.config"
        config.write_text("CONFIG_MULTIUSER=n\n")
        options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                   "--policy-report", str(self.report), "--config", str(config)]
        with patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, self.filter_arguments + options)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("configurations must match", result.output)
        run.assert_not_called()
        self.assertFalse(self.report.exists())

    def test_filter_report_cannot_overwrite_tracked_source(self) -> None:
        before = self.unit.read_bytes()
        options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                   "--policy-report", str(self.unit)]
        with patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, self.filter_arguments + options)
        self.assertEqual(result.exit_code, 1, result.output)
        run.assert_not_called()
        self.assertEqual(self.unit.read_bytes(), before)

    def test_filter_cache_cannot_collide_with_report_or_frozen_inputs(self) -> None:
        options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                   "--policy-report", str(self.report)]
        for destination in (self.report, self.profile, self.unit, self.prelude):
            with self.subTest(destination=destination), patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
                result = CliRunner().invoke(app, self.filter_arguments + options + ["--policy-cache", str(destination)])
                self.assertEqual(result.exit_code, 1, result.output)
                run.assert_not_called()
                self.assertFalse(self.report.exists())

    def test_filter_outputs_cannot_overwrite_raw_seccomp_or_aliases(self) -> None:
        destinations = self.pin_raw_seccomp()
        before = destinations[0].read_bytes()
        for option in ("--policy-report", "--policy-cache", "--source-pruning-report"):
            for destination in destinations:
                with self.subTest(option=option, destination=destination), patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
                    options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                               "--policy-report", str(self.report)]
                    if option == "--policy-report":
                        options[-1] = str(destination)
                    elif option == "--source-pruning-report":
                        options += ["--source-pruning", option, str(destination)]
                    else:
                        options += [option, str(destination)]
                    result = CliRunner().invoke(app, self.filter_arguments + options)
                    self.assertEqual(result.exit_code, 2 if option == "--source-pruning-report" else 1, result.output)
                    run.assert_not_called()
                    self.assertEqual(destinations[0].read_bytes(), before)
                    self.assertFalse(self.report.exists())

    def test_combined_outputs_cannot_truncate_raw_or_destination_databases(self) -> None:
        destination_db = self.root / "destination.sqlite"
        destination_db.write_bytes(b"destination database sentinel")
        whitespace = self.root / "whitespace.jsonl"
        whitespace.write_text("existing whitespace report")
        for destination in (self.raw_database.db, destination_db,
                            Path(str(self.raw_database.db) + "-wal")):
            if not destination.exists():
                destination.write_bytes(b"database sidecar sentinel")
            for option in ("--policy-report", "--policy-cache"):
                with self.subTest(destination=destination, option=option):
                    before = destination.read_bytes()
                    options = ["--policy-profile", str(self.profile), "--policy-build-context", str(self.context),
                               "--policy-report", str(self.report), "--whitespace-report", str(whitespace)]
                    if option == "--policy-report":
                        options[5] = str(destination)
                    else:
                        options += [option, str(destination)]
                    with patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), \
                         patch("kpatch.cli._path_for_db_name", return_value=destination_db), \
                         patch("kpatch.cli.run_filter") as run:
                        result = CliRunner().invoke(app, self.filter_arguments + options)
                    self.assertEqual(result.exit_code, 2, result.output)
                    self.assertEqual(destination.read_bytes(), before)
                    self.assertEqual(whitespace.read_text(), "existing whitespace report")
                    run.assert_not_called()

    def test_missing_policy_options_fail_before_creating_a_source_report(self) -> None:
        raw = self.pin_raw_seccomp()[0]
        before = raw.read_bytes()
        options = ["--policy-profile", str(self.profile), "--source-pruning",
                   "--source-pruning-report", str(raw)]
        with patch("kpatch.cli.GitDb.load_name", return_value=self.raw_database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, self.filter_arguments + options)
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("requires --policy-build-context", result.output)
        run.assert_not_called()
        self.assertEqual(raw.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
