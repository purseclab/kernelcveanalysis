import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import ConfigFilter, DeadCodeFilter, FilterContext, FilteredCommit, FilterPipeline
from kpatch.filter.config_filter import ConfigValue
from kpatch.filter.policy_clang import ClangAnalyzer, ClangToolchain, ClangUnavailable
from kpatch.filter.policy_context import PolicyBuildContext
from kpatch.filter.preprocessing import PreprocessingDecision, TargetPreprocessorFilter
from kpatch.git import GitCommit, GitDb, GitRepo


class TargetPreprocessingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.worker = ClangToolchain.discover().build()
        except ClangUnavailable as error:
            raise unittest.SkipTest(str(error)) from error
        compiler = shutil.which("clang")
        if compiler is None:
            raise unittest.SkipTest("Clang is required")
        cls.clang = compiler

    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.build = self.root / "source", self.root / "build"
        self.source.mkdir()
        self.build.mkdir()
        self.repo = GitRepo(self.source)
        self.git("init", "-q")
        self.git("config", "user.name", "Preprocessing test")
        self.git("config", "user.email", "preprocessing@example.invalid")
        self.analyzer = ClangAnalyzer(self.worker)
        self.addCleanup(self.analyzer.close)
        self.records: list[PreprocessingDecision] = []

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE).decode().strip()

    def write(self, files: dict[str, str]) -> None:
        for path, text in files.items():
            destination = self.source / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text)

    def change(self, old: dict[str, str], new: dict[str, str], *, missing_command: str = "") -> tuple[GitCommit, PolicyBuildContext]:
        self.write(old)
        self.git("add", ".")
        self.git("commit", "-qm", "parent")
        parent = self.git("rev-parse", "HEAD")
        self.write(new)
        self.git("add", ".")
        self.git("commit", "-qm", "child")
        commit = next(self.repo.iter_commits_from_revision("HEAD^!"))
        self.git("checkout", "--detach", "-q", parent)
        config = self.build / ".config"
        config.write_text("CONFIG_ARM64=y\nCONFIG_TEST=y\n")
        commands = [{"directory": str(self.build), "file": str(path),
                     "arguments": [self.clang, "-std=gnu11", "-nostdinc", "-I", str(self.source),
                                   "-DCONFIG_TEST=1", "-c", str(path)]}
                    for path in sorted(self.source.rglob("*.c")) if path.name != missing_command]
        database = self.build / "compile_commands.json"
        database.write_text(json.dumps(commands))
        return commit, PolicyBuildContext.capture(self.source, self.build, database, config)

    def run_stage(self, commit: GitCommit, build: PolicyBuildContext, *, cache: Path | None = None) -> tuple[list[FilteredCommit], TargetPreprocessorFilter]:
        stage = TargetPreprocessorFilter(build, cache_path=cache, analyzer=self.analyzer, on_decision=self.records.append)
        result = FilterPipeline([stage], reference_cache_path=self.root / "references.sqlite").filter_mutable_commits(
            [FilteredCommit(commit)], FilterContext(self.repo), False,
        )
        return result, stage

    def test_redundant_include_and_condition_rewrite_are_removed(self) -> None:
        header = "#ifndef API_H\n#define API_H\nint api(void);\n#endif\n"
        old = '#include "api.h"\n#include "api.h"\n#ifdef CONFIG_TEST\nint value = 3;\n#endif\n'
        new = '#include "api.h"\n#if defined(CONFIG_TEST)\nint value = 3;\n#endif\n'
        commit, build = self.change({"api.h": header, "unit.c": old}, {"unit.c": new})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(result, [])
        self.assertEqual(self.records[-1].reason, "equivalent_expanded_inputs")
        self.assertEqual(self.records[-1].units[0].old_digest, self.records[-1].units[0].new_digest)

    def test_unused_header_macro_change_checks_both_compiled_consumers(self) -> None:
        files = {"api.h": "#define UNUSED 1\n", "unit.c": '#include "api.h"\nint run(void) { return 3; }\n',
                 "other.c": '#include "api.h"\nint other(void) { return 4; }\n',
                 "Makefile": "obj-y += unit.o other.o\n"}
        commit, build = self.change(files, {"api.h": "#define UNUSED 2\n"})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(result, [])
        self.assertEqual([unit.path for unit in self.records[-1].units], ["other.c", "unit.c"])

    def test_reachable_second_consumer_vetoes_header_removal(self) -> None:
        files = {"api.h": "#define VALUE 1\n", "unit.c": '#include "api.h"\nint run(void) { return 3; }\n',
                 "other.c": '#include "api.h"\nint other(void) { return VALUE; }\n',
                 "Makefile": "obj-y += unit.o other.o\n"}
        commit, build = self.change(files, {"api.h": "#define VALUE 2\n"})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(self.records[-1].reason, "expanded_inputs_changed")

    def test_missing_live_consumer_command_is_unknown(self) -> None:
        files = {"api.h": "#define UNUSED 1\n", "unit.c": '#include "api.h"\nint run;\n',
                 "other.c": '#include "api.h"\nint other;\n', "Makefile": "obj-y += unit.o other.o\n"}
        commit, build = self.change(files, {"api.h": "#define UNUSED 2\n"}, missing_command="other.c")
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertIn("missing_consumer_compilation_command", self.records[-1].reason)

    def test_changed_expanded_line_value_is_retained(self) -> None:
        commit, build = self.change({"unit.c": "int run(void) { return __LINE__; }\n"},
                                    {"unit.c": "\nint run(void) { return __LINE__; }\n"})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(self.records[-1].reason, "expanded_inputs_changed")

    def test_unobserved_line_directive_changes_are_metadata_only(self) -> None:
        commit, build = self.change({"unit.c": '#line 20 "before.c"\nint value = 3;\n'},
                                    {"unit.c": '#line 80 "after.c"\nint value = 3;\n'})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(result, [])

    def test_pragma_pack_changes_are_retained(self) -> None:
        old = "#pragma pack(1)\nstruct state { char c; int n; };\nstruct state state;\n"
        commit, build = self.change({"unit.c": old}, {"unit.c": old.replace("pack(1)", "pack(2)")})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(self.records[-1].reason, "expanded_inputs_changed")

    def test_preprocessor_errors_do_not_produce_masks(self) -> None:
        commit, build = self.change({"unit.c": "#error stop\nint value;\n"}, {"unit.c": "#error stop\nint value; /* comment */\n"})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].edit_masks, ())
        self.assertEqual(self.records[-1].status, "unknown")

    def test_known_raw_source_consumer_still_vetoes(self) -> None:
        commit, build = self.change({"unit.c": "#define UNUSED 1\nint value;\n", "blob.S": '.incbin "unit.c"\n'},
                                    {"unit.c": "#define UNUSED 2\nint value;\n"})
        result, _ = self.run_stage(commit, build)
        self.assertEqual(len(result), 1)
        self.assertEqual(self.records[-1].reason, "raw_source_input_or_failed_inventory")

    def test_successful_results_reuse_persistent_dependency_checked_cache(self) -> None:
        commit, build = self.change({"unit.c": "#define UNUSED 1\nint value;\n"},
                                    {"unit.c": "#define UNUSED 2\nint value;\n"})
        cache = self.root / "preprocessed.sqlite"
        result, first = self.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [])
        self.assertEqual(first.compiler.stats.preprocessing_extractions, 2)
        result, second = self.run_stage(commit, build, cache=cache)
        self.assertEqual(result, [])
        self.assertEqual(second.compiler.stats.preprocessing_extractions, 0)
        self.assertEqual(second.compiler.stats.preprocessing_cache_hits, 2)
        self.assertEqual(hashlib.sha256(build.config_file.read_bytes()).hexdigest(), build.config_sha256)

    def test_cli_enables_standalone_preprocessing_without_policy_profile(self) -> None:
        _, build = self.change({"unit.c": "#define UNUSED 1\nint value;\n"},
                                {"unit.c": "#define UNUSED 2\nint value;\n"})
        context = self.root / "context.json"
        context.write_text(build.model_dump_json())
        report = self.root / "decisions.jsonl"
        database = GitDb(self.root / "commits.sqlite")
        with patch("kpatch.cli.GitDb.load_name", return_value=database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, ["filter", "--repo", str(self.source), "--db", "unused",
                                              "--dest", "unused-preprocessing-destination", "config",
                                              "--preprocess-build-context", str(context), "--preprocess-report", str(report)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsInstance(run.call_args.args[1].filters[-1], TargetPreprocessorFilter)
        self.assertTrue(report.is_file())

    def test_cli_rejects_report_collision_before_writing_compiler_inputs(self) -> None:
        _, build = self.change({"unit.c": "#define UNUSED 1\nint value;\n"},
                                {"unit.c": "#define UNUSED 2\nint value;\n"})
        context = self.root / "context.json"
        context.write_text(build.model_dump_json())
        before = build.config_file.read_bytes()
        database = GitDb(self.root / "commits.sqlite")
        with patch("kpatch.cli.GitDb.load_name", return_value=database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, ["filter", "--repo", str(self.source), "--db", "unused",
                                              "--dest", "unused-preprocessing-destination", "config",
                                              "--preprocess-build-context", str(context),
                                              "--preprocess-report", str(build.config_file)])
        self.assertEqual(result.exit_code, 2, result.output)
        run.assert_not_called()
        self.assertEqual(build.config_file.read_bytes(), before)

    def test_cli_shares_vendor_inputs_with_configuration_and_source_analysis(self) -> None:
        _, build = self.change({"unit.c": "#define UNUSED 1\nint value;\n"},
                                {"unit.c": "#define UNUSED 2\nint value;\n"})
        manifest = self.root / "inputs.json"
        manifest.write_text(json.dumps({"schema_version": 1, "inputs": [
            {"path": "drivers/vendor.c", "mode": "m", "origin": "observed module"},
        ]}))
        database = GitDb(self.root / "commits.sqlite")
        with patch("kpatch.cli.GitDb.load_name", return_value=database), patch("kpatch.cli.run_filter") as run:
            result = CliRunner().invoke(app, ["filter", "--repo", str(self.source), "--db", "unused",
                                              "--dest", "unused-preprocessing-destination", "config",
                                              "--config", str(build.config_file), "--build-inputs", str(manifest),
                                              "--source-pruning"])
        self.assertEqual(result.exit_code, 0, result.output)
        stages = run.call_args.args[1].filters
        configured = next(stage for stage in stages if isinstance(stage, ConfigFilter))
        unused = next(stage for stage in stages if isinstance(stage, DeadCodeFilter))
        self.assertIs(configured.config, unused.config)
        self.assertEqual(configured.config.additional_inputs, {"drivers/vendor.c": ConfigValue.MODULE})
