from dataclasses import dataclass
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from kpatch.filter.policy_clang import (
    ClangAnalyzer, ClangFunction, ClangSpan, ClangVersion, CompileCommand, SourceOverlay,
    SourcePoint, TranslationUnitFacts,
)
from kpatch.filter.policy_context import InputDigest, PolicyBuildContext, RevisionCompiler
from kpatch.git import GitRepo


@dataclass(frozen=True, slots=True)
class ExtractionRequest:
    command: CompileCommand
    overlays: tuple[SourceOverlay, ...]
    tracked_paths: tuple[Path, ...]


class RecordingAnalyzer(ClangAnalyzer):
    """Exact typed TU fixtures; these tests exercise context/caching, not CFGs."""

    def __init__(self, dependencies: tuple[Path, ...]) -> None:
        worker = dependencies[0].parent.parent / "fixture-worker"
        worker.write_bytes(b"typed context-fixture worker v1")
        super().__init__(worker_path=worker)
        version = subprocess.check_output(["clang", "--version"], text=True).splitlines()[0]
        match = re.search(r"clang version (\d+)", version)
        assert match is not None
        self._version = ClangVersion(major=int(match[1]), compiler=version)
        self.dependencies = dependencies
        self.requests: list[ExtractionRequest] = []
        self.failure: str | None = None

    def analyze(self, command: CompileCommand, *, overlays: tuple[SourceOverlay, ...] = (),
                tracked_paths: tuple[Path, ...] = (), function_names: tuple[str, ...] = ()) -> TranslationUnitFacts:
        self.requests.append(ExtractionRequest(command, overlays, tracked_paths))
        if self.failure is not None:
            return TranslationUnitFacts.failure(self.failure)
        start = SourcePoint(path=command.file, line=2, column=1, offset=17)
        end = SourcePoint(path=command.file, line=2, column=35, offset=51)
        span = ClangSpan(start=start, end=end)
        function = ClangFunction(name="run", usr="c:@F@run", span=span, body_span=span,
                                 is_static=False)
        return TranslationUnitFacts(complete=True, functions=(function,), dependencies=self.dependencies,
                                    compiler_major=self.version.major, compiler_version=self.version.compiler)


class PolicyContextTests(unittest.TestCase):
    def setUp(self) -> None:
        compiler = shutil.which("clang")
        if compiler is None:
            self.skipTest("Clang is required for compile-context version validation")
        self.compiler = compiler
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.output = self.root / "build"
        self.source.mkdir()
        self.output.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Policy Test")
        self.git("config", "user.email", "policy@example.invalid")
        (self.source / "include").mkdir()
        (self.source / "shadow").mkdir()
        self.unit = self.source / "unit.c"
        self.header = self.source / "include/api.h"
        self.unit.write_text('#include <api.h>\nint run(void) { return VALUE; }\n')
        self.header.write_text("#define VALUE 1\n")
        (self.source / "other.c").write_text("int other(void) { return 1; }\n")
        (self.source / "Makefile").write_text("obj-y += unit.o other.o\n")
        (self.source / "generator.json").write_text('{"value": 1}\n')
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        self.base = self.git("rev-parse", "HEAD")
        self.config = self.output / ".config"
        self.generated = self.output / "generated.h"
        self.unused_generated = self.output / "unused-generated.h"
        self.config.write_text("CONFIG_TEST=y\n")
        self.generated.write_text("#define GENERATED_VALUE 1\n")
        self.unused_generated.write_text("#define OTHER_GENERATED_VALUE 1\n")
        self.compdb = self.output / "compile_commands.json"
        self.write_commands()
        self.build = PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)
        self.repo = GitRepo(self.source)

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE).decode().strip()

    def write_commands(self, *, extra_flags: tuple[str, ...] = ()) -> None:
        command = {"directory": str(self.output), "file": str(self.unit),
                   "arguments": [self.compiler, "-std=gnu11", "-nostdinc", "-I", str(self.source / "shadow"),
                                 "-I", str(self.source / "include"), "-include", str(self.generated),
                                 *extra_flags, "-c", str(self.unit), "-o", str(self.output / "unit.o")]}
        self.compdb.write_text(json.dumps([command]))

    def revision(self, files: dict[str, str | None]) -> str:
        self.git("checkout", "--detach", "-q", self.base)
        for relative, contents in files.items():
            path = self.source / relative
            if contents is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
        self.git("add", "-A")
        self.git("commit", "-qm", "variant")
        revision = self.git("rev-parse", "HEAD")
        self.git("checkout", "--detach", "-q", self.base)
        return revision

    def analyzer(self) -> RecordingAnalyzer:
        return RecordingAnalyzer((self.unit, self.header, self.generated))

    def context(self, analyzer: RecordingAnalyzer, *, cache: Path | None = None) -> RevisionCompiler:
        compiler = RevisionCompiler(self.repo, self.build, analyzer, cache_path=cache)
        self.addCleanup(compiler.close)
        return compiler

    def test_capture_pins_clean_revision_config_generated_inputs_and_toolchain(self) -> None:
        self.assertEqual(self.build.base_revision, self.base)
        self.assertEqual(self.build.config_sha256, hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertIn(self.generated, {item.path for item in self.build.generated_inputs})
        self.assertIn("clang", self.build.compiler_version.lower())

    def test_capture_rejects_unpinned_external_include_search_root(self) -> None:
        external = self.root / "mutable-headers"
        external.mkdir()
        self.write_commands(extra_flags=("-I", str(external)))
        with self.assertRaisesRegex(ValueError, "outside pinned roots"):
            PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)

    def test_capture_requires_explicit_nostdinc(self) -> None:
        self.compdb.write_text(self.compdb.read_text().replace('"-nostdinc", ', ""))
        with self.assertRaisesRegex(ValueError, "require -nostdinc"):
            PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)

    def test_capture_rejects_response_files_and_hidden_include_controls(self) -> None:
        response = self.output / "arguments.rsp"
        response.write_text("-DVALUE=2\n")
        for extra in (("@" + str(response),), ("-Wp,-I," + str(self.root),), ("-Xclang", "-fno-builtin")):
            with self.subTest(extra=extra):
                self.write_commands(extra_flags=extra)
                with self.assertRaisesRegex(ValueError, "hidden compiler input"):
                    PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)

    def test_capture_accepts_explicit_frozen_source_and_build_include_roots(self) -> None:
        self.write_commands(extra_flags=("-I", str(self.output)))
        context = PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)
        self.assertEqual(context.source_root, self.source)
        self.assertEqual(context.build_root, self.output)

    def test_capture_rejects_implicit_include_environment(self) -> None:
        with patch.dict(os.environ, {"CPATH": str(self.root)}):
            with self.assertRaisesRegex(ValueError, "implicit compiler search environment CPATH"):
                PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)

    def test_capture_rejects_automatic_precompiled_header_siblings(self) -> None:
        for suffix in (".pch", ".gch"):
            with self.subTest(suffix=suffix):
                artifact = Path(str(self.generated) + suffix)
                artifact.write_bytes(b"precompiled fixture")
                try:
                    with self.assertRaisesRegex(ValueError, "Precompiled header"):
                        PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)
                finally:
                    artifact.unlink()

    def test_precompiled_header_appearing_after_context_creation_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        Path(str(self.generated) + ".pch").write_bytes(b"precompiled fixture")
        result = context.facts(self.base, "unit.c")
        self.assertFalse(result.complete)
        self.assertIn("precompiled_header_input_appeared", result.unknowns)
        self.assertEqual(len(analyzer.requests), 1)

    def test_implicit_include_environment_changed_after_context_creation_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        with patch.dict(os.environ, {"CPATH": str(self.root)}):
            self.assertFalse(context.facts(self.base, "unit.c").complete)
        self.assertEqual(analyzer.requests, [])

    def test_cold_then_warm_facts_reuse_without_reextraction(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        first = context.facts(self.base, "unit.c")
        second = context.facts(self.base, "unit.c")
        self.assertTrue(first.complete)
        self.assertEqual(first, second)
        self.assertEqual(len(analyzer.requests), 1)
        self.assertEqual(context.stats.extractions, 1)
        self.assertEqual(context.stats.cache_hits, 1)

    def test_persisted_facts_reused_by_new_context(self) -> None:
        cache = self.root / "facts.sqlite"
        first = self.context(self.analyzer(), cache=cache)
        self.assertTrue(first.facts(self.base, "unit.c").complete)
        analyzer = self.analyzer()
        second = self.context(analyzer, cache=cache)
        self.assertTrue(second.facts(self.base, "unit.c").complete)
        self.assertEqual(analyzer.requests, [])
        self.assertEqual(second.stats.cache_hits, 1)

    def test_source_revision_uses_overlay_and_does_not_modify_baseline(self) -> None:
        contents = '#include <api.h>\nint run(void) { return VALUE + 1; }\n'
        revision = self.revision({"unit.c": contents})
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(revision, "unit.c").complete)
        overlays = {item.path: item.contents for item in analyzer.requests[0].overlays}
        self.assertEqual(overlays[self.unit], contents)
        self.assertNotEqual(self.unit.read_text(), contents)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.base)

    def test_header_edit_invalidates_unchanged_source_facts(self) -> None:
        revision = self.revision({"include/api.h": "#define VALUE 2\n"})
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.assertTrue(context.facts(revision, "unit.c").complete)
        self.assertEqual(len(analyzer.requests), 2)
        overlays = {item.path: item.contents for item in analyzer.requests[1].overlays}
        self.assertEqual(overlays[self.header], "#define VALUE 2\n")

    def test_included_text_file_edit_is_overlaid_and_invalidates_source_cache(self) -> None:
        text_header = self.header.with_suffix(".txt")
        self.header.rename(text_header)
        self.header = text_header
        self.unit.write_text(self.unit.read_text().replace("api.h", "api.txt"))
        self.git("add", "-A")
        self.git("commit", "-qm", "include text file")
        self.base = self.git("rev-parse", "HEAD")
        self.build = PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)
        revision = self.revision({"include/api.txt": "#define VALUE 2\n"})
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.assertTrue(context.facts(revision, "unit.c").complete)
        self.assertEqual(len(analyzer.requests), 2)
        overlays = {item.path: item.contents for item in analyzer.requests[1].overlays}
        self.assertEqual(overlays[text_header], "#define VALUE 2\n")

    def test_unrelated_c_edit_reuses_dependency_valid_facts(self) -> None:
        revision = self.revision({"other.c": "int other(void) { return 2; }\n"})
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.assertTrue(context.facts(revision, "unit.c").complete)
        self.assertEqual(len(analyzer.requests), 1)

    def test_added_deleted_and_build_epoch_paths_are_incomplete(self) -> None:
        changes: tuple[dict[str, str | None], ...] = (
            {"added.h": "#define NEW 1\n"}, {"other.c": None}, {"Makefile": "obj-y += unit.o\n"},
            {"generator.json": '{"value": 2}\n'},
        )
        for files in changes:
            revision = self.revision(files)
            analyzer = self.analyzer()
            result = self.context(analyzer).facts(revision, "unit.c")
            with self.subTest(files=files):
                self.assertFalse(result.complete)
                self.assertEqual(analyzer.requests, [])
                if "generator.json" in files:
                    self.assertIn("unsupported_snapshot_input", result.unknowns)

    def test_missing_source_compilation_command_is_unknown(self) -> None:
        analyzer = self.analyzer()
        result = self.context(analyzer).facts(self.base, "other.c")
        self.assertFalse(result.complete)
        self.assertIn("missing_compilation_command", result.unknowns)
        self.assertEqual(analyzer.requests, [])

    def test_seccomp_dispatch_and_metadata_contract_changes_require_new_context(self) -> None:
        contracts = ("include/linux/tracepoint.h", "include/uapi/linux/audit.h", "include/uapi/linux/elf-em.h",
                     "kernel/seccomp.c", "net/core/filter.c", "kernel/bpf/core.c", "include/linux/filter.h",
                     "arch/arm64/net/bpf_jit_comp.c", "arch/arm64/kernel/syscall.c", "arch/arm64/kernel/ptrace.c")
        for relative in contracts:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("/* pinned framework contract */\n")
        self.git("add", ".")
        self.git("commit", "-qm", "framework inputs")
        self.base = self.git("rev-parse", "HEAD")
        self.build = PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)
        for relative in contracts:
            with self.subTest(contract=relative):
                revision = self.revision({relative: "/* changed framework contract */\n"})
                analyzer = self.analyzer()
                result = self.context(analyzer).facts(revision, "unit.c")
                self.assertFalse(result.complete)
                self.assertIn("build_epoch_changed", result.unknowns)
                self.assertEqual(analyzer.requests, [])

    def test_dirty_source_capture_rejected(self) -> None:
        self.unit.write_text("int dirty;\n")
        with self.assertRaisesRegex(ValueError, "clean source"):
            PolicyBuildContext.capture(self.source, self.output, self.compdb, self.config)

    def test_source_modified_after_context_capture_is_incomplete(self) -> None:
        self.unit.write_text("int dirty;\n")
        analyzer = self.analyzer()
        result = self.context(analyzer).facts(self.base, "unit.c")
        self.assertFalse(result.complete)
        self.assertEqual(analyzer.requests, [])

    def test_config_or_generated_change_before_context_construction_is_incomplete(self) -> None:
        for path in (self.config, self.generated):
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            analyzer = self.analyzer()
            with self.subTest(path=path):
                self.assertFalse(self.context(analyzer).facts(self.base, "unit.c").complete)
                self.assertEqual(analyzer.requests, [])
            path.write_bytes(original)

    def test_config_change_after_cache_fill_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.config.write_text("CONFIG_TEST=n\n")
        self.assertFalse(context.facts(self.base, "unit.c").complete)

    def test_unused_generated_input_change_after_cache_fill_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.unused_generated.write_text("#define OTHER_GENERATED_VALUE 2\n")
        self.assertFalse(context.facts(self.base, "unit.c").complete)

    def test_source_checkout_change_after_cache_fill_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        self.unit.write_text("int dirty;\n")
        self.assertFalse(context.facts(self.base, "unit.c").complete)

    def test_untracked_shadow_header_after_cache_fill_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        context = self.context(analyzer)
        self.assertTrue(context.facts(self.base, "unit.c").complete)
        (self.source / "shadow").mkdir(exist_ok=True)
        (self.source / "shadow/api.h").write_text("#define VALUE 2\n")
        self.assertFalse(context.facts(self.base, "unit.c").complete)

    def test_compilation_database_changed_after_capture_is_incomplete(self) -> None:
        self.write_commands(extra_flags=("-DVALUE_OVERRIDE=1",))
        analyzer = self.analyzer()
        self.assertFalse(self.context(analyzer).facts(self.base, "unit.c").complete)

    def test_context_load_resolves_relative_generated_input_paths(self) -> None:
        relative = self.build.model_copy(update={
            "source_root": Path("source"), "build_root": Path("build"),
            "compilation_database": Path("build/compile_commands.json"), "config_file": Path("build/.config"),
            "generated_inputs": (InputDigest(path=Path("build/generated.h"), sha256=hashlib.sha256(self.generated.read_bytes()).hexdigest()),),
        })
        path = self.root / "context.json"
        path.write_text(relative.model_dump_json())
        loaded = PolicyBuildContext.load(path)
        self.assertEqual(loaded.generated_inputs[0].path, self.generated)

    def test_incomplete_analyzer_results_reuse_memory_cache_without_becoming_proof(self) -> None:
        analyzer = self.analyzer()
        analyzer.failure = "file_scope_assembly"
        context = self.context(analyzer)
        self.assertFalse(context.facts(self.base, "unit.c").complete)
        cached = context.facts(self.base, "unit.c")
        self.assertFalse(cached.complete)
        self.assertIn("file_scope_assembly", cached.unknowns)
        self.assertEqual(cached.functions, ())
        self.assertEqual(len(analyzer.requests), 1)
        self.assertEqual(context.stats.cache_hits, 1)
        self.assertEqual(context.stats.unknown_cache_hits, 1)

    def test_incomplete_analyzer_results_reuse_disk_cache_without_new_invocation(self) -> None:
        cache = self.root / "facts.sqlite"
        analyzer = self.analyzer()
        analyzer.failure = "file_scope_assembly"
        first = self.context(analyzer, cache=cache)
        self.assertFalse(first.facts(self.base, "unit.c").complete)
        self.assertEqual(len(analyzer.requests), 1)
        second_analyzer = self.analyzer()
        second = self.context(second_analyzer, cache=cache)
        cached = second.facts(self.base, "unit.c")
        self.assertFalse(cached.complete)
        self.assertIn("file_scope_assembly", cached.unknowns)
        self.assertEqual(cached.functions, ())
        self.assertEqual(second_analyzer.requests, [])
        self.assertEqual(second.stats.cache_hits, 1)
        self.assertEqual(second.stats.unknown_cache_hits, 1)

    def test_negative_cache_rejects_payload_claiming_complete_facts(self) -> None:
        cache = self.root / "facts.sqlite"
        analyzer = self.analyzer()
        analyzer.failure = "file_scope_assembly"
        first = self.context(analyzer, cache=cache)
        self.assertFalse(first.facts(self.base, "unit.c").complete)
        payload = TranslationUnitFacts(complete=True).model_dump_json()
        with closing(sqlite3.connect(cache)) as database:
            database.execute("UPDATE policy_unknown_tus SET payload=?, checksum=?",
                             (payload, hashlib.sha256(payload.encode()).hexdigest()))
            database.commit()
        second_analyzer = self.analyzer()
        second = self.context(second_analyzer, cache=cache)
        self.assertTrue(second.facts(self.base, "unit.c").complete)
        self.assertEqual(len(second_analyzer.requests), 1)
        self.assertEqual(second.stats.unknown_cache_hits, 0)

    def test_changed_revision_retries_incomplete_analyzer_despite_identical_source_dependencies(self) -> None:
        revision = self.revision({"other.c": "int other(void) { return 2; }\n"})
        analyzer = self.analyzer()
        analyzer.failure = "file_scope_assembly"
        context = self.context(analyzer)
        self.assertFalse(context.facts(self.base, "unit.c").complete)
        analyzer.failure = None
        self.assertTrue(context.facts(revision, "unit.c").complete)
        self.assertEqual(len(analyzer.requests), 2)

    def test_incomplete_cache_drops_partial_function_facts(self) -> None:
        analyzer = self.analyzer()
        command = CompileCommand(directory=self.output, file=self.unit,
                                 arguments=(self.compiler, "-nostdinc", "-c", str(self.unit)))
        partial = analyzer.analyze(command).model_copy(update={"complete": False, "unknowns": ("file_scope_assembly",)})
        self.assertTrue(partial.functions)
        context = self.context(analyzer)
        with patch.object(analyzer, "analyze", return_value=partial) as extract:
            self.assertFalse(context.facts(self.base, "unit.c").complete)
            cached = context.facts(self.base, "unit.c")
            self.assertFalse(cached.complete)
            self.assertEqual(cached.functions, ())
            extract.assert_called_once()

    def test_build_inputs_changed_during_extraction_are_not_certified(self) -> None:
        generated = self.unused_generated

        class MutatingAnalyzer(RecordingAnalyzer):
            def analyze(self, command: CompileCommand, *, overlays: tuple[SourceOverlay, ...] = (),
                        tracked_paths: tuple[Path, ...] = (), function_names: tuple[str, ...] = ()) -> TranslationUnitFacts:
                result = super().analyze(command, overlays=overlays, tracked_paths=tracked_paths,
                                         function_names=function_names)
                generated.write_text("#define OTHER_GENERATED_VALUE 2\n")
                return result

        analyzer = MutatingAnalyzer((self.unit, self.header, self.generated))
        self.assertFalse(self.context(analyzer).facts(self.base, "unit.c").complete)

    def test_wrong_linked_frontend_version_is_incomplete(self) -> None:
        analyzer = self.analyzer()
        analyzer._version = ClangVersion(major=1, compiler="clang version 1.0.0")
        self.assertFalse(self.context(analyzer).facts(self.base, "unit.c").complete)


if __name__ == "__main__":
    unittest.main()
