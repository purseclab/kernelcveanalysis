from hashlib import sha256
import subprocess
import unittest
from unittest.mock import patch
import weakref

from kexploit_utils import Architecture

from kpatch.filter.config_filter import (
    ConfigFilter,
    ConfigValue,
    KbuildDirectory,
    KbuildMakefile,
    KbuildMakefileCache,
    KbuildState,
    KernelConfig,
    SourceAnalysisCache,
)
from kpatch.filter.ifdef_filter import get_active_lines
from kpatch.filter.source_filter import SourceIncludeIndex
from kpatch.diff import Diff, DiffFile, DiffFileType
from kpatch.git import GitRepo


class MemoryGitRepo(GitRepo):
    def __init__(self, commits: dict[str, dict[str, str]]):
        self.commits = commits

    def read_file(self, commit: str, path: str) -> bytes:
        try:
            return self.commits[commit][path].encode()
        except KeyError as error:
            raise FileNotFoundError(f"{commit}:{path}") from error


def make_diff(
    path: str,
    change_type: DiffFileType,
    old_file: str | None = None,
) -> Diff:
    return Diff(
        text="",
        files=[
            DiffFile(
                file=path,
                old_file=old_file,
                old_mode=None,
                new_mode=None,
                change_type=change_type,
                binary=False,
                header_lines=[],
                chunks=[],
            )
        ],
    )


class KernelConfigTests(unittest.TestCase):
    def test_parses_tristates_unset_and_scalar_values(self) -> None:
        config = KernelConfig(
            """
            CONFIG_ENABLED=y
            CONFIG_MODULE=m
            CONFIG_DISABLED=n
            # CONFIG_UNSET is not set
            CONFIG_NUMBER=42
            CONFIG_STRING="value=#fragment=second"
            # ordinary comment
            NOT_A_CONFIG=y
            """
        )

        self.assertEqual(config.get("CONFIG_ENABLED"), ConfigValue.ENABLED)
        self.assertEqual(config.get("CONFIG_MODULE"), ConfigValue.MODULE)
        self.assertEqual(config.get("CONFIG_DISABLED"), ConfigValue.DISABLED)
        self.assertEqual(config.get("CONFIG_UNSET"), ConfigValue.DISABLED)
        self.assertEqual(config.get("CONFIG_NUMBER"), ConfigValue.ENABLED)
        self.assertEqual(config.get("CONFIG_STRING"), ConfigValue.ENABLED)
        self.assertEqual(config.get("CONFIG_UNKNOWN"), ConfigValue.DISABLED)
        self.assertEqual(config.get_raw("CONFIG_DISABLED"), "")
        self.assertEqual(config.get_raw("CONFIG_UNSET"), "")
        self.assertEqual(config.get_raw("CONFIG_NUMBER"), "42")
        self.assertEqual(
            config.get_raw("CONFIG_STRING"), '"value=#fragment=second"'
        )
        self.assertNotIn("CONFIG_UNKNOWN", config.values)
        self.assertNotIn("NOT_A_CONFIG", config.values)

    def test_parses_shared_architecture_type(self) -> None:
        self.assertIs(
            KernelConfig("CONFIG_X86_32=y").architecture,
            Architecture.X86,
        )
        self.assertIs(
            KernelConfig("CONFIG_X86_64=y").architecture,
            Architecture.AMD64,
        )
        self.assertIs(
            KernelConfig("CONFIG_ARM=y").architecture,
            Architecture.ARM,
        )
        self.assertIs(
            KernelConfig("CONFIG_ARM64=y").architecture,
            Architecture.AARCH64,
        )
        self.assertIsNone(KernelConfig("").architecture)

    def test_rejects_multiple_architectures(self) -> None:
        with self.assertRaises(ValueError):
            KernelConfig("CONFIG_X86_64=y\nCONFIG_ARM64=y")


class KbuildMakefileTests(unittest.TestCase):
    def parse(
        self,
        contents: str,
        config: str = "",
        folder: str = "drivers/example",
    ) -> KbuildMakefile:
        return KbuildMakefile(contents, KernelConfig(config), folder)

    def test_direct_objects_directories_and_config_values(self) -> None:
        makefile = self.parse(
            """
            obj-y += built-in.o always/
            obj-m += explicit-module.o
            obj-$(CONFIG_DRIVER) += driver.o driver-dir/
            obj-$(CONFIG_MODULE_DRIVER) += module-driver.o
            obj-$(CONFIG_DISABLED_DRIVER) += disabled.o
            """,
            """
            CONFIG_DRIVER=y
            CONFIG_MODULE_DRIVER=m
            # CONFIG_DISABLED_DRIVER is not set
            """,
        )

        self.assertEqual(
            makefile.get("drivers/example/built-in.c"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/always"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/driver-dir/"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/explicit-module.c"), ConfigValue.MODULE
        )
        self.assertEqual(
            makefile.get("drivers/example/module-driver.c"), ConfigValue.MODULE
        )
        self.assertIsNone(makefile.get("drivers/example/disabled.c"))

    def test_composite_objects_and_conditional_members(self) -> None:
        makefile = self.parse(
            """
            obj-$(CONFIG_EXT2_FS) += ext2.o
            ext2-y := balloc.o dir.o \\
                      inode.o
            ext2-$(CONFIG_EXT2_FS_XATTR) += xattr.o
            ext2-$(CONFIG_UNUSED) += unused.o
            """,
            """
            CONFIG_EXT2_FS=m
            CONFIG_EXT2_FS_XATTR=y
            """,
        )

        self.assertEqual(
            makefile.get("drivers/example/balloc.c"), ConfigValue.MODULE
        )
        self.assertEqual(
            makefile.get("drivers/example/inode.c"), ConfigValue.MODULE
        )
        self.assertEqual(
            makefile.get("drivers/example/xattr.c"), ConfigValue.MODULE
        )
        self.assertIsNone(makefile.get("drivers/example/ext2.c"))
        self.assertIsNone(makefile.get("drivers/example/unused.c"))

    def test_builtin_composite_does_not_include_module_only_members(self) -> None:
        makefile = self.parse(
            """
            obj-y += example.o
            example-y += core.o
            example-m += module-only.o
            """
        )

        self.assertEqual(
            makefile.get("drivers/example/core.c"), ConfigValue.ENABLED
        )
        self.assertIsNone(makefile.get("drivers/example/module-only.c"))

    def test_lib_objects_and_variable_expansion(self) -> None:
        makefile = self.parse(
            """
            objects = first.o
            objects += second.o
            lib-y += $(objects)
            lib-m += selected-as-m.o
            obj-y += assembly.o
            """
        )

        self.assertTrue(makefile.includes("drivers/example/first.c"))
        self.assertTrue(makefile.includes("drivers/example/second.c"))
        self.assertEqual(
            makefile.get("drivers/example/selected-as-m.c"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/assembly.S"), ConfigValue.ENABLED
        )

    def test_config_conditionals_and_else_if(self) -> None:
        makefile = self.parse(
            """
            ifdef CONFIG_FIRST
            obj-y += first.o
            else ifeq ($(CONFIG_SECOND),m)
            obj-m += second.o
            else
            obj-y += fallback.o
            endif

            ifndef CONFIG_MISSING
            obj-y += missing-is-unset.o
            endif
            """,
            "CONFIG_SECOND=m",
        )

        self.assertIsNone(makefile.get("drivers/example/first.c"))
        self.assertEqual(
            makefile.get("drivers/example/second.c"), ConfigValue.MODULE
        )
        self.assertIsNone(makefile.get("drivers/example/fallback.c"))
        self.assertEqual(
            makefile.get("drivers/example/missing-is-unset.c"),
            ConfigValue.ENABLED,
        )

    def test_scalar_config_value_is_available_to_make_conditionals(self) -> None:
        makefile = self.parse(
            """
            ifeq ($(CONFIG_NAME),"value=with=equals")
            obj-y += selected.o
            endif
            """,
            'CONFIG_NAME="value=with=equals"',
        )

        self.assertEqual(
            makefile.get("drivers/example/selected.c"), ConfigValue.ENABLED
        )

    def test_builtin_wins_when_object_has_both_modes(self) -> None:
        makefile = self.parse("obj-y += shared.o\nobj-m += shared.o")

        self.assertEqual(
            makefile.get("drivers/example/shared.c"), ConfigValue.ENABLED
        )

    def test_queries_use_repository_paths(self) -> None:
        makefile = self.parse("obj-y += selected.o")

        self.assertEqual(
            makefile.get("drivers/example/selected.c"), ConfigValue.ENABLED
        )
        self.assertIsNone(makefile.get("selected.c"))

    def test_resolves_subdirectory_goals_to_repository_paths(self) -> None:
        makefile = self.parse("obj-y += child/ child/direct.o")

        self.assertEqual(
            makefile.get("drivers/example/child"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/child/direct.c"), ConfigValue.ENABLED
        )
        self.assertIsNone(makefile.get("child/direct.c"))

    def test_subst_function_can_select_a_builtin_directory(self) -> None:
        makefile = self.parse(
            "obj-$(subst m,y,$(CONFIG_DRIVER)) += host/",
            "CONFIG_DRIVER=m",
        )

        self.assertEqual(
            makefile.get("drivers/example/host"),
            ConfigValue.ENABLED,
        )

    def test_if_function_can_force_a_builtin_object(self) -> None:
        makefile = self.parse(
            "obj-$(if $(CONFIG_DRIVER),y) += hooks.o",
            "CONFIG_DRIVER=m",
        )

        self.assertEqual(
            makefile.get("drivers/example/hooks.c"),
            ConfigValue.ENABLED,
        )

    def test_filter_function_can_select_conditional_components(self) -> None:
        makefile = self.parse(
            """
            obj-y += controller.o
            controller-y := core.o
            ifneq ($(filter y,$(CONFIG_HOST) $(CONFIG_DUAL_ROLE)),)
\tcontroller-y += host.o
            endif
            ifneq ($(filter y,$(CONFIG_GADGET) $(CONFIG_DUAL_ROLE)),)
\tcontroller-y += gadget.o
            endif
            """,
            "CONFIG_DUAL_ROLE=y",
        )

        self.assertEqual(
            makefile.get("drivers/example/host.c"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("drivers/example/gadget.c"), ConfigValue.ENABLED
        )

    def test_explicit_and_pattern_dependencies_resolve_custom_objects(self) -> None:
        folder = "arch/arm64/kvm/hyp/nvhe"
        makefile = KbuildMakefile(
            """
            hyp-obj-y := timer-sr.o ../shared.o
            hyp-obj := $(patsubst %.o,%.nvhe.o,$(hyp-obj-y))
            obj-y := kvm_nvhe.o
            $(obj)/kvm_nvhe.o: $(addprefix $(obj)/,$(hyp-obj)) FORCE
            $(obj)/%.nvhe.o: $(src)/%.c FORCE
            """,
            KernelConfig(""),
            folder,
            variables={"obj": folder, "src": folder},
        )

        self.assertEqual(
            makefile.get(f"{folder}/timer-sr.c"), ConfigValue.ENABLED
        )
        self.assertEqual(
            makefile.get("arch/arm64/kvm/hyp/shared.c"),
            ConfigValue.ENABLED,
        )
        self.assertIsNone(makefile.get(f"{folder}/kvm_nvhe.c"))

    def test_non_build_prerequisites_preserve_implicit_object_source(self) -> None:
        makefile = self.parse(
            """
            obj-y += direct.o
            $(obj)/direct.o: FORCE include/linux/generated.h
            """
        )

        self.assertEqual(
            makefile.get("drivers/example/direct.c"), ConfigValue.ENABLED
        )

    def test_recipe_and_define_bodies_are_not_parsed_as_kbuild_rules(self) -> None:
        makefile = self.parse(
            """
            obj-y += selected.o
            define commands
            obj-y += macro-only.o
            endef
            target:
\tobj-y = recipe-only.o
            """
        )

        self.assertEqual(
            makefile.get("drivers/example/selected.c"), ConfigValue.ENABLED
        )
        self.assertIsNone(makefile.get("drivers/example/macro-only.c"))
        self.assertIsNone(makefile.get("drivers/example/recipe-only.c"))

    def test_root_relative_expansion_is_not_joined_to_current_folder(self) -> None:
        makefile = KbuildMakefile(
            "obj-y += $(srctree)/shared/source.o",
            KernelConfig(""),
            "drivers/example",
            variables={"srctree": ""},
        )

        self.assertEqual(
            makefile.get("shared/source.c"),
            ConfigValue.ENABLED,
        )


class KbuildMakefileCacheTests(unittest.TestCase):
    def parse(
        self,
        cache: KbuildMakefileCache,
        contents: str,
        folder: str = "drivers",
        *,
        variables: dict[str, str] | None = None,
        goals: tuple[tuple[str, ConfigValue], ...] | None = None,
        extra_goals: dict[str, ConfigValue] | None = None,
    ) -> KbuildMakefile:
        return cache.parse(
            contents,
            folder,
            variables=variables or {},
            include_reader=lambda path: (path, None),
            source_path=f"{folder}/Makefile",
            goals=goals,
            extra_goals=extra_goals,
        )

    def test_reuses_pure_parse_across_commits_without_retaining_directory(self) -> None:
        config = KernelConfig("")
        cache = KbuildMakefileCache(config)
        repo = MemoryGitRepo(
            {
                "base": {"drivers/Makefile": "obj-y += selected.o\n"},
                "next": {"drivers/Kbuild": "obj-y += selected.o\n"},
            }
        )
        first = KbuildDirectory(repo, "base", config, "drivers", makefile_cache=cache)
        second = KbuildDirectory(repo, "next", config, "drivers", makefile_cache=cache)

        self.assertIs(first._makefiles[0], second._makefiles[0])
        self.assertEqual(first.source_files, {"drivers/Makefile"})
        self.assertEqual(second.source_files, {"drivers/Kbuild"})
        self.assertIsNone(first._makefiles[0]._include_reader)
        first_reference = weakref.ref(first)
        del first
        self.assertIsNone(first_reference())
        self.assertEqual(len(cache), 1)

    def test_key_preserves_every_parse_input(self) -> None:
        cache = KbuildMakefileCache(KernelConfig(""))
        contents = "obj-y += $(OBJECT)\n"
        variables = {"OBJECT": "first.o"}
        first = self.parse(cache, contents, variables=variables)
        self.assertIs(first, self.parse(cache, contents, variables=variables))

        changed_variables = self.parse(
            cache, contents, variables={"OBJECT": "second.o"}
        )
        self.assertTrue(changed_variables.includes("drivers/second.c"))
        self.assertFalse(changed_variables.includes("drivers/first.c"))
        changed_folder = self.parse(cache, contents, "other", variables=variables)
        self.assertTrue(changed_folder.includes("other/first.c"))
        changed_contents = self.parse(cache, "obj-y += other.o\n", variables=variables)
        self.assertTrue(changed_contents.includes("drivers/other.c"))
        changed_goals = self.parse(cache, contents, variables=variables, goals=())
        self.assertFalse(changed_goals.includes("drivers/first.c"))
        extra = self.parse(
            cache,
            contents,
            variables=variables,
            extra_goals={"extra.o": ConfigValue.MODULE},
        )
        self.assertEqual(extra.get("drivers/extra.c"), ConfigValue.MODULE)
        self.assertIsNone(first.get("drivers/extra.c"))
        self.assertEqual(len(cache), 6)

    def test_lru_is_bounded_and_preserves_recently_used_entries(self) -> None:
        cache = KbuildMakefileCache(KernelConfig(""), max_entries=2)
        first = self.parse(cache, "obj-y += first.o\n")
        second = self.parse(cache, "obj-y += second.o\n")
        self.assertIs(first, self.parse(cache, "obj-y += first.o\n"))
        self.parse(cache, "obj-y += third.o\n")

        self.assertEqual(len(cache), 2)
        self.assertIs(first, self.parse(cache, "obj-y += first.o\n"))
        self.assertIsNot(second, self.parse(cache, "obj-y += second.o\n"))
        self.assertEqual(len(cache), 2)
        with self.assertRaises(ValueError):
            KbuildMakefileCache(KernelConfig(""), max_entries=0)

    def test_fragment_dependent_parses_are_never_cached_even_when_missing(self) -> None:
        config = KernelConfig("")
        cache = KbuildMakefileCache(config)
        files = {"drivers/Makefile": "-include $(src)/objects.mk\n"}
        repo = MemoryGitRepo(
            {
                "missing": files,
                "before": {**files, "drivers/objects.mk": "obj-y += before.o\n"},
                "after": {**files, "drivers/objects.mk": "obj-y += after.o\n"},
            }
        )
        missing = KbuildDirectory(
            repo, "missing", config, "drivers", makefile_cache=cache
        )
        before = KbuildDirectory(
            repo, "before", config, "drivers", makefile_cache=cache
        )
        after = KbuildDirectory(repo, "after", config, "drivers", makefile_cache=cache)

        self.assertIsNot(missing._makefiles[0], before._makefiles[0])
        self.assertIsNot(before._makefiles[0], after._makefiles[0])
        self.assertEqual(missing._makefiles[0].included_files, {"drivers/objects.mk"})
        self.assertTrue(before.includes("drivers/before.c"))
        self.assertFalse(after.includes("drivers/before.c"))
        self.assertTrue(after.includes("drivers/after.c"))
        self.assertEqual(len(cache), 0)

    def test_cache_is_bound_to_its_config(self) -> None:
        enabled = KernelConfig("CONFIG_FEATURE=y")
        disabled = KernelConfig("")
        enabled_cache = KbuildMakefileCache(enabled)
        contents = "obj-$(CONFIG_FEATURE) += feature.o\n"
        self.assertTrue(
            self.parse(enabled_cache, contents).includes("drivers/feature.c")
        )
        self.assertFalse(
            self.parse(KbuildMakefileCache(disabled), contents).includes(
                "drivers/feature.c"
            )
        )
        repo = MemoryGitRepo({"base": {"drivers/Makefile": contents}})
        with self.assertRaisesRegex(ValueError, "different kernel config"):
            KbuildDirectory(
                repo, "base", disabled, "drivers", makefile_cache=enabled_cache
            )
        with self.assertRaisesRegex(ValueError, "different kernel config"):
            ConfigFilter(repo, disabled, "base", makefile_cache=enabled_cache)

    def test_branch_copy_shares_cache_and_reuses_invalidated_pure_parse(self) -> None:
        files = {"drivers/Makefile": "obj-y += selected.o\n"}
        original = ConfigFilter(
            MemoryGitRepo({"base": files, "next": files}), KernelConfig(""), "base"
        )
        self.assertTrue(original.file_included("drivers/selected.c"))
        copied = ConfigFilter.copy(original)
        self.assertIs(copied._makefile_cache, original._makefile_cache)
        copied.update_filter_state(
            make_diff("drivers/Makefile", DiffFileType.DEFAULT), "next"
        )

        with patch.object(
            KbuildMakefile, "_parse", side_effect=AssertionError("reparsed")
        ):
            self.assertTrue(copied.file_included("drivers/selected.c"))
        self.assertIsNot(
            copied.kbuild_cache["drivers"].rules, original.kbuild_cache["drivers"].rules
        )
        self.assertIs(
            copied.kbuild_cache["drivers"].rules._makefiles[0],
            original.kbuild_cache["drivers"].rules._makefiles[0],
        )


class SourceAnalysisCacheTests(unittest.TestCase):
    def test_reuses_analysis_across_roots_without_retaining_states(self) -> None:
        source = "drivers/wrapper.c"
        target = "drivers/local.h"
        files = {source: '#include "local.h"\n'}
        repo = MemoryGitRepo({"first": files, "second": files})
        config = KernelConfig("")
        index = SourceIncludeIndex("", (source, target))
        cache = SourceAnalysisCache(config, index)

        with (
            patch(
                "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
            ) as evaluate,
            patch.object(
                index, "target_from_line", wraps=index.target_from_line
            ) as resolve,
            patch.object(repo, "read_file", wraps=repo.read_file) as read_file,
        ):
            first = KbuildState(
                repo, config, "first", index, source_analysis_cache=cache
            )
            second = KbuildState(
                repo, config, "second", index, source_analysis_cache=cache
            )
            result = first._active_source_includes(source, ConfigValue.ENABLED)
            reused = second._active_source_includes(source, ConfigValue.ENABLED)
            self.assertIs(result, reused)
            self.assertEqual(result, frozenset((target,)))
            self.assertEqual(evaluate.call_count, 1)
            self.assertEqual(resolve.call_count, 1)
            self.assertEqual(read_file.call_count, 2)

        self.assertEqual(len(cache), 1)
        reference = weakref.ref(first)
        del first
        self.assertIsNone(reference())

    def test_source_path_and_build_mode_are_separate_inputs(self) -> None:
        contents = (
            b"#ifdef MODULE\n"
            b'#include "module.h"\n'
            b"#else\n"
            b'#include "builtin.h"\n'
            b"#endif\n"
        )
        index = SourceIncludeIndex(
            "",
            (
                "first/wrapper.c",
                "first/module.h",
                "first/builtin.h",
                "second/wrapper.c",
                "second/builtin.h",
            ),
        )
        cache = SourceAnalysisCache(KernelConfig(""), index)
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            builtin = cache.analyze("first/wrapper.c", ConfigValue.ENABLED, contents)
            module = cache.analyze("first/wrapper.c", ConfigValue.MODULE, contents)
            other = cache.analyze("second/wrapper.c", ConfigValue.ENABLED, contents)
            self.assertIs(
                builtin, cache.analyze("first/wrapper.c", ConfigValue.ENABLED, contents)
            )

        self.assertEqual(builtin, frozenset(("first/builtin.h",)))
        self.assertEqual(module, frozenset(("first/module.h",)))
        self.assertEqual(other, frozenset(("second/builtin.h",)))
        self.assertEqual(evaluate.call_count, 3)
        self.assertEqual(len(cache), 3)

    def test_empty_analyses_are_reused(self) -> None:
        cache = SourceAnalysisCache(
            KernelConfig(""), SourceIncludeIndex("", ("source.c", "target.h"))
        )
        contents = b'#ifdef CONFIG_DISABLED\n#include "target.h"\n#endif\n'
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            first = cache.analyze("source.c", ConfigValue.ENABLED, contents)
            second = cache.analyze("source.c", ConfigValue.ENABLED, contents)

        self.assertEqual(first, frozenset())
        self.assertIs(first, second)
        self.assertEqual(evaluate.call_count, 1)
        self.assertEqual(len(cache), 1)

    def test_key_hashes_raw_bytes_before_replacement_decoding(self) -> None:
        cache = SourceAnalysisCache(
            KernelConfig(""), SourceIncludeIndex("", ("source.c", "target.h"))
        )
        first = b'#include "target.h"\n// invalid: \xff\n'
        second = b'#include "target.h"\n// invalid: \xfe\n'
        self.assertEqual(
            first.decode("utf-8", errors="replace"),
            second.decode("utf-8", errors="replace"),
        )
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            for contents in (first, second, first, second):
                self.assertEqual(
                    cache.analyze("source.c", ConfigValue.ENABLED, contents),
                    frozenset(("target.h",)),
                )

        self.assertEqual(evaluate.call_count, 2)
        self.assertEqual(len(cache), 2)
        self.assertEqual(
            {key.contents_sha256 for key in cache._entries},
            {sha256(first).digest(), sha256(second).digest()},
        )

    def test_cache_is_bound_to_exact_config(self) -> None:
        source = "drivers/wrapper.c"
        target = "drivers/feature.h"
        contents = b'#ifdef CONFIG_FEATURE\n#include "feature.h"\n#endif\n'
        enabled = KernelConfig("CONFIG_FEATURE=y")
        disabled = KernelConfig("")
        index = SourceIncludeIndex("", (source, target))
        cache = SourceAnalysisCache(enabled, index)
        self.assertEqual(
            cache.analyze(source, ConfigValue.ENABLED, contents), frozenset((target,))
        )
        self.assertEqual(
            SourceAnalysisCache(disabled, index).analyze(
                source, ConfigValue.ENABLED, contents
            ),
            frozenset(),
        )
        repo = MemoryGitRepo({"base": {source: contents.decode()}})
        for config in (disabled, KernelConfig("CONFIG_FEATURE=y")):
            with self.assertRaisesRegex(ValueError, "different kernel config"):
                KbuildState(
                    repo, config, "base", index, source_analysis_cache=cache
                )

    def test_cache_is_bound_to_exact_source_index(self) -> None:
        source = "drivers/wrapper.c"
        contents = b'#include "local.h"\n'
        config = KernelConfig("")
        paths = (source, "drivers/local.h", "include/local.h")
        index = SourceIncludeIndex("", paths)
        other = SourceIncludeIndex("", (source, "include/local.h"))
        cache = SourceAnalysisCache(config, index)
        self.assertEqual(
            cache.analyze(source, ConfigValue.ENABLED, contents),
            frozenset(("drivers/local.h",)),
        )
        self.assertEqual(
            SourceAnalysisCache(config, other).analyze(
                source, ConfigValue.ENABLED, contents
            ),
            frozenset(("include/local.h",)),
        )
        repo = MemoryGitRepo({"base": {source: contents.decode()}})
        for different_index in (other, SourceIncludeIndex("", paths), None):
            with self.assertRaisesRegex(ValueError, "different source include index"):
                KbuildState(
                    repo,
                    config,
                    "base",
                    different_index,
                    source_analysis_cache=cache,
                )

    def test_lru_is_bounded_and_preserves_recent_entries(self) -> None:
        index = SourceIncludeIndex("", ("source.c", "first.h", "second.h", "third.h"))
        cache = SourceAnalysisCache(KernelConfig(""), index, max_entries=2)
        first_contents = b'#include "first.h"\n'
        second_contents = b'#include "second.h"\n'
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            first = cache.analyze("source.c", ConfigValue.ENABLED, first_contents)
            second = cache.analyze("source.c", ConfigValue.ENABLED, second_contents)
            self.assertIs(
                first, cache.analyze("source.c", ConfigValue.ENABLED, first_contents)
            )
            cache.analyze("source.c", ConfigValue.ENABLED, b'#include "third.h"\n')
            self.assertEqual(len(cache), 2)
            self.assertIs(
                first, cache.analyze("source.c", ConfigValue.ENABLED, first_contents)
            )
            self.assertIsNot(
                second, cache.analyze("source.c", ConfigValue.ENABLED, second_contents)
            )

        self.assertEqual(evaluate.call_count, 4)
        self.assertEqual(len(cache), 2)
        for max_entries in (0, -1):
            with self.assertRaises(ValueError):
                SourceAnalysisCache(KernelConfig(""), index, max_entries=max_entries)

    def test_copy_shares_analysis_but_invalidates_only_local_state(self) -> None:
        source = "drivers/wrapper.c"
        files = {
            "drivers/Makefile": "obj-y += wrapper.o\n",
            source: '#include "before.h"\n',
            "drivers/before.h": "",
            "drivers/after.h": "",
        }
        next_files = {**files, source: '#include "after.h"\n'}
        repo = MemoryGitRepo({"base": files, "next": next_files, "again": files})
        index = SourceIncludeIndex("", files)
        for contents in (files[source], next_files[source]):
            index.add_line(source, contents)
        original = KbuildState(repo, KernelConfig(""), "base", index)

        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            self.assertTrue(original.file_included("drivers/before.h"))
            self.assertFalse(original.file_included("drivers/after.h"))
            before = original._active_includes_cache[(source, ConfigValue.ENABLED)]
            copied = KbuildState.copy(original)
            self.assertIs(
                copied._source_analysis_cache, original._source_analysis_cache
            )
            self.assertIsNot(
                copied._active_includes_cache, original._active_includes_cache
            )
            self.assertIsNot(
                copied._include_value_cache, original._include_value_cache
            )
            copied.update_filter_state(make_diff(source, DiffFileType.DEFAULT), "next")
            self.assertFalse(copied.file_included("drivers/before.h"))
            self.assertTrue(copied.file_included("drivers/after.h"))
            self.assertTrue(original.file_included("drivers/before.h"))
            self.assertFalse(original.file_included("drivers/after.h"))
            copied.update_filter_state(make_diff(source, DiffFileType.DEFAULT), "again")
            self.assertTrue(copied.file_included("drivers/before.h"))
            self.assertFalse(copied.file_included("drivers/after.h"))
            self.assertIs(
                copied._active_includes_cache[(source, ConfigValue.ENABLED)], before
            )

        self.assertEqual(evaluate.call_count, 2)
        assert original._source_analysis_cache is not None
        self.assertEqual(len(original._source_analysis_cache), 2)

    def test_missing_reads_are_cached_only_locally(self) -> None:
        source = "drivers/wrapper.c"
        target = "drivers/local.h"
        for error in (
            FileNotFoundError("missing"),
            subprocess.CalledProcessError(128, "git"),
        ):
            with self.subTest(error=type(error).__name__):
                repo = MemoryGitRepo({"base": {source: '#include "local.h"\n'}})
                config = KernelConfig("")
                index = SourceIncludeIndex("", (source, target))
                cache = SourceAnalysisCache(config, index)
                with patch.object(repo, "read_file", side_effect=error) as read_file:
                    missing = KbuildState(
                        repo, config, "base", index, source_analysis_cache=cache
                    )
                    for _ in range(2):
                        self.assertEqual(
                            missing._active_source_includes(source, ConfigValue.ENABLED),
                            frozenset(),
                        )
                    self.assertEqual(read_file.call_count, 1)
                self.assertEqual(len(cache), 0)
                present = KbuildState(
                    repo, config, "base", index, source_analysis_cache=cache
                )
                self.assertEqual(
                    present._active_source_includes(source, ConfigValue.ENABLED),
                    frozenset((target,)),
                )
                self.assertEqual(len(cache), 1)

    def test_unexpected_errors_propagate_without_caching(self) -> None:
        source = "drivers/wrapper.c"
        repo = MemoryGitRepo({"base": {source: '#include "local.h"\n'}})
        index = SourceIncludeIndex("", (source, "drivers/local.h"))
        state = KbuildState(repo, KernelConfig(""), "base", index)
        with patch.object(state, "_read_file", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                state._active_source_includes(source, ConfigValue.ENABLED)
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", side_effect=ValueError("bad")
        ):
            with self.assertRaises(ValueError):
                state._active_source_includes(source, ConfigValue.ENABLED)

        self.assertEqual(state._active_includes_cache, {})
        assert state._source_analysis_cache is not None
        self.assertEqual(len(state._source_analysis_cache), 0)
        self.assertEqual(
            state._active_source_includes(source, ConfigValue.ENABLED),
            frozenset(("drivers/local.h",)),
        )

    def test_unknown_conditions_remain_conservative(self) -> None:
        index = SourceIncludeIndex("", ("source.c", "first.h", "second.h"))
        cache = SourceAnalysisCache(KernelConfig(""), index)
        self.assertEqual(
            cache.analyze(
                "source.c",
                ConfigValue.ENABLED,
                b'#if UNKNOWN_GUARD\n#include "first.h"\n'
                b'#else\n#include "second.h"\n#endif\n',
            ),
            frozenset(("first.h", "second.h")),
        )

    def test_repeated_branches_evaluate_once_per_content(self) -> None:
        source = "drivers/wrapper.c"
        target = "drivers/local.h"
        branch_count = 32
        contents = '#ifdef CONFIG_FEATURE\n#include "local.h"\n#endif\n'
        commits = {
            f"branch-{number}": {source: contents} for number in range(branch_count)
        }
        repo = MemoryGitRepo(commits)
        config = KernelConfig("CONFIG_FEATURE=y")
        index = SourceIncludeIndex("", (source, target))
        cache = SourceAnalysisCache(config, index)
        with patch(
            "kpatch.filter.ifdef_filter.get_active_lines", wraps=get_active_lines
        ) as evaluate:
            for commit in commits:
                state = KbuildState(
                    repo, config, commit, index, source_analysis_cache=cache
                )
                self.assertEqual(
                    state._active_source_includes(source, ConfigValue.ENABLED),
                    frozenset((target,)),
                )
            self.assertEqual(evaluate.call_count, 1)

            evaluate.reset_mock()
            for commit in commits:
                state = KbuildState(repo, config, commit, index)
                state._active_source_includes(source, ConfigValue.ENABLED)
            self.assertEqual(evaluate.call_count, branch_count)


class ConfigFilterTests(unittest.TestCase):
    def make_filter(
        self,
        commits: dict[str, dict[str, str]],
        base_commit: str = "base",
    ) -> ConfigFilter:
        return ConfigFilter(
            MemoryGitRepo(commits),
            KernelConfig(""),
            base_commit,
        )

    def test_follows_parent_and_child_makefiles(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                }
            }
        )

        self.assertTrue(filter.file_included("drivers/example/selected.c"))
        self.assertFalse(filter.file_included("drivers/example/excluded.c"))

    def test_relative_makefile_include_is_resolved_from_its_folder(self) -> None:
        repo = MemoryGitRepo(
            {
                "base": {
                    "tools/testing/Makefile": (
                        "top_srcdir := ../..\n"
                        "include $(top_srcdir)/scripts/objects.mk\n"
                        "obj-y += direct.o\n"
                    ),
                    "scripts/objects.mk": "obj-y += included.o\n",
                }
            }
        )

        rules = KbuildDirectory(
            repo,
            "base",
            KernelConfig(""),
            "tools/testing",
        )

        self.assertTrue(rules.includes("tools/testing/direct.c"))
        self.assertTrue(rules.includes("tools/testing/included.c"))

    def test_module_directory_mode_is_inherited_by_builtin_child_objects(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-m += example/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                }
            }
        )

        self.assertEqual(
            filter.get("drivers/example/selected.c"), ConfigValue.MODULE
        )

    def test_root_kbuild_selects_only_configured_architecture(self) -> None:
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": {
                        "Kbuild": "obj-y += arch/$(SRCARCH)/ drivers/\n",
                        "Makefile": "obj-y += arch/x86/\n",
                        "arch/arm64/Kbuild": "obj-y += kernel/\n",
                        "arch/arm64/kernel/Makefile": "obj-y += selected.o\n",
                        "arch/x86/Kbuild": "obj-y += kernel/\n",
                        "arch/x86/kernel/Makefile": "obj-y += excluded.o\n",
                        "drivers/Makefile": "obj-y += common.o\n",
                    }
                }
            ),
            KernelConfig("CONFIG_ARM64=y"),
            "base",
        )

        self.assertTrue(filter.file_included("arch/arm64/kernel/selected.c"))
        self.assertFalse(filter.file_included("arch/x86/kernel/excluded.c"))
        self.assertTrue(filter.file_included("drivers/common.c"))

    def test_architecture_makefile_contributes_global_directories(self) -> None:
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": {
                        "Kbuild": "obj-y += arch/$(SRCARCH)/\n",
                        "arch/arm64/Kbuild": "obj-y += kernel/\n",
                        "arch/arm64/Makefile": (
                            "libs-y := arch/arm64/lib/ $(libs-y)\n"
                        ),
                        "arch/arm64/lib/Makefile": "lib-y += insn.o\n",
                    }
                }
            ),
            KernelConfig("CONFIG_ARM64=y"),
            "base",
        )

        self.assertTrue(filter.file_included("arch/arm64/lib/insn.c"))

    def test_root_global_lists_retain_generic_library(self) -> None:
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": {
                        "Kbuild": "obj-y += arch/$(SRCARCH)/ $(ARCH_LIB)\n",
                        "Makefile": "libs-y := lib/\n",
                        "arch/arm64/Kbuild": "obj-y += kernel/\n",
                        "arch/arm64/Makefile": (
                            "libs-y := arch/arm64/lib/ $(libs-y)\n"
                        ),
                        "lib/Makefile": "lib-y += generic.o\n",
                    }
                }
            ),
            KernelConfig("CONFIG_ARM64=y"),
            "base",
        )

        self.assertTrue(filter.file_included("lib/generic.c"))

    def test_source_and_header_includes_inherit_built_source_mode(self) -> None:
        repo = MemoryGitRepo(
            {
                "base": {
                    "drivers/Makefile": "obj-m += wrapper.o\n",
                    "drivers/wrapper.c": (
                        '#include "implementation.c"\n'
                        '#include "local.h"\n'
                    ),
                    "drivers/local.h": "#include <linux/shared.h>\n",
                    "drivers/implementation.c": "int implementation;\n",
                    "include/linux/shared.h": "struct shared;\n",
                }
            }
        )
        index = SourceIncludeIndex(
            "arm64",
            (
                "drivers/wrapper.c",
                "drivers/implementation.c",
                "drivers/local.h",
                "include/linux/shared.h",
            ),
        )
        index.add_line("drivers/wrapper.c", '#include "implementation.c"')
        index.add_line("drivers/wrapper.c", '#include "local.h"')
        index.add_line("drivers/local.h", "#include <linux/shared.h>")
        filter = ConfigFilter(repo, KernelConfig("CONFIG_ARM64=y"), "base", index)

        self.assertEqual(
            filter.get("drivers/implementation.c"), ConfigValue.MODULE
        )
        self.assertEqual(filter.get("drivers/local.h"), ConfigValue.MODULE)
        self.assertEqual(
            filter.get("include/linux/shared.h"), ConfigValue.MODULE
        )
        self.assertTrue(filter.file_included("include/linux/shared.h"))

    def test_parent_generated_target_enables_child_sources(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": (
                        "obj-y += wrapper.o\n"
                        "$(obj)/wrapper.o: $(obj)/child/image.so\n"
                    ),
                    "drivers/child/Makefile": (
                        "objects := code.o\n"
                        "objects := $(addprefix $(obj)/,$(objects))\n"
                        "$(obj)/image.so: $(objects) $(obj)/image.lds\n"
                        "$(objects): %.o: %.c FORCE\n"
                    ),
                    "drivers/child/code.c": "int code;\n",
                    "drivers/child/image.lds.S": "SECTIONS {}\n",
                }
            }
        )

        self.assertTrue(filter.file_included("drivers/child/code.c"))
        self.assertTrue(filter.file_included("drivers/child/image.lds.S"))

    def test_generated_goal_crosses_intermediate_directory_without_makefile(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": (
                        "obj-y += wrapper.o\n"
                        "$(obj)/wrapper.o: "
                        "$(obj)/intermediate/child/image.so\n"
                    ),
                    "drivers/intermediate/child/Makefile": (
                        "$(obj)/image.so: $(obj)/code.o\n"
                    ),
                }
            }
        )

        self.assertEqual(
            filter.get("drivers/intermediate/child/code.c"),
            ConfigValue.ENABLED,
        )

    def test_inactive_source_include_does_not_enable_file(self) -> None:
        repo = MemoryGitRepo(
            {
                "base": {
                    "drivers/Makefile": "obj-y += wrapper.o\n",
                    "drivers/wrapper.c": (
                        "#ifdef CONFIG_DISABLED\n"
                        '#include "hidden.c"\n'
                        "#endif\n"
                    ),
                    "drivers/hidden.c": "int hidden;\n",
                }
            }
        )
        index = SourceIncludeIndex(
            "arm64", ("drivers/wrapper.c", "drivers/hidden.c")
        )
        index.add_line("drivers/wrapper.c", '#include "hidden.c"')
        filter = ConfigFilter(repo, KernelConfig("CONFIG_ARM64=y"), "base", index)

        self.assertFalse(filter.file_included("drivers/hidden.c"))

    def test_source_change_invalidates_only_dependent_include_results(self) -> None:
        repo = MemoryGitRepo(
            {
                "base": {
                    "drivers/Makefile": "obj-y += wrapper.o\n",
                    "drivers/wrapper.c": '#include "before.c"\n',
                    "drivers/before.c": "int before;\n",
                    "drivers/after.c": "int after;\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += wrapper.o\n",
                    "drivers/wrapper.c": '#include "after.c"\n',
                    "drivers/before.c": "int before;\n",
                    "drivers/after.c": "int after;\n",
                },
            }
        )
        index = SourceIncludeIndex(
            "arm64",
            ("drivers/wrapper.c", "drivers/before.c", "drivers/after.c"),
        )
        index.add_line("drivers/wrapper.c", '#include "before.c"')
        index.add_line("drivers/wrapper.c", '#include "after.c"')
        filter = ConfigFilter(repo, KernelConfig("CONFIG_ARM64=y"), "base", index)
        self.assertTrue(filter.file_included("drivers/before.c"))
        self.assertFalse(filter.file_included("drivers/after.c"))

        filter.update_filter_state(
            make_diff("drivers/wrapper.c", DiffFileType.DEFAULT),
            "next",
        )

        self.assertFalse(filter.file_included("drivers/before.c"))
        self.assertTrue(filter.file_included("drivers/after.c"))

    def test_source_index_reports_transitive_dependent_targets(self) -> None:
        index = SourceIncludeIndex(
            "arm64",
            ("wrapper.c", "middle.h", "target.h"),
        )
        index.add_line("wrapper.c", '#include "middle.h"')
        index.add_line("middle.h", '#include "target.h"')

        self.assertEqual(
            index.dependent_targets(("wrapper.c",)),
            frozenset(("middle.h", "target.h")),
        )

    def test_kbuild_include_contributes_to_composite_object(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": (
                        "obj-y += combined.o\n"
                        "combined-y += local.o\n"
                        "include $(src)/objects.mk\n"
                    ),
                    "drivers/example/objects.mk": (
                        "combined-y += included.o\n"
                    ),
                }
            }
        )

        self.assertTrue(filter.file_included("drivers/example/local.c"))
        self.assertTrue(filter.file_included("drivers/example/included.c"))

    def test_architecture_include_can_own_files_in_another_directory(self) -> None:
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": {
                        "Kbuild": "obj-y += arch/$(SRCARCH)/ virt/\n",
                        "arch/arm64/Kbuild": "obj-$(CONFIG_KVM) += kvm/\n",
                        "arch/arm64/kvm/Makefile": (
                            "include $(srctree)/virt/kvm/Makefile.kvm\n"
                            "obj-$(CONFIG_KVM) += kvm.o\n"
                        ),
                        "virt/Makefile": "obj-y += lib/\n",
                        "virt/kvm/Makefile.kvm": (
                            "KVM ?= ../../../virt/kvm\n"
                            "kvm-y := $(KVM)/kvm_main.o $(KVM)/eventfd.o\n"
                        ),
                    }
                }
            ),
            KernelConfig("CONFIG_ARM64=y\nCONFIG_KVM=y"),
            "base",
        )

        self.assertTrue(filter.file_included("virt/kvm/eventfd.c"))

    def test_copy_rebuilds_cache_tree_and_shares_makefiles(self) -> None:
        original = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                }
            }
        )
        self.assertTrue(original.file_included("drivers/example/selected.c"))
        original.delegated.add("drivers/delegated")

        copied = ConfigFilter.copy(original)

        original_parent = original.kbuild_cache["drivers"]
        original_child = original.kbuild_cache["drivers/example"]
        copied_parent = copied.kbuild_cache["drivers"]
        copied_child = copied.kbuild_cache["drivers/example"]

        self.assertIsNot(copied_parent, original_parent)
        self.assertIsNot(copied_child, original_child)
        self.assertIs(copied_parent.rules, original_parent.rules)
        self.assertIs(copied_child.rules, original_child.rules)
        self.assertIs(copied_child.parent, copied_parent)
        self.assertIs(copied_parent.children["drivers/example"], copied_child)
        self.assertIsNot(copied.delegated, original.delegated)
        self.assertEqual(copied.delegated, original.delegated)

        copied.repo.commits["next"] = {
            "drivers/Makefile": "obj-y += example/\n",
            "drivers/example/Makefile": "obj-y += replacement.o\n",
        }
        copied.update_filter_state(
            make_diff("drivers/example/Makefile", DiffFileType.DEFAULT),
            "next",
        )
        copied.delegated.add("drivers/copied-only")

        self.assertTrue(original.file_included("drivers/example/selected.c"))
        self.assertFalse(original.file_included("drivers/example/replacement.c"))
        self.assertFalse(copied.file_included("drivers/example/selected.c"))
        self.assertTrue(copied.file_included("drivers/example/replacement.c"))
        self.assertNotIn("drivers/copied-only", original.delegated)

    def test_update_to_included_fragment_invalidates_cached_rules(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": (
                        "obj-y += combined.o\n"
                        "include $(src)/objects.mk\n"
                    ),
                    "drivers/example/objects.mk": "combined-y += before.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": (
                        "obj-y += combined.o\n"
                        "include $(src)/objects.mk\n"
                    ),
                    "drivers/example/objects.mk": "combined-y += after.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/before.c"))

        filter.update_filter_state(
            make_diff("drivers/example/objects.mk", DiffFileType.DEFAULT),
            "next",
        )

        self.assertFalse(filter.file_included("drivers/example/before.c"))
        self.assertTrue(filter.file_included("drivers/example/after.c"))

    def test_updates_cached_makefile_contents(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += before.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += after.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/before.c"))

        filter.update_filter_state(
            make_diff("drivers/example/Makefile", DiffFileType.DEFAULT),
            "next",
        )

        self.assertFalse(filter.file_included("drivers/example/before.c"))
        self.assertTrue(filter.file_included("drivers/example/after.c"))

    def test_deleted_kbuild_falls_back_to_makefile(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": "obj-y += preferred.o\n",
                    "drivers/example/Makefile": "obj-y += fallback.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += fallback.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/preferred.c"))

        filter.update_filter_state(
            make_diff("drivers/example/Kbuild", DiffFileType.DELETE),
            "next",
        )

        self.assertFalse(filter.file_included("drivers/example/preferred.c"))
        self.assertTrue(filter.file_included("drivers/example/fallback.c"))

    def test_new_kbuild_replaces_cached_makefile(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += fallback.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": "obj-y += preferred.o\n",
                    "drivers/example/Makefile": "obj-y += fallback.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/fallback.c"))

        filter.update_filter_state(
            make_diff("drivers/example/Kbuild", DiffFileType.NEW),
            "next",
        )

        self.assertTrue(filter.file_included("drivers/example/preferred.c"))
        self.assertFalse(filter.file_included("drivers/example/fallback.c"))

    def test_new_makefile_keeps_parent_owned_direct_object(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": (
                        "obj-y += example/ example/direct.o\n"
                    ),
                },
                "next": {
                    "drivers/Makefile": (
                        "obj-y += example/ example/direct.o\n"
                    ),
                    "drivers/example/Makefile": "obj-y += local.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/direct.c"))

        filter.update_filter_state(
            make_diff("drivers/example/Makefile", DiffFileType.NEW),
            "next",
        )

        self.assertTrue(filter.file_included("drivers/example/direct.c"))
        self.assertTrue(filter.file_included("drivers/example/local.c"))

    def test_parent_update_disables_cached_child(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += other/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/selected.c"))

        filter.update_filter_state(
            make_diff("drivers/Makefile", DiffFileType.DEFAULT),
            "next",
        )

        self.assertFalse(filter.file_included("drivers/example/selected.c"))

    def test_makefile_renamed_to_kbuild_keeps_cached_directory(self) -> None:
        filter = self.make_filter(
            {
                "base": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Makefile": "obj-y += selected.o\n",
                },
                "next": {
                    "drivers/Makefile": "obj-y += example/\n",
                    "drivers/example/Kbuild": "obj-y += selected.o\n",
                },
            }
        )
        self.assertTrue(filter.file_included("drivers/example/selected.c"))

        filter.update_filter_state(
            make_diff(
                "drivers/example/Kbuild",
                DiffFileType.RENAME,
                old_file="drivers/example/Makefile",
            ),
            "next",
        )

        self.assertTrue(filter.file_included("drivers/example/selected.c"))

    def test_shared_fragment_invalidates_all_owners_only(self) -> None:
        files = {
            "drivers/Makefile": "obj-y += first/ second/ unrelated/\n",
            "drivers/first/Makefile": "include scripts/objects.mk\n",
            "drivers/second/Makefile": "include scripts/objects.mk\n",
            "drivers/unrelated/Makefile": "obj-y += selected.o\n",
            "scripts/objects.mk": "obj-y += before.o\n",
        }
        filter = self.make_filter(
            {
                "base": files,
                "next": {**files, "scripts/objects.mk": "obj-y += after.o\n"},
            }
        )
        for folder in ("first", "second"):
            self.assertTrue(filter.file_included(f"drivers/{folder}/before.c"))
        self.assertTrue(filter.file_included("drivers/unrelated/selected.c"))
        unrelated = filter.kbuild_cache["drivers/unrelated"]

        filter.update_filter_state(
            make_diff("scripts/objects.mk", DiffFileType.DEFAULT), "next"
        )

        for folder in ("first", "second"):
            self.assertFalse(filter.file_included(f"drivers/{folder}/before.c"))
            self.assertTrue(filter.file_included(f"drivers/{folder}/after.c"))
        self.assertIs(filter.kbuild_cache["drivers/unrelated"], unrelated)

    def test_removed_fragment_dependency_keeps_former_owner_cached(self) -> None:
        files = {
            "drivers/Makefile": "obj-y += example/\n",
            "drivers/example/Makefile": "include scripts/objects.mk\n",
            "scripts/objects.mk": "obj-y += before.o\n",
        }
        next_files = {**files, "drivers/example/Makefile": "obj-y += local.o\n"}
        filter = self.make_filter(
            {
                "base": files,
                "next": next_files,
                "last": {**next_files, "scripts/objects.mk": "obj-y += after.o\n"},
            }
        )
        self.assertTrue(filter.file_included("drivers/example/before.c"))
        filter.update_filter_state(
            make_diff("drivers/example/Makefile", DiffFileType.DEFAULT), "next"
        )
        self.assertTrue(filter.file_included("drivers/example/local.c"))
        entry = filter.kbuild_cache["drivers/example"]

        filter.update_filter_state(
            make_diff("scripts/objects.mk", DiffFileType.DEFAULT), "last"
        )

        self.assertIs(filter.kbuild_cache["drivers/example"], entry)
        self.assertFalse(filter.file_included("drivers/example/after.c"))

    def test_new_optional_fragment_invalidates_its_cached_owner(self) -> None:
        files = {
            "drivers/Makefile": "obj-y += example/\n",
            "drivers/example/Makefile": "-include $(src)/objects.mk\n",
        }
        filter = self.make_filter(
            {
                "base": files,
                "next": {
                    **files,
                    "drivers/example/objects.mk": "obj-y += selected.o\n",
                },
            }
        )
        self.assertFalse(filter.file_included("drivers/example/selected.c"))

        filter.update_filter_state(
            make_diff("drivers/example/objects.mk", DiffFileType.NEW), "next"
        )

        self.assertTrue(filter.file_included("drivers/example/selected.c"))

    def make_cross_directory_filter(self) -> ConfigFilter:
        files = {
            "Kbuild": "obj-y += owners/\n",
            "owners/Makefile": "obj-y += builtin/ unrelated/\nobj-m += module/\n",
            "owners/builtin/Makefile": (
                "obj-y += local.o ../../shared/common.o "
                "../../shared/direct.c ../../shared/image.lds\n"
            ),
            "owners/module/Makefile": "obj-y += local.o ../../shared/common.o\n",
            "owners/unrelated/Makefile": "obj-y += local.o\n",
            "owners/disabled/Makefile": "obj-y += ../../shared/disabled.o\n",
        }
        filter = self.make_filter(
            {
                "base": files,
                "next": {
                    **files,
                    "owners/builtin/Makefile": "obj-y += local.o\n",
                },
            }
        )
        self.assertEqual(filter.get("owners/module/local.c"), ConfigValue.MODULE)
        self.assertEqual(filter.get("owners/builtin/local.c"), ConfigValue.ENABLED)
        self.assertEqual(filter.get("owners/unrelated/local.c"), ConfigValue.ENABLED)
        self.assertIsNone(filter.get("owners/disabled/local.c"))
        return filter

    def test_cross_directory_lookup_merges_modes_and_direct_source_paths(self) -> None:
        filter = self.make_cross_directory_filter()

        self.assertEqual(filter.get("shared/common.c"), ConfigValue.ENABLED)
        self.assertEqual(filter.get("shared/common.S"), ConfigValue.ENABLED)
        self.assertEqual(filter.get("shared/direct.c"), ConfigValue.ENABLED)
        self.assertEqual(filter.get("shared/image.lds.S"), ConfigValue.ENABLED)
        self.assertIsNone(filter.get("shared/disabled.c"))

    def test_cross_directory_miss_does_not_query_unrelated_cached_rules(self) -> None:
        filter = self.make_cross_directory_filter()
        unrelated = filter.kbuild_cache["owners/unrelated"].rules

        with patch.object(
            unrelated, "get", side_effect=AssertionError("unrelated rule lookup")
        ):
            self.assertIsNone(filter.get("shared/missing.c"))

    def test_new_intermediate_makefile_preserves_cached_fallback(self) -> None:
        files = {
            "Kbuild": "obj-y += drivers/ drivers/intermediate/\n",
            "drivers/intermediate/child/Makefile": "obj-y += local.o\n",
        }
        filter = self.make_filter(
            {
                "base": files,
                "next": {
                    **files,
                    "drivers/intermediate/Makefile": (
                        "obj-y += child/ child/selected.o\n"
                    ),
                },
            }
        )
        self.assertIsNone(filter.get("drivers/intermediate/child/selected.c"))
        child = filter.kbuild_cache["drivers/intermediate/child"]
        self.assertEqual(child.parent.path, "")

        filter.update_filter_state(
            make_diff("drivers/intermediate/Makefile", DiffFileType.NEW), "next"
        )
        filter._kbuild_cache_get("drivers/intermediate")

        # The old child still bypasses the newly loaded intermediate node.
        # Fallback lookup must nevertheless see every cached owner's rules.
        self.assertIs(filter.kbuild_cache[child.path], child)
        self.assertEqual(
            filter.get("drivers/intermediate/child/selected.c"), ConfigValue.ENABLED
        )

    def test_copied_reverse_indices_remain_independent_after_reload(self) -> None:
        original = self.make_cross_directory_filter()
        copied = ConfigFilter.copy(original)
        copied.update_filter_state(
            make_diff("owners/builtin/Makefile", DiffFileType.DEFAULT), "next"
        )
        self.assertEqual(copied.get("owners/builtin/local.c"), ConfigValue.ENABLED)

        self.assertEqual(original.get("shared/common.c"), ConfigValue.ENABLED)
        self.assertEqual(copied.get("shared/common.c"), ConfigValue.MODULE)
        self.assertIsNone(copied.get("shared/direct.c"))
        self.assertEqual(original.get("shared/direct.c"), ConfigValue.ENABLED)

        # Copy again after removal/reinsertion changed cache insertion order.
        reloaded_copy = ConfigFilter.copy(copied)
        parent = reloaded_copy.kbuild_cache["owners"]
        child = reloaded_copy.kbuild_cache["owners/builtin"]
        self.assertIs(child.parent, parent)
        self.assertIs(parent.children[child.path], child)
        reloaded_copy.update_filter_state(
            make_diff("owners/module/Makefile", DiffFileType.DEFAULT), "next"
        )
        self.assertIsNone(reloaded_copy.get("shared/common.c"))
        self.assertEqual(copied.get("shared/common.c"), ConfigValue.MODULE)
        self.assertEqual(original.get("shared/common.c"), ConfigValue.ENABLED)

    def test_architecture_fragment_update_reindexes_cross_directory_rules(self) -> None:
        files = {
            "Kbuild": "obj-y += arch/$(SRCARCH)/\n",
            "arch/arm64/Kbuild": "obj-y += kvm/\n",
            "arch/arm64/kvm/Makefile": (
                "include $(srctree)/virt/kvm/objects.mk\n"
            ),
            "virt/kvm/objects.mk": "obj-y += ../../../virt/kvm/before.o\n",
        }
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": files,
                    "next": {
                        **files,
                        "virt/kvm/objects.mk": (
                            "obj-y += ../../../virt/kvm/after.o\n"
                        ),
                    },
                }
            ),
            KernelConfig("CONFIG_ARM64=y"),
            "base",
        )
        self.assertTrue(filter.file_included("virt/kvm/before.c"))

        filter.update_filter_state(
            make_diff("virt/kvm/objects.mk", DiffFileType.DEFAULT), "next"
        )

        self.assertFalse(filter.file_included("virt/kvm/before.c"))
        self.assertTrue(filter.file_included("virt/kvm/after.c"))

    def test_architecture_makefile_invalidates_root_and_architecture(self) -> None:
        files = {
            "Kbuild": "obj-y += arch/$(SRCARCH)/\n",
            "arch/arm64/Kbuild": "obj-y += kernel/\n",
            "arch/arm64/Makefile": "libs-y += arch/arm64/before/\n",
            "arch/arm64/before/Makefile": "lib-y += selected.o\n",
            "arch/arm64/after/Makefile": "lib-y += selected.o\n",
        }
        filter = ConfigFilter(
            MemoryGitRepo(
                {
                    "base": files,
                    "next": {
                        **files,
                        "arch/arm64/Makefile": "libs-y += arch/arm64/after/\n",
                    },
                }
            ),
            KernelConfig("CONFIG_ARM64=y"),
            "base",
        )
        self.assertTrue(filter.file_included("arch/arm64/before/selected.c"))
        self.assertFalse(filter.file_included("arch/arm64/after/selected.c"))

        filter.update_filter_state(
            make_diff("arch/arm64/Makefile", DiffFileType.DEFAULT), "next"
        )

        self.assertFalse(filter.file_included("arch/arm64/before/selected.c"))
        self.assertTrue(filter.file_included("arch/arm64/after/selected.c"))

    def test_source_change_invalidates_transitive_include_results_only(self) -> None:
        files = {
            "drivers/Makefile": "obj-y += wrapper.o unrelated.o\n",
            "drivers/wrapper.c": '#include "before.h"\n',
            "drivers/before.h": '#include "before_leaf.h"\n',
            "drivers/after.h": '#include "after_leaf.h"\n',
            "drivers/unrelated.c": '#include "unchanged.h"\n',
            "drivers/before_leaf.h": "",
            "drivers/after_leaf.h": "",
            "drivers/unchanged.h": "",
        }
        next_files = {**files, "drivers/wrapper.c": '#include "after.h"\n'}
        index = SourceIncludeIndex("", files)
        for source_files in (files, next_files):
            for path, contents in source_files.items():
                for line in contents.splitlines():
                    index.add_line(path, line)
        filter = ConfigFilter(
            MemoryGitRepo({"base": files, "next": next_files}),
            KernelConfig(""),
            "base",
            index,
        )
        self.assertTrue(filter.file_included("drivers/before_leaf.h"))
        self.assertFalse(filter.file_included("drivers/after_leaf.h"))
        self.assertTrue(filter.file_included("drivers/unchanged.h"))
        unrelated_key = ("drivers/unrelated.c", ConfigValue.ENABLED)
        unchanged = filter._active_includes_cache[unrelated_key]

        filter.update_filter_state(
            make_diff("drivers/wrapper.c", DiffFileType.DEFAULT), "next"
        )

        self.assertNotIn("drivers/before_leaf.h", filter._include_value_cache)
        self.assertNotIn("drivers/after_leaf.h", filter._include_value_cache)
        self.assertIn("drivers/unchanged.h", filter._include_value_cache)
        self.assertIs(filter._active_includes_cache[unrelated_key], unchanged)
        self.assertFalse(filter.file_included("drivers/before_leaf.h"))
        self.assertTrue(filter.file_included("drivers/after_leaf.h"))

    def test_source_rename_invalidates_both_active_include_modes_only(self) -> None:
        repo = MemoryGitRepo(
            {
                "base": {
                    "old.c": '#include "target.h"\n',
                    "unrelated.c": '#include "target.h"\n',
                },
                "next": {
                    "new.c": '#include "target.h"\n',
                    "unrelated.c": '#include "target.h"\n',
                },
            }
        )
        index = SourceIncludeIndex(
            "", ("old.c", "new.c", "unrelated.c", "target.h")
        )
        filter = ConfigFilter(repo, KernelConfig(""), "base", index)
        for path in ("old.c", "new.c", "unrelated.c"):
            for mode in (ConfigValue.ENABLED, ConfigValue.MODULE):
                filter._active_source_includes(path, mode)
        unrelated_key = ("unrelated.c", ConfigValue.ENABLED)
        unchanged = filter._active_includes_cache[unrelated_key]

        filter.update_filter_state(
            make_diff("new.c", DiffFileType.RENAME, old_file="old.c"), "next"
        )

        self.assertIs(filter._active_includes_cache[unrelated_key], unchanged)
        for mode in (ConfigValue.ENABLED, ConfigValue.MODULE):
            self.assertEqual(filter._active_source_includes("old.c", mode), frozenset())
            self.assertEqual(
                filter._active_source_includes("new.c", mode), frozenset(("target.h",))
            )


if __name__ == "__main__":
    unittest.main()
