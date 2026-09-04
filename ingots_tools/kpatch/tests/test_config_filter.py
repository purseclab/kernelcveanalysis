import unittest

from kexploit_utils import Architecture

from kpatch.filter.config_filter import (
    ConfigFilter,
    ConfigValue,
    KbuildDirectory,
    KbuildMakefile,
    KernelConfig,
)
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


if __name__ == "__main__":
    unittest.main()
