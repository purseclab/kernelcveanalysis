import unittest

from kpatch.config_filter import (
    ConfigFilter,
    ConfigValue,
    KbuildMakefile,
    KernelConfig,
)
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
    old_path: str | None = None,
) -> Diff:
    return Diff(
        text="",
        files=[
            DiffFile(
                file=path,
                old_file=old_path,
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

    def test_new_makefile_replaces_delegation(self) -> None:
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

        self.assertFalse(filter.file_included("drivers/example/direct.c"))
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
                old_path="drivers/example/Makefile",
            ),
            "next",
        )

        self.assertTrue(filter.file_included("drivers/example/selected.c"))


if __name__ == "__main__":
    unittest.main()
