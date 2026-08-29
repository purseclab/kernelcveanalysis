import unittest

from kpatch.filter import FileFilter


class FileFilterTests(unittest.TestCase):
    def test_matches_path_prefix_and_exact_extensions(self) -> None:
        file_filter = FileFilter(["drivers", "fs"], ["c", ".h"])

        self.assertTrue(file_filter.matches_file("drivers/foo.c"))
        self.assertTrue(file_filter.matches_file("drivers/net/core/foo.h"))
        self.assertTrue(file_filter.matches_file("fs/name.c"))
        self.assertFalse(file_filter.matches_file("drivers2/foo.c"))
        self.assertFalse(file_filter.matches_file("kernel/foo.c"))
        self.assertFalse(file_filter.matches_file("drivers/foo.cpp"))
        self.assertFalse(file_filter.matches_file("drivers/foo.c.bak"))

    def test_escapes_prefix_and_extension(self) -> None:
        file_filter = FileFilter(["drivers/net+"], ["c++"])

        self.assertTrue(file_filter.matches_file("drivers/net+/socket.c++"))
        self.assertFalse(file_filter.matches_file("drivers/net/socket.c++"))
        self.assertFalse(file_filter.matches_file("drivers/net+/socket.cpp"))

    def test_empty_path_list_matches_nothing(self) -> None:
        self.assertFalse(FileFilter([], ["c"]).matches_file("foo.c"))

    def test_empty_extension_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            FileFilter(["drivers"], [""]).build_regex()


if __name__ == "__main__":
    unittest.main()
