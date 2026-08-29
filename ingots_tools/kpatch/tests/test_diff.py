import unittest

from kpatch.diff import Diff, DiffFileType


class DiffParserTests(unittest.TestCase):
    def parse_one(self, text: str):
        diff = Diff.parse(text)
        self.assertEqual(len(diff.files), 1)
        return diff.files[0]

    def test_modified_file(self) -> None:
        file = self.parse_one(
            """diff --git a/file.c b/file.c
index 1234567..89abcde 100644
--- a/file.c
+++ b/file.c
@@ -1 +1 @@
-old
+new
"""
        )

        self.assertEqual(file.file, "file.c")
        self.assertIsNone(file.old_file)
        self.assertEqual(file.change_type, DiffFileType.DEFAULT)
        self.assertEqual(file.old_mode, "100644")
        self.assertEqual(file.new_mode, "100644")
        self.assertFalse(file.mode_changed)
        self.assertFalse(file.binary)
        self.assertEqual(len(file.chunks), 1)

    def test_new_and_deleted_files(self) -> None:
        new_file = self.parse_one(
            """diff --git a/new.txt b/new.txt
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+new
"""
        )
        deleted_file = self.parse_one(
            """diff --git a/old.txt b/old.txt
deleted file mode 100644
index 1234567..0000000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-old
"""
        )

        self.assertEqual(new_file.file, "new.txt")
        self.assertIsNone(new_file.old_file)
        self.assertEqual(new_file.change_type, DiffFileType.NEW)
        self.assertIsNone(new_file.old_mode)
        self.assertEqual(new_file.new_mode, "100644")

        self.assertEqual(deleted_file.file, "old.txt")
        self.assertIsNone(deleted_file.old_file)
        self.assertEqual(deleted_file.change_type, DiffFileType.DELETE)
        self.assertEqual(deleted_file.old_mode, "100644")
        self.assertIsNone(deleted_file.new_mode)

    def test_pure_rename_and_rename_with_edits(self) -> None:
        pure_rename = self.parse_one(
            """diff --git a/old.c b/new.c
similarity index 100%
rename from old.c
rename to new.c
"""
        )
        edited_rename = self.parse_one(
            """diff --git a/old.c b/new.c
similarity index 85%
rename from old.c
rename to new.c
index 1234567..89abcde 100644
--- a/old.c
+++ b/new.c
@@ -1 +1 @@
-old
+new
"""
        )

        for file in (pure_rename, edited_rename):
            self.assertEqual(file.file, "new.c")
            self.assertEqual(file.old_file, "old.c")
            self.assertEqual(file.change_type, DiffFileType.RENAME)

        self.assertEqual(pure_rename.chunks, [])
        self.assertEqual(len(edited_rename.chunks), 1)

    def test_copy(self) -> None:
        file = self.parse_one(
            """diff --git a/original.c b/copy.c
similarity index 100%
copy from original.c
copy to copy.c
"""
        )

        self.assertEqual(file.file, "copy.c")
        self.assertEqual(file.old_file, "original.c")
        self.assertEqual(file.change_type, DiffFileType.COPY)
        self.assertEqual(file.chunks, [])

    def test_mode_only_and_binary_changes(self) -> None:
        mode_change = self.parse_one(
            """diff --git a/script.sh b/script.sh
old mode 100644
new mode 100755
"""
        )
        binary_change = self.parse_one(
            """diff --git a/image.png b/image.png
index 1234567..89abcde 100644
Binary files a/image.png and b/image.png differ
"""
        )

        self.assertTrue(mode_change.mode_changed)
        self.assertEqual(mode_change.old_mode, "100644")
        self.assertEqual(mode_change.new_mode, "100755")
        self.assertEqual(mode_change.chunks, [])

        self.assertTrue(binary_change.binary)
        self.assertEqual(binary_change.change_type, DiffFileType.DEFAULT)
        self.assertEqual(binary_change.chunks, [])


if __name__ == "__main__":
    unittest.main()
