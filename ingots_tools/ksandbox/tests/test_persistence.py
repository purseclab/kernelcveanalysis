from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ksandbox.docker_sandbox import (
    MountInfo,
    _SandboxStore,
    _StoredSandbox,
    _hash_mount_tree,
)


class MountHashTests(unittest.TestCase):
    def test_hash_covers_paths_contents_types_and_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "file").write_text("one")
            os.symlink("file", root / "link")
            initial = _hash_mount_tree(root)

            (root / "file").write_text("two")
            self.assertNotEqual(initial, _hash_mount_tree(root))

            (root / "file").write_text("one")
            os.unlink(root / "link")
            os.symlink("other", root / "link")
            self.assertNotEqual(initial, _hash_mount_tree(root))

            os.unlink(root / "link")
            (root / "nested").mkdir()
            (root / "nested" / "file").write_text("one")
            self.assertNotEqual(initial, _hash_mount_tree(root))


class SandboxStoreTests(unittest.TestCase):
    def test_start_claim_and_stop_hash_update_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir) / "mount"
            root.mkdir()
            mount_hash = _hash_mount_tree(root)
            store = _SandboxStore(Path(tempdir) / "sandboxes.sqlite3")
            stored = _StoredSandbox(
                id="sandbox-id",
                state="stopped",
                runtime_dir=Path(tempdir) / "runtime",
                image="ksandbox:test",
                created="",
                name="sandbox",
                mounts=[MountInfo(root, "input", "test input", False)],
                mount_hashes=[mount_hash],
            )
            store.create(stored)

            self.assertTrue(store.claim_start("sandbox-id"))
            self.assertFalse(store.claim_start("sandbox-id"))

            (root / "changed").write_text("changed")
            changed_hash = _hash_mount_tree(root)
            self.assertTrue(store.stop("sandbox-id", [changed_hash]))
            reloaded = store.get("sandbox-id")
            assert reloaded is not None
            self.assertEqual(reloaded.state, "stopped")
            self.assertEqual(reloaded.mount_hashes, [changed_hash])


if __name__ == "__main__":
    unittest.main()
