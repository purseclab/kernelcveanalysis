from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ksandbox.tool_bundle import (
    TOOL_NAMES,
    _extract_bundle,
    ensure_tool_bundle,
    tool_bundle_path,
)


def _write_fake_bundle(path: Path) -> None:
    path.mkdir(parents=True)
    for name in TOOL_NAMES:
        binary = path / name
        binary.write_bytes(b"\x7fELFfake")
        binary.chmod(0o555)


class ToolBundleTests(unittest.TestCase):
    def test_existing_valid_bundle_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir, patch.dict(
            os.environ, {"XDG_CACHE_HOME": tempdir}
        ):
            expected = tool_bundle_path()
            _write_fake_bundle(expected)
            self.assertEqual(ensure_tool_bundle(), expected)

    def test_extract_bundle_selects_only_expected_regular_files(self) -> None:
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
            for name in TOOL_NAMES:
                data = b"\x7fELFbinary"
                info = tarfile.TarInfo(f"bin/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            unwanted = b"ignored"
            info = tarfile.TarInfo("bin/unwanted")
            info.size = len(unwanted)
            archive.addfile(info, io.BytesIO(unwanted))

        with tempfile.TemporaryDirectory() as tempdir:
            destination = Path(tempdir)
            _extract_bundle(archive_buffer.getvalue(), destination)
            self.assertEqual(set(item.name for item in destination.iterdir()), set(TOOL_NAMES))
            self.assertTrue(all(os.access(destination / name, os.X_OK) for name in TOOL_NAMES))


if __name__ == "__main__":
    unittest.main()
