"""Opt-in checks against a real CodeQL C extraction (requires codeql and gcc)."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from object_db import SynthesisMetadata, load_object_set, setup_synthesis_object_db


@unittest.skipUnless(
    os.environ.get("OBJECTDB_RUN_CODEQL_TESTS") == "1",
    "Set OBJECTDB_RUN_CODEQL_TESTS=1 to run CodeQL integration",
)
class CodeqlIntegrationTests(unittest.TestCase):
    def test_codeql_to_sqlite_layout_and_allocation_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="objectdb-integration-") as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            shutil.copy(
                Path(__file__).parent / "fixtures" / "objects.c", source / "fixture.c"
            )
            # A second declaration of the same typedef can resolve to one
            # CodeQL entity with multiple source locations.
            (source / "other.c").write_text("typedef unsigned long size_t;\n")
            subprocess.run(
                [
                    "codeql",
                    "database",
                    "create",
                    str(root / "codeql-db"),
                    "--language=cpp",
                    f"--source-root={source}",
                    "--command=gcc -c fixture.c other.c",
                    "--threads=2",
                ],
                check=True,
            )
            metadata = SynthesisMetadata(
                kernel_name="fixture",
                codeql_db=root / "codeql-db",
                linux_src=source,
                synthesis_data=root / "synthesis",
            )
            setup_synthesis_object_db(metadata)
            objects = load_object_set(metadata.data_path() / "object_db.sqlite")
            calls = objects.all_kmalloc_calls()
            self.assertEqual(len(calls), 7, repr(calls))
            self.assertEqual(objects.linked_kmalloc_call_count(), 7)
            self.assertEqual(len(objects.get_by_name("many")), 2)
            many = max(objects.get_by_name("many"), key=lambda obj: len(obj.fields))
            self.assertEqual(
                [field.name for field in many.fields], [f"f{i}" for i in range(12)]
            )
            outer = objects.get_by_name("outer")[0]
            self.assertTrue(outer.has_pointer_field_at_offset(0))
            self.assertTrue(outer.has_pointer_field_at_offset(8))
            self.assertTrue(outer.has_pointer_field_at_offset(24))
            self.assertTrue(
                any(field.points_to_kind("FUNC_PROTO") for field in outer.fields)
            )
            bits = outer.field_named("bits")
            assert bits is not None
            self.assertEqual(bits.bitfield_size, 3)
            self.assertEqual(bits.byte_offset, 32)
            anonymous = objects.get_by_name("anonymous_outer")[0]
            self.assertTrue(anonymous.has_pointer_field_at_offset(0))
            self.assertTrue(
                any(field.path == "anonymous_ptr" for field in anonymous.iter_fields()),
                repr([field.path for field in anonymous.iter_fields()]),
            )
            self.assertEqual(
                [
                    call.kmalloc_cache_name
                    for call in calls
                    if call.call_type == "kmem_cache_alloc"
                ],
                ["outer_cache"],
            )
            self.assertTrue(
                next(
                    call
                    for call in objects.all_kmalloc_calls()
                    if call.struct_type == "flex"
                ).is_flexible
            )
