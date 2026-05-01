import tempfile
import unittest
from pathlib import Path

from object_db import SynthesisMetadata, load_object_set, load_object_set_from_synthesis_dir
from object_db.btf_types import BtfTypes
from object_db.object_db import DBHeapObject, DBKmallocCall, ObjectDb


def _sample_btf_types() -> BtfTypes:
    return BtfTypes(
        {
            "types": [
                {
                    "id": 1,
                    "kind": "INT",
                    "name": "u64",
                    "size": 8,
                    "bits_offset": 0,
                    "nr_bits": 64,
                    "encoding": "UNSIGNED",
                },
                {"id": 2, "kind": "PTR", "name": "file_ptr", "type_id": 5},
                {"id": 3, "kind": "PTR", "name": "task_ptr", "type_id": 6},
                {"id": 4, "kind": "TYPEDEF", "name": "file_handle", "type_id": 2},
                {"id": 5, "kind": "STRUCT", "name": "file", "size": 16, "vlen": 0, "members": []},
                {"id": 6, "kind": "STRUCT", "name": "task_struct", "size": 24, "vlen": 0, "members": []},
                {
                    "id": 7,
                    "kind": "STRUCT",
                    "name": "my_obj",
                    "size": 24,
                    "vlen": 3,
                    "members": [
                        {"name": "file", "type_id": 2, "bits_offset": 0, "bitfield_size": 0},
                        {"name": "aliased_file", "type_id": 4, "bits_offset": 64, "bitfield_size": 0},
                        {"name": "flags", "type_id": 1, "bits_offset": 128, "bitfield_size": 0},
                    ],
                },
            ]
        }
    )


class ObjectQueryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "object_db.sqlite"

        self.object_db = ObjectDb(self.db_path)
        self.addCleanup(self.object_db.close)
        btf_types = _sample_btf_types()
        self.object_db.save_btf_types(list(btf_types.types.values()))
        self.object_db.save_heap_object(
            DBHeapObject(
                id=123,
                type_id=7,
                location="fs/example.c:1:1:1:1",
                source_code="struct my_obj { ... }",
                is_anon=False,
            )
        )
        self.object_db.save_heap_object(
            DBHeapObject(
                id=200,
                type_id=1,
                location="kernel/example.c:2:1:2:5",
                source_code="u64 flags;",
                is_anon=False,
            )
        )
        self.object_db.save_kmalloc_call(
            DBKmallocCall(
                call_site="mm/slab.c:10:1:10:20",
                call_type="kmalloc",
                struct_type="my_obj",
                struct_def="fs/example.c:1:1:1:1",
                struct_size=24,
                flags="GFP_KERNEL",
                alloc_size=24,
                is_flexible=False,
                kmalloc_cache_name="kmalloc-64",
                heap_object_id=123,
            )
        )
        self.object_db.save_kmalloc_call(
            DBKmallocCall(
                call_site="mm/slab.c:15:1:15:20",
                call_type="kzalloc",
                struct_type="unknown",
                struct_def="fs/other.c:1:1:1:1",
                struct_size=8,
                flags="GFP_ATOMIC",
                alloc_size=8,
                is_flexible=False,
                kmalloc_cache_name=None,
                heap_object_id=None,
            )
        )

    def test_load_object_set_exposes_object_helpers(self):
        objects = load_object_set(self.db_path)

        self.assertEqual(len(objects), 2)
        obj = objects.get_by_id(123)
        self.assertIsNotNone(obj)
        assert obj is not None
        self.assertEqual(obj.type_name, "my_obj")
        self.assertEqual(obj.type_kind, "STRUCT")
        self.assertEqual(obj.size, 24)
        self.assertTrue(obj.has_field_named("file"))
        self.assertTrue(obj.has_pointer_field_at_offset(0))
        self.assertFalse(obj.has_pointer_field_at_offset(16))
        self.assertTrue(obj.has_pointer_to_type_name("file"))
        self.assertFalse(obj.has_pointer_to_type_name("task_struct"))
        self.assertTrue(obj.is_allocated_from_cache("kmalloc-64"))
        self.assertTrue(obj.has_kmalloc_call(lambda call: call.call_type == "kmalloc"))

        file_field = obj.field_named("file")
        self.assertIsNotNone(file_field)
        assert file_field is not None
        self.assertTrue(file_field.is_pointer())
        self.assertTrue(file_field.points_to_type_name("file"))

        aliased_field = obj.field_at_offset(8)
        self.assertIsNotNone(aliased_field)
        assert aliased_field is not None
        self.assertTrue(aliased_field.points_to_type_name("file"))

        scalar_obj = objects.get_by_id(200)
        self.assertIsNotNone(scalar_obj)
        assert scalar_obj is not None
        self.assertEqual(scalar_obj.fields, [])
        self.assertEqual(scalar_obj.kmalloc_calls, [])

    def test_object_set_filter_and_name_lookup(self):
        objects = load_object_set(self.db_path)

        self.assertEqual(len(objects.get_by_name("my_obj")), 1)
        self.assertEqual(len(objects.get_by_name("missing")), 0)

        filtered = objects.filter(lambda obj: obj.is_allocated_from_cache("kmalloc-64"))
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered.get_by_id(123).type_name, "my_obj")

    def test_load_from_synthesis_dir_and_metadata_path(self):
        metadata = SynthesisMetadata(
            kernel_name="test_kernel",
            vmlinux=self.temp_path / "vmlinux",
            codeql_db=self.temp_path / "codeql-db",
            linux_src=self.temp_path / "linux-src",
            synthesis_data=self.temp_path,
        )
        metadata.save()

        by_dir = load_object_set_from_synthesis_dir(self.temp_path)
        by_metadata = load_object_set_from_synthesis_dir(self.temp_path / "metadata.json")

        self.assertEqual(len(by_dir), 2)
        self.assertEqual(len(by_metadata), 2)
        self.assertIsNotNone(by_dir.get_by_id(123))

    def test_load_from_synthesis_dir_requires_db_file(self):
        missing_dir = self.temp_path / "missing"
        missing_dir.mkdir()
        metadata = SynthesisMetadata(
            kernel_name="test_kernel",
            vmlinux=missing_dir / "vmlinux",
            codeql_db=missing_dir / "codeql-db",
            linux_src=missing_dir / "linux-src",
            synthesis_data=missing_dir,
        )
        metadata.save()

        with self.assertRaises(FileNotFoundError):
            load_object_set_from_synthesis_dir(missing_dir)
