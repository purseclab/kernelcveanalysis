import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from object_db import (
    DBHeapObject,
    DBKmallocCall,
    ObjectDb,
    SynthesisMetadata,
    TypeGraph,
    TypeInfo,
    TypeKind,
    TypeMember,
    load_object_set,
    load_object_set_from_synthesis_dir,
)


def sample_type_graph() -> TypeGraph:
    types = [
        TypeInfo(id=1, kind=TypeKind.INTEGER, name="u64", size=8),
        TypeInfo(
            id=2, kind=TypeKind.POINTER, name="file *", referenced_type_id=5, size=8
        ),
        TypeInfo(
            id=3, kind=TypeKind.POINTER, name="task *", referenced_type_id=6, size=8
        ),
        TypeInfo(
            id=4,
            kind=TypeKind.TYPEDEF,
            name="file_handle",
            referenced_type_id=2,
            size=8,
        ),
        TypeInfo(id=5, kind=TypeKind.STRUCT, name="file", size=16),
        TypeInfo(id=6, kind=TypeKind.STRUCT, name="task_struct", size=24),
        TypeInfo(
            id=7,
            kind=TypeKind.STRUCT,
            name="my_obj",
            size=24,
            location="example.c:1:1:1:20",
        ),
        TypeInfo(id=8, kind=TypeKind.UNION, name="choice", size=8),
        TypeInfo(id=9, kind=TypeKind.STRUCT, name="inner", size=16),
        TypeInfo(
            id=10,
            kind=TypeKind.ARRAY,
            name="files[2]",
            size=16,
            referenced_type_id=4,
            element_count=2,
        ),
        TypeInfo(id=11, kind=TypeKind.STRUCT, name="outer", size=48),
        TypeInfo(
            id=12,
            kind=TypeKind.QUALIFIED,
            name="const file",
            size=16,
            referenced_type_id=5,
        ),
        TypeInfo(
            id=13,
            kind=TypeKind.POINTER,
            name="const file *",
            size=8,
            referenced_type_id=12,
        ),
        TypeInfo(
            id=14,
            kind=TypeKind.STRUCT,
            name="my_obj",
            size=8,
            location="other.c:1:1:1:20",
        ),
    ]
    members = [
        TypeMember(owner_type_id=7, index=0, name="file", type_id=2, byte_offset=0),
        TypeMember(
            owner_type_id=7, index=1, name="aliased_file", type_id=4, byte_offset=8
        ),
        TypeMember(owner_type_id=7, index=2, name="flags", type_id=1, byte_offset=16),
        TypeMember(owner_type_id=8, index=0, name="scalar", type_id=1, byte_offset=0),
        TypeMember(owner_type_id=8, index=1, name="ptr", type_id=13, byte_offset=0),
        TypeMember(owner_type_id=9, index=0, name="ptr", type_id=4, byte_offset=8),
        TypeMember(
            owner_type_id=11, index=0, name="embedded", type_id=9, byte_offset=0
        ),
        TypeMember(
            owner_type_id=11, index=1, name="alternatives", type_id=8, byte_offset=16
        ),
        TypeMember(owner_type_id=11, index=2, name="array", type_id=10, byte_offset=24),
        TypeMember(
            owner_type_id=11,
            index=3,
            name="bits",
            type_id=1,
            byte_offset=40,
            bit_offset=3,
            bitfield_size=5,
        ),
    ]
    return TypeGraph(types, members)


def sample_call(type_id: int, object_id: int | None) -> DBKmallocCall:
    return DBKmallocCall(
        call_site="mm/slab.c:10:1:10:20",
        call_type="kmalloc",
        type_id=type_id,
        struct_type="my_obj",
        struct_def="example.c:1:1:1:20",
        struct_size=24,
        flags="GFP_KERNEL",
        alloc_size=24,
        is_flexible=False,
        kmalloc_cache_name="kmalloc-64",
        heap_object_id=object_id,
    )


class ObjectQueryApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "object_db.sqlite"
        self.object_db = ObjectDb(self.db_path)
        self.addCleanup(self.object_db.close)
        self.object_db.save_type_graph(sample_type_graph())
        self.object_db.save_heap_objects(
            [
                DBHeapObject(
                    id=123,
                    type_id=7,
                    location="example.c:1:1:1:20",
                    source_code="struct my_obj {}",
                    is_anon=False,
                ),
                DBHeapObject(
                    id=200,
                    type_id=1,
                    location="example.c:2:1:2:5",
                    source_code="u64 flags;",
                    is_anon=False,
                ),
            ]
        )
        self.object_db.save_kmalloc_calls([sample_call(7, 123), sample_call(1, None)])

    def test_load_object_set_exposes_object_helpers(self) -> None:
        objects = load_object_set(self.db_path)
        self.assertEqual(len(objects), 2)
        obj = objects.get_by_id(123)
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
        aliased_field = obj.field_at_offset(8)
        assert aliased_field is not None
        self.assertTrue(aliased_field.points_to_type_name("file"))
        self.assertTrue(aliased_field.points_to_type_id(5))
        self.assertTrue(aliased_field.points_to_kind("STRUCT"))
        scalar_obj = objects.get_by_id(200)
        assert scalar_obj is not None
        self.assertEqual(scalar_obj.fields, [])
        self.assertEqual(scalar_obj.kmalloc_calls, [])

    def test_object_set_filter_and_name_lookup(self) -> None:
        objects = load_object_set(self.db_path)
        self.assertEqual(len(objects.get_by_name("my_obj")), 1)
        self.assertEqual(len(objects.get_by_name("missing")), 0)
        filtered = objects.filter(lambda obj: obj.is_allocated_from_cache("kmalloc-64"))
        self.assertEqual(len(filtered), 1)
        self.assertEqual(len(filtered.all_kmalloc_calls()), 1)
        self.assertEqual(len(objects.all_kmalloc_calls()), 2)

    def test_nested_union_array_and_qualified_pointer_layout(self) -> None:
        self.object_db.save_heap_objects(
            [
                DBHeapObject(
                    id=11, type_id=11, location="", source_code="", is_anon=False
                ),
                DBHeapObject(
                    id=8, type_id=8, location="", source_code="", is_anon=False
                ),
            ]
        )
        objects = load_object_set(self.db_path)
        union = objects.get_by_id(8)
        outer = objects.get_by_id(11)
        assert union is not None and outer is not None
        self.assertTrue(union.has_pointer_field_at_offset(0))
        self.assertTrue(outer.has_pointer_field_at_offset(8))
        self.assertTrue(outer.has_pointer_field_at_offset(16))
        self.assertTrue(outer.has_pointer_field_at_offset(32))
        self.assertFalse(outer.has_pointer_field_at_offset(40))
        self.assertEqual(
            [field.path for field in outer.fields_at_offset(16) if field.is_pointer()],
            ["alternatives.ptr"],
        )
        self.assertEqual(
            [field.path for field in outer.fields_at_offset(32) if field.is_pointer()],
            ["array[1]"],
        )
        self.assertTrue(outer.has_pointer_to_type_id(5))
        bits = outer.field_named("bits")
        assert bits is not None
        self.assertEqual((bits.bit_offset, bits.bitfield_size), (3, 5))

    def test_duplicate_type_names_survive_storage(self) -> None:
        graph = self.object_db.load_type_graph()
        self.assertEqual({record.id for record in graph.get_by_name("my_obj")}, {7, 14})

    def test_alternative_field_facts_at_one_member_index_survive_storage(self) -> None:
        graph = sample_type_graph()
        members = [
            member for type_id in graph.types for member in graph.members_of(type_id)
        ]
        members.append(
            TypeMember(
                owner_type_id=7,
                index=0,
                name="file",
                type_id=13,
                byte_offset=0,
            )
        )
        alternative_db = ObjectDb(self.temp_path / "alternatives.sqlite")
        try:
            alternative_db.save_type_graph(
                TypeGraph(list(graph.types.values()), members)
            )
            loaded = alternative_db.load_type_graph()
        finally:
            alternative_db.close()
        self.assertEqual(
            {member.type_id for member in loaded.members_of(7) if member.index == 0},
            {2, 13},
        )

    def test_load_from_synthesis_dir_and_metadata_path(self) -> None:
        SynthesisMetadata(
            kernel_name="test",
            codeql_db=self.temp_path / "codeql-db",
            linux_src=self.temp_path,
            synthesis_data=self.temp_path,
        ).save()
        self.assertEqual(len(load_object_set_from_synthesis_dir(self.temp_path)), 2)
        self.assertEqual(
            len(load_object_set_from_synthesis_dir(self.temp_path / "metadata.json")), 2
        )

    def test_load_requires_existing_db_without_creating_it(self) -> None:
        missing_db = self.temp_path / "does-not-exist.sqlite"
        with self.assertRaises(FileNotFoundError):
            load_object_set(missing_db)
        self.assertFalse(missing_db.exists())

    def test_legacy_db_rejected_without_modifying_it(self) -> None:
        legacy = self.temp_path / "legacy.sqlite"
        with closing(sqlite3.connect(legacy)) as connection:
            connection.execute("CREATE TABLE btf_types (id INTEGER)")
            connection.commit()
        original = legacy.read_bytes()
        with self.assertRaisesRegex(ValueError, "Rebuild.*CodeQL only"):
            load_object_set(legacy)
        self.assertEqual(legacy.read_bytes(), original)

    def test_read_connection_cannot_write(self) -> None:
        read_only = ObjectDb(self.db_path, read_only=True)
        try:
            with self.assertRaisesRegex(Exception, "readonly"):
                read_only.save_kmalloc_calls([sample_call(7, 123)])
        finally:
            read_only.close()
