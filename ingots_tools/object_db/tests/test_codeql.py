import csv
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from test_query_api import sample_type_graph

from object_db import (
    AllocType,
    CodeqlContext,
    CodeQlKmallocCallResult,
    CodeqlQuery,
    ObjectDb,
    SynthesisMetadata,
    load_object_set,
    setup_synthesis_object_db,
)


class CsvContext(CodeqlContext):
    def __init__(self, types: list[list[str]], fields: list[list[str]]):
        super().__init__(Path("/unused"))
        self.type_rows = types
        self.field_rows = fields

    def run_query_raw(self, query: CodeqlQuery) -> str:
        rows = self.type_rows if query == CodeqlQuery.Types else self.field_rows
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["header"])
        writer.writerows(rows)
        return output.getvalue()


class CodeqlExtractionTests(unittest.TestCase):
    def test_numeric_member_order_and_duplicate_names(self) -> None:
        types = [
            ["1", "int", "INT", "4", "4", "1", "-1", "", "0"],
            ["2", "same", "STRUCT", "48", "4", "2", "-1", "a.c:1:1:1:20", "0"],
            ["3", "same", "STRUCT", "4", "4", "3", "-1", "b.c:1:1:1:20", "0"],
            ["4", "", "STRUCT", "4", "4", "4", "-1", "b.c:2:1:2:20", "1"],
        ]
        fields = [
            ["2", str(i), f"f{i}", "1", str(i * 4), "0", "0"]
            for i in sorted(range(12), key=str)
        ] + [["3", "0", "different", "1", "0", "0", "0"]]
        graph = CsvContext(types, fields).get_type_graph()
        self.assertEqual(
            [member.name for member in graph.members_of(2)],
            [f"f{i}" for i in range(12)],
        )
        self.assertEqual(graph.members_of(3)[0].name, "different")
        self.assertEqual(len(graph.get_by_name("same")), 2)
        self.assertEqual(graph.members_of(4), [])
        self.assertTrue(graph.get_type(4).is_anon)

    def test_csv_preserves_quoted_newlines(self) -> None:
        types = [["1", "a\nb", "INT", "4", "4", "1", "-1", "", "0"]]
        graph = CsvContext(types, []).get_type_graph()
        self.assertEqual(graph.get_type(1).name, "a\nb")

    def test_missing_type_reference_is_reported(self) -> None:
        types = [["1", "missing *", "PTR", "8", "8", "999", "-1", "", "0"]]
        with self.assertRaises(KeyError):
            CsvContext(types, []).get_type_graph()

    def test_allocation_parser_retains_type_identity(self) -> None:
        row = [
            "a.c:1:1:1:20",
            "kmalloc",
            "42",
            "same",
            "b.c:1:1:1:20",
            "-1",
            "",
            "unknown",
            "true",
            "default",
        ]
        result = CodeQlKmallocCallResult.from_csv_row(row)
        self.assertEqual(result.type_id, 42)
        self.assertEqual(result.call_type, AllocType.KMALLOC)
        self.assertIsNone(result.struct_size)
        self.assertIsNone(result.alloc_size)
        self.assertTrue(result.is_flexible)

    def test_rebuild_links_by_entity_id_and_does_not_duplicate_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "example.c").write_text("struct my_obj {};\n")
            metadata = SynthesisMetadata(
                kernel_name="test",
                codeql_db=root / "codeql",
                linux_src=root,
                synthesis_data=root / "synthesis",
            )
            # Same name, different identity: this allocation belongs to type 14.
            call = CodeQlKmallocCallResult.from_csv_row(
                [
                    "example.c:1:1:1:20",
                    "kmalloc",
                    "14",
                    "my_obj",
                    "other.c:1:1:1:20",
                    "8",
                    "",
                    "8",
                    "false",
                    "default",
                ]
            )
            with patch("object_db.setup.CodeqlContext") as context:
                context.return_value.get_type_graph.return_value = sample_type_graph()
                context.return_value.get_kmalloc_calls.return_value = [call]
                setup_synthesis_object_db(metadata)
                setup_synthesis_object_db(metadata)
            objects = load_object_set(metadata.data_path() / "object_db.sqlite")
            self.assertEqual(len(objects.get_by_name("my_obj")), 2)
            self.assertEqual(len(objects.all_kmalloc_calls()), 1)
            self.assertEqual(objects.all_kmalloc_calls()[0].heap_object_id, 14)
            obj = objects.get_by_id(7)
            assert obj is not None
            self.assertEqual(obj.kmalloc_calls, [])

    def test_failed_rebuild_preserves_original_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = SynthesisMetadata(
                kernel_name="test",
                codeql_db=root / "codeql",
                linux_src=root,
                synthesis_data=root,
            )
            db_path = root / "object_db.sqlite"
            original_db = ObjectDb(db_path)
            original_db.close()
            original = db_path.read_bytes()
            with patch("object_db.setup.CodeqlContext") as context:
                context.return_value.get_type_graph.return_value = sample_type_graph()
                context.return_value.get_kmalloc_calls.side_effect = RuntimeError(
                    "query failed"
                )
                with self.assertRaisesRegex(RuntimeError, "query failed"):
                    setup_synthesis_object_db(metadata)
            self.assertEqual(db_path.read_bytes(), original)
            self.assertEqual(list(root.glob(".objectdb-*")), [])
