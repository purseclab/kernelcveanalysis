import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_query_api import sample_type_graph
from typer.testing import CliRunner

from object_db import DBHeapObject, ObjectDb, SynthesisMetadata
from object_db.cli import FieldOffsetsResponse, TypeSizesResponse, app


class LayoutCliTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db_path = Path(directory.name) / "object_db.sqlite"
        database = ObjectDb(self.db_path)
        try:
            database.save_type_graph(sample_type_graph())
            database.save_heap_objects(
                [
                    DBHeapObject(
                        id=11, type_id=11, location="", source_code="", is_anon=False
                    ),
                ]
            )
        finally:
            database.close()
        self.runner = CliRunner()

    def test_sizeof_preserves_duplicate_names(self) -> None:
        result = self.runner.invoke(
            app, ["--db", str(self.db_path), "--json", "sizeof", "my_obj"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        response = TypeSizesResponse.model_validate_json(result.output)
        self.assertEqual({record.id for record in response.results}, {7, 14})

    def test_field_offset_resolves_nested_array_path(self) -> None:
        result = self.runner.invoke(
            app, ["--db", str(self.db_path), "--json", "field-offset", "outer.array[1]"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        response = FieldOffsetsResponse.model_validate_json(result.output)
        self.assertEqual(response.results[0].byte_offset, 32)

    def test_field_offset_reports_missing_path(self) -> None:
        result = self.runner.invoke(
            app, ["--db", str(self.db_path), "field-offset", "outer.no_such_field"]
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("was not found", result.output)

    def test_create_without_vmlinux(self) -> None:
        root = self.db_path.parent
        compile_commands = root / "input_commands.json"
        compile_commands.write_text("[]")

        def build_empty_database(metadata: SynthesisMetadata) -> None:
            metadata.data_path().mkdir(parents=True, exist_ok=True)
            database = ObjectDb(metadata.data_path() / "object_db.sqlite")
            database.close()

        with (
            patch("object_db.cli.synthesis_data_dir", return_value=root),
            patch(
                "object_db.cli.setup_synthesis_object_db",
                side_effect=build_empty_database,
            ),
        ):
            result = self.runner.invoke(
                app,
                [
                    "create",
                    "--kernel",
                    "created",
                    "--codeql-db",
                    str(root),
                    "--linux-src",
                    str(root),
                    "--compile-commands",
                    str(compile_commands),
                ],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNone(SynthesisMetadata.load(root / "created").vmlinux)

    def test_failed_create_keeps_existing_metadata_and_commands(self) -> None:
        root = self.db_path.parent
        destination = root / "existing"
        destination.mkdir()
        metadata_path = destination / "metadata.json"
        commands_path = destination / "compile_commands.json"
        metadata_path.write_text("old metadata")
        commands_path.write_text("old commands")
        compile_commands = root / "input_commands.json"
        compile_commands.write_text("[]")
        with (
            patch("object_db.cli.synthesis_data_dir", return_value=root),
            patch(
                "object_db.cli.setup_synthesis_object_db",
                side_effect=RuntimeError("query failed"),
            ),
        ):
            result = self.runner.invoke(
                app,
                [
                    "create",
                    "--kernel",
                    "existing",
                    "--codeql-db",
                    str(root),
                    "--linux-src",
                    str(root),
                    "--compile-commands",
                    str(compile_commands),
                ],
            )
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(metadata_path.read_text(), "old metadata")
        self.assertEqual(commands_path.read_text(), "old commands")
