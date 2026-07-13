import tempfile
import unittest
from pathlib import Path

import object_db_query


class ObjectDbQueryScriptTemplateTests(unittest.TestCase):
    def test_render_script_template_uses_relative_object_db_path_inside_repo(self):
        output_path = object_db_query.REPO_ROOT / "tmp" / "analysis.py"

        template = object_db_query._render_script_template(output_path)

        self.assertIn('dependencies = ["object_db"]', template)
        self.assertIn('object_db = { path = "../object_db", editable = true }', template)
        self.assertIn("DEFAULT_DB_PATH = None", template)
        self.assertIn('source.add_argument("--db", type=Path, help="Path to object_db.sqlite")', template)
        self.assertIn("--synthesis-dir", template)
        self.assertIn("Provide --db or --synthesis-dir", template)

    def test_render_script_template_uses_absolute_object_db_path_outside_repo(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "analysis.py"

            template = object_db_query._render_script_template(output_path)

        expected = f'object_db = {{ path = "{object_db_query.OBJECT_DB_PROJECT_DIR}", editable = true }}'
        self.assertIn(expected, template)

    def test_render_script_template_can_bake_default_paths(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "analysis.py"
            default_db = Path(tmp_dir) / "object_db.sqlite"
            template = object_db_query._render_script_template(
                output_path,
                default_db=default_db,
                default_kernel="ingots_5.10.107",
                default_kexploit_data_dir="/tmp/kexploit-data",
            )

        self.assertIn(f"DEFAULT_DB_PATH = {str(default_db)!r}", template)
        self.assertIn("DEFAULT_KERNEL = 'ingots_5.10.107'", template)
        self.assertIn("DEFAULT_KEXPLOIT_DATA_DIR = '/tmp/kexploit-data'", template)
        self.assertIn("elif DEFAULT_DB_PATH is not None", template)
        self.assertIn("elif default_synthesis_dir() is not None", template)
