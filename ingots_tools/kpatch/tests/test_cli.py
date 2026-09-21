import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app


class CliEnvironmentTests(unittest.TestCase):
    def test_loads_dotenv_from_invocation_directory(self) -> None:
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            invocation_directory = Path(directory)
            (invocation_directory / ".env").write_text(
                "KPATCH_DOTENV_NEW=from-file\n"
                "KPATCH_DOTENV_EXISTING=from-file\n"
            )
            previous_directory = Path.cwd()

            try:
                os.chdir(invocation_directory)
                with (
                    patch.dict(
                        os.environ,
                        {"KPATCH_DOTENV_EXISTING": "from-environment"},
                        clear=False,
                    ),
                    patch(
                        "kpatch.cli.load_commits_from_db",
                        return_value=[],
                    ),
                    patch(
                        "kpatch.cli.show_commit_sunburst",
                        return_value=Path("visualization.html"),
                    ),
                ):
                    os.environ.pop("KPATCH_DOTENV_NEW", None)
                    result = runner.invoke(app, ["visualize"])

                    self.assertEqual(result.exit_code, 0)
                    self.assertEqual(
                        os.environ["KPATCH_DOTENV_NEW"],
                        "from-file",
                    )
                    self.assertEqual(
                        os.environ["KPATCH_DOTENV_EXISTING"],
                        "from-environment",
                    )
            finally:
                os.chdir(previous_directory)


if __name__ == "__main__":
    unittest.main()
