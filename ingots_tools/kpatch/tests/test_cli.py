import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from typing import cast

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import ClassifierFilter, CountFilter, FilterPipeline


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


class CliRankTests(unittest.TestCase):
    def test_all_option_removes_sampling_stage(self) -> None:
        for options, expected_stages in (
            ([], [CountFilter, ClassifierFilter]),
            (["--all"], [ClassifierFilter]),
        ):
            with (
                self.subTest(options=options),
                patch("kpatch.cli.GitDb.load_name"),
                patch("kpatch.cli.run_filter") as run_filter,
            ):
                result = CliRunner().invoke(
                    app,
                    [
                        "filter", "--repo", "linux", "--db", "filtered_after_2025",
                        "--dest", "ranked_after_2025", "rank", *options,
                    ],
                )

                self.assertEqual(result.exit_code, 0, result.output)
                pipeline = cast(FilterPipeline, run_filter.call_args.args[1])
                self.assertEqual(
                    [type(stage) for stage in pipeline.filters], expected_stages
                )


if __name__ == "__main__":
    unittest.main()
