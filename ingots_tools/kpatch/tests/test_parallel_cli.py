from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from kpatch.cli import app
from kpatch.filter import FilterPipeline, MergeCommitFilter, WhitespaceFilter


class ParallelCliTests(unittest.TestCase):
    def _assert_workers(self, arguments: list[str], expected: int) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "kernel.config"
            config.write_text("CONFIG_TEST=y\n")
            with (
                patch("kpatch.cli.GitDb.load_name"),
                patch("kpatch.cli.ConfigFilter", return_value=MergeCommitFilter()) as configured,
                patch("kpatch.cli.run_filter") as run_filter,
            ):
                result = CliRunner().invoke(
                    app,
                    [
                        "filter", "--repo", directory, "--db", "unused-source",
                        "--dest", "unused-destination", "config", "--config", str(config),
                        *arguments,
                    ],
                )
                self.assertEqual(result.exit_code, 0, result.output)
                configured.assert_called_once()
                self.assertEqual(configured.call_args.kwargs, {"workers": expected})
                pipeline = cast(FilterPipeline, run_filter.call_args.args[1])
                self.assertEqual(len(pipeline.filters), 4)

    def test_default_workers_is_four(self) -> None:
        self._assert_workers([], 4)

    def test_explicit_positive_workers(self) -> None:
        for workers in (1, 2, 7):
            with self.subTest(workers=workers):
                self._assert_workers(["--workers", str(workers)], workers)

    def test_rejects_nonpositive_workers(self) -> None:
        for workers in ("0", "-1"):
            with self.subTest(workers=workers), TemporaryDirectory() as directory:
                with (
                    patch("kpatch.cli.GitDb.load_name"),
                    patch("kpatch.cli.ConfigFilter") as configured,
                    patch("kpatch.cli.run_filter") as run_filter,
                ):
                    result = CliRunner().invoke(
                        app,
                        [
                            "filter", "--repo", directory, "--db", "unused-source",
                            "--dest", "unused-destination", "config", "--workers", workers,
                        ],
                    )
                    self.assertEqual(result.exit_code, 2, result.output)
                    self.assertIn("--workers", result.output)
                    configured.assert_not_called()
                    run_filter.assert_not_called()

    def test_without_config_has_no_parallel_phase(self) -> None:
        with TemporaryDirectory() as directory:
            with (
                patch("kpatch.cli.GitDb.load_name"),
                patch("kpatch.cli.ConfigFilter") as configured,
                patch("kpatch.cli.run_filter") as run_filter,
            ):
                result = CliRunner().invoke(
                    app,
                    [
                        "filter", "--repo", directory, "--db", "unused-source",
                        "--dest", "unused-destination", "config", "--workers", "3",
                    ],
                )
                self.assertEqual(result.exit_code, 0, result.output)
                configured.assert_not_called()
                pipeline = cast(FilterPipeline, run_filter.call_args.args[1])
                self.assertEqual(
                    [type(stage) for stage in pipeline.filters],
                    [MergeCommitFilter, WhitespaceFilter],
                )


if __name__ == "__main__":
    unittest.main()
