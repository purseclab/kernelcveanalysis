from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from verify_kernel_poc.cli import app
from verify_kernel_poc.metadata import BEGIN_MARKER, END_MARKER


def _binary(path: Path, block: dict[str, object]) -> Path:
    path.write_bytes(
        b"\x00ELF\x00"
        + BEGIN_MARKER
        + json.dumps(block).encode()
        + END_MARKER
        + b"\x00"
    )
    return path


def test_print_metadata(tmp_path: Path) -> None:
    poc = _binary(tmp_path / "exp", {"schema": 1, "target": "android"})
    result = CliRunner().invoke(app, ["--print-metadata", str(poc)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["found"] is True
    assert payload["metadata"]["target"] == "android"


def test_dry_run_needs_no_guest(tmp_path: Path) -> None:
    poc = _binary(
        tmp_path / "exp",
        {
            "schema": 1,
            "target": "android",
            "artifact": "shared",
            "run": "ld_preload",
            "payload": {"kind": "shell"},
        },
    )
    result = CliRunner().invoke(app, ["--dry-run", str(poc)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["artifact"] == "shared"
    assert payload["plan"]["root_check_mode"] == "flag"


def test_print_metadata_missing_file() -> None:
    result = CliRunner().invoke(app, ["--print-metadata", "/does/not/exist"])

    assert result.exit_code == 2
    assert "PoC is not a file" in (result.stderr or "")


def test_from_app_dry_run(tmp_path: Path) -> None:
    poc = _binary(
        tmp_path / "exp.so",
        {
            "schema": 1,
            "target": "android",
            "artifact": "jni",
            "run": "jni",
            "payload": {"kind": "shell"},
        },
    )
    result = CliRunner().invoke(
        app, ["--dry-run", "--from-app", "1", str(poc)]
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["from_app"] is True
    assert payload["plan"]["app_package"] == "com.purdue.kpoc.verify.one"
    assert payload["plan"]["app_path"].startswith(
        "/data/data/com.purdue.kpoc.verify.one/files/"
    )
    assert payload["plan"]["app_port"] >= 20000
    assert payload["plan"]["app_mode"] == "jni"


def test_from_app_rejects_executable(tmp_path: Path) -> None:
    poc = _binary(
        tmp_path / "exp",
        {
            "schema": 1,
            "target": "android",
            "artifact": "executable",
            "run": "exec",
        },
    )
    result = CliRunner().invoke(
        app, ["--dry-run", "--from-app", "2", str(poc)]
    )

    assert result.exit_code == 3
    assert "shared or jni" in (result.stderr or "")


def test_from_app_all_dry_run(tmp_path: Path) -> None:
    poc = _binary(
        tmp_path / "exp.so",
        {
            "schema": 1,
            "target": "android",
            "artifact": "shared",
            "run": "ld_preload",
            "payload": {"kind": "shell"},
        },
    )
    result = CliRunner().invoke(
        app, ["--dry-run", "--from-app", "all", str(poc)]
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [run["app"] for run in payload["runs"]] == ["1", "2"]
    assert payload["runs"][0]["plan"]["app_package"] == (
        "com.purdue.kpoc.verify.one"
    )
    assert payload["runs"][1]["plan"]["app_package"] == (
        "com.purdue.kpoc.verify.two"
    )


def test_normalize_bare_from_app() -> None:
    from verify_kernel_poc.cli import _normalize_from_app_args

    assert _normalize_from_app_args(["--from-app", "1"]) == [
        "--from-app",
        "1",
    ]
    assert _normalize_from_app_args(["--from-app", "/tmp/exp"]) == [
        "--from-app",
        "random",
        "/tmp/exp",
    ]
    assert _normalize_from_app_args(["--from-app", "all"]) == [
        "--from-app",
        "all",
    ]


def test_run_only_dry_run(tmp_path: Path) -> None:
    poc = _binary(
        tmp_path / "exp",
        {
            "schema": 1,
            "target": "android",
            "artifact": "executable",
            "run": "exec",
            "payload": {"kind": "shell"},
        },
    )
    result = CliRunner().invoke(app, ["--dry-run", "--run-only", str(poc)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["plan"]["root_check_mode"] == "none"


def test_run_only_rejects_root_options(tmp_path: Path) -> None:
    poc = _binary(tmp_path / "exp", {"schema": 1, "target": "android"})
    result = CliRunner().invoke(
        app,
        ["--dry-run", "--run-only", "--root-check", "flag", str(poc)],
    )

    assert result.exit_code == 2
    assert "cannot be combined" in (result.stderr or "")
