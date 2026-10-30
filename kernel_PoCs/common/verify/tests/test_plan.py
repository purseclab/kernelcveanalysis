from __future__ import annotations

from pathlib import Path

import pytest

from verify_kernel_poc.cli import _resolve_metadata
from verify_kernel_poc.metadata import MetadataScan
from verify_kernel_poc.models import Metadata, PayloadSpec, RunPlan, UnsupportedError
from verify_kernel_poc.rootcheck import build_root_check_lines, pipeline_command
from verify_kernel_poc.runner import build_app_intent, build_run_command


def _metadata(**overrides: object) -> Metadata:
    data = {
        "schema": 1,
        "target": "android",
        "arch": "aarch64",
        "artifact": "executable",
        "run": "exec",
        "payload": {"kind": "shell"},
        "root_check": {"mode": "shell"},
    }
    data.update(overrides)
    return Metadata.from_dict(data)


def test_resolve_uses_metadata() -> None:
    scan = MetadataScan(metadata=_metadata())
    (
        metadata,
        artifact,
        run_mode,
        payload,
        root_check,
        run_command,
    ) = _resolve_metadata(
        scan,
        artifact="auto",
        payload="auto",
        payload_ip=None,
        payload_port=None,
        root_check="auto",
        run_command=None,
    )

    assert metadata is scan.metadata
    assert artifact == "executable"
    assert run_mode == "exec"
    assert payload.kind == "shell"
    assert root_check == "flag"
    assert run_command is None


def test_resolve_cli_overrides() -> None:
    scan = MetadataScan(
        metadata=_metadata(
            artifact="shared",
            run="ld_preload",
            payload={"kind": "listening_shell", "port": 1337},
        )
    )
    (
        _,
        artifact,
        run_mode,
        payload,
        root_check,
        _,
    ) = _resolve_metadata(
        scan,
        artifact="executable",
        payload="reverse-shell",
        payload_ip="127.0.0.1",
        payload_port=4444,
        root_check="regex",
        run_command=None,
    )

    assert artifact == "executable"
    assert run_mode == "exec"
    assert payload == PayloadSpec(
        kind="reverse_shell", ip="127.0.0.1", port=4444
    )
    assert root_check == "regex"


def test_jni_requires_run_command() -> None:
    scan = MetadataScan(metadata=_metadata(artifact="jni", run="jni"))
    with pytest.raises(UnsupportedError):
        from verify_kernel_poc.cli import _build_plan

        _build_plan(
            poc=Path("/tmp/exp"),
            remote_path="/data/local/tmp/exp",
            metadata=scan.metadata,
            artifact="jni",
            run_mode="jni",
            payload=PayloadSpec(),
            root_check="flag",
            run_command=None,
            root_check_command=None,
            root_check_regex=None,
            poc_args=[],
        )


def test_run_commands() -> None:
    base = dict(
        artifact="executable",
        run_mode="exec",
        payload=PayloadSpec(),
        run_command=None,
        poc_args=("--preflight",),
        root_check_mode="flag",
        root_check_command=None,
        root_check_regex=None,
        remote_path="/data/local/tmp/x/exp",
        local_path="/tmp/exp",
        metadata=None,
    )
    plan = RunPlan(**base)
    assert build_run_command(plan) == "/data/local/tmp/x/exp --preflight"

    shared = RunPlan(**{**base, "artifact": "shared", "run_mode": "ld_preload"})
    assert (
        build_run_command(shared)
        == "LD_PRELOAD=/data/local/tmp/x/exp /system/bin/sleep 200"
    )

    custom = RunPlan(**{**base, "run_command": "env A=1 {poc}"})
    assert (
        build_run_command(custom)
        == "env A=1 /data/local/tmp/x/exp"
    )


def test_root_check_lines_and_pipeline() -> None:
    lines = build_root_check_lines(None, command=None, regex=None)
    assert lines == ["id", "getenforce", "exit"]
    command = pipeline_command("/data/local/tmp/exp", ["id", "cat '/x y'"])
    assert command.startswith("printf '%s\\n'")
    assert " | /data/local/tmp/exp" in command


def test_app_mode_requires_shared_or_jni() -> None:
    from verify_kernel_poc.cli import _build_plan

    with pytest.raises(UnsupportedError, match="shared or jni"):
        _build_plan(
            poc=Path("/tmp/exp"),
            remote_path="/data/local/tmp/exp",
            metadata=None,
            artifact="executable",
            run_mode="exec",
            payload=PayloadSpec(),
            root_check="flag",
            run_command=None,
            root_check_command=None,
            root_check_regex=None,
            poc_args=[],
            from_app=True,
            app_package="com.purdue.kpoc.verify",
            app_apk="/tmp/helper.apk",
            app_path="/data/data/com.purdue.kpoc.verify/files/exp.so",
        )


def test_app_mode_intent() -> None:
    plan = RunPlan(
        artifact="jni",
        run_mode="jni",
        payload=PayloadSpec(),
        run_command=None,
        poc_args=(),
        root_check_mode="flag",
        root_check_command=None,
        root_check_regex=None,
        remote_path="/data/local/tmp/x/exp.so",
        local_path="/tmp/exp.so",
        metadata=None,
        from_app=True,
        app_package="com.purdue.kpoc.verify",
        app_apk="/tmp/helper.apk",
        app_apk_path="/data/app/x/base.apk",
        app_path="/data/data/com.purdue.kpoc.verify/files/exp.so",
        app_port=23456,
        app_mode="jni",
    )

    command = build_app_intent(plan, pump=True)
    assert command.startswith("am start -W -n com.purdue.kpoc.verify/.RunActivity ")
    assert "--es mode jni" in command
    assert "--ei port 23456" in command
    assert "--es lib_path /data/data/com.purdue.kpoc.verify/files/exp.so" in command
