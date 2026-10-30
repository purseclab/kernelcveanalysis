from __future__ import annotations

import typer

from .models import VerificationResult


def _fmt(value: str | None) -> str:
    return value if value else "-"


def print_human_result(result: VerificationResult) -> None:
    metadata = result.metadata
    if metadata is None:
        metadata_text = "none (using CLI overrides)"
    else:
        payload = metadata.payload
        payload_text = payload.kind
        if payload.ip:
            payload_text += f" {payload.ip}"
        if payload.port:
            payload_text += f":{payload.port}"
        metadata_text = (
            f"{metadata.source}: {metadata.target}/{metadata.arch or '?'}/"
            f"{metadata.artifact}/{payload_text}"
        )

    typer.echo("")
    typer.echo(f"template:         {_fmt(result.template)}")
    typer.echo(f"template selinux: {_fmt(result.template_selinux)}")
    typer.echo(f"instance:         {result.instance_name}")
    typer.echo(f"adb:              {result.adb_target}")
    typer.echo(f"poc:              {result.local_poc}")
    typer.echo(f"poc sha256:       {result.poc_sha256}")
    typer.echo(f"metadata:         {metadata_text}")
    typer.echo(f"artifact:         {result.plan.artifact} ({result.plan.run_mode})")
    typer.echo(f"payload:          {result.plan.payload.kind}")
    if result.plan.from_app:
        typer.echo(f"app context:      {result.plan.app_package}")
        if result.plan.app_apk_path:
            typer.echo(f"app apk:          {result.plan.app_apk_path}")
        if result.plan.app_port:
            typer.echo(f"app port:         {result.plan.app_port}")
    if result.before is not None:
        typer.echo(f"kernel:           {result.before.kernel}")
        typer.echo(f"uid before:       {result.before.uid_id}")
        typer.echo(f"selinux before:   {result.before.selinux}")
    if result.after is not None:
        typer.echo(f"uid after:        {result.after.uid_id}")
        typer.echo(f"selinux after:    {result.after.selinux}")
    if result.root_flag_path:
        typer.echo(f"root flag:        {result.root_flag_path}")
    typer.echo(
        f"root token:       {'matched' if result.root_token_matched else 'not matched'}"
        f" (uid=0 seen: {'yes' if result.root_uid_seen else 'no'})"
    )
    typer.echo(f"attempts:         {result.attempts}")
    typer.echo(f"duration:         {result.duration_sec:.2f}s")
    typer.echo(f"result:           {'PASS' if result.passed else 'FAIL'}: {result.reason}")

    if result.warnings:
        typer.echo("warnings:")
        for warning in result.warnings:
            typer.echo(f"  - {warning}")

    if result.command:
        typer.echo("")
        typer.echo("command:")
        typer.echo(f"  {result.command}")

    if result.output:
        typer.echo("")
        typer.echo("guest output:")
        output = result.output
        if len(output) > 12000:
            output = "[... output truncated ...]\n" + output[-12000:]
        typer.echo(output.rstrip())
    typer.echo("")
