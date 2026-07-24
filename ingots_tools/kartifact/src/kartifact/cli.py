from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Annotated, Any, Callable, TypeVar

import typer

from .errors import KartifactError, SourceUpdateError
from .models import ArtifactInfo
from .registry import default_registry
from .store import ArtifactStore


app = typer.Typer(add_completion=False, no_args_is_help=True)


@dataclass(frozen=True)
class CliContext:
    json_output: bool


@app.callback()
def callback(
    ctx: typer.Context,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON output."),
    ] = False,
) -> None:
    ctx.obj = CliContext(json_output=json_output)


def _build_store() -> ArtifactStore:
    return ArtifactStore(default_registry)


def _emit(ctx: typer.Context, human: str, payload: Any, error: bool = False) -> None:
    state = ctx.ensure_object(CliContext)
    if state.json_output:
        typer.echo(json.dumps(payload, indent=2), err=error)
    else:
        typer.echo(human, err=error)


def _info_payload(info: ArtifactInfo) -> dict[str, Any]:
    return info.model_dump(mode="json")


ReturnT = TypeVar("ReturnT")


def _run(ctx: typer.Context, operation: Callable[[], ReturnT]) -> ReturnT:
    try:
        return operation()
    except KartifactError as exc:
        payload: dict[str, Any] = {"error": exc.code, "message": str(exc)}
        if isinstance(exc, SourceUpdateError):
            payload["artifact"] = _info_payload(exc.artifact)

        _emit(ctx, f"Error: {exc}", payload, error=True)
        raise typer.Exit(code=1) from exc


@app.command("create")
def create_template(
    ctx: typer.Context,
    artifact_type: Annotated[str, typer.Argument(help="Registered artifact type.")],
    folder: Annotated[Path, typer.Argument(help="Missing or empty destination folder.")],
    name: Annotated[str, typer.Option("--name", help="Filesystem-safe artifact name.")],
) -> None:
    def operation() -> Path:
        with _build_store() as store:
            return store.create_template(artifact_type, folder, name=name)

    output = _run(ctx, operation)
    _emit(
        ctx,
        f"Created {output}",
        {
            "artifact_type": artifact_type,
            "name": name,
            "folder": str(folder),
            "artifact_toml": str(output),
        },
    )


@app.command("write")
def write_artifact(
    ctx: typer.Context,
    folder: Annotated[Path, typer.Argument(help="Artifact working folder.")],
) -> None:
    def operation() -> ArtifactInfo:
        with _build_store() as store:
            return store.write_artifact(folder)

    info = _run(ctx, operation)
    _emit(ctx, f"Wrote {info.artifact_type}/{info.name} ({info.id})", _info_payload(info))


@app.command("list")
def list_artifacts(
    ctx: typer.Context,
    artifact_type: Annotated[str, typer.Argument(help="Registered artifact type.")],
    include_shadowed: Annotated[
        bool,
        typer.Option("--include-shadowed", help="Include superseded revisions."),
    ] = False,
) -> None:
    def operation() -> list[ArtifactInfo]:
        with _build_store() as store:
            return store.list_artifacts(
                artifact_type,
                include_shadowed=include_shadowed,
            )

    artifacts = _run(ctx, operation)
    payload = {"artifact_type": artifact_type, "artifacts": [_info_payload(a) for a in artifacts]}
    if artifacts:
        lines = ["ID  NAME  PARENT  CREATED  SHADOWED"]
        lines.extend(
            f"{artifact.id}  {artifact.name}  {artifact.parent_id or '-'}  "
            f"{artifact.created_at.isoformat()}  {'yes' if artifact.shadowed else 'no'}"
            for artifact in artifacts
        )
        human = "\n".join(lines)
    else:
        human = f"No {artifact_type} artifacts."
    _emit(ctx, human, payload)


@app.command("pull")
def pull_artifact(
    ctx: typer.Context,
    artifact_id: Annotated[str, typer.Argument(help="Immutable artifact revision UUID.")],
    folder: Annotated[Path, typer.Argument(help="Missing or empty destination folder.")],
) -> None:
    def operation() -> ArtifactInfo:
        with _build_store() as store:
            return store.pull_artifact(artifact_id, folder)

    info = _run(ctx, operation)
    _emit(
        ctx,
        f"Pulled {info.artifact_type}/{info.name} ({info.id}) to {folder}",
        {"artifact": _info_payload(info), "folder": str(folder)},
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
