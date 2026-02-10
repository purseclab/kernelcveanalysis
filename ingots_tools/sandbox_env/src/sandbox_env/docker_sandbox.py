from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass
from typing import Optional

import docker  # type: ignore
from deepagents.backends.protocol import (
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
    SandboxBackendProtocol,
)
from deepagents.backends.sandbox import (
    BaseSandbox,
)
import typer

@dataclass
class DockerMetadata:
    id: str
    status: str
    image: str
    created: str
    name: str


class DockerSandbox(BaseSandbox):
    def __init__(self, container: docker.models.containers.Container):
        self.container = container

    @property
    def id(self) -> str:
        return self.container.id

    def execute(
        self,
        command: str,
    ) -> ExecuteResponse:
        # Wrap command in shell to support heredocs and complex redirection used by BaseSandbox
        wrapped_cmd = ["/bin/sh", "-c", command]
        exit_code, output = self.container.exec_run(wrapped_cmd, demux=False)

        try:
            output_str = output.decode("utf-8")
        except UnicodeDecodeError:
            output_str = output.decode("utf-8", errors="replace")

        return ExecuteResponse(
            output=output_str,
            exit_code=exit_code,
            truncated=False,  # Docker output truncation handling would require more logic
        )

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        responses = []
        for path, content in files:
            try:
                # Create tar stream in memory
                file_obj = io.BytesIO(content)
                tar_stream = io.BytesIO()
                with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                    info = tarfile.TarInfo(name=os.path.basename(path))
                    info.size = len(content)
                    tar.addfile(info, file_obj)

                tar_stream.seek(0)
                dirname = os.path.dirname(path)
                if not dirname:
                    dirname = "/"

                # Ensure directory exists before uploading?
                # For now, rely on docker put_archive handling.
                self.container.put_archive(path=dirname, data=tar_stream)
                responses.append(FileUploadResponse(path=path))
            except Exception as e:
                responses.append(FileUploadResponse(path=path, error=str(e)))
        return responses

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        responses = []
        for path in paths:
            try:
                bits, stat = self.container.get_archive(path)
                # Reconstruct tar stream
                tar_stream = io.BytesIO()
                for chunk in bits:
                    tar_stream.write(chunk)
                tar_stream.seek(0)

                with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                    member = tar.next()
                    if member and member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            # Try to decode if text, or return bytes?
                            # Protocol says content is bytes usually?
                            # Wait, SandboxBackendProtocol definition wasn't fully visible but usually it handles bytes/str.
                            # Let's check BaseSandbox usage.
                            # Actually FileDownloadResponse usually expects bytes or str?
                            # If the library expects bytes, fine. If str, decode.
                            # Checking BaseSandbox read() it returns str.
                            # But download_files is for batch transfer.
                            # Let's assume bytes for download_files or decode if possible.
                            # Given the type hint wasn't explicit in my read, I'll stick to bytes if the response object supports it,
                            # or try decode.
                            # Let's look at the protocol definition I saw in `sandbox.py` imports...
                            # `FileDownloadResponse` structure wasn't shown in detail.
                            # But usually these are for file contents.
                            # I'll return bytes if the class accepts it, otherwise decode.
                            # Assuming bytes for now as it is safest for binary files.
                            responses.append(FileDownloadResponse(path=path, content=content))  # type: ignore
                        else:
                            responses.append(
                                FileDownloadResponse(path=path, error="Could not extract file")
                            )
                    else:
                        responses.append(
                            FileDownloadResponse(
                                path=path, error="Path is not a regular file or not found"
                            )
                        )
            except Exception as e:
                responses.append(FileDownloadResponse(path=path, error=str(e)))
        return responses

IMAGE_TAG = 'kexploit_sandbox'

class DockerSandboxProvider:
    def __init__(self) -> None:
        self.client = docker.from_env()

    def build_image(self):
        docker_build_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
        self.client.images.build(
            path=docker_build_dir,
            rm=True,
            tag=IMAGE_TAG,
        )

    def list(
        self,
        *,
        status: str | None = None,
    ) -> list[DockerMetadata]:
        filters = {"label": "created_by=deepagents"}
        if status:
            filters["status"] = status

        containers = self.client.containers.list(all=True, filters=filters)

        items = []
        for c in containers:
            items.append(DockerMetadata(
                id=c.id,
                status=c.status,
                image=str(c.image.tags),
                created=c.attrs.get('Created', ''),
                name=c.name,
            ))

        return items

    def create_instance(self, *, name: Optional[str] = None) -> SandboxBackendProtocol:
        image = client.containers.get(IMAGE_TAG)
        container = self.client.containers.run(
            image,
            command="/bin/sh -c 'while true; do sleep 3600; done'",
            detach=True,
            name=name,
            labels={"created_by": "deepagents"},
            cap_drop=['ALL'],
            security_opt=[],
        )

        return DockerSandbox(container)

    def get_instance(self, sandbox_id) -> SandboxBackendProtocol:
        try:
            container = self.client.containers.get(sandbox_id)
            if container.status != "running":
                container.start()
            return DockerSandbox(container)
        except docker.errors.NotFound as e:
            raise Exception(f"Sandbox {sandbox_id} not found") from e

    def delete(
        self,
        sandbox_id: str,
        *,
        force: bool = True,
    ) -> None:
        try:
            container = self.client.containers.get(sandbox_id)
            container.remove(force=force)
        except docker.errors.NotFound:
            pass

app = typer.Typer()

@app.command(help='Build docker image for sandbox')
def build_image():
    provider = DockerSandboxProvider()
    provider.build_image()

def main():
    app()
