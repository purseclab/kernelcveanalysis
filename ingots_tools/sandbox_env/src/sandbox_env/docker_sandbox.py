from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass
from typing import Optional, Self

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

WORKDIR = "/exp"

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

        truncated = False
        if len(output_str) > 128_000:
            output_str = output_str[:128_000]
            truncated = True

        return ExecuteResponse(
            output=output_str,
            exit_code=exit_code,
            truncated=truncated,
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

    def upload_workdir(self, src_path: Path):
        # tar src file into BytesIO
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar:
            # arcname='.' ensures files are not nested in tar
            tar.add(src_path, arcname='.')
        tar_stream.seek(0)

        # delete old workdir if it exists
        self.execute(f'rm -rf {WORKDIR}')
        # must make directory for put_archive to work
        self.execute(f'mkdir {WORKDIR}')

        self.container.put_archive(path=WORKDIR, data=tar_stream)

    def download_workdir(self, dst_path: Path):
        bits, state = self.container.get_archive(WORKDIR)
        # Reconstruct tar stream
        tar_stream = io.BytesIO()
        for chunk in bits:
            tar_stream.write(chunk)
        tar_stream.seek(0)

        with tarfile.open(fileobj=tar_stream, mode='r') as tar:
            members = []

            for member in tar.getmembers():
                member.name = '/'.join(member.name.split('/')[1:])
                if member.name.strip() == '':
                    member.name == '.'
                else:
                    member.name = './' + member.name

                members.append(member)

            tar.extractall(path=dst_path, members=members)

IMAGE_TAG = 'kexploit_sandbox'

_PROVIDER = None

class DockerSandboxProvider:
    def __init__(self) -> None:
        self.client = docker.from_env()

    @classmethod
    def get(cls) -> Self:
        global _PROVIDER

        if _PROVIDER is None:
            _PROVIDER = cls()

        return _PROVIDER

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

    def create_instance(self, *, name: Optional[str] = None) -> DockerSandbox:
        image = self.client.images.get(IMAGE_TAG)
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

    def get_instance(self, sandbox_id) -> DockerSandbox:
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
    provider = DockerSandboxProvider.get()
    # try:
    #     sandbox = provider.create_instance()
    #     from pathlib import Path
    #     sandbox.upload_workdir(Path('./template'))
    #     sandbox.execute('echo lmao > /exp/out')
    #     sandbox.download_workdir(Path('./template_modified'))
    # finally:
    #     provider.delete(sandbox.id)
    print('building image...')
    provider.build_image()

def main():
    app()
