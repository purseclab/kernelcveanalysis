from __future__ import annotations

from enum import StrEnum
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from typing import Self
from uuid import UUID
import zlib

from kexploit_utils import Architecture  # type: ignore[attr-defined]
from sqlalchemy import Boolean, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from ..errors import InvalidArtifactError
from ..models import (
    NAME_PATTERN,
    ArtifactHeader,
    ArtifactInfo,
    ArtifactMetadata,
    ArtifactRecord,
)
from ..registry import ArtifactDefinition
from ..store import ArtifactStore
from ..toml_io import ARTIFACT_FILE_NAME, render_artifact


class KernelFile(StrEnum):
    IMAGE = "image"
    VMLINUX = "vmlinux"


class KernelOptionalFile(StrEnum):
    CONFIG = "config"
    INITRD = "initrd"


IMAGE_FILE_NAME = KernelFile.IMAGE.value
VMLINUX_FILE_NAME = KernelFile.VMLINUX.value
CONFIG_FILE_NAME = KernelOptionalFile.CONFIG.value
INITRD_FILE_NAME = KernelOptionalFile.INITRD.value


class KernelRecord(ArtifactRecord):
    __tablename__ = "kernel_artifacts"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        primary_key=True,
    )
    architecture: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    full_version: Mapped[str | None] = mapped_column(String(512), nullable=True)
    has_config: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_initrd: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __mapper_args__ = {"polymorphic_identity": "kernel"}


class KernelMetadata(ArtifactMetadata[KernelRecord]):
    architecture: Architecture
    version: str
    full_version: str | None = None
    has_config: bool = False
    has_initrd: bool = False

    mandatory_files = KernelFile
    optional_files = KernelOptionalFile


    @classmethod
    def default(cls) -> Self:
        return cls(
            architecture=Architecture.AMD64,
            version="unknown",
        )

    def build_updated_record(self, old: KernelRecord | None) -> KernelRecord:
        del old
        return KernelRecord(
            architecture=str(self.architecture),
            version=self.version,
            full_version=self.full_version,
            has_config=self.has_config,
            has_initrd=self.has_initrd,
        )


KERNEL_DEFINITION = ArtifactDefinition(
    type_name="kernel",
    metadata_model=KernelMetadata,
    record_model=KernelRecord,
    supports_create=False,
)


def detect_elf_architecture(elf_path: Path) -> Architecture:
    with open(elf_path, "rb") as f:
        ident = f.read(20)
    if len(ident) < 20 or ident[:4] != b"\x7fELF":
        raise InvalidArtifactError(f"{elf_path} is not a valid ELF binary")
    endian = "<" if ident[5] == 1 else ">"
    e_machine = struct.unpack(f"{endian}H", ident[18:20])[0]
    match e_machine:
        case 62:  # EM_X86_64
            return Architecture.AMD64
        case 183:  # EM_AARCH64
            return Architecture.AARCH64
        case 40:  # EM_ARM
            return Architecture.ARM
        case 3:  # EM_386
            return Architecture.X86
        case _:
            raise InvalidArtifactError(f"unsupported ELF e_machine: {e_machine}")


def extract_kernel_config(elf_path: Path) -> bytes | None:
    with open(elf_path, "rb") as f:
        data = f.read()
    pos = data.find(b"IKCFG_ST\x1f\x8b\x08")
    if pos == -1:
        return None
    try:
        return zlib.decompress(data[pos + 8 :], 16 + zlib.MAX_WBITS)
    except Exception:
        return None


def parse_version_from_output(stdout: str) -> tuple[str, str | None]:
    match = re.search(r"Version string:\s*Linux version\s+([^\s]+)(?:\s+(.*))?", stdout)
    if match:
        version = match.group(1)
        rest = match.group(2) or ""
        full_version = f"Linux version {version} {rest}".strip()
        return version, full_version
    return "unknown", None


def run_vmlinux_to_elf(input_image: Path, output_elf: Path) -> str:
    try:
        proc = subprocess.run(
            ["vmlinux-to-elf", str(input_image), str(output_elf)],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout
    except FileNotFoundError as exc:
        raise InvalidArtifactError(
            "vmlinux-to-elf executable not found in PATH; please ensure it is installed"
        ) from exc
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.strip() or exc.stdout.strip()
        raise InvalidArtifactError(f"vmlinux-to-elf conversion failed: {err}") from exc


def import_kernel_artifact(
    store: ArtifactStore,
    image: Path,
    name: str,
    initrd: Path | None = None,
) -> ArtifactInfo:
    if not NAME_PATTERN.fullmatch(name):
        raise InvalidArtifactError(
            "artifact name must contain 1-128 letters, digits, '.', '_', or '-'"
        )

    image_path = Path(image).resolve()
    if not image_path.is_file():
        raise InvalidArtifactError(f"kernel image not found or not a file: {image_path}")

    initrd_path: Path | None = None
    if initrd is not None:
        initrd_path = Path(initrd).resolve()
        if not initrd_path.is_file():
            raise InvalidArtifactError(
                f"initrd not found or not a file: {initrd_path}"
            )

    temp_dir = Path(tempfile.mkdtemp(prefix="kartifact-kernel-import-"))
    try:
        target_image = temp_dir / IMAGE_FILE_NAME
        shutil.copyfile(image_path, target_image)

        has_initrd = False
        if initrd_path is not None:
            target_initrd = temp_dir / INITRD_FILE_NAME
            shutil.copyfile(initrd_path, target_initrd)
            has_initrd = True

        target_vmlinux = temp_dir / VMLINUX_FILE_NAME
        stdout = run_vmlinux_to_elf(target_image, target_vmlinux)

        if not target_vmlinux.is_file() or target_vmlinux.stat().st_size == 0:
            raise InvalidArtifactError(
                "vmlinux-to-elf did not generate a valid ELF file"
            )

        arch = detect_elf_architecture(target_vmlinux)
        version, full_version = parse_version_from_output(stdout)

        has_config = False
        config_bytes = extract_kernel_config(target_vmlinux)
        if config_bytes is not None:
            (temp_dir / CONFIG_FILE_NAME).write_bytes(config_bytes)
            has_config = True

        metadata = KernelMetadata(
            architecture=arch,
            version=version,
            full_version=full_version,
            has_config=has_config,
            has_initrd=has_initrd,
        )
        header = ArtifactHeader(type=KERNEL_DEFINITION.type_name, name=name)
        (temp_dir / ARTIFACT_FILE_NAME).write_text(
            render_artifact(header, metadata),
            encoding="utf-8",
        )

        return store.commit_imported_artifact(temp_dir)
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

