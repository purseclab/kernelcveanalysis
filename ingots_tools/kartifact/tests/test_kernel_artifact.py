from __future__ import annotations

import json
from pathlib import Path
import struct
import tomllib
from typing import Iterator
import gzip
import zlib

from kexploit_utils import Architecture  # type: ignore[attr-defined]
import pytest  # type: ignore[import-not-found]
from typer.testing import CliRunner

from kartifact import (
    ArtifactRegistry,
    ArtifactStore,
    CreateNotSupportedError,
    InvalidArtifactError,
    cli,
    default_registry,
)
from kartifact.artifacts.kernel import (
    CONFIG_FILE_NAME,
    IMAGE_FILE_NAME,
    INITRD_FILE_NAME,
    KERNEL_DEFINITION,
    VMLINUX_FILE_NAME,
    KernelFile,
    KernelMetadata,
    KernelOptionalFile,
    detect_elf_architecture,
    extract_kernel_config,
    import_kernel_artifact,
    parse_version_from_output,
)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ArtifactStore]:
    registry = ArtifactRegistry()
    registry.register(KERNEL_DEFINITION)
    val = ArtifactStore(registry, tmp_path / "db")
    yield val
    val.close()


def make_dummy_elf(e_machine: int = 62, ikconfig_bytes: bytes | None = None) -> bytes:
    # 64-byte ELF header (ELF64, little-endian, e_machine at byte 18)
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # 64-bit
    hdr[5] = 1  # little-endian
    hdr[6] = 1  # version
    struct.pack_into("<H", hdr, 18, e_machine)
    data = bytes(hdr) + b"\x00" * 128
    if ikconfig_bytes is not None:
        data += b"PADDING" + b"IKCFG_ST" + gzip.compress(ikconfig_bytes)
    return data


def test_kernel_definition_rejects_create_and_write(tmp_path: Path, store: ArtifactStore) -> None:
    assert KERNEL_DEFINITION.supports_create is False

    dest = tmp_path / "kernel_template"
    with pytest.raises(CreateNotSupportedError):
        store.create_template("kernel", dest, name="test-kernel")

    working = tmp_path / "working"
    working.mkdir()
    (working / "artifact.toml").write_text(
        '[artifact]\ntype = "kernel"\nname = "test-kernel"\n[metadata]\narchitecture = "amd64"\nversion = "5.10"\n',
        encoding="utf-8",
    )
    with pytest.raises(CreateNotSupportedError):
        store.write_artifact(working)


def test_detect_elf_architecture(tmp_path: Path) -> None:
    # Test valid architectures
    arch_cases = [
        (62, Architecture.AMD64),
        (183, Architecture.AARCH64),
        (40, Architecture.ARM),
        (3, Architecture.X86),
    ]
    for em, expected in arch_cases:
        elf_file = tmp_path / f"elf_{em}.bin"
        elf_file.write_bytes(make_dummy_elf(e_machine=em))
        assert detect_elf_architecture(elf_file) == expected

    # Test invalid e_machine
    bad_elf = tmp_path / "bad_elf.bin"
    bad_elf.write_bytes(make_dummy_elf(e_machine=999))
    with pytest.raises(InvalidArtifactError, match="unsupported ELF e_machine"):
        detect_elf_architecture(bad_elf)

    # Test non-ELF
    not_elf = tmp_path / "not_elf.bin"
    not_elf.write_bytes(b"HELLO_NOT_ELF")
    with pytest.raises(InvalidArtifactError, match="not a valid ELF binary"):
        detect_elf_architecture(not_elf)


def test_extract_kernel_config(tmp_path: Path) -> None:
    config_content = b"CONFIG_FOO=y\nCONFIG_BAR=m\n"
    elf_with_config = tmp_path / "with_config.elf"
    elf_with_config.write_bytes(make_dummy_elf(ikconfig_bytes=config_content))

    extracted = extract_kernel_config(elf_with_config)
    assert extracted is not None
    assert extracted == config_content

    elf_no_config = tmp_path / "no_config.elf"
    elf_no_config.write_bytes(make_dummy_elf())
    assert extract_kernel_config(elf_no_config) is None


def test_parse_version_from_output() -> None:
    sample_stdout = (
        "[+] Kernel successfully decompressed in-memory\n"
        "[+] Version string: Linux version 5.10.107+ (jack@build) (gcc 10.5.0) #1 SMP Mon Apr 27 2026\n"
        "[+] Guessed architecture: x86_64 successfully in 13.70 seconds\n"
    )
    ver, full = parse_version_from_output(sample_stdout)
    assert ver == "5.10.107+"
    assert full == "Linux version 5.10.107+ (jack@build) (gcc 10.5.0) #1 SMP Mon Apr 27 2026"

    # Missing banner
    ver2, full2 = parse_version_from_output("no version here")
    assert ver2 == "unknown"
    assert full2 is None


def test_import_kernel_artifact_full_flow(
    tmp_path: Path, store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    image_file = tmp_path / "bzImage"
    image_file.write_bytes(b"FAKE_BZIMAGE_DATA")

    initrd_file = tmp_path / "initrd.cpio.gz"
    initrd_file.write_bytes(b"FAKE_INITRD_DATA")

    config_content = b"CONFIG_TEST=y\n"
    dummy_elf = make_dummy_elf(e_machine=62, ikconfig_bytes=config_content)

    def mock_run_vmlinux_to_elf(input_img: Path, output_elf: Path) -> str:
        output_elf.write_bytes(dummy_elf)
        return (
            "[+] Version string: Linux version 5.10.107+ (jack@test) #1 SMP 2026\n"
            "[+] Guessed architecture: x86_64\n"
        )

    import kartifact.artifacts.kernel as kernel_mod

    monkeypatch.setattr(kernel_mod, "run_vmlinux_to_elf", mock_run_vmlinux_to_elf)

    info = import_kernel_artifact(
        store=store,
        image=image_file,
        name="linux-5.10-test",
        initrd=initrd_file,
    )

    assert info.name == "linux-5.10-test"
    assert info.artifact_type == "kernel"

    # Pull the artifact to a checkout destination and verify all files
    checkout = tmp_path / "checkout"
    pulled_info = store.pull_artifact(info.id, checkout)
    assert pulled_info.id == info.id

    assert (checkout / IMAGE_FILE_NAME).read_bytes() == b"FAKE_BZIMAGE_DATA"
    assert (checkout / VMLINUX_FILE_NAME).read_bytes() == dummy_elf
    assert (checkout / INITRD_FILE_NAME).read_bytes() == b"FAKE_INITRD_DATA"
    assert (checkout / CONFIG_FILE_NAME).read_bytes() == config_content

    manifest = tomllib.loads((checkout / "artifact.toml").read_text(encoding="utf-8"))
    assert manifest["artifact"]["type"] == "kernel"
    assert manifest["artifact"]["name"] == "linux-5.10-test"
    assert manifest["metadata"]["architecture"] == "amd64"
    assert manifest["metadata"]["version"] == "5.10.107+"
    assert manifest["metadata"]["has_config"] is True
    assert manifest["metadata"]["has_initrd"] is True

    # Test store.get_artifact returns bound KernelMetadata
    kernel_meta = store.get_artifact(info.id, KernelMetadata)
    assert kernel_meta.read_bytes(KernelFile.IMAGE) == b"FAKE_BZIMAGE_DATA"
    assert kernel_meta.read_bytes(KernelFile.VMLINUX) == dummy_elf
    assert kernel_meta.read_optional_bytes(KernelOptionalFile.INITRD) == b"FAKE_INITRD_DATA"
    assert kernel_meta.read_optional_str(KernelOptionalFile.CONFIG) == config_content.decode("utf-8")



def test_cli_import_kernel_and_list_pull(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "database"
    registry = ArtifactRegistry()
    registry.register(KERNEL_DEFINITION)
    monkeypatch.setattr(cli, "_build_store", lambda: ArtifactStore(registry, root))

    image_file = tmp_path / "bzImage"
    image_file.write_bytes(b"CLI_BZIMAGE_DATA")

    dummy_elf = make_dummy_elf(e_machine=183)  # aarch64

    def mock_run_vmlinux_to_elf(input_img: Path, output_elf: Path) -> str:
        output_elf.write_bytes(dummy_elf)
        return "[+] Version string: Linux version 6.1.25-arm64 (build@host)\n"

    import kartifact.artifacts.kernel as kernel_mod

    monkeypatch.setattr(kernel_mod, "run_vmlinux_to_elf", mock_run_vmlinux_to_elf)

    runner = CliRunner()

    # CLI create kernel is rejected
    res_create = runner.invoke(
        cli.app,
        ["create", "kernel", str(tmp_path / "bad"), "--name", "fail"],
    )
    assert res_create.exit_code == 1
    assert "Error: artifact type does not support create: kernel" in res_create.output

    # CLI import-kernel --json
    res_import = runner.invoke(
        cli.app,
        ["--json", "import-kernel", str(image_file), "--name", "arm64-kernel"],
    )
    assert res_import.exit_code == 0, res_import.output
    payload = json.loads(res_import.output)
    assert payload["name"] == "arm64-kernel"
    assert payload["artifact_type"] == "kernel"
    artifact_id = payload["id"]

    # CLI list kernel
    res_list = runner.invoke(cli.app, ["--json", "list", "kernel"])
    assert res_list.exit_code == 0
    list_payload = json.loads(res_list.output)
    assert len(list_payload["artifacts"]) == 1
    assert list_payload["artifacts"][0]["id"] == artifact_id

    # CLI pull
    dest = tmp_path / "cli_pulled"
    res_pull = runner.invoke(cli.app, ["--json", "pull", artifact_id, str(dest)])
    assert res_pull.exit_code == 0
    assert (dest / IMAGE_FILE_NAME).read_bytes() == b"CLI_BZIMAGE_DATA"
    assert (dest / VMLINUX_FILE_NAME).read_bytes() == dummy_elf
    manifest = tomllib.loads((dest / "artifact.toml").read_text(encoding="utf-8"))
    assert manifest["metadata"]["architecture"] == "aarch64"
    assert manifest["metadata"]["version"] == "6.1.25-arm64"
    assert manifest["metadata"]["has_config"] is False
    assert manifest["metadata"]["has_initrd"] is False
