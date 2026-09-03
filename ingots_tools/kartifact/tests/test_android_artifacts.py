from __future__ import annotations

import json
from pathlib import Path
import tomllib
from typing import Iterator

import pytest  # type: ignore[import-not-found]
from typer.testing import CliRunner

from kartifact import (
    ArtifactNotFoundError,
    ArtifactRegistry,
    ArtifactStore,
    InvalidArtifactError,
    cli,
    default_registry,
)
from kartifact.artifacts import (
    ANDROID_APP_DEFINITION,
    ANDROID_SYSTEM_DEFINITION,
    AndroidAppMetadata,
    AndroidSystemMetadata,
    AppFile,
    KERNEL_DEFINITION,
    KernelMetadata,
)
from kartifact.toml_io import ARTIFACT_FILE_NAME, render_artifact
from kartifact.models import ArtifactHeader


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ArtifactStore]:
    val = ArtifactStore(default_registry, tmp_path / "db")
    yield val
    val.close()


def test_android_app_template_and_mandatory_apk(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "app_template"
    store.create_template("android_app", folder, name="my-bluetooth-app")

    assert (folder / ARTIFACT_FILE_NAME).is_file()
    manifest = tomllib.loads((folder / ARTIFACT_FILE_NAME).read_text(encoding="utf-8"))
    assert manifest["artifact"]["type"] == "android_app"
    assert manifest["artifact"]["name"] == "my-bluetooth-app"

    # Writing without app.apk fails
    with pytest.raises(InvalidArtifactError, match="missing mandatory file for artifact: app.apk"):
        store.write_artifact(folder)

    # Adding app.apk succeeds
    (folder / "app.apk").write_bytes(b"FAKE_APK_BYTES")
    (folder / "NOTES.md").write_text("# Vulnerability Notes\nAttacking Bluetooth service.", encoding="utf-8")
    info = store.write_artifact(folder)
    assert info.name == "my-bluetooth-app"

    # Read back via get_artifact
    app_meta = store.get_artifact(info.id, AndroidAppMetadata)
    assert app_meta.read_bytes(AppFile.APK) == b"FAKE_APK_BYTES"

    # Pull to destination and verify NOTES.md is preserved
    checkout = tmp_path / "app_checkout"
    store.pull_artifact(info.id, checkout)
    assert (checkout / "app.apk").read_bytes() == b"FAKE_APK_BYTES"
    assert (checkout / "NOTES.md").read_text(encoding="utf-8") == "# Vulnerability Notes\nAttacking Bluetooth service."



def test_android_app_file_overrides(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "app_custom"
    folder.mkdir()
    header = ArtifactHeader(type="android_app", name="settings-app")
    meta = AndroidAppMetadata(package_name="com.android.settings")
    meta.set_file_overrides({"app.apk": "Settings.apk"})
    (folder / ARTIFACT_FILE_NAME).write_text(render_artifact(header, meta), encoding="utf-8")

    # Missing Settings.apk fails
    with pytest.raises(InvalidArtifactError, match="missing mandatory file for artifact: Settings.apk"):
        store.write_artifact(folder)

    (folder / "Settings.apk").write_bytes(b"SETTINGS_APK_CONTENT")
    info = store.write_artifact(folder)

    # get_artifact reads through override
    retrieved = store.get_artifact(info.id, AndroidAppMetadata)
    assert retrieved.file_overrides == {"app.apk": "Settings.apk"}
    assert retrieved.read_bytes(AppFile.APK) == b"SETTINGS_APK_CONTENT"


def test_store_existence_and_lookup_by_name(tmp_path: Path, store: ArtifactStore) -> None:
    folder = tmp_path / "app_lookup"
    folder.mkdir()
    header = ArtifactHeader(type="android_app", name="nfc-app")
    meta = AndroidAppMetadata(package_name="com.android.nfc")
    (folder / ARTIFACT_FILE_NAME).write_text(render_artifact(header, meta), encoding="utf-8")
    (folder / "app.apk").write_bytes(b"NFC_APK")
    info = store.write_artifact(folder)

    # has_artifact_name
    assert store.has_artifact_name("android_app", "nfc-app") is True
    assert store.has_artifact_name("android_app", "nonexistent") is False

    # ensure_artifact_exists
    store.ensure_artifact_exists("android_app", "nfc-app")
    with pytest.raises(InvalidArtifactError, match="referenced 'android_app' artifact does not exist: 'missing'"):
        store.ensure_artifact_exists("android_app", "missing")

    # get_artifact_by_name
    by_name = store.get_artifact_by_name("android_app", "nfc-app", AndroidAppMetadata)
    assert by_name.package_name == "com.android.nfc"
    assert by_name.read_bytes(AppFile.APK) == b"NFC_APK"

    with pytest.raises(ArtifactNotFoundError, match="no visible 'android_app' artifact with name 'missing'"):
        store.get_artifact_by_name("android_app", "missing")


def test_android_system_write_validation(tmp_path: Path, store: ArtifactStore) -> None:
    # 1. Create kernel artifact directly in store
    k_staging = tmp_path / "kernel_staging"
    k_staging.mkdir()
    k_header = ArtifactHeader(type="kernel", name="goldfish-5.10")
    k_meta = KernelMetadata.default()
    (k_staging / ARTIFACT_FILE_NAME).write_text(render_artifact(k_header, k_meta), encoding="utf-8")
    (k_staging / "image").write_bytes(b"KERNEL_IMAGE")
    (k_staging / "vmlinux").write_bytes(b"KERNEL_VMLINUX")
    store.commit_imported_artifact(k_staging)

    # 2. Create app artifact in store
    app_staging = tmp_path / "app_staging"
    app_staging.mkdir()
    app_header = ArtifactHeader(type="android_app", name="bluetooth-app")
    app_meta = AndroidAppMetadata()
    (app_staging / ARTIFACT_FILE_NAME).write_text(render_artifact(app_header, app_meta), encoding="utf-8")
    (app_staging / "app.apk").write_bytes(b"BT_APK")
    store.write_artifact(app_staging)

    # 3. Create android_system working dir
    sys_dir = tmp_path / "sys_working"
    sys_dir.mkdir()
    sys_header = ArtifactHeader(type="android_system", name="pixel-goldfish-env")

    # Referencing non-existent kernel fails
    bad_k_meta = AndroidSystemMetadata(kernel_name="nonexistent-kernel", app_names=["bluetooth-app"])
    (sys_dir / ARTIFACT_FILE_NAME).write_text(render_artifact(sys_header, bad_k_meta), encoding="utf-8")
    with pytest.raises(InvalidArtifactError, match="referenced 'kernel' artifact does not exist: 'nonexistent-kernel'"):
        store.write_artifact(sys_dir)

    # Referencing non-existent app fails
    bad_app_meta = AndroidSystemMetadata(kernel_name="goldfish-5.10", app_names=["bluetooth-app", "ghost-app"])
    (sys_dir / ARTIFACT_FILE_NAME).write_text(render_artifact(sys_header, bad_app_meta), encoding="utf-8")
    with pytest.raises(InvalidArtifactError, match="referenced 'android_app' artifact does not exist: 'ghost-app'"):
        store.write_artifact(sys_dir)

    # Valid kernel and apps succeed
    good_meta = AndroidSystemMetadata(kernel_name="goldfish-5.10", app_names=["bluetooth-app"])
    (sys_dir / ARTIFACT_FILE_NAME).write_text(render_artifact(sys_header, good_meta), encoding="utf-8")
    (sys_dir / "NOTES.md").write_text("# Composition Notes", encoding="utf-8")
    sys_info = store.write_artifact(sys_dir)
    assert sys_info.name == "pixel-goldfish-env"

    # get_artifact
    sys_loaded = store.get_artifact(sys_info.id, AndroidSystemMetadata)
    assert sys_loaded.kernel_name == "goldfish-5.10"
    assert sys_loaded.app_names == ["bluetooth-app"]

    # pull
    sys_checkout = tmp_path / "sys_checkout"
    store.pull_artifact(sys_info.id, sys_checkout)
    assert (sys_checkout / "NOTES.md").read_text(encoding="utf-8") == "# Composition Notes"


def test_cli_android_app_and_system_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "cli_db"
    monkeypatch.setattr(cli, "_build_store", lambda: ArtifactStore(default_registry, root))

    runner = CliRunner()

    # Create app
    app_dir = tmp_path / "cli_app"
    res_app_create = runner.invoke(cli.app, ["create", "android_app", str(app_dir), "--name", "cli-app"])
    assert res_app_create.exit_code == 0

    (app_dir / "app.apk").write_bytes(b"CLI_APK")
    res_app_write = runner.invoke(cli.app, ["--json", "write", str(app_dir)])
    assert res_app_write.exit_code == 0
    app_payload = json.loads(res_app_write.output)
    assert app_payload["name"] == "cli-app"

    # Create dummy kernel in store
    k_dir = tmp_path / "cli_kernel"
    k_dir.mkdir()
    k_header = ArtifactHeader(type="kernel", name="cli-kernel")
    (k_dir / ARTIFACT_FILE_NAME).write_text(render_artifact(k_header, KernelMetadata.default()), encoding="utf-8")
    (k_dir / "image").write_bytes(b"IMG")
    (k_dir / "vmlinux").write_bytes(b"VMLINUX")
    ArtifactStore(default_registry, root).commit_imported_artifact(k_dir)

    # Create system
    sys_dir = tmp_path / "cli_sys"
    res_sys_create = runner.invoke(cli.app, ["create", "android_system", str(sys_dir), "--name", "cli-sys"])
    assert res_sys_create.exit_code == 0

    # Modify system artifact.toml with valid kernel and app
    sys_toml = f"""
[artifact]
type = "android_system"
name = "cli-sys"

[metadata]
kernel_name = "cli-kernel"
app_names = ["cli-app"]
"""
    (sys_dir / ARTIFACT_FILE_NAME).write_text(sys_toml, encoding="utf-8")

    res_sys_write = runner.invoke(cli.app, ["--json", "write", str(sys_dir)])
    assert res_sys_write.exit_code == 0
    sys_payload = json.loads(res_sys_write.output)
    assert sys_payload["name"] == "cli-sys"
