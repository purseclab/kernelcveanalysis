from __future__ import annotations

import fcntl
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import uuid
from pathlib import Path

import docker  # type: ignore

from .logging_utils import get_logger

TOOL_BUNDLE_SCHEMA = "v1-linux-amd64"
TOOL_NAMES = ("ksandbox-daemon", "rg", "fd")

logger = get_logger(__name__)


def tool_cache_root() -> Path:
    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg_cache) if xdg_cache else Path.home() / ".cache"
    return base / "ksandbox" / "tool-bundles"


def tool_bundle_version() -> str:
    package_root = Path(__file__).resolve().parents[2]
    digest = hashlib.sha256()
    sources = [
        package_root / "tool-bundle.Dockerfile",
        package_root / "daemon" / "Cargo.toml",
        package_root / "daemon" / "Cargo.lock",
        package_root / "daemon" / "src" / "main.rs",
    ]
    for source in sources:
        digest.update(source.name.encode("utf-8"))
        digest.update(source.read_bytes())
    return f"{TOOL_BUNDLE_SCHEMA}-{digest.hexdigest()[:12]}"


def tool_bundle_path() -> Path:
    return tool_cache_root() / tool_bundle_version()


def _valid_bundle(path: Path) -> bool:
    for name in TOOL_NAMES:
        binary = path / name
        try:
            if not binary.is_file() or not os.access(binary, os.X_OK):
                return False
            with binary.open("rb") as handle:
                if handle.read(4) != b"\x7fELF":
                    return False
        except OSError:
            return False
    return True


def _extract_bundle(archive: bytes, destination: Path) -> None:
    found: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar.getmembers():
            name = Path(member.name).name
            if name not in TOOL_NAMES or not member.isfile():
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            target = destination / name
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o555)
            found.add(name)
    missing = set(TOOL_NAMES) - found
    if missing:
        raise RuntimeError(f"tool bundle archive is missing: {sorted(missing)}")


def _build_bundle(client) -> Path:
    package_root = Path(__file__).resolve().parents[2]
    bundle_image = f"ksandbox-tools:{tool_bundle_version()}"
    logger.info("Building static ksandbox tool bundle image %s", bundle_image)
    image, _ = client.images.build(
        path=str(package_root),
        dockerfile="tool-bundle.Dockerfile",
        rm=True,
        tag=bundle_image,
        platform="linux/amd64",
    )
    # Docker requires a command even though this temporary container is never started.
    container = client.containers.create(
        image, command=["/opt/ksandbox/bin/ksandbox-daemon"]
    )
    try:
        stream, _ = container.get_archive("/opt/ksandbox/bin")
        archive = b"".join(stream)
    finally:
        container.remove(force=True)

    cache_root = tool_cache_root()
    temp_path = Path(tempfile.mkdtemp(prefix=".bundle-", dir=cache_root))
    try:
        _extract_bundle(archive, temp_path)
        if not _valid_bundle(temp_path):
            raise RuntimeError("built ksandbox tool bundle failed validation")
        destination = tool_bundle_path()
        old_path: Path | None = None
        if destination.exists():
            old_path = cache_root / f".old-{uuid.uuid4().hex}"
            destination.replace(old_path)
        try:
            temp_path.replace(destination)
        except Exception:
            if old_path is not None and old_path.exists():
                old_path.replace(destination)
            raise
        if old_path is not None:
            shutil.rmtree(old_path, ignore_errors=True)
        for stale_path in cache_root.glob(f"{TOOL_BUNDLE_SCHEMA}-*"):
            if stale_path != destination and stale_path.is_dir():
                shutil.rmtree(stale_path, ignore_errors=True)
        return destination
    except Exception:
        shutil.rmtree(temp_path, ignore_errors=True)
        raise


def ensure_tool_bundle(*, force: bool = False, client=None) -> Path:
    destination = tool_bundle_path()
    if not force and _valid_bundle(destination):
        return destination

    cache_root = tool_cache_root()
    cache_root.mkdir(parents=True, exist_ok=True)
    lock_path = cache_root / ".setup.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if not force and _valid_bundle(destination):
            return destination
        return _build_bundle(client or docker.from_env())

