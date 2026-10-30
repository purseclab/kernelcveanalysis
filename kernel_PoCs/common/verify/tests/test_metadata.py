from __future__ import annotations

import json
from pathlib import Path

from verify_kernel_poc.metadata import (
    BEGIN_MARKER,
    END_MARKER,
    scan_metadata_file,
)


def _write_block(data: bytes, block: object) -> bytes:
    raw = json.dumps(block).encode()
    return data + BEGIN_MARKER + raw + END_MARKER


def test_scan_embedded_metadata(tmp_path: Path) -> None:
    metadata = {
        "schema": 1,
        "target": "android",
        "arch": "aarch64",
        "artifact": "executable",
        "run": "exec",
        "payload": {"kind": "listening_shell", "port": 1337},
        "root_check": {"mode": "shell"},
    }
    path = tmp_path / "exp"
    path.write_bytes(_write_block(b"\x00ELF\x00", metadata) + b"\x00tail")

    scan = scan_metadata_file(path)

    assert scan.found
    assert scan.metadata is not None
    assert scan.metadata.target == "android"
    assert scan.metadata.payload.kind == "listening_shell"
    assert scan.metadata.payload.port == 1337
    assert scan.warnings == []


def test_scan_skips_malformed_block(tmp_path: Path) -> None:
    path = tmp_path / "exp"
    path.write_bytes(
        BEGIN_MARKER
        + b"{not json}"
        + END_MARKER
        + _write_block(b"", {"schema": 1, "artifact": "executable"})
    )

    scan = scan_metadata_file(path)

    assert scan.found
    assert scan.metadata is not None
    assert len(scan.warnings) == 1


def test_scan_missing_end_marker(tmp_path: Path) -> None:
    path = tmp_path / "exp"
    path.write_bytes(BEGIN_MARKER + b'{"schema":1}')

    scan = scan_metadata_file(path)

    assert not scan.found
    assert scan.warnings
    assert "no end marker" in scan.warnings[0]


def test_scan_no_metadata(tmp_path: Path) -> None:
    path = tmp_path / "exp"
    path.write_bytes(b"plain executable")

    scan = scan_metadata_file(path)

    assert not scan.found
    assert scan.warnings == []
