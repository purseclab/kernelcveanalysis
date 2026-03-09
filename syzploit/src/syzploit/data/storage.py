"""
data.storage — File and directory management.

Centralises paths relative to ``$SYZBOT_REPRO_DATA_DIR`` (or a default).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import requests


def base_dir() -> Path:
    """Return the root data directory (from env or default ``./data``)."""
    p = Path(os.environ.get("SYZBOT_REPRO_DATA_DIR", "./data")).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir(name: str) -> Path:
    """Return (and create) a named sub-directory under the base data dir."""
    p = base_dir() / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def syzkaller_db_dir() -> Path:
    """Directory for syzkaller/syzbot bug metadata."""
    return data_dir("syzbot_bugs")


def download_file(path: Path, url: str) -> None:
    """Download *url* to *path* if not already present."""
    if path.exists():
        return
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)


def write_if_missing(path: Path, content: str) -> None:
    """Write *content* to *path* only if the file doesn't already exist."""
    if path.exists():
        return
    path.write_text(content)
