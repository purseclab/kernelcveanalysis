from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Metadata, MetadataError

BEGIN_MARKER = b"__KPOC_METADATA_V1_BEGIN__"
END_MARKER = b"__KPOC_METADATA_V1_END__"


@dataclass(slots=True)
class MetadataScan:
    metadata: Metadata | None = None
    raw_json: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return self.metadata is not None


def scan_metadata_file(path: Path) -> MetadataScan:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise MetadataError(f"failed to read {path}: {exc}") from exc

    scan = MetadataScan()
    search_from = 0
    block_index = 0
    while True:
        begin = data.find(BEGIN_MARKER, search_from)
        if begin < 0:
            break
        block_index += 1
        json_start = begin + len(BEGIN_MARKER)
        end = data.find(END_MARKER, json_start)
        if end < 0:
            scan.warnings.append(
                f"metadata block {block_index} has a begin marker but no end marker"
            )
            break
        raw_bytes = data[json_start:end]
        search_from = end + len(END_MARKER)
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            scan.warnings.append(
                f"metadata block {block_index} is not valid UTF-8: {exc}"
            )
            continue
        try:
            parsed = json.loads(raw_text)
            metadata = Metadata.from_dict(parsed)
        except (json.JSONDecodeError, ValueError, MetadataError) as exc:
            scan.warnings.append(f"metadata block {block_index} is invalid: {exc}")
            continue

        # Prefer the first valid block. This keeps the result stable even if a
        # compiler merged another copy of the header into the binary.
        scan.metadata = metadata
        scan.raw_json = json.dumps(parsed, indent=2, sort_keys=True)
        break

    return scan
