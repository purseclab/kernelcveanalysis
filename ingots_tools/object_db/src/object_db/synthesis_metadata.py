from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel

METADATA_FILE_NAME = "metadata.json"


class SynthesisMetadata(BaseModel):
    kernel_name: str
    vmlinux: Path
    codeql_db: Path
    linux_src: Path
    synthesis_data: Path | None = None

    def data_path(self) -> Path:
        if self.synthesis_data is None:
            raise ValueError("synthesis_data is not set on SynthesisMetadata")
        return self.synthesis_data

    def compile_commands_path(self) -> Path:
        return self.data_path() / "compile_commands.json"

    def save(self):
        metadata_path = self.data_path() / METADATA_FILE_NAME
        metadata_path.write_text(self.model_dump_json(), "utf-8")

    @classmethod
    def load(cls, synthesis_data: Path) -> Self:
        metadata_path = synthesis_data / METADATA_FILE_NAME
        metadata = cls.model_validate_json(metadata_path.read_text("utf-8"))
        if metadata.synthesis_data is None:
            metadata.synthesis_data = synthesis_data
        return metadata
