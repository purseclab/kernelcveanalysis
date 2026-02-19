from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class TargetType(StrEnum):
    Linux = "linux"
    Android = "android"
    Any = "any"


class Metadata(BaseModel):
    name: str
    description: str
    target: TargetType
    version: Optional[str] = None


@dataclass
class Primitive:
    """
    Represents an exploit primitive.
    """

    path: Path
    metadata: Metadata
    detailed_description: str
    code: str

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def description(self) -> str:
        return self.metadata.description


def load_primitives(directory: Path) -> list[Primitive]:
    """
    Loads primitives from a specified directory.

    The directory is expected to contain subdirectories, each representing a primitive
    and containing 'metadata.json', 'PRIMITIVE.md', and 'primitive.c'.
    """
    primitives = []

    if not directory.exists() or not directory.is_dir():
        print(f"Warning: Primitive directory '{directory}' does not exist.")
        return []

    for item in directory.iterdir():
        if item.is_dir():
            metadata_path = item / "metadata.json"
            markdown_path = item / "PRIMITIVE.md"
            code_path = item / "primitive.c"

            if metadata_path.exists() and markdown_path.exists() and code_path.exists():
                try:
                    with open(metadata_path, "r") as f:
                        metadata = Metadata.model_validate_json(f.read())

                    with open(markdown_path, "r") as f:
                        markdown = f.read()

                    with open(code_path, "r") as f:
                        code = f.read()

                    primitive = Primitive(
                        path=item,
                        metadata=metadata,
                        detailed_description=markdown,
                        code=code,
                    )
                    primitives.append(primitive)
                except Exception as e:
                    print(f"Error loading primitive from {item}: {e}")
            else:
                print(f"Warning: missing files in primitive {item}")
                pass

    return primitives


def load_default_primitives() -> list[Primitive]:
    """
    Loads primitives from the default data directory included in the package.
    """
    # Assuming 'data' is a sibling of this file in the installed package
    package_dir = Path(__file__).parent.parent
    data_dir = package_dir / "primitive_data"
    return load_primitives(data_dir)
