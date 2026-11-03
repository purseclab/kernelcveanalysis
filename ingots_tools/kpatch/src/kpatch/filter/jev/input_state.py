from dataclasses import dataclass


@dataclass
class InputState:
    patch_decsription: str
    # Mapping from patched files to diffs with full patched function bodies.
    patched_files: dict[str, str]
    # Nearby functions in the call chain, supplied as additional context.
    context_functions: list[str]


__all__ = ["InputState"]
