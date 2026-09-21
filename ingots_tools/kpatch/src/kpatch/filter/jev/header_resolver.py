import posixpath
from typing import Sequence

from ..repository_file import RepositoryFileReader
from .c_parser import IncludeDirective, ParsedCFile, parse_c_file


def resolve_include_candidates(source_file_path: str, include: IncludeDirective) -> list[str]:
    """Generate candidate repository paths for a C #include directive."""
    candidates: list[str] = []
    source_dir = posixpath.dirname(source_file_path)

    # For quote includes ("..."), check relative to the source file first
    if not include.is_system:
        candidates.append(posixpath.normpath(posixpath.join(source_dir, include.path)))

    # Standard Linux kernel include search paths
    candidates.extend([
        posixpath.join("include", include.path),
        posixpath.join("include/uapi", include.path),
        posixpath.join("arch/x86/include", include.path),
        posixpath.join("arch/x86/include/uapi", include.path),
        posixpath.join("arch/arm64/include", include.path),
        posixpath.join("arch/arm64/include/uapi", include.path),
    ])

    # Fallback for system includes if placed in source dir
    if include.is_system:
        candidates.append(posixpath.normpath(posixpath.join(source_dir, include.path)))

    return candidates


class HeaderResolver:
    """Resolve and cache parsed header files across git commits."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], ParsedCFile] = {}

    def resolve_and_parse(
        self,
        commit_id: str,
        source_file_path: str,
        include: IncludeDirective,
        reader: RepositoryFileReader,
    ) -> ParsedCFile | None:
        """Resolve an include directive to a file in git and return its parsed AST."""
        candidates = resolve_include_candidates(source_file_path, include)
        for candidate in candidates:
            cache_key = (commit_id, candidate)
            if cache_key in self._cache:
                return self._cache[cache_key]

            try:
                content_bytes = reader.read_file(commit_id, candidate)
            except (FileNotFoundError, RuntimeError, ValueError):
                continue

            content = content_bytes.decode("utf-8", errors="replace")
            parsed = parse_c_file(candidate, content)
            self._cache[cache_key] = parsed
            return parsed

        return None

    def resolve_all_direct_headers(
        self,
        commit_id: str,
        source_file_path: str,
        includes: Sequence[IncludeDirective],
        reader: RepositoryFileReader,
    ) -> list[ParsedCFile]:
        """Resolve and parse all directly included header files for a source file."""
        resolved: list[ParsedCFile] = []
        for inc in includes:
            parsed = self.resolve_and_parse(commit_id, source_file_path, inc, reader)
            if parsed is not None:
                resolved.append(parsed)
        return resolved
