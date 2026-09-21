from typing import Sequence

from ..repository_file import RepositoryFileReader
from .c_parser import ItemSpan, ParsedCFile, extract_item_references
from .header_resolver import HeaderResolver


def resolve_referenced_context(
    expanded_items: Sequence[ItemSpan],
    source_file: ParsedCFile,
    source_content: str,
    commit_id: str,
    reader: RepositoryFileReader,
    header_resolver: HeaderResolver | None = None,
    max_context_items: int = 15,
) -> list[str]:
    """Resolve referenced functions and types in expanded items from current file and direct headers."""
    if not expanded_items:
        return []

    resolver = header_resolver or HeaderResolver()
    headers = resolver.resolve_all_direct_headers(
        commit_id=commit_id,
        source_file_path=source_file.path,
        includes=source_file.includes,
        reader=reader,
    )

    all_called_functions: set[str] = set()
    all_referenced_types: set[str] = set()

    for item in expanded_items:
        refs = extract_item_references(item, source_content)
        all_called_functions.update(refs.called_functions)
        all_referenced_types.update(refs.referenced_types)

    expanded_names = {it.name for it in expanded_items if it.name}
    resolved_blocks: list[str] = []
    seen_names: set[str] = set(expanded_names)

    # 1. Look for intra-file definitions
    for name in sorted(all_called_functions | all_referenced_types):
        if len(resolved_blocks) >= max_context_items:
            break
        if name in source_file.name_to_item and name not in seen_names:
            item = source_file.name_to_item[name]
            resolved_blocks.append(f"/* Context: {item.name} from {source_file.path} */\n{item.code}")
            seen_names.add(name)
            if item.name:
                seen_names.add(item.name)

    # 2. Look across directly included headers
    for name in sorted(all_called_functions | all_referenced_types):
        if len(resolved_blocks) >= max_context_items:
            break
        if name in seen_names:
            continue

        for header in headers:
            if name in header.name_to_item:
                item = header.name_to_item[name]
                resolved_blocks.append(f"/* Context: {item.name} from {header.path} */\n{item.code}")
                seen_names.add(name)
                if item.name:
                    seen_names.add(item.name)
                break

    return resolved_blocks
