from dataclasses import dataclass
import difflib
from typing import Sequence

from ...diff import DiffFile, DiffFileType
from ..base import FilterContext, FilteredCommit
from ..repository_file import RepositoryFileReader
from .c_parser import ItemKind, ItemSpan, parse_c_file
from .context_resolver import resolve_referenced_context
from .header_resolver import HeaderResolver
from .jev_filter import InputState

_C_EXTENSIONS: frozenset[str] = frozenset({"c", "h", "cc", "cpp", "cxx", "hpp", "hh"})
_EXPANDABLE_KINDS: frozenset[ItemKind] = frozenset({
    ItemKind.FUNCTION,
    ItemKind.STRUCT,
    ItemKind.UNION,
    ItemKind.ENUM,
    ItemKind.MACRO,
})


def is_c_source(path: str) -> bool:
    """Return whether the path represents a C or C++ source/header file."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext in _C_EXTENSIONS


@dataclass(frozen=True, slots=True)
class LineSpan:
    """A 1-indexed line span [start, end] inclusive."""

    start: int
    end: int

    @property
    def is_empty(self) -> bool:
        return self.end < self.start

    def overlaps_or_adjacent(self, other: "LineSpan") -> bool:
        if self.is_empty or other.is_empty:
            return False
        return not (self.end < other.start - 1 or other.end < self.start - 1)

    def merge(self, other: "LineSpan") -> "LineSpan":
        if self.is_empty:
            return other
        if other.is_empty:
            return self
        return LineSpan(min(self.start, other.start), max(self.end, other.end))


@dataclass(frozen=True, slots=True)
class _DiffTarget:
    old_span: LineSpan
    new_span: LineSpan
    name: str
    expanded_new_item: ItemSpan | None


def _find_item_covering(items: Sequence[ItemSpan], line: int) -> ItemSpan | None:
    for it in items:
        if it.start_line <= line <= it.end_line and it.kind in _EXPANDABLE_KINDS:
            return it
    return None


def _find_items_intersecting(items: Sequence[ItemSpan], start: int, end: int) -> list[ItemSpan]:
    return [
        it for it in items
        if it.kind in _EXPANDABLE_KINDS and not (it.end_line < start or it.start_line > end)
    ]


def generate_extended_file_diff(
    diff_file: DiffFile,
    old_content: str,
    new_content: str,
) -> tuple[str, list[ItemSpan]]:
    """Generate an extended coverage diff for diff_file, returning the diff text and expanded items."""
    file_old = diff_file.old_file or diff_file.file
    file_new = diff_file.file

    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    # For binary files or non-C files, fall back to standard diff representation
    if diff_file.binary or not is_c_source(diff_file.file):
        diff_lines = list(difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{file_old}",
            tofile=f"b/{file_new}",
        ))
        return "".join(diff_lines), []

    old_parsed = parse_c_file(file_old, old_content)
    new_parsed = parse_c_file(file_new, new_content)

    targets: list[_DiffTarget] = []
    expanded_items: list[ItemSpan] = []

    for chunk in diff_file.chunks:
        old_chunk_end = chunk.old_start + max(1, chunk.old_count) - 1 if chunk.old_count > 0 else chunk.old_start
        new_chunk_end = chunk.new_start + max(1, chunk.new_count) - 1 if chunk.new_count > 0 else chunk.new_start

        hit_old = _find_items_intersecting(old_parsed.items, chunk.old_start, old_chunk_end) if chunk.old_count > 0 else []
        hit_new = _find_items_intersecting(new_parsed.items, chunk.new_start, new_chunk_end) if chunk.new_count > 0 else []

        if hit_old and hit_new:
            for o_it in hit_old:
                # Match new item by name, or use hit_new[0]
                n_it = next((n for n in hit_new if n.name == o_it.name), hit_new[0])
                targets.append(_DiffTarget(
                    old_span=LineSpan(o_it.start_line, o_it.end_line),
                    new_span=LineSpan(n_it.start_line, n_it.end_line),
                    name=o_it.name,
                    expanded_new_item=n_it,
                ))
                expanded_items.append(n_it)
        elif hit_old and not hit_new:
            # Check if this item exists in new_items (e.g. deletion inside existing item)
            covering_in_new = _find_item_covering(new_parsed.items, chunk.new_start)
            if covering_in_new is not None and covering_in_new.name == hit_old[0].name:
                n_it = covering_in_new
                for o_it in hit_old:
                    targets.append(_DiffTarget(
                        old_span=LineSpan(o_it.start_line, o_it.end_line),
                        new_span=LineSpan(n_it.start_line, n_it.end_line),
                        name=o_it.name,
                        expanded_new_item=n_it,
                    ))
                    expanded_items.append(n_it)
            else:
                # Pure deletion of item
                for o_it in hit_old:
                    targets.append(_DiffTarget(
                        old_span=LineSpan(o_it.start_line, o_it.end_line),
                        new_span=LineSpan(chunk.new_start, chunk.new_start - 1),
                        name=o_it.name,
                        expanded_new_item=None,
                    ))
        elif hit_new and not hit_old:
            # Check if this item exists in old_items (e.g. addition inside existing item)
            covering_in_old = _find_item_covering(old_parsed.items, chunk.old_start)
            if covering_in_old is not None and covering_in_old.name == hit_new[0].name:
                o_it = covering_in_old
                for n_it in hit_new:
                    targets.append(_DiffTarget(
                        old_span=LineSpan(o_it.start_line, o_it.end_line),
                        new_span=LineSpan(n_it.start_line, n_it.end_line),
                        name=n_it.name,
                        expanded_new_item=n_it,
                    ))
                    expanded_items.append(n_it)
            else:
                # Pure addition of item
                for n_it in hit_new:
                    targets.append(_DiffTarget(
                        old_span=LineSpan(chunk.old_start, chunk.old_start - 1),
                        new_span=LineSpan(n_it.start_line, n_it.end_line),
                        name=n_it.name,
                        expanded_new_item=n_it,
                    ))
                    expanded_items.append(n_it)
        else:
            # Change outside any expandable item (e.g. #include at top of file)
            # Use chunk range with 3 lines of context
            old_ctx_start = max(1, chunk.old_start - 3)
            old_ctx_end = min(len(old_lines), old_chunk_end + 3)
            new_ctx_start = max(1, chunk.new_start - 3)
            new_ctx_end = min(len(new_lines), new_chunk_end + 3)

            targets.append(_DiffTarget(
                old_span=LineSpan(old_ctx_start, old_ctx_end) if chunk.old_count > 0 else LineSpan(chunk.old_start, chunk.old_start - 1),
                new_span=LineSpan(new_ctx_start, new_ctx_end) if chunk.new_count > 0 else LineSpan(chunk.new_start, chunk.new_start - 1),
                name=chunk.section or "",
                expanded_new_item=None,
            ))

    # Deduplicate targets by span
    unique_targets: list[_DiffTarget] = []
    for t in targets:
        if not any(u.old_span == t.old_span and u.new_span == t.new_span for u in unique_targets):
            unique_targets.append(t)

    # Sort targets by line order
    unique_targets.sort(key=lambda t: (t.new_span.start if not t.new_span.is_empty else t.old_span.start))

    # Merge overlapping or adjacent targets
    merged_targets: list[_DiffTarget] = []
    for t in unique_targets:
        if not merged_targets:
            merged_targets.append(t)
            continue
        last = merged_targets[-1]
        if last.old_span.overlaps_or_adjacent(t.old_span) or last.new_span.overlaps_or_adjacent(t.new_span):
            merged = _DiffTarget(
                old_span=last.old_span.merge(t.old_span),
                new_span=last.new_span.merge(t.new_span),
                name=last.name or t.name,
                expanded_new_item=last.expanded_new_item or t.expanded_new_item,
            )
            merged_targets[-1] = merged
        else:
            merged_targets.append(t)

    # Generate unified diff hunks
    hunks: list[str] = []
    for target in merged_targets:
        old_slice = old_lines[target.old_span.start - 1 : target.old_span.end] if not target.old_span.is_empty else []
        new_slice = new_lines[target.new_span.start - 1 : target.new_span.end] if not target.new_span.is_empty else []

        patch_lines = list(difflib.unified_diff(
            old_slice,
            new_slice,
            n=max(len(old_slice), len(new_slice)),
        ))
        if len(patch_lines) >= 3:
            old_start = target.old_span.start if not target.old_span.is_empty else (target.old_span.start)
            new_start = target.new_span.start if not target.new_span.is_empty else (target.new_span.start)
            sig = f" {target.name}" if target.name else ""
            hunk_header = f"@@ -{old_start},{len(old_slice)} +{new_start},{len(new_slice)} @@{sig}\n"
            patch_lines[2] = hunk_header
            hunks.append("".join(patch_lines[2:]))

    file_header = f"--- a/{file_old}\n+++ b/{file_new}\n"
    full_diff = file_header + "".join(hunks) if hunks else ""

    # Deduplicate expanded_items
    dedup_expanded: list[ItemSpan] = []
    seen_items: set[str] = set()
    for it in expanded_items:
        key = f"{it.name}:{it.start_line}"
        if key not in seen_items:
            seen_items.add(key)
            dedup_expanded.append(it)

    return full_diff, dedup_expanded


def generate_extended_commit_diff(
    commit: FilteredCommit,
    reader: RepositoryFileReader,
    header_resolver: HeaderResolver | None = None,
    max_context_items: int = 15,
) -> tuple[dict[str, str], list[str]]:
    """Generate extended coverage diffs and resolve context functions for an entire commit."""
    resolver = header_resolver or HeaderResolver()
    parent_commit_id = commit.original.parents[0].commit_id if commit.original.parents else None
    commit_id = commit.original.commit_id

    patched_files: dict[str, str] = {}
    all_context_functions: list[str] = []
    seen_context: set[str] = set()

    for diff_file in commit.diff.files:
        old_path = diff_file.old_file or diff_file.file
        new_path = diff_file.file

        old_content = ""
        if parent_commit_id is not None and diff_file.change_type != DiffFileType.NEW:
            try:
                old_content = reader.read_file(parent_commit_id, old_path).decode("utf-8", errors="replace")
            except (FileNotFoundError, RuntimeError, ValueError):
                old_content = ""

        new_content = ""
        if diff_file.change_type != DiffFileType.DELETE:
            try:
                new_content = reader.read_file(commit_id, new_path).decode("utf-8", errors="replace")
            except (FileNotFoundError, RuntimeError, ValueError):
                new_content = ""

        ext_diff, expanded_items = generate_extended_file_diff(diff_file, old_content, new_content)
        patched_files[new_path] = ext_diff

        # If items were expanded in this file, resolve their referenced context
        if expanded_items and new_content:
            new_parsed = parse_c_file(new_path, new_content)
            ctx_items = resolve_referenced_context(
                expanded_items=expanded_items,
                source_file=new_parsed,
                source_content=new_content,
                commit_id=commit_id,
                reader=reader,
                header_resolver=resolver,
                max_context_items=max_context_items,
            )
            for ctx in ctx_items:
                if ctx not in seen_context and len(all_context_functions) < max_context_items:
                    seen_context.add(ctx)
                    all_context_functions.append(ctx)

    return patched_files, all_context_functions


def build_input_state(
    commit: FilteredCommit,
    context: FilterContext,
    reader: RepositoryFileReader | None = None,
    max_context_items: int = 15,
) -> InputState:
    """Build an InputState populated with extended coverage diffs and referenced context."""
    if reader is not None:
        patched_files, context_funcs = generate_extended_commit_diff(
            commit, reader, max_context_items=max_context_items
        )
    else:
        with RepositoryFileReader(context.repo) as new_reader:
            patched_files, context_funcs = generate_extended_commit_diff(
                commit, new_reader, max_context_items=max_context_items
            )

    return InputState(
        patch_decsription=commit.original.message,
        patched_files=patched_files,
        context_functions=context_funcs,
    )
