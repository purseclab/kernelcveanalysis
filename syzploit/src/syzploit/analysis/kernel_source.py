"""
analysis.kernel_source — Kernel source context extraction.

Given a local kernel git checkout, extracts relevant source code
for vulnerable functions, struct definitions, and related callers /
callees.  This context is fed to the LLM so it can generate exploits
that match the actual kernel source, not hallucinated APIs.

Also supports extracting Kconfig options and subsystem membership.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.log import console


class KernelSourceContext:
    """Interface to a local kernel source tree (git checkout).

    Provides targeted extraction of function bodies, struct
    definitions, and call-graph neighbours for LLM prompt injection.
    """

    def __init__(self, kernel_tree: str) -> None:
        self._root = Path(kernel_tree).resolve()
        if not self._root.is_dir():
            raise FileNotFoundError(f"Kernel tree not found: {kernel_tree}")

    @property
    def root(self) -> Path:
        return self._root

    # ── Public API ────────────────────────────────────────────────────

    def get_vulnerable_function(
        self,
        function_name: str,
        *,
        max_lines: int = 200,
    ) -> Optional[str]:
        """Extract the full body of a C function from the kernel tree.

        Uses ``git grep`` to locate the function definition, then reads
        the file and extracts lines from the opening brace to the
        matching closing brace.

        Returns the function source or None if not found.
        """
        locations = self._find_function_def(function_name)
        if not locations:
            console.print(f"  [dim]Function {function_name} not found in tree[/]")
            return None

        filepath, lineno = locations[0]
        body = self._extract_function_body(filepath, lineno, max_lines)
        if body:
            console.print(
                f"  [dim]Extracted {function_name} from "
                f"{filepath.relative_to(self._root)}:{lineno} "
                f"({len(body.splitlines())} lines)[/]"
            )
        return body

    def get_struct_definition(
        self,
        struct_name: str,
        *,
        max_lines: int = 150,
    ) -> Optional[str]:
        """Extract a struct definition from kernel headers.

        Searches for ``struct <name> {`` and extracts up to the closing
        ``};``.
        """
        pattern = rf"struct\s+{re.escape(struct_name)}\s*\{{"
        hits = self._grep(pattern, include="*.h", max_results=5)
        if not hits:
            # Also search .c files (some structs are defined there)
            hits = self._grep(pattern, include="*.c", max_results=5)
        if not hits:
            return None

        filepath, lineno = hits[0]
        return self._extract_brace_block(filepath, lineno, max_lines)

    def get_related_functions(
        self,
        function_name: str,
        *,
        max_callers: int = 5,
        max_callees: int = 5,
    ) -> Dict[str, List[str]]:
        """Find callers and callees of a function (best-effort via grep).

        Returns ``{"callers": [...], "callees": [...]}``.
        This is a rough text-based approximation — for precise results
        use cscope or CTags.
        """
        result: Dict[str, List[str]] = {"callers": [], "callees": []}

        # Callers: lines that call function_name (excluding its definition)
        caller_hits = self._grep(
            rf"{re.escape(function_name)}\s*\(",
            include="*.c",
            max_results=50,
        )
        seen_files: set[str] = set()
        for fpath, lno in caller_hits:
            rel = str(fpath.relative_to(self._root))
            if rel not in seen_files:
                # Read the enclosing function name
                enclosing = self._enclosing_function(fpath, lno)
                if enclosing and enclosing != function_name:
                    result["callers"].append(f"{enclosing} ({rel}:{lno})")
                    seen_files.add(rel)
            if len(result["callers"]) >= max_callers:
                break

        # Callees: functions called from within function_name's body
        body = self.get_vulnerable_function(function_name, max_lines=300)
        if body:
            # Simple regex: word followed by ( that isn't a keyword
            keywords = {
                "if", "for", "while", "switch", "return", "sizeof",
                "typeof", "case", "goto", function_name,
            }
            calls = re.findall(r"\b([a-zA-Z_]\w*)\s*\(", body)
            seen: set[str] = set()
            for c in calls:
                if c not in keywords and c not in seen:
                    seen.add(c)
                    result["callees"].append(c)
                if len(result["callees"]) >= max_callees:
                    break

        return result

    def get_file_for_function(self, function_name: str) -> Optional[str]:
        """Return the relative path of the file containing a function."""
        locations = self._find_function_def(function_name)
        if locations:
            return str(locations[0][0].relative_to(self._root))
        return None

    def get_kconfig_for_file(self, filepath: str) -> List[str]:
        """Find Kconfig symbols that control compilation of a source file.

        Looks in the Makefile of the file's directory for ``obj-$(CONFIG_X)``
        entries mentioning the file's object.
        """
        p = Path(filepath)
        if p.is_absolute():
            p = p.relative_to(self._root)

        obj_name = p.stem + ".o"
        makefile = self._root / p.parent / "Makefile"
        if not makefile.exists():
            return []

        configs: List[str] = []
        try:
            text = makefile.read_text(errors="replace")
            for line in text.splitlines():
                if obj_name in line:
                    m = re.search(r"CONFIG_(\w+)", line)
                    if m:
                        configs.append(f"CONFIG_{m.group(1)}")
        except OSError:
            pass
        return configs

    def get_subsystem(self, function_name: str) -> str:
        """Guess the kernel subsystem from the file path."""
        filepath = self.get_file_for_function(function_name)
        if not filepath:
            return "unknown"

        parts = Path(filepath).parts
        subsystem_dirs = {
            "drivers": 2,  # drivers/binder → "binder"
            "fs": 1,
            "net": 1,
            "kernel": 1,
            "mm": 0,
            "security": 1,
            "ipc": 0,
            "block": 0,
            "io_uring": 0,
        }
        for i, part in enumerate(parts):
            if part in subsystem_dirs:
                depth = subsystem_dirs[part]
                if depth > 0 and i + depth < len(parts):
                    return "/".join(parts[i : i + depth + 1])
                return part
        return parts[0] if parts else "unknown"

    def format_context_for_prompt(
        self,
        function_names: List[str],
        struct_names: Optional[List[str]] = None,
        *,
        max_total_lines: int = 500,
    ) -> str:
        """Build a combined source-context block for LLM prompts.

        Extracts each function and struct, truncating to stay under
        *max_total_lines*.
        """
        sections: List[str] = []
        total = 0

        for func in function_names:
            if total >= max_total_lines:
                break
            body = self.get_vulnerable_function(func, max_lines=100)
            if body:
                header = f"// ── {func}() ──"
                section = f"{header}\n{body}"
                lines = section.count("\n") + 1
                sections.append(section)
                total += lines

        for struct in struct_names or []:
            if total >= max_total_lines:
                break
            defn = self.get_struct_definition(struct, max_lines=80)
            if defn:
                header = f"// ── struct {struct} ──"
                section = f"{header}\n{defn}"
                lines = section.count("\n") + 1
                sections.append(section)
                total += lines

        if not sections:
            return ""

        return (
            "=== Kernel Source Context ===\n"
            + "\n\n".join(sections)
        )

    # ── Private helpers ───────────────────────────────────────────────

    def _grep(
        self,
        pattern: str,
        *,
        include: str = "*.c",
        max_results: int = 10,
    ) -> List[Tuple[Path, int]]:
        """Run ``git grep -nP`` in the kernel tree."""
        try:
            result = subprocess.run(
                [
                    "git", "grep", "-nP", "--no-color",
                    f"--include={include}",
                    pattern,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=self._root,
            )
            hits: List[Tuple[Path, int]] = []
            for line in result.stdout.splitlines():
                m = re.match(r"^([^:]+):(\d+):", line)
                if m:
                    hits.append((self._root / m.group(1), int(m.group(2))))
                    if len(hits) >= max_results:
                        break
            return hits
        except (subprocess.SubprocessError, OSError):
            return []

    def _find_function_def(
        self, function_name: str
    ) -> List[Tuple[Path, int]]:
        """Find definition sites of a C function via git grep.

        Looks for the pattern: return_type function_name(...)
        at the start of a line (allowing for type qualifiers).
        """
        # Pattern: function name at start or after type, followed by (
        pattern = rf"^[a-zA-Z_][\w\s\*]*\b{re.escape(function_name)}\s*\("
        return self._grep(pattern, include="*.c", max_results=5)

    def _extract_function_body(
        self, filepath: Path, start_line: int, max_lines: int
    ) -> Optional[str]:
        """Extract a function body starting near *start_line*.

        Scans forward from the function signature to find the opening
        ``{``, then counts braces until balanced.
        """
        try:
            all_lines = filepath.read_text(errors="replace").splitlines()
        except OSError:
            return None

        # Find the opening brace (might be on the same line or next)
        idx = start_line - 1  # 0-based
        brace_start = None
        for i in range(idx, min(idx + 5, len(all_lines))):
            if "{" in all_lines[i]:
                brace_start = i
                break

        if brace_start is None:
            # Return a few lines anyway
            end = min(start_line + max_lines, len(all_lines))
            return "\n".join(all_lines[idx:end])

        # Count braces
        depth = 0
        body_lines: List[str] = []
        for i in range(idx, min(idx + max_lines, len(all_lines))):
            line = all_lines[i]
            body_lines.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0 and i > brace_start:
                break

        return "\n".join(body_lines)

    def _extract_brace_block(
        self, filepath: Path, start_line: int, max_lines: int
    ) -> Optional[str]:
        """Extract a brace-delimited block (struct, enum, etc.)."""
        try:
            all_lines = filepath.read_text(errors="replace").splitlines()
        except OSError:
            return None

        idx = start_line - 1
        depth = 0
        block_lines: List[str] = []
        started = False

        for i in range(idx, min(idx + max_lines, len(all_lines))):
            line = all_lines[i]
            block_lines.append(line)
            depth += line.count("{") - line.count("}")
            if "{" in line:
                started = True
            if started and depth <= 0:
                break

        return "\n".join(block_lines)

    def _enclosing_function(self, filepath: Path, lineno: int) -> Optional[str]:
        """Find the name of the function enclosing a given line number.

        Scans backwards from the line looking for a function definition.
        """
        try:
            lines = filepath.read_text(errors="replace").splitlines()
        except OSError:
            return None

        # Scan backwards for a function definition pattern
        func_re = re.compile(
            r"^[a-zA-Z_][\w\s\*]*\b(\w+)\s*\([^;]*$"
        )
        for i in range(lineno - 1, max(lineno - 200, -1), -1):
            if i < 0 or i >= len(lines):
                continue
            m = func_re.match(lines[i])
            if m:
                return m.group(1)
        return None
