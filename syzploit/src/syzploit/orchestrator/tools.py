"""
orchestrator.tools — Tool registry and base interface.

Each *tool* is a callable that takes a ``TaskContext`` and returns it
(mutated).  Tools are registered by name so the agent can reference
them in its reasoning loop.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Protocol

from ..core.config import Config
from .context import TaskContext


class Tool(Protocol):
    """Protocol every tool must satisfy."""

    name: str
    description: str

    def __call__(self, ctx: TaskContext, cfg: Config, **kwargs: Any) -> TaskContext: ...


class ToolRegistry:
    """
    Registry of available tools the agent can invoke.

    Tools self-register via the ``@registry.register`` decorator or
    programmatically via ``registry.add()``.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, Tool] = {}

    def add(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        """Return a list of {name, description} for prompt injection."""
        return [{"name": t.name, "description": t.description} for t in self._tools.values()]

    def names(self) -> List[str]:
        return list(self._tools.keys())

    def register(self, name: str, description: str) -> Callable:
        """Decorator to register a plain function as a tool."""

        def decorator(fn: Callable) -> Callable:
            fn.name = name  # type: ignore[attr-defined]
            fn.description = description  # type: ignore[attr-defined]
            self._tools[name] = fn  # type: ignore[assignment]
            return fn

        return decorator


# ── Global default registry ───────────────────────────────────────────

default_registry = ToolRegistry()
