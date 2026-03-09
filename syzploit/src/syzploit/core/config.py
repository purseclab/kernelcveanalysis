"""
core.config — Centralised configuration management.

Loads settings from environment variables and .env files.
Every other module accesses configuration through ``Config``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field

_env_loaded = False


def _load_dotenv() -> None:
    """Load .env from the project root and other standard paths.

    Search order:
        1. ``<project-root>/.env``  (two levels above ``core/``)
        2. ``$CWD/.env``
        3. ``~/.env``

    All matching files are loaded (later files do NOT override earlier
    values because ``python-dotenv`` respects existing env vars by
    default).
    """
    global _env_loaded
    if _env_loaded:
        return

    # <project-root> is  …/syzploit/  (contains pyproject.toml)
    _pkg_root = Path(__file__).resolve().parent.parent          # src/syzploit
    _project_root = _pkg_root.parent.parent                     # syzploit/

    search = [
        _project_root / ".env",       # syzploit/.env  (primary)
        _pkg_root / ".env",           # src/syzploit/.env
        Path.cwd() / ".env",          # working directory
        Path.home() / ".env",         # home fallback
    ]
    for p in search:
        if p.exists():
            load_dotenv(p, override=False)
    _env_loaded = True


class Config(BaseModel):
    """
    Global runtime configuration.

    Attributes are populated from environment variables / .env.
    Create via ``load_config()`` which pre-loads the env file.
    """

    # ── LLM ──────────────────────────────────────────────────────────
    llm_model: str = Field(default="gpt-4o", description="Default LiteLLM model identifier")
    llm_decision_model: str = Field(
        default="",
        description=(
            "Cheaper/faster model for agent routing decisions. "
            "Falls back to llm_model when empty. Set to e.g. "
            "'gpt-4o-mini' to reduce cost."
        ),
    )
    llm_analysis_model: str = Field(
        default="",
        description=(
            "Model for crash/CVE/blog analysis and root-cause reasoning. "
            "Falls back to llm_model when empty."
        ),
    )
    llm_codegen_model: str = Field(
        default="",
        description=(
            "Model for code generation: exploit synthesis, reproducer "
            "generation, and compilation-error fixing. Falls back to "
            "llm_model when empty."
        ),
    )
    llm_planning_model: str = Field(
        default="",
        description=(
            "Model for exploit strategy planning. "
            "Falls back to llm_model when empty."
        ),
    )
    llm_temperature: float = 0.2
    llm_max_tokens: int = 8192
    llm_decision_max_tokens: int = Field(
        default=4096,
        description="Max tokens for agent decision calls (JSON output)",
    )
    api_key: Optional[str] = None  # resolved at load time

    # ── Paths ────────────────────────────────────────────────────────
    data_dir: Path = Field(default_factory=lambda: Path(os.environ.get("SYZBOT_REPRO_DATA_DIR", "./data")))
    workspace_dir: Path = Field(default_factory=Path.cwd)

    # ── Infrastructure ───────────────────────────────────────────────
    default_arch: str = "arm64"
    default_platform: str = "android"
    ssh_host: str = "localhost"
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_key: Optional[str] = None
    adb_base_port: int = 6520
    instance: Optional[int] = None
    persistent: bool = True
    setup_tunnels: bool = False

    # ── VM control ───────────────────────────────────────────────────
    start_cmd: Optional[str] = None
    stop_cmd: Optional[str] = None
    exploit_start_cmd: Optional[str] = None
    gdb_port: int = 1234
    kernel_image: Optional[str] = None
    vmlinux_path: Optional[str] = None
    system_map: Optional[str] = None

    # ── Compilation ──────────────────────────────────────────────────
    compile_timeout: int = 120

    # ── Debug ────────────────────────────────────────────────────────
    debug: bool = False
    verbose: bool = False


def _resolve_api_key() -> Optional[str]:
    """Return the first available LLM API key from env."""
    for var in (
        "OPENAI_API_KEY",
        "OPENAI_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
    ):
        val = os.environ.get(var)
        if val:
            return val
    return None


def load_config(**overrides: object) -> Config:
    """
    Load ``Config`` from environment, applying optional overrides.

    Call this once at startup; pass the returned object to subsystems.
    """
    _load_dotenv()
    defaults: dict = {
        "api_key": _resolve_api_key(),
        "debug": os.environ.get("SYZPLOIT_DEBUG", "").lower() in ("1", "true", "yes"),
        "verbose": os.environ.get("SYZPLOIT_VERBOSE", "").lower() in ("1", "true", "yes"),
    }
    model_env = os.environ.get("SYZPLOIT_LLM_MODEL")
    if model_env:
        defaults["llm_model"] = model_env
    decision_model_env = os.environ.get("SYZPLOIT_LLM_DECISION_MODEL")
    if decision_model_env:
        defaults["llm_decision_model"] = decision_model_env
    analysis_model_env = os.environ.get("SYZPLOIT_LLM_ANALYSIS_MODEL")
    if analysis_model_env:
        defaults["llm_analysis_model"] = analysis_model_env
    codegen_model_env = os.environ.get("SYZPLOIT_LLM_CODEGEN_MODEL")
    if codegen_model_env:
        defaults["llm_codegen_model"] = codegen_model_env
    planning_model_env = os.environ.get("SYZPLOIT_LLM_PLANNING_MODEL")
    if planning_model_env:
        defaults["llm_planning_model"] = planning_model_env
    # SSH from env
    ssh_host = os.environ.get("SYZPLOIT_SSH_HOST")
    if ssh_host:
        defaults.setdefault("ssh_host", ssh_host)
    ssh_port = os.environ.get("SYZPLOIT_SSH_PORT")
    if ssh_port:
        defaults.setdefault("ssh_port", int(ssh_port))
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]
