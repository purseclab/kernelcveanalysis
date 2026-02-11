"""
Environment variable and API key management.

Centralizes .env loading and API key resolution so that
only ONE .env file is needed at the syzploit package root.
"""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


# Cache to avoid repeated file system lookups
_env_loaded = False


def load_env() -> None:
    """Load the single .env file from the syzploit package root."""
    global _env_loaded
    if _env_loaded:
        return

    # Look for .env relative to this file:
    # utils/env.py -> syzploit/.env
    env_paths = [
        Path(__file__).parent.parent / ".env",       # syzploit/.env (primary)
        Path(__file__).parent.parent.parent / ".env", # src/.env
        Path.home() / ".env",                         # ~/.env (fallback)
    ]

    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(env_path)
            _env_loaded = True
            return

    _env_loaded = True  # Mark as attempted even if no file found


def get_api_key() -> Optional[str]:
    """
    Get OpenAI API key from environment or .env file.

    Checks OPENAI_API_KEY and OPENAI_KEY environment variables.
    If not found, loads the .env file and retries.

    Returns:
        The API key string, or None if not found.
    """
    # Check environment first (fastest path)
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")
    if api_key:
        return api_key

    # Try loading .env
    load_env()
    return os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENAI_KEY")


def get_hf_token() -> Optional[str]:
    """Get HuggingFace access token from environment or .env file."""
    token = os.environ.get("HF_ACCESS_TOKEN")
    if token:
        return token

    load_env()
    return os.environ.get("HF_ACCESS_TOKEN")
