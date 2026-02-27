"""
Utils module for shared utilities across syzploit subpackages.

Provides:
- env: Environment variable and API key management
- debug: Debug logging helpers
- adb: ADB port calculation and device management
- compilation: Cross-compilation utilities
"""

from .env import get_api_key, load_env
from .debug import debug_print
from .adb import (
    calculate_adb_port,
    get_adb_target,
    parse_adb_target,
    instance_from_port,
    ADB_BASE_PORT,
    ADB_DEFAULT_HOST,
)
from .compilation import compile_exploit, verify_syntax

__all__ = [
    'get_api_key',
    'load_env',
    'debug_print',
    # ADB utilities
    'calculate_adb_port',
    'get_adb_target',
    'parse_adb_target',
    'instance_from_port',
    'ADB_BASE_PORT',
    'ADB_DEFAULT_HOST',
    # Compilation utilities
    'compile_exploit',
    'verify_syntax',
]
