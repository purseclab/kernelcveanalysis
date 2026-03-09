"""
infra.adb — ADB port calculation and device management for Cuttlefish.
"""

from __future__ import annotations

ADB_BASE_PORT = 6520
ADB_DEFAULT_HOST = "0.0.0.0"


def calculate_adb_port(instance: int) -> int:
    """Calculate ADB port for a Cuttlefish instance (1-based)."""
    if instance < 1:
        raise ValueError(f"Instance number must be >= 1, got {instance}")
    return ADB_BASE_PORT + (instance - 1)


def get_adb_target(instance: int, host: str = ADB_DEFAULT_HOST) -> str:
    """Return ``host:port`` string for the given Cuttlefish instance."""
    return f"{host}:{calculate_adb_port(instance)}"


def parse_adb_target(target: str) -> tuple[str, int]:
    """Parse ``host:port`` into ``(host, port)``."""
    if ":" not in target:
        raise ValueError(f"Invalid ADB target: {target}")
    host, port_str = target.rsplit(":", 1)
    return host, int(port_str)


def instance_from_port(port: int) -> int:
    """Calculate Cuttlefish instance number from ADB port."""
    if port < ADB_BASE_PORT:
        raise ValueError(f"Port {port} is below base port {ADB_BASE_PORT}")
    return (port - ADB_BASE_PORT) + 1
